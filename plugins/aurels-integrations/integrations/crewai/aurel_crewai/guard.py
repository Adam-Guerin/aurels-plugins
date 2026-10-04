from __future__ import annotations

import json
import copy
import asyncio
import inspect
import hashlib
import math
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .redaction import redact

MAX_AUREL_RESPONSE_BYTES = 1024 * 1024
MAX_AUREL_REQUEST_BYTES = 1024 * 1024
MAX_AUREL_STRING_CHARS = 65536
MAX_AUREL_ARRAY_ITEMS = 512
MAX_AUREL_OBJECT_KEYS = 512


class AurelActionPayloadError(RuntimeError):
    """The requested action cannot be evaluated without changing its meaning."""


class AurelProtocolError(AurelActionPayloadError):
    """Invalid policy data is never an outage that can allow execution."""
_DESTRUCTIVE_CONTENT = re.compile(
    r"rm\s+-[a-z]*r[a-z]*f|remove-item\s+.*-recurse|format\s+[a-z]:|drop\s+(?:database|table|schema)|truncate\s+table|delete\s+from|\b(?:send|transfer|pay|purchase|delete|destroy|overwrite|chmod|chown)\b",
    re.IGNORECASE,
)


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never forward the workspace API key to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AurelToolBlockedError(RuntimeError):
    pass


@dataclass(frozen=True)
class AurelCrewAIConfig:
    enabled: bool = field(default_factory=lambda: _env_bool("AUREL_ENABLED", True))
    api_url: str = field(default_factory=lambda: os.getenv("AURELS_API_URL") or os.getenv("AUREL_API_URL") or os.getenv("INTENTGUARD_API_URL") or "https://www.aurels.dev")
    api_key: str = field(default_factory=lambda: os.getenv("AURELS_API_KEY") or os.getenv("AUREL_API_KEY") or os.getenv("INTENTGUARD_API_KEY") or "")
    timeout_ms: int = field(default_factory=lambda: _env_int("AUREL_TIMEOUT_MS", 1500, 100, 30000))
    fail_mode: str = field(default_factory=lambda: "open" if os.getenv("AUREL_FAIL_MODE") == "open" else "closed")
    fail_open_privileged_actions: str = field(default_factory=lambda: _env_enum("AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS", {"block", "allow"}, "block"))
    telemetry_enabled: bool = field(default_factory=lambda: _env_bool("AUREL_TELEMETRY_ENABLED", True))
    telemetry_async: bool = field(default_factory=lambda: _env_bool("AUREL_TELEMETRY_ASYNC", True))
    include_results: bool = field(default_factory=lambda: _env_bool("AUREL_TELEMETRY_INCLUDE_RESULTS", False))
    max_payload_bytes: int = field(default_factory=lambda: _env_int("AUREL_TELEMETRY_MAX_PAYLOAD_BYTES", _env_int("AUREL_MAX_PAYLOAD_BYTES", 32768, 1024, 262144), 1024, 262144))
    redaction_enabled: bool = field(default_factory=lambda: _env_bool("AUREL_REDACTION_ENABLED", True))
    tools_include: tuple[str, ...] = field(default_factory=lambda: tuple(_env_list("AUREL_TOOLS_INCLUDE")))
    tools_exclude: tuple[str, ...] = field(default_factory=lambda: tuple(_env_list("AUREL_TOOLS_EXCLUDE")))
    approval_handler: Callable[[Mapping[str, Any], Mapping[str, Any]], bool] | None = None


class AurelCrewAIGuard:
    def __init__(self, config: AurelCrewAIConfig | None = None):
        self.config = config or AurelCrewAIConfig()
        parsed = urllib.parse.urlparse(self.config.api_url)
        if not parsed.hostname or (parsed.port is not None and parsed.port == 0):
            raise ValueError("Aurel API URL must contain a valid host and port")
        loopback_http = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}
        if (parsed.scheme != "https" and not loopback_http) or parsed.username or parsed.password:
            raise ValueError("Aurel API URL requires HTTPS or loopback HTTP without credentials")

    def run_protected(
        self,
        *,
        tool_name: str,
        args: Any,
        execute: Callable[[Any], Any],
        agent_id: str | None = None,
        task_id: str | None = None,
    ) -> Any:
        if not _should_intercept_tool(tool_name, self.config):
            return execute(args)

        try:
            evaluated_args = _snapshot_action_arguments(args)
        except AurelActionPayloadError as exc:
            raise AurelToolBlockedError("Aurel security verification is unavailable.") from exc
        action = self._action(tool_name, evaluated_args, agent_id, task_id)
        pre_started = _now_ms()
        try:
            decision = self._post_json("/api/v1/actions/evaluate", action)
            decision = _parse_decision(decision)
        except Exception as exc:
            if not isinstance(exc, AurelActionPayloadError) and self.config.fail_mode == "open" and not _should_block_fail_open_outage(tool_name, args, self.config):
                print(f"[aurel-crewai] fail-open verification failure ({type(exc).__name__})")
                return execute(evaluated_args)
            raise AurelToolBlockedError("Aurel security verification is unavailable.") from exc

        kind = decision.get("decision")
        call_args = evaluated_args
        if kind in {"block", "quarantine"}:
            self._telemetry(action, decision.get("traceId"), "blocked", _now_ms() - pre_started, decision=decision)
            raise AurelToolBlockedError("Aurel blocked this action because it violates the active security policy.")
        if kind == "require_approval":
            self._telemetry(action, decision.get("traceId"), "approval_requested", _now_ms() - pre_started, decision=decision)
            if self.config.approval_handler is None:
                raise AurelToolBlockedError("Aurel requires human approval before this action can run.")
            try:
                # Approval callbacks can display or annotate their own copies,
                # but cannot replace the payload whose decision was evaluated.
                approved = self.config.approval_handler(copy.deepcopy(action), copy.deepcopy(decision)) is True
            except Exception as exc:
                self._telemetry(action, decision.get("traceId"), "failure", _now_ms() - pre_started, decision=decision, error_category=type(exc).__name__)
                raise AurelToolBlockedError("Aurel approval failed before this action could run.") from exc
            if not approved:
                self._telemetry(action, decision.get("traceId"), "approval_denied", _now_ms() - pre_started, decision=decision)
                raise AurelToolBlockedError("Aurel requires human approval before this action can run.")
            self._telemetry(action, decision.get("traceId"), "approval_allowed", _now_ms() - pre_started, decision=decision)
        if kind == "rewrite":
            call_args = decision.get("rewrittenArguments", evaluated_args)
        elif kind not in {"allow", "require_approval"}:
            raise AurelToolBlockedError("Aurel blocked this action because it violates the active security policy.")

        tool_started = _now_ms()

        def record_completion(status, result=None, error=None):
            self._telemetry(
                action, decision.get("traceId"), status, _now_ms() - pre_started,
                _now_ms() - tool_started, type(error).__name__ if error is not None else None,
                result=result, executed_args=call_args,
                original_args=evaluated_args if kind == "rewrite" else None,
                rewrite_applied=kind == "rewrite",
            )

        try:
            result = execute(call_args)
            if inspect.isawaitable(result):
                async def await_completion():
                    try:
                        completed = await result
                    except (Exception, asyncio.CancelledError) as error:
                        record_completion("failure", error=error)
                        raise
                    record_completion("success", result=completed)
                    return completed

                return await_completion()
            record_completion("success", result=result)
            return result
        except Exception as exc:
            record_completion("failure", error=exc)
            raise

    def _action(self, tool_name: str, args: Any, agent_id: str | None, task_id: str | None) -> dict[str, Any]:
        return {
            "version": "1",
            "integration": "crewai",
            "action": {
                "id": f"crewai-act-{uuid.uuid4()}",
                "name": tool_name,
                "type": "crewai.tool",
                "arguments": args,
            },
            "agent": {"id": agent_id, "runId": task_id},
            "context": {"metadata": {"sdk": "crewai"}},
            "timestamp": _iso_now(),
        }
    def _telemetry(
        self,
        action: Mapping[str, Any],
        trace_id: str | None,
        status: str,
        preflight_ms: int,
        tool_ms: int | None = None,
        error_category: str | None = None,
        result: Any = None,
        executed_args: Any = None,
        original_args: Any = None,
        rewrite_applied: bool = False,
        decision: Mapping[str, Any] | None = None,
    ) -> None:
        if not self.config.telemetry_enabled:
            return
        post_started = _now_ms()
        metadata = {
            "tool": action["action"]["name"],
            "args": redact(executed_args if executed_args is not None else action["action"]["arguments"], enabled=self.config.redaction_enabled, max_payload_bytes=self.config.max_payload_bytes),
            "rewriteApplied": rewrite_applied,
            "resultIncluded": self.config.include_results and result is not None,
        }
        if decision is not None:
            metadata["decision"] = decision.get("decision")
            metadata["riskScore"] = decision.get("riskScore")
            metadata["category"] = decision.get("category")
            metadata["ruleIds"] = decision.get("ruleIds")
        if rewrite_applied:
            metadata["originalArgs"] = redact(original_args, enabled=self.config.redaction_enabled, max_payload_bytes=self.config.max_payload_bytes)
        if self.config.include_results and result is not None:
            metadata["result"] = redact(result, enabled=self.config.redaction_enabled, max_payload_bytes=self.config.max_payload_bytes)
        telemetry = {
            "version": "1",
            "integration": "crewai",
            "actionId": action["action"]["id"],
            "traceId": trace_id,
            "agent": action.get("agent"),
            "outcome": {"status": status, "durationMs": tool_ms, "errorCategory": error_category},
            "timings": {
                "aurelPreflightLatencyMs": preflight_ms,
                "toolExecutionLatencyMs": tool_ms,
                "aurelPostflightLatencyMs": max(0, _now_ms() - post_started),
            },
            "metadata": metadata,
            "timestamp": _iso_now(),
        }

        if self.config.telemetry_async:
            thread = threading.Thread(target=lambda: self._send_telemetry(telemetry), name="aurel-crewai-telemetry", daemon=True)
            try:
                thread.start()
            except Exception:
                # Reporting failure must never turn completed tool execution
                # into an apparent failure that the caller might retry.
                print("[aurel-crewai] telemetry worker unavailable; event was not sent")
            return
        self._send_telemetry(telemetry)


    def _send_telemetry(self, telemetry: Mapping[str, Any]) -> None:
        try:
            _retry(lambda: self._post_json("/api/v1/actions/telemetry", telemetry))
        except Exception as exc:
            print(f"[aurel-crewai] telemetry failed ({type(exc).__name__})")

    def _post_json(self, path: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not self.config.api_key:
            raise RuntimeError("Aurel API key is not configured")
        data = _json_payload(payload, exact=path == "/api/v1/actions/evaluate")
        req = urllib.request.Request(
            _normalize_base_url(self.config.api_url) + path,
            data=data,
            method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": self.config.api_key,
                "idempotency-key": _idempotency_key_for(path, payload),
                "user-agent": "aurel-crewai/0.1.0",
            },
        )
        try:
            with urllib.request.build_opener(_RejectRedirects()).open(req, timeout=max(0.1, self.config.timeout_ms / 1000)) as res:
                raw = res.read(MAX_AUREL_RESPONSE_BYTES + 1)
                if len(raw) > MAX_AUREL_RESPONSE_BYTES:
                    raise AurelProtocolError("Aurel response exceeded maximum size")
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"Aurel HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Aurel network error: {exc.reason}") from exc
        except TimeoutError as exc:
            raise RuntimeError("Aurel request timed out") from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AurelProtocolError("Aurel returned invalid JSON") from exc


def _snapshot_action_arguments(args: Any) -> Any:
    try:
        serialized = json.dumps(args, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        if len(serialized.encode("utf-8")) > MAX_AUREL_REQUEST_BYTES:
            raise AurelActionPayloadError("Aurel action payload exceeded maximum size; exact arguments were not evaluated")
        return json.loads(serialized)
    except AurelActionPayloadError:
        raise
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise AurelActionPayloadError("Aurel action payload is not losslessly JSON-serializable") from exc


def protect_tool(tool: Any, guard: AurelCrewAIGuard | None = None, *, name: str | None = None) -> Any:
    active_guard = guard or AurelCrewAIGuard()
    tool_name = name or getattr(tool, "name", None) or tool.__class__.__name__

    if callable(tool) and not hasattr(tool, "_run"):
        if inspect.iscoroutinefunction(tool) or inspect.iscoroutinefunction(getattr(tool, "__call__", None)):
            async def protected_async_callable(*args: Any, **kwargs: Any) -> Any:
                payload = _invocation_payload(args, kwargs)
                result = active_guard.run_protected(tool_name=tool_name, args=payload, execute=lambda safe_args: _invoke_with_original_shape(tool, safe_args, args, kwargs))
                return await result if inspect.isawaitable(result) else result

            protected_async_callable.__name__ = getattr(tool, "__name__", f"aurel_{tool_name}")
            return protected_async_callable

        def protected_callable(*args: Any, **kwargs: Any) -> Any:
            payload = _invocation_payload(args, kwargs)
            return active_guard.run_protected(tool_name=tool_name, args=payload, execute=lambda safe_args: _invoke_with_original_shape(tool, safe_args, args, kwargs))

        protected_callable.__name__ = getattr(tool, "__name__", f"aurel_{tool_name}")
        return protected_callable

    original_run = getattr(tool, "_run", None)
    original_arun = getattr(tool, "_arun", None)
    if not callable(original_run):
        raise TypeError("CrewAI tool must be callable or expose _run")

    class ProtectedTool(tool.__class__):
        def _run(self, *args: Any, **kwargs: Any) -> Any:
            payload = _invocation_payload(args, kwargs)
            return active_guard.run_protected(
                tool_name=tool_name,
                args=payload,
                execute=lambda safe_args: _invoke_with_original_shape(original_run, safe_args, args, kwargs),
            )

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            if not callable(original_arun):
                raise TypeError("This tool does not implement async execution")
            payload = _invocation_payload(args, kwargs)
            result = active_guard.run_protected(
                tool_name=tool_name, args=payload,
                execute=lambda safe_args: _invoke_with_original_shape(original_arun, safe_args, args, kwargs),
            )
            return await result if inspect.isawaitable(result) else result

    protected = ProtectedTool.__new__(ProtectedTool)
    # Pydantic v2 BaseModel instances keep runtime state outside __dict__.
    # Copy the complete model state before exposing the subclass as a tool;
    # otherwise CrewAI's BaseTool.run() fails before reaching our _run hook.
    model_copy = getattr(tool, "model_copy", None)
    if callable(model_copy):
        copied = model_copy(deep=False)
        protected.__dict__.update(copied.__dict__)
        for state_name in ("__pydantic_fields_set__", "__pydantic_extra__", "__pydantic_private__"):
            if hasattr(copied, state_name):
                object.__setattr__(protected, state_name, getattr(copied, state_name))
    else:
        protected.__dict__.update(getattr(tool, "__dict__", {}))
    return protected


def _invocation_payload(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> Any:
    if args and kwargs:
        return {"args": list(args), "kwargs": dict(kwargs)}
    return kwargs if kwargs else args[0] if len(args) == 1 else list(args)


def _invoke_with_original_shape(fn: Callable[..., Any], safe_args: Any, original_args: tuple[Any, ...], original_kwargs: Mapping[str, Any]) -> Any:
    if original_args and original_kwargs:
        if (not isinstance(safe_args, Mapping) or set(safe_args) != {"args", "kwargs"}
                or not isinstance(safe_args["args"], list) or not isinstance(safe_args["kwargs"], dict)):
            raise AurelToolBlockedError("Aurel replacement arguments do not describe the complete invocation.")
        return fn(*safe_args["args"], **safe_args["kwargs"])
    if original_kwargs:
        return fn(**safe_args) if isinstance(safe_args, Mapping) else fn(safe_args)
    if len(original_args) == 1:
        if isinstance(original_args[0], Mapping):
            return fn(safe_args)
        if isinstance(safe_args, Mapping):
            return fn(**safe_args)
        return fn(safe_args)
    if isinstance(safe_args, list):
        return fn(*safe_args)
    if isinstance(safe_args, tuple):
        return fn(*safe_args)
    return fn(safe_args)


def _now_ms() -> int:
    return int(time.perf_counter() * 1000)


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _should_intercept_tool(tool_name: str, config: AurelCrewAIConfig) -> bool:
    if not config.enabled:
        return False
    return not config.tools_include or tool_name in config.tools_include


def _should_block_fail_open_outage(tool_name: str, args: Any, config: AurelCrewAIConfig) -> bool:
    if config.fail_open_privileged_actions == "allow":
        return False
    return _is_privileged_tool_name(tool_name) or _contains_destructive_content(args)


def _contains_destructive_content(value: Any, seen: set[int] | None = None) -> bool:
    if isinstance(value, str):
        return bool(_DESTRUCTIVE_CONTENT.search(value))
    if not isinstance(value, (Mapping, list, tuple)):
        return False
    visited = seen if seen is not None else set()
    identity = id(value)
    if identity in visited:
        return False
    visited.add(identity)
    try:
        items = value.values() if isinstance(value, Mapping) else value
        return any(_contains_destructive_content(item, visited) for item in items)
    except Exception:
        return True
    finally:
        visited.discard(identity)


def _is_privileged_tool_name(tool_name: str) -> bool:
    normalized = tool_name.lower().replace("-", "_").replace(".", "_").replace(":", "_")
    privileged = {
        "bash",
        "shell",
        "terminal",
        "exec",
        "execute",
        "process",
        "spawn",
        "run_command",
        "file_write",
        "write_file",
        "delete_file",
        "remove_file",
        "patch",
        "apply_patch",
        "git_push",
        "network",
        "browser",
        "http",
        "fetch",
        "email",
        "send_email",
        "message",
        "database",
        "db",
        "sql",
        "cloud",
        "package",
        "install",
        "schedule",
        "subagent",
        "delegate",
        "mcp",
        "api",
        "payment",
        "finance",
        "permission",
        "auth",
        "credential",
    }
    return any(part in privileged for part in normalized.split("_"))


def _parse_decision(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict) or not isinstance(body.get("decision"), str):
        raise AurelProtocolError("Aurel returned a malformed decision")
    if body["decision"] == "flag":
        parsed = dict(body)
        parsed["decision"] = "require_approval"
        body = parsed
    if body["decision"] not in {"allow", "block", "require_approval", "rewrite", "quarantine"}:
        raise AurelProtocolError("Aurel returned an unsupported decision")
    try:
        _validate_decision_metadata(body)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise AurelProtocolError("Aurel returned invalid decision metadata") from exc
    if body["decision"] == "rewrite":
        if "rewrittenArguments" not in body:
            raise AurelProtocolError("Aurel returned a rewrite without replacement arguments")
        body = {**body, "rewrittenArguments": _snapshot_action_arguments(body["rewrittenArguments"])}
    return body


def _json_payload(payload: Mapping[str, Any], *, exact: bool = False) -> bytes:
    if exact:
        try:
            data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, RecursionError) as exc:
            raise AurelActionPayloadError("Aurel action payload is not losslessly JSON-serializable") from exc
        if len(data) > MAX_AUREL_REQUEST_BYTES:
            raise AurelActionPayloadError("Aurel action payload exceeded maximum size; exact arguments were not evaluated")
        return data
    data = json.dumps(_json_safe(payload, set(), 0), separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(data) <= MAX_AUREL_REQUEST_BYTES:
        return data
    fallback = json.dumps(_json_safe(_bound_action_arguments(payload), set(), 0), separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(fallback) <= MAX_AUREL_REQUEST_BYTES:
        return fallback
    raise RuntimeError("Aurel request payload exceeded maximum size")


def _json_safe(value: Any, seen: set[int], depth: int) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else "[NonFiniteNumber]"
    if isinstance(value, str):
        return value[:MAX_AUREL_STRING_CHARS] + "...[truncated]" if len(value) > MAX_AUREL_STRING_CHARS else value
    if depth > 12:
        return "[MaxDepth]"
    if isinstance(value, (list, tuple)):
        identity = id(value)
        if identity in seen:
            return "[Circular]"
        seen.add(identity)
        try:
            items = [_json_safe(item, seen, depth + 1) for item in list(value)[:MAX_AUREL_ARRAY_ITEMS]]
            if len(value) > MAX_AUREL_ARRAY_ITEMS:
                items.append(f"[{len(value) - MAX_AUREL_ARRAY_ITEMS} items truncated]")
            return items
        finally:
            seen.remove(identity)
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in seen:
            return "[Circular]"
        seen.add(identity)
        try:
            try:
                keys = list(value)[:MAX_AUREL_OBJECT_KEYS]
                key_count = len(value)
            except Exception:
                return "[UnserializableMapping]"
            output = {}
            for key in keys:
                try:
                    entry = value[key]
                except Exception:
                    output[str(key)] = "[UnserializableProperty]"
                    continue
                output[str(key)] = _json_safe(entry, seen, depth + 1)
            if key_count > MAX_AUREL_OBJECT_KEYS:
                output["__truncatedKeys"] = key_count - MAX_AUREL_OBJECT_KEYS
            return output
        finally:
            seen.remove(identity)
    return f"[{type(value).__name__}]"


def _bound_action_arguments(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    action = payload.get("action")
    if not isinstance(action, Mapping):
        return {"truncated": True, "reason": "payload_limit"}
    return {
        **payload,
        "action": {
            **action,
            "arguments": {"truncated": True, "reason": "payload_limit"},
        },
    }


def _validate_decision_metadata(body: Mapping[str, Any]) -> None:
    risk_score = body.get("riskScore")
    if (
        risk_score is not None
        and (not isinstance(risk_score, (int, float)) or isinstance(risk_score, bool) or not math.isfinite(risk_score) or risk_score < 0 or risk_score > 100)
    ):
        raise RuntimeError("Aurel returned an invalid risk score")

    for field in ("reason", "category", "traceId", "policyVersion"):
        value = body.get(field)
        if value is not None and (not isinstance(value, str) or len(value) > 4096):
            raise RuntimeError(f"Aurel returned an invalid {field}")

    rule_ids = body.get("ruleIds")
    if rule_ids is not None:
        if not isinstance(rule_ids, list) or len(rule_ids) > 128 or any(not isinstance(rule_id, str) or len(rule_id) > 512 for rule_id in rule_ids):
            raise RuntimeError("Aurel returned invalid rule IDs")


def _retry(fn: Callable[[], Any]) -> None:
    delays = (0.05, 0.15, 0.35)
    last_error: Exception | None = None
    for index, delay in enumerate(delays):
        try:
            fn()
            return
        except Exception as exc:
            last_error = exc
            if index + 1 < len(delays):
                time.sleep(delay)
    if last_error is not None:
        raise last_error


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    lowered = value.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    return default


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, ""))
    except ValueError:
        value = default
    return max(minimum, min(maximum, value))


def _env_list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _env_enum(name: str, allowed: set[str], default: str) -> str:
    value = os.getenv(name)
    return value if value in allowed else default


def _normalize_base_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def _idempotency_key_for(path: str, payload: Mapping[str, Any]) -> str:
    action = payload.get("action")
    if path.endswith("/evaluate") and isinstance(action, Mapping) and isinstance(action.get("id"), str):
        fingerprint = hashlib.sha256(_json_payload({"action": action})).hexdigest()
        return _idempotency_key("action-evaluate", action["id"], fingerprint)
    if path.endswith("/telemetry") and isinstance(payload.get("actionId"), str):
        outcome = payload.get("outcome")
        status = outcome.get("status") if isinstance(outcome, Mapping) else "unknown"
        fingerprint = hashlib.sha256(_json_payload(payload)).hexdigest()
        return _idempotency_key("action-telemetry", payload["actionId"], status if isinstance(status, str) else "unknown", fingerprint)
    return _idempotency_key("aurel-request", path)


def _idempotency_key(prefix: str, *parts: str) -> str:
    encoded = [urllib.parse.quote(str(part), safe="")[:256] for part in parts]
    return ":".join([prefix, *encoded])
