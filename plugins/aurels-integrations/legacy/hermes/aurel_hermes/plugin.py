from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any, Mapping

from .client import AurelActionPayloadError, AurelClient
from .config import AurelConfig, is_privileged_tool_name, load_config, should_intercept
from .redaction import redact

LOGGER = logging.getLogger("aurel.hermes")
BLOCKED_MESSAGE = "Aurel blocked this action because it violates the active security policy."
UNAVAILABLE_MESSAGE = "Aurel security verification is unavailable."


class AurelHermesPlugin:
    def __init__(self, config: AurelConfig, client: AurelClient | None = None):
        self.config = config
        self.client = client or AurelClient(config)
        self._state: dict[str, dict[str, Any]] = {}
        self._reported: set[str] = set()
        self._lock = threading.Lock()
        self._last_decision: dict[str, Any] | None = None

    def pre_tool_call(self, tool_name: str, args: dict[str, Any] | None = None, task_id: str | None = None, **kwargs: Any) -> dict[str, Any] | None:
        if not should_intercept(tool_name, self.config):
            return None

        started = _now_ms()
        action = normalize_hermes_action(tool_name=tool_name, args=args or {}, task_id=task_id, extra=kwargs)

        try:
            decision = self.client.evaluate_action(action)
            preflight_latency = _now_ms() - started
        except Exception as exc:
            if isinstance(exc, AurelActionPayloadError) or self.config.fail_mode == "closed" or self._should_block_fail_open_outage(tool_name):
                LOGGER.error("Aurel preflight failed; blocking tool call: %s", exc)
                return {"action": "block", "message": UNAVAILABLE_MESSAGE}
            LOGGER.warning("Aurel preflight failed; fail_mode=open allows tool call: %s", exc)
            return None

        self._last_decision = decision
        state = {
            "action_id": action["action"]["id"],
            "trace_id": decision.get("traceId"),
            "agent": action.get("agent"),
            "preflight_latency_ms": preflight_latency,
            "expires_at_ms": _now_ms() + self.config.state_ttl_ms,
            "reported": False,
        }
        tool_call_id = _tool_call_id(kwargs)
        with self._lock:
            self._sweep_state_locked()
            state_key = _state_key(tool_name, task_id, action["action"]["id"] if tool_call_id else None)
            self._state[state_key] = state
            self._reported.discard(state_key)

        result = self._map_decision(decision, tool_name)
        if result and result.get("action") == "block":
            self._record_pre_execution_outcome(state_key, state, decision, tool_name, args or {}, task_id)
        elif result and result.get("action") == "approve":
            self._record_approval_requested(state, decision, tool_name, args or {}, task_id)
        return result

    def post_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        result: Any = None,
        task_id: str | None = None,
        duration_ms: int | None = None,
        **kwargs: Any,
    ) -> None:
        if not self.config.telemetry.enabled or not should_intercept(tool_name, self.config):
            return

        post_started = _now_ms()
        key = _state_key(tool_name, task_id, _tool_call_id(kwargs))
        with self._lock:
            self._sweep_state_locked()
            if key in self._reported:
                return
            state = self._state.pop(key, None)
            self._reported.add(key)
            if len(self._reported) > 2048:
                self._reported.clear()

        metadata: dict[str, Any] = {
            "tool": tool_name,
            "args": redact(args or {}, enabled=self.config.redaction.enabled, max_payload_bytes=self.config.telemetry.max_payload_bytes),
            "task_id": task_id,
        }
        if self.config.telemetry.include_results:
            metadata["result"] = redact(result, enabled=self.config.redaction.enabled, max_payload_bytes=self.config.telemetry.max_payload_bytes)

        telemetry = {
            "version": "1",
            "integration": "hermes",
            "actionId": (state or {}).get("action_id") or f"hm-act-{uuid.uuid4()}",
            "traceId": (state or {}).get("trace_id"),
            "agent": (state or {}).get("agent") or {"runId": task_id},
            "outcome": {
                "status": "failure" if _looks_like_failure(result, kwargs) else "success",
                "durationMs": duration_ms,
                "errorCategory": _error_category(result, kwargs),
            },
            "timings": {
                "aurelPreflightLatencyMs": (state or {}).get("preflight_latency_ms"),
                "toolExecutionLatencyMs": duration_ms,
                "aurelPostflightLatencyMs": 0,
            },
            "metadata": metadata,
            "timestamp": _iso_now(),
        }

        telemetry["timings"]["aurelPostflightLatencyMs"] = max(0, _now_ms() - post_started)
        thread = threading.Thread(target=lambda: self._safe_record_telemetry(telemetry), name="aurel-hermes-telemetry", daemon=True)
        thread.start()

    def _record_pre_execution_outcome(
        self,
        state_key: str,
        state: Mapping[str, Any],
        decision: Mapping[str, Any],
        tool_name: str,
        args: Mapping[str, Any],
        task_id: str | None,
    ) -> None:
        if not self.config.telemetry.enabled:
            return
        post_started = _now_ms()
        with self._lock:
            if state_key in self._reported:
                return
            self._state.pop(state_key, None)
            self._reported.add(state_key)
            if len(self._reported) > 2048:
                self._reported.clear()

        telemetry = {
            "version": "1",
            "integration": "hermes",
            "actionId": state.get("action_id"),
            "traceId": state.get("trace_id"),
            "agent": state.get("agent"),
            "outcome": {"status": "blocked"},
            "timings": {
                "aurelPreflightLatencyMs": state.get("preflight_latency_ms"),
                "aurelPostflightLatencyMs": max(0, _now_ms() - post_started),
            },
            "metadata": {
                "tool": tool_name,
                "args": redact(args, enabled=self.config.redaction.enabled, max_payload_bytes=self.config.telemetry.max_payload_bytes),
                "task_id": task_id,
                "decision": decision.get("decision"),
                "riskScore": decision.get("riskScore"),
                "category": decision.get("category"),
                "ruleIds": decision.get("ruleIds"),
            },
            "timestamp": _iso_now(),
        }

        thread = threading.Thread(target=lambda: self._safe_record_telemetry(telemetry), name="aurel-hermes-telemetry", daemon=True)
        thread.start()

    def _safe_record_telemetry(self, telemetry: Mapping[str, Any]) -> None:
        try:
            self.client.record_telemetry(telemetry)
        except Exception as exc:
            LOGGER.warning("Aurel telemetry failed: %s", exc)

    def _record_approval_requested(
        self,
        state: Mapping[str, Any],
        decision: Mapping[str, Any],
        tool_name: str,
        args: Mapping[str, Any],
        task_id: str | None,
    ) -> None:
        if not self.config.telemetry.enabled:
            return
        post_started = _now_ms()
        telemetry = {
            "version": "1",
            "integration": "hermes",
            "actionId": state.get("action_id"),
            "traceId": state.get("trace_id"),
            "agent": state.get("agent"),
            "outcome": {"status": "approval_requested"},
            "timings": {
                "aurelPreflightLatencyMs": state.get("preflight_latency_ms"),
                "aurelPostflightLatencyMs": max(0, _now_ms() - post_started),
            },
            "metadata": {
                "tool": tool_name,
                "args": redact(args, enabled=self.config.redaction.enabled, max_payload_bytes=self.config.telemetry.max_payload_bytes),
                "task_id": task_id,
                "decision": decision.get("decision"),
                "riskScore": decision.get("riskScore"),
                "category": decision.get("category"),
                "ruleIds": decision.get("ruleIds"),
            },
            "timestamp": _iso_now(),
        }
        thread = threading.Thread(target=lambda: self._safe_record_telemetry(telemetry), name="aurel-hermes-telemetry", daemon=True)
        thread.start()

    def status_text(self) -> str:
        last = self._last_decision.get("decision") if self._last_decision else "none"
        return "\n".join(
            [
                f"Aurel: {'configured' if self.config.api_key else 'missing api key'}",
                f"Protection: {'enabled' if self.config.enabled else 'disabled'}",
                f"Fail mode: {self.config.fail_mode}",
                f"Telemetry: {'enabled' if self.config.telemetry.enabled else 'disabled'}",
                f"Last decision: {last}",
            ]
        )

    def _sweep_state_locked(self) -> None:
        now_ms = _now_ms()
        expired = [key for key, state in self._state.items() if isinstance(state.get("expires_at_ms"), int) and state["expires_at_ms"] <= now_ms]
        for key in expired:
            self._state.pop(key, None)

    def _map_decision(self, decision: Mapping[str, Any], tool_name: str) -> dict[str, Any] | None:
        kind = decision.get("decision")
        if kind == "allow":
            return None
        if kind in {"block", "quarantine"}:
            return {"action": "block", "message": BLOCKED_MESSAGE}
        if kind == "require_approval":
            if self.config.approval.enabled and self.config.approval.native_directive:
                return {"action": "approve", "message": "Aurel requires human approval before this action can run."}
            # Hermes v0.15.1 only consumes explicit block directives from
            # pre_tool_call. Returning an unsupported approval directive would
            # allow the tool through, so degrade securely.
            return {"action": "block", "message": BLOCKED_MESSAGE}
        if kind == "rewrite":
            # Hermes pre_tool_call supports explicit blocking, not safe argument
            # mutation. Approval fallback is only safe on hosts that consume the
            # native approval directive.
            if (
                self.config.rewrite.unsupported_fallback == "block"
                or not self.config.approval.enabled
                or not self.config.approval.native_directive
            ):
                return {"action": "block", "message": BLOCKED_MESSAGE}
            return {"action": "approve", "message": "Aurel requires approval because Hermes cannot safely rewrite this tool call."}
        LOGGER.warning("Aurel returned unsupported decision for %s: %r", tool_name, kind)
        return {"action": "block", "message": BLOCKED_MESSAGE}

    def _should_block_fail_open_outage(self, tool_name: str) -> bool:
        return (
            self.config.fail_mode == "open"
            and self.config.fail_open_privileged_actions == "block"
            and is_privileged_tool_name(tool_name)
        )


def normalize_hermes_action(tool_name: str, args: dict[str, Any], task_id: str | None, extra: Mapping[str, Any]) -> dict[str, Any]:
    action_id = _str(extra.get("tool_call_id")) or _str(extra.get("toolCallId")) or f"hm-act-{uuid.uuid4()}"
    session_id = _str(extra.get("session_id")) or _str(extra.get("sessionId"))
    agent_id = _str(extra.get("agent_id")) or _str(extra.get("agentId"))
    parent_action_id = _str(extra.get("parent_action_id")) or _str(extra.get("parentActionId"))
    requester = extra.get("requester") if isinstance(extra.get("requester"), Mapping) else None

    return {
        "version": "1",
        "integration": "hermes",
        "action": {
            "id": action_id,
            "name": tool_name or "unknown",
            "type": _str(extra.get("tool_kind")) or _str(extra.get("toolKind")),
            "arguments": args,
        },
        "agent": {
            "id": agent_id,
            "sessionId": session_id,
            "runId": task_id,
        },
        "requester": _requester(requester),
        "context": {
            "workingDirectory": _str(extra.get("cwd")) or _str(extra.get("working_directory")),
            "targetPaths": extra.get("derived_paths") if isinstance(extra.get("derived_paths"), list) else None,
            "parentActionId": parent_action_id,
            "metadata": {
                key: value
                for key, value in extra.items()
                if key not in {"requester", "cwd", "working_directory", "derived_paths"} and _json_safe_scalar(value)
            },
        },
        "timestamp": _iso_now(),
    }


def register(ctx: Any) -> None:
    config = load_config(_ctx_config(ctx))
    plugin = AurelHermesPlugin(config)
    ctx.register_hook("pre_tool_call", plugin.pre_tool_call)
    ctx.register_hook("post_tool_call", plugin.post_tool_call)
    if hasattr(ctx, "register_command"):
        ctx.register_command("aurel", handler=lambda raw_args="", **kwargs: plugin.status_text(), description="Show Aurel plugin status.")


def _ctx_config(ctx: Any) -> Mapping[str, Any]:
    for attr in ("config", "plugin_config"):
        value = getattr(ctx, attr, None)
        if isinstance(value, Mapping):
            return value.get("aurel", value) if isinstance(value.get("aurel", value), Mapping) else {}
    getter = getattr(ctx, "get_config", None)
    if callable(getter):
        value = getter()
        if isinstance(value, Mapping):
            return value.get("aurel", value) if isinstance(value.get("aurel", value), Mapping) else {}
    return {}


def _requester(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    return {
        "channel": _str(value.get("channel")),
        "accountId": _str(value.get("accountId") or value.get("account_id")),
        "senderId": _str(value.get("senderId") or value.get("sender_id")),
        "isOwner": value.get("isOwner") if isinstance(value.get("isOwner"), bool) else value.get("senderIsOwner"),
        "roleIds": value.get("roleIds") if isinstance(value.get("roleIds"), list) else None,
    }


def _state_key(tool_name: str, task_id: str | None, action_id: str | None) -> str:
    if action_id:
        return f"action:{action_id}"
    if task_id:
        return f"task:{task_id}:{tool_name}"
    return f"tool:{tool_name}"


def _tool_call_id(values: Mapping[str, Any]) -> str | None:
    return _str(values.get("tool_call_id")) or _str(values.get("toolCallId"))


def _looks_like_failure(result: Any, kwargs: Mapping[str, Any]) -> bool:
    if kwargs.get("error") is not None:
        return True
    if isinstance(result, Mapping) and result.get("error"):
        return True
    return False


def _error_category(result: Any, kwargs: Mapping[str, Any]) -> str | None:
    error = kwargs.get("error")
    if error is not None:
        return type(error).__name__
    if isinstance(result, Mapping) and result.get("error"):
        return "tool_error"
    return None


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _json_safe_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def _now_ms() -> int:
    return int(time.perf_counter() * 1000)


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
