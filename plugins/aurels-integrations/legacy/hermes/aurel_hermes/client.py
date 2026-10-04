from __future__ import annotations

import json
import hashlib
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping

from .config import AurelConfig

MAX_AUREL_RESPONSE_BYTES = 1024 * 1024
MAX_AUREL_REQUEST_BYTES = 1024 * 1024
MAX_AUREL_STRING_CHARS = 65536
MAX_AUREL_ARRAY_ITEMS = 512
MAX_AUREL_OBJECT_KEYS = 512


class AurelClientError(Exception):
    pass


class AurelProtocolError(AurelClientError):
    pass


class AurelActionPayloadError(AurelProtocolError):
    """The action cannot be evaluated exactly, so fail-open is unsafe."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect while an API key is attached to the request."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


@dataclass(frozen=True)
class AurelClient:
    config: AurelConfig

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlparse(self.config.api_url)
        if parsed.scheme not in {"http", "https"}:
            raise AurelClientError("Aurel API URL must use http or https")
        if parsed.username or parsed.password:
            raise AurelClientError("Aurel API URL must not include credentials")

    def evaluate_action(self, action: Mapping[str, Any]) -> dict[str, Any]:
        body = self._post_json("/api/v1/actions/evaluate", action)
        return _parse_decision(body)

    def record_telemetry(self, telemetry: Mapping[str, Any]) -> None:
        delays = (0.05, 0.15, 0.35)
        last_error: Exception | None = None
        for index, delay in enumerate(delays):
            try:
                self._post_json("/api/v1/actions/telemetry", telemetry)
                return
            except Exception as exc:  # telemetry is best effort, retry bounded
                last_error = exc
                if index + 1 < len(delays):
                    time.sleep(delay)
        if last_error is not None:
            raise last_error

    def _post_json(self, path: str, payload: Mapping[str, Any]) -> Any:
        if not self.config.api_key:
            raise AurelClientError("Aurel API key is not configured")

        url = _normalize_base_url(self.config.api_url) + path
        data = _json_payload(payload, exact=path == "/api/v1/actions/evaluate")
        request = urllib.request.Request(
            url,
            data=data,
            method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": self.config.api_key,
                "idempotency-key": _idempotency_key_for(path, payload),
                "user-agent": "aurel-hermes-plugin/0.1.0",
            },
        )
        timeout_seconds = max(0.1, self.config.timeout_ms / 1000)
        try:
            # urllib follows redirects by default and can forward X-API-Key to a
            # different origin. Treat every 30x response as an HTTP error.
            with _open_no_redirect(request, timeout_seconds) as response:
                raw = response.read(MAX_AUREL_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise AurelClientError(f"Aurel HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise AurelClientError(f"Aurel network error: {exc.reason}") from exc
        except TimeoutError as exc:
            raise AurelClientError("Aurel request timed out") from exc

        if len(raw) > MAX_AUREL_RESPONSE_BYTES:
            raise AurelProtocolError("Aurel response exceeded maximum size")

        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AurelProtocolError("Aurel returned invalid JSON") from exc


def _normalize_base_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))


def _open_no_redirect(request: urllib.request.Request, timeout: float) -> Any:
    return urllib.request.build_opener(_RejectRedirects()).open(request, timeout=timeout)


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
    raise AurelProtocolError("Aurel request payload exceeded maximum size")


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


def _parse_decision(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict) or not isinstance(body.get("decision"), str):
        raise AurelProtocolError("Aurel returned a malformed decision")
    decision = body["decision"]
    if decision == "flag":
        body = dict(body)
        body["decision"] = "require_approval"
        decision = body["decision"]
    if decision not in {"allow", "block", "require_approval", "rewrite", "quarantine"}:
        raise AurelProtocolError(f"Unsupported Aurel decision: {decision}")
    _validate_decision_metadata(body)
    return body


def _validate_decision_metadata(body: Mapping[str, Any]) -> None:
    risk_score = body.get("riskScore")
    if (
        risk_score is not None
        and (not isinstance(risk_score, (int, float)) or isinstance(risk_score, bool) or not math.isfinite(risk_score) or risk_score < 0 or risk_score > 100)
    ):
        raise AurelProtocolError("Aurel returned an invalid risk score")

    for field in ("reason", "category", "traceId", "policyVersion"):
        value = body.get(field)
        if value is not None and (not isinstance(value, str) or len(value) > 4096):
            raise AurelProtocolError(f"Aurel returned an invalid {field}")

    rule_ids = body.get("ruleIds")
    if rule_ids is not None:
        if not isinstance(rule_ids, list) or len(rule_ids) > 128 or any(not isinstance(rule_id, str) or len(rule_id) > 512 for rule_id in rule_ids):
            raise AurelProtocolError("Aurel returned invalid rule IDs")


def _idempotency_key_for(path: str, payload: Mapping[str, Any]) -> str:
    action = payload.get("action")
    if path.endswith("/evaluate") and isinstance(action, Mapping) and isinstance(action.get("id"), str):
        return _idempotency_key("action-evaluate", action["id"], _action_fingerprint(action))
    if path.endswith("/telemetry") and isinstance(payload.get("actionId"), str):
        outcome = payload.get("outcome")
        status = outcome.get("status") if isinstance(outcome, Mapping) else "unknown"
        return _idempotency_key("action-telemetry", payload["actionId"], status if isinstance(status, str) else "unknown", _action_fingerprint(payload))
    return _idempotency_key("aurel-request", path)


def _idempotency_key(prefix: str, *parts: str) -> str:
    encoded = [urllib.parse.quote(str(part), safe="")[:256] for part in parts]
    return ":".join([prefix, *encoded])


def _action_fingerprint(action: Mapping[str, Any]) -> str:
    # _json_safe is the same bounded, circular-safe representation sent over
    # the wire, so a key cannot be reused for a different evaluated envelope.
    serialized = json.dumps(_json_safe(action, set(), 0), separators=(",", ":"), ensure_ascii=False, allow_nan=False, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
