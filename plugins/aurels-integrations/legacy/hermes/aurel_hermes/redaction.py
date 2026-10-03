from __future__ import annotations

import json
import re
from typing import Any

SENSITIVE_KEY_PATTERN = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|apikey|authorization|cookie|session|private[_-]?key|credential|access[_-]?token|refresh[_-]?token)",
    re.IGNORECASE,
)


def redact(value: Any, *, enabled: bool = True, max_payload_bytes: int = 32768) -> Any:
    if not enabled:
        return _bound(value, max_payload_bytes)
    return _bound(_redact_value(value, set(), 0), max_payload_bytes)


def _redact_value(value: Any, seen: set[int], depth: int) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _clean(value, 4096)
    if depth > 8:
        return "[MaxDepth]"

    obj_id = id(value)
    if isinstance(value, (dict, list, tuple, set)):
        if obj_id in seen:
            return "[Circular]"
        seen.add(obj_id)

    if isinstance(value, dict):
        try:
            out: dict[str, Any] = {}
            for key in list(value)[:100]:
                safe_key = _clean(str(key), 256)
                if SENSITIVE_KEY_PATTERN.search(str(key)):
                    out[safe_key] = "[REDACTED]"
                    continue
                try:
                    item = value[key]
                except Exception:
                    out[safe_key] = "[UnserializableProperty]"
                    continue
                out[safe_key] = _redact_value(item, seen, depth + 1)
            return out
        finally:
            seen.remove(obj_id)
    if isinstance(value, (list, tuple, set)):
        try:
            return [_redact_value(item, seen, depth + 1) for item in list(value)[:50]]
        finally:
            seen.remove(obj_id)
    return _clean(repr(value), 1024)


def _bound(value: Any, max_payload_bytes: int) -> Any:
    encoded = safe_json(value).encode("utf-8", errors="replace")
    if len(encoded) <= max_payload_bytes:
        return value
    preview = encoded[: min(max_payload_bytes, 4096)].decode("utf-8", errors="replace")
    return {"truncated": True, "reason": "payload_limit", "preview": preview}


def safe_json(value: Any) -> str:
    try:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return '"[Unserializable]"'


def _clean(value: str, max_len: int) -> str:
    cleaned = "".join(ch if ch >= " " or ch in "\n\r\t" else "\ufffd" for ch in value)
    return cleaned if len(cleaned) <= max_len else cleaned[:max_len] + "...[truncated]"
