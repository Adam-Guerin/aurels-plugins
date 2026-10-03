import re

SENSITIVE = re.compile(r"password|secret|token|api[_-]?key|authorization|cookie|credential", re.I)
SENSITIVE_VALUE = re.compile(
    r"(bearer\s+[a-z0-9\-_.=]+"
    r"|(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+"
    r"|-----BEGIN [A-Z ]+PRIVATE KEY-----"
    r"|\bsk-(?:proj-)?[a-z0-9_-]{20,}\b"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|\bgh[pousr]_[a-z0-9_]{30,}\b"
    r"|\beyJ[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\.[a-z0-9_-]{8,}\b)",
    re.I,
)

def redact(value, seen=None, depth=0):
    if seen is None:
        seen = set()
    if not value or not isinstance(value, (dict, list)):
        if isinstance(value, str):
            clipped = value[:4096]
            return "[REDACTED]" if SENSITIVE_VALUE.search(clipped) else clipped
        return value
    if depth > 8:
        return "[MaxDepth]"
    obj_id = id(value)
    if obj_id in seen:
        return "[Circular]"
    seen.add(obj_id)
    try:
        if isinstance(value, dict):
            return {key: "[REDACTED]" if SENSITIVE.search(str(key)) else redact(item, seen, depth + 1) for key, item in list(value.items())[:100]}
        if isinstance(value, list):
            return [redact(item, seen, depth + 1) for item in value[:50]]
    finally:
        seen.discard(obj_id)
    return value
