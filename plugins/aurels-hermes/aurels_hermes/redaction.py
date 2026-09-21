import re

SENSITIVE = re.compile(r"password|secret|token|api[_-]?key|authorization|cookie|credential", re.I)
SENSITIVE_VALUE = re.compile(r"(bearer\s+[a-z0-9\-_.=]+|(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+|-----BEGIN [A-Z ]+PRIVATE KEY-----)", re.I)

def redact(value):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if SENSITIVE.search(str(key)) else redact(item) for key, item in list(value.items())[:100]}
    if isinstance(value, list):
        return [redact(item) for item in value[:50]]
    if isinstance(value, str):
        clipped = value[:4096]
        return "[REDACTED]" if SENSITIVE_VALUE.search(clipped) else clipped
    return value
