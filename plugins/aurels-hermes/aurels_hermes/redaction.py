import re

SENSITIVE = re.compile(r"password|secret|token|api[_-]?key|authorization|cookie|credential", re.I)

def redact(value):
    if isinstance(value, dict):
        return {key: "[REDACTED]" if SENSITIVE.search(str(key)) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value
