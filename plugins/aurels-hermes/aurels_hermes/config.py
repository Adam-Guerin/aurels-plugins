from dataclasses import dataclass
import os

@dataclass(frozen=True)
class Config:
    api_url: str
    api_key: str
    fail_mode: str = "closed"
    timeout_ms: int = 1500
    telemetry_enabled: bool = True

    @classmethod
    def from_mapping(cls, value=None):
        value = value or {}
        timeout = int(value.get("timeout_ms", os.getenv("AURELS_TIMEOUT_MS", "1500")))
        fail_mode = value.get("fail_mode", os.getenv("AURELS_FAIL_MODE", "closed"))
        if fail_mode not in {"closed", "open"}:
            raise ValueError("fail_mode must be 'closed' or 'open'")
        return cls(
            api_url=str(value.get("api_url", os.getenv("AURELS_API_URL", "https://www.aurels.dev"))).rstrip("/"),
            api_key=str(value.get("api_key", os.getenv("AURELS_API_KEY", ""))),
            fail_mode=fail_mode,
            timeout_ms=min(max(timeout, 100), 30000),
            telemetry_enabled=bool(value.get("telemetry_enabled", os.getenv("AURELS_TELEMETRY_ENABLED", "true").lower() != "false")),
        )
