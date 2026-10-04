from dataclasses import dataclass
import os

@dataclass(frozen=True)
class Config:
    enabled: bool
    api_url: str
    api_key: str
    mode: str = "local"
    timeout_ms: int = 1500
    telemetry_enabled: bool = True
    telemetry_durable: bool = False
    telemetry_spool_dir: str = ""
    trust_native_hook_order: bool = False

    @classmethod
    def from_mapping(cls, value=None):
        value = value or {}
        timeout = int(value.get("timeout_ms", os.getenv("AURELS_TIMEOUT_MS", "1500")))
        api_key = str(value.get("api_key", os.getenv("AURELS_API_KEY", "")))
        mode = str(value.get("mode", os.getenv("AURELS_MODE", "remote" if api_key else "local"))).lower()
        if mode not in {"closed", "open", "local", "remote", "retrospective"}:
            raise ValueError("mode must be 'local', 'remote', or 'retrospective'")
        normalized_mode = "remote" if mode == "open" else "local" if mode == "closed" else mode
        return cls(
            enabled=_parse_bool(value.get("enabled", os.getenv("AURELS_ENABLED", "true"))),
            api_url=str(value.get("api_url", os.getenv("AURELS_API_URL", "https://www.aurels.dev"))).rstrip("/"),
            api_key=api_key,
            mode=normalized_mode,
            timeout_ms=min(max(timeout, 100), 30000),
            telemetry_enabled=_parse_bool(value.get("telemetry_enabled", os.getenv("AURELS_TELEMETRY_ENABLED", "true"))),
            telemetry_durable=_parse_bool(value.get("telemetry_durable", os.getenv("AURELS_TELEMETRY_DURABLE", "false"))),
            telemetry_spool_dir=str(value.get("telemetry_spool_dir", os.getenv("AURELS_TELEMETRY_SPOOL_DIR", ""))),
            trust_native_hook_order=_parse_bool(
                value.get("trust_native_hook_order", os.getenv("AURELS_HERMES_TRUST_NATIVE_HOOK_ORDER", "false"))
            ),
        )


def _parse_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() not in {"0", "false", "no", "off", ""}
