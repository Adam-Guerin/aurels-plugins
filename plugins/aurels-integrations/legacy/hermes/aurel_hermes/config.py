import os
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class TelemetryConfig:
    enabled: bool = True
    include_results: bool = False
    max_payload_bytes: int = 32768


@dataclass(frozen=True)
class ApprovalConfig:
    enabled: bool = True
    native_directive: bool = False


@dataclass(frozen=True)
class RewriteConfig:
    unsupported_fallback: str = "approval"


@dataclass(frozen=True)
class ToolConfig:
    include: tuple[str, ...] = field(default_factory=tuple)
    exclude: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class RedactionConfig:
    enabled: bool = True


@dataclass(frozen=True)
class AurelConfig:
    enabled: bool = True
    api_url: str = "https://www.aurels.dev"
    api_key: str = ""
    fail_mode: str = "closed"
    fail_open_privileged_actions: str = "block"
    timeout_ms: int = 1500
    state_ttl_ms: int = 600000
    log_level: str = "warning"
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    approval: ApprovalConfig = field(default_factory=ApprovalConfig)
    rewrite: RewriteConfig = field(default_factory=RewriteConfig)
    tools: ToolConfig = field(default_factory=ToolConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)


def load_config(raw: Mapping[str, Any] | None = None) -> AurelConfig:
    data = dict(raw or {})
    telemetry = _mapping(data.get("telemetry"))
    approval = _mapping(data.get("approval"))
    rewrite = _mapping(data.get("rewrite"))
    tools = _mapping(data.get("tools"))
    redaction = _mapping(data.get("redaction"))

    return AurelConfig(
        enabled=_bool(data.get("enabled"), _env_bool("AUREL_ENABLED", True)),
        api_url=_str(data.get("api_url") or data.get("apiUrl"), os.getenv("AURELS_API_URL") or os.getenv("AUREL_API_URL") or os.getenv("INTENTGUARD_API_URL") or "https://www.aurels.dev"),
        api_key=_str(data.get("api_key") or data.get("apiKey"), os.getenv("AURELS_API_KEY") or os.getenv("AUREL_API_KEY") or os.getenv("INTENTGUARD_API_KEY") or ""),
        fail_mode="open" if (data.get("fail_mode") or data.get("failMode") or os.getenv("AUREL_FAIL_MODE")) == "open" else "closed",
        fail_open_privileged_actions=_enum(
            data.get("fail_open_privileged_actions") or data.get("failOpenPrivilegedActions"),
            {"block", "allow"},
            _env_enum("AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS", {"block", "allow"}, "block"),
        ),
        timeout_ms=_int(data.get("timeout_ms") or data.get("timeoutMs"), _int(os.getenv("AUREL_TIMEOUT_MS"), 1500, 100, 30000), 100, 30000),
        state_ttl_ms=_int(data.get("state_ttl_ms") or data.get("stateTtlMs"), _int(os.getenv("AUREL_STATE_TTL_MS"), 600000, 1000, 3600000), 1000, 3600000),
        log_level=_enum(data.get("log_level") or data.get("logLevel"), {"critical", "error", "warning", "info", "debug"}, _env_enum("AUREL_LOG_LEVEL", {"critical", "error", "warning", "info", "debug"}, "warning")),
        telemetry=TelemetryConfig(
            enabled=_bool(telemetry.get("enabled"), _env_bool("AUREL_TELEMETRY_ENABLED", True)),
            include_results=_bool(_first_present(telemetry, "include_results", "includeResults"), _env_bool("AUREL_TELEMETRY_INCLUDE_RESULTS", False)),
            max_payload_bytes=_int(
                _first_present(telemetry, "max_payload_bytes", "maxPayloadBytes"),
                _int(os.getenv("AUREL_TELEMETRY_MAX_PAYLOAD_BYTES"), 32768, 1024, 262144),
                1024,
                262144,
            ),
        ),
        approval=ApprovalConfig(
            enabled=_bool(approval.get("enabled"), True),
            native_directive=_bool(
                _first_present(approval, "native_directive", "nativeDirective"),
                _env_bool("AUREL_HERMES_NATIVE_APPROVAL", False),
            ),
        ),
        rewrite=RewriteConfig(
            unsupported_fallback=_enum(
                _first_present(rewrite, "unsupported_fallback", "unsupportedFallback"),
                {"approval", "block"},
                _env_enum("AUREL_REWRITE_UNSUPPORTED_FALLBACK", {"approval", "block"}, "approval"),
            )
        ),
        tools=ToolConfig(
            include=tuple(_str_list(tools.get("include"), _env_list("AUREL_TOOLS_INCLUDE"))),
            exclude=tuple(_str_list(tools.get("exclude"), _env_list("AUREL_TOOLS_EXCLUDE"))),
        ),
        redaction=RedactionConfig(enabled=_bool(redaction.get("enabled"), _env_bool("AUREL_REDACTION_ENABLED", True))),
    )


def should_intercept(tool_name: str, config: AurelConfig) -> bool:
    if not config.enabled:
        return False
    if tool_name in config.tools.exclude:
        return False
    return not config.tools.include or tool_name in config.tools.include


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _bool(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _str(value: Any, default: str) -> str:
    return value if isinstance(value, str) and value else default


def _enum(value: Any, allowed: set[str], default: str) -> str:
    return value if isinstance(value, str) and value in allowed else default


def _int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def _str_list(value: Any, default: list[str] | None = None) -> list[str]:
    if not isinstance(value, list):
        return list(default or [])
    return [item for item in value if isinstance(item, str) and item]


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


def _env_list(name: str) -> list[str]:
    value = os.getenv(name)
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _env_enum(name: str, allowed: set[str], default: str) -> str:
    value = os.getenv(name)
    return value if value in allowed else default


def _first_present(mapping: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def is_privileged_tool_name(tool_name: str) -> bool:
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
