# Aurel for Claude Code

Use your own Jev key or local Laya/Ollama model with the [self-hosted evaluator](../../../aurels-evaluator/README.md). The guide generates the local URL/token configuration; this adapter retains its existing enforcement and approval contract.

Claude Code exposes native hooks at tool-call boundaries. Aurel uses `PreToolUse` for enforcement and `PostToolUse` / `PostToolUseFailure` for telemetry.

This adapter is experimental and is not covered by the supported plugin release contract. A native plugin bundle is published as `aurels-claude-code-plugin.zip` with each GitHub release.

## Install

Extract the archive, then load its directory for a local test with `claude --plugin-dir <extracted-plugin-directory>` (or install it using Claude Code's plugin marketplace). Review the hooks and set the environment values below for the Claude Code process:

```text
AUREL_API_URL=https://your-aurel.example.com
AUREL_API_KEY=...
AUREL_FAIL_MODE=closed
AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=block
AUREL_TIMEOUT_MS=1500
AUREL_HOOK_MAX_STDIN_BYTES=1048576
AUREL_ENABLED=true
AUREL_TOOLS_INCLUDE=
AUREL_TOOLS_EXCLUDE= # legacy; exclusions no longer bypass preflight
AUREL_TELEMETRY_ENABLED=true
AUREL_TELEMETRY_MAX_PAYLOAD_BYTES=32768
AUREL_REDACTION_ENABLED=true
AUREL_REWRITE_UNSUPPORTED_FALLBACK=approval
```

Use an Aurel API key with `operator` or `admin` role. `viewer` keys are rejected by the live action evaluation and telemetry endpoints.

`AUREL_TOOLS_INCLUDE` is a comma-separated allowlist of exact tool names; an empty list means evaluate every tool call. `AUREL_TOOLS_EXCLUDE` is retained as a deprecated configuration field but is ignored because exclusions bypass the security decision. To protect a subset, use the include list, understanding that non-included tools are deliberately outside Aurels' protection boundary.

If `AUREL_FAIL_MODE=open`, low-risk tools can proceed during an outage, but privileged tool names such as `Bash`, terminal/shell/process, browser/network, file mutation, messaging, database/cloud/package/schedule/delegation/MCP/API/finance/auth, and credential tools still return a sanitized deny decision by default. Set `AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=allow` only when pure fail-open behavior is intentional.

## Behavior

- `allow`: hook returns `permissionDecision: "allow"`.
- `block` / `quarantine`: hook returns `permissionDecision: "deny"` with a sanitized reason.
- `require_approval` / legacy `flag`: hook returns `permissionDecision: "ask"`.
- `rewrite`: Claude Code hooks cannot safely mutate tool input, so rewrite falls back to ask or deny.

Project-level hooks also apply inside Claude Code subagents when the workspace is trusted.

The package and hook contract are structurally tested in CI, but this repository's CI does not launch a full Claude Code agent session. Treat the adapter as experimental until host-level installation and tool-dispatch E2E has been run on the exact Claude Code release you deploy.

Tool names are not treated as trusted Aurel identity: even a tool called `aurel.exec` is evaluated. The enforcement client is an HTTP request made by this hook, not a Claude tool, so no prefix-based bypass is needed.

Blocked decisions emit terminal `blocked` telemetry before the hook returns `deny`, because Claude Code will not run the underlying tool. Approval decisions emit `approval_requested` telemetry before the hook returns `ask`. Telemetry redaction preserves prototype-pollution-shaped keys as inert data, strips control characters from text, and bounds argument metadata with `AUREL_TELEMETRY_MAX_PAYLOAD_BYTES`. Set `AUREL_REDACTION_ENABLED=false` only for local diagnostics; execution arguments are never mutated by redaction. The hook persists only minimal correlation state for allowed calls: action id, trace id, agent context, and preflight latency. Tool inputs and outputs are not stored in that state file.

Hook stdin is bounded before parsing (default 1 MiB, clamped between 1 KiB and 16 MiB). Malformed or oversized hook input fails closed with the sanitized unavailable message. Pending correlation filenames contain only a hash of the action ID; the local state directory is permission-restricted and capped at 1,024 entries, evicting the oldest orphaned states. A stale lock left by a crashed hook expires so later calls can recover. The E2E suite exercises concurrent hook processes and stale-lock recovery.
