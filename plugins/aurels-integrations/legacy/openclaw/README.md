# Legacy Aurel OpenClaw source snapshot

This is the former application-bundled adapter retained for migration history. Do not install or release it. Use the maintained package at [`plugins/aurels-openclaw`](../../../aurels-openclaw/README.md).

Aurel's OpenClaw integration is a native hook plugin. It registers `before_tool_call` as the enforcement gate and `after_tool_call` for bounded outcome telemetry.

Requires an OpenClaw runtime that exposes `api.on("before_tool_call", ...)` / `api.on("after_tool_call", ...)` or the older `registerHook` equivalent; package metadata declares `openclaw >=2026.3.2`. The plugin prefers `api.on` when available and falls back to `registerHook` for local OpenClaw 2026.3.2 compatibility. The installed OpenClaw 2026.3.2 hook result contract exposes `params`, `block`, and `blockReason`; it does not expose a consumed `requireApproval` result. Approval-required actions are therefore blocked by default on this runtime instead of being allowed by an ignored directive.

## Installation

This snapshot is not installable. Use the maintained package at [`plugins/aurels-openclaw`](../../../aurels-openclaw/README.md).

OpenClaw native plugins ship `openclaw.plugin.json`; package entrypoints live under `package.json` `openclaw.extensions` and `openclaw.runtimeExtensions`.

## Configuration

The plugin reads native plugin config when OpenClaw supplies it and falls back to:

```text
AUREL_API_URL=http://localhost:3000
AUREL_API_KEY=...
AUREL_FAIL_MODE=closed
AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=block
AUREL_TIMEOUT_MS=1500
AUREL_LOG_LEVEL=warn
AUREL_TELEMETRY_ENABLED=true
AUREL_TELEMETRY_INCLUDE_RESULTS=false
AUREL_TELEMETRY_MAX_PAYLOAD_BYTES=32768
AUREL_REDACTION_ENABLED=true
AUREL_OPENCLAW_NATIVE_APPROVAL=false
AUREL_TOOLS_INCLUDE=
AUREL_TOOLS_EXCLUDE=
```

`tools.include=[]` means every tool. `tools.exclude` removes specific tool names; treating an executable tool as excluded is an explicit bypass. Default fail mode is `closed`.

If `AUREL_FAIL_MODE=open`, low-risk tools can proceed during an Aurel outage, but privileged tool names such as `exec`, `terminal`, `browser`, file mutation, database/cloud/package/schedule/delegation/MCP/API/finance/auth, and credential tools still return a sanitized block by default. Set `AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=allow` only for an intentional pure fail-open deployment.

Use an Aurel API key with `operator` or `admin` role. `viewer` keys are rejected by the live action evaluation and telemetry endpoints.

## Decisions

- `allow`: execution continues.
- `block` / `quarantine`: returns `{ block: true, blockReason }` with a sanitized message.
- `require_approval`: returns a sanitized block by default on OpenClaw 2026.3.2 because that host does not consume native approval directives from `before_tool_call`. Set `AUREL_OPENCLAW_NATIVE_APPROVAL=true` only after verifying a future OpenClaw hook contract that consumes `requireApproval`.
- `rewrite`: returns rewritten `params` when supported; otherwise blocks by default on OpenClaw 2026.3.2, or falls back to native approval only when a future host supports approval directives and `AUREL_OPENCLAW_NATIVE_APPROVAL=true`.

## Flow

```text
Agent            Aurel Plugin        Aurel API          Tool
 │                    │                  │               │
 │ tool_call          │                  │               │
 ├───────────────────►│                  │               │
 │                    │ evaluate         │               │
 │                    ├─────────────────►│               │
 │                    │ ALLOW            │               │
 │                    │◄─────────────────┤               │
 │                    │                                  │
 │                    ├─────────────────────────────────►│
 │                    │                                  │
 │                    │ result                           │
 │                    │◄─────────────────────────────────┤
 │                    │ telemetry        │               │
 │                    ├─────────────────►│               │
```

```text
Agent            Aurel Plugin        Aurel API
 │                    │                  │
 │ dangerous action   │                  │
 ├───────────────────►│                  │
 │                    │ evaluate         │
 │                    ├─────────────────►│
 │                    │ BLOCK            │
 │                    │◄─────────────────┤
 │
 │      BLOCKED       │
 │◄───────────────────┤
 │
 X tool never executes
```

## Security

The plugin uses direct HTTP, not an agent-visible tool. Telemetry redacts sensitive keys, bounds payload size, handles circular values, and excludes raw tool output unless `telemetry.includeResults=true`.

Blocked decisions are reported to Aurel immediately as terminal `blocked` telemetry, since a blocked action should never reach the tool and may not produce an `after_tool_call` event. If a future OpenClaw runtime consumes native approval directives and `AUREL_OPENCLAW_NATIVE_APPROVAL=true` is enabled, approval requests are reported immediately as `approval_requested`, then any approval resolution is recorded as `approval_allowed` or `approval_denied`. If OpenClaw omits `toolCallId`, the plugin falls back to run/tool correlation so trace IDs still attach to post-action telemetry where possible.

## Development

```bash
npm run dev:aurel-harness
$env:AUREL_API_URL="http://127.0.0.1:8787"
$env:AUREL_API_KEY="test"
npm test -- tests/openclaw-aurel.test.ts
```

Uninstall:

```bash
openclaw plugins disable aurel
openclaw plugins uninstall aurel
```
