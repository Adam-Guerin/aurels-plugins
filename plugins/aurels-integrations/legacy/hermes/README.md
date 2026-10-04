# Legacy Aurel Hermes source snapshot

This is the former application-bundled adapter retained for migration history. Do not install or release it. Use the maintained package at [`plugins/aurels-hermes`](../../../aurels-hermes/README.md).

Aurel's Hermes integration is a standalone native third-party plugin. It registers `pre_tool_call` for enforcement and `post_tool_call` for outcome telemetry from `register(ctx)`.

## Installation

This snapshot is not installable. Use the maintained package at [`plugins/aurels-hermes`](../../../aurels-hermes/README.md).

Hermes native plugins use `plugin.yaml` plus `__init__.py`. The manifest declares `provides_hooks`, and the plugin calls:

```python
ctx.register_hook("pre_tool_call", plugin.pre_tool_call)
ctx.register_hook("post_tool_call", plugin.post_tool_call)
```

## Configuration

```text
AUREL_API_URL=http://localhost:3000
AUREL_API_KEY=...
AUREL_FAIL_MODE=closed
AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=block
AUREL_TIMEOUT_MS=1500
AUREL_STATE_TTL_MS=600000
AUREL_LOG_LEVEL=warning
AUREL_TELEMETRY_ENABLED=true
AUREL_TELEMETRY_INCLUDE_RESULTS=false
AUREL_TELEMETRY_MAX_PAYLOAD_BYTES=32768
AUREL_REDACTION_ENABLED=true
AUREL_ENABLED=true
AUREL_TOOLS_INCLUDE=
AUREL_TOOLS_EXCLUDE=
AUREL_HERMES_NATIVE_APPROVAL=false
AUREL_REWRITE_UNSUPPORTED_FALLBACK=approval
```

Use an Aurel API key with `operator` or `admin` role. `viewer` keys are rejected by the live action evaluation and telemetry endpoints.

`AUREL_TOOLS_INCLUDE` and `AUREL_TOOLS_EXCLUDE` are comma-separated exact tool names when using environment configuration. An empty include list means every tool; exclude entries always pass through without preflight or telemetry. Do not put executable tools in the exclude list: it is an explicit bypass.

Fail-closed is the default. Because Hermes catches plugin callback exceptions, the plugin never relies on throwing to block execution. If Aurel is unavailable in fail-closed mode, `pre_tool_call` explicitly returns:

```python
{"action": "block", "message": "Aurel security verification is unavailable."}
```

If `AUREL_FAIL_MODE=open`, low-risk tools can proceed during an outage, but privileged tool names such as terminal/shell/process, browser/network, file mutation, messaging, database/cloud/package/schedule/delegation/MCP/API/finance/auth, and credential tools still return that explicit block by default. Set `AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=allow` only when pure fail-open behavior is intentional.

The Aurel API URL must be `http` or `https` and cannot contain embedded credentials. Query strings and fragments are stripped before endpoint paths are appended, oversized Aurel responses are rejected, and redirects are treated as errors so an API key is never forwarded to a new origin.

## Decisions

- `allow`: return `None` so Hermes continues.
- `block` / `quarantine`: return `{"action": "block", "message": sanitized_message}`.
- `require_approval`: current Hermes v0.15.1 only consumes `{"action": "block"}` from `pre_tool_call`, so approval-required actions are blocked by default rather than accidentally allowed. Set `AUREL_HERMES_NATIVE_APPROVAL=true` only after verifying a Hermes build that consumes `{"action": "approve"}` from `pre_tool_call`.
- `rewrite`: Hermes does not expose safe argument mutation for `pre_tool_call`; rewrites fall back to block by default, or to native approval only when `AUREL_HERMES_NATIVE_APPROVAL=true` is explicitly enabled.

Post-tool telemetry includes tool name, redacted args metadata, task id, duration, Aurel action id, and trace id. Terminal pre-execution decisions emit telemetry immediately: blocked approval-required actions are reported as `blocked` with the original Aurel decision metadata, while explicitly enabled native approval directives report `approval_requested`. When Hermes supplies `tool_call_id` or `toolCallId`, the plugin uses it for correlation so concurrent same-tool calls within one task stay isolated. Duplicate post-hook delivery for the same call is reported only once. Stale correlation state expires after `AUREL_STATE_TTL_MS` (default 10 minutes, clamped between 1 second and 1 hour). Raw tool output is excluded by default.

## Flow

```text
agent action -> Aurel -> allow / block / approval-if-supported / rewrite-if-supported -> execution -> telemetry
```

## Development

```bash
npm run dev:aurel-harness
$env:AUREL_API_URL="http://127.0.0.1:8787"
$env:AUREL_API_KEY="test"
npm run test:hermes
```

Uninstall:

```bash
hermes plugins disable aurel
hermes plugins uninstall aurel
```
