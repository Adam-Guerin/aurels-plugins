# Aurel MCP Proxy

The MCP integration is a stdio JSON-RPC proxy. Run it in front of any local MCP server so `tools/call` requests are evaluated by Aurel before they reach the upstream tool server.

## Usage

```bash
npm install "https://github.com/Adam-Guerin/aurels-plugins/releases/latest/download/aurels-mcp-proxy-0.1.0.tgz"
```

Then configure the host's MCP server command to `npx --no-install aurels-mcp-proxy -- npx some-mcp-server`. Put the real MCP server command and arguments after `--`. The archive installs a standalone command and has no runtime npm dependencies.

Common environment settings:

```text
AUREL_API_URL=https://your-aurel.example.com
AUREL_API_KEY=...
AUREL_FAIL_MODE=closed
AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=block
AUREL_TIMEOUT_MS=1500
AUREL_ENABLED=true
AUREL_TOOLS_INCLUDE=
AUREL_TOOLS_EXCLUDE= # legacy; exclusions no longer bypass preflight
AUREL_TELEMETRY_ENABLED=true
AUREL_TELEMETRY_MAX_PAYLOAD_BYTES=32768
AUREL_REDACTION_ENABLED=true
AUREL_MCP_MAX_FRAME_BYTES=1048576
AUREL_MCP_TRANSPORT=newline
AUREL_MCP_MAX_PENDING=1024
AUREL_MCP_PENDING_TTL_MS=600000
AURELS_MCP_EXECUTION_PERMITS=false
AUREL_AGENT_ID=coding-agent
AUREL_AGENT_ENVIRONMENT=production
```

`AUREL_TOOLS_INCLUDE` is a comma-separated allowlist of exact MCP tool names; an empty list means evaluate every tool call. `AUREL_TOOLS_EXCLUDE` is retained as a deprecated configuration field but is ignored because exclusions bypass the security decision. To protect a subset, use the include list, understanding that non-included tools are deliberately outside Aurels' protection boundary.

If `AUREL_FAIL_MODE=open`, low-risk MCP tools can proceed during an outage, but privileged tool names such as terminal/shell/process, browser/network, file mutation, messaging, database/cloud/package/schedule/delegation/MCP/API/finance/auth, and credential tools still return a sanitized JSON-RPC error by default. Set `AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=allow` only when pure fail-open behavior is intentional.

## Decisions

The default transport is UTF-8 JSON-RPC with one message per line, matching the [MCP stdio specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports). Initialization, listing tools, and guarded calls are tested through the official MCP JavaScript SDK 1.32.0, including from an installed proxy archive. Set `AUREL_MCP_TRANSPORT=content-length` only for a legacy host and upstream server that both explicitly use that older framing; it is not the normal MCP transport.

`AUREL_MCP_MAX_PENDING` bounds active policy checks and outstanding tool calls (default 1,024; range 1–4,096). Excess calls are refused rather than queued without limit. Cancellation received during evaluation aborts the policy request and prevents dispatch; cancellation after dispatch is forwarded upstream, whose server determines whether an already-running action can stop. Closing host stdin drains active evaluations before closing upstream stdin, with a bounded shutdown grace period. Malformed policy decisions and unreadable policy JSON always block, including in outage fail-open mode.

- `allow`: forwards the MCP request unchanged.
- `block` / `quarantine`: returns a JSON-RPC error and never forwards to upstream.
- `require_approval` / legacy `flag`: returns a JSON-RPC error because MCP stdio has no portable approval prompt.
- `rewrite`: forwards with rewritten `params.arguments`.

The proxy uses direct HTTP to Aurel and does not expose Aurel itself as an MCP tool. Preflight requests fail closed by default, enforce a bounded timeout across response headers and body parsing, and are not retried. Postflight telemetry reports the tool name and redacted argument metadata, preserves prototype-pollution-shaped keys as inert data, strips control characters from text, bounds argument metadata with `AUREL_TELEMETRY_MAX_PAYLOAD_BYTES`, and excludes raw tool results. Tool names are never treated as trusted Aurel identity; a tool called `aurel.*` is still evaluated. Set `AUREL_REDACTION_ENABLED=false` only for local diagnostics.

Host JSON-RPC frames are bounded by `AUREL_MCP_MAX_FRAME_BYTES` (default 1 MiB, clamped between 1 KiB and 16 MiB). Malformed or oversized host frames return a sanitized parse error and are not forwarded upstream. Pending action correlations expire after `AUREL_MCP_PENDING_TTL_MS` (default 10 minutes, clamped between 1 second and 1 hour) so crashed or disconnected upstream servers cannot leak correlation state in a long-running proxy.

When Aurel returns a supported rewrite, the proxy forwards rewritten `params.arguments` upstream. Telemetry records the redacted executed arguments and, for rewrite decisions only, redacted `originalArgs` plus `rewriteApplied: true`.

Set `AURELS_MCP_EXECUTION_PERMITS=true` to use the Aurels v1 authorization API. In this mode the gateway maps the MCP tool call to a normalized request, obtains a signed execution permit for allowed calls, consumes that one-time permit, and only then forwards to the upstream MCP server. Blocked calls never reach the upstream server. `AUREL_MCP_EXECUTION_PERMITS` remains a deprecated compatibility alias.
