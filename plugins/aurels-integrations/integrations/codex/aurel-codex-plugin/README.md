# Aurels Guard for Codex

Use your own Jev key or local Laya/Ollama model with the [self-hosted evaluator](../../../../aurels-evaluator/README.md). The guide generates the local URL/token configuration; this adapter retains its existing enforcement and approval contract.

This is a portable Codex plugin bundle. It uses Codex's native synchronous `PreToolUse` and `PostToolUse` hooks to check supported local function tools before execution and send post-action telemetry.

## Install

Download and extract `aurels-codex-guard-plugin.zip`, then add the extracted folder to a local plugin marketplace or copy it into your Codex plugin directory. Review/trust its hooks in Codex (`/hooks`) before relying on them. The command hook requires Node.js 20+ in the Codex execution environment.

Set `AURELS_API_URL` and `AURELS_API_KEY` in the environment inherited by Codex. The default API URL is `https://www.aurels.dev`. Keep `AUREL_FAIL_MODE=closed` unless fail-open behavior is an explicit policy choice.

## Decision behavior

- `allow`: permits the input checked by this hook. Final dispatch remains owned by Codex; other host hooks must not replace it afterward.
- `block` / `quarantine`: Codex denies the call before execution.
- `flag` / `require_approval`: denied. Codex does not currently support returning “ask” from `PreToolUse`; this plugin does not pretend an approval happened.
- `rewrite`: conservatively denied by this adapter. Current Codex hooks can accept replacement input, but this package does not enable that path without full host validation.
- API, malformed response, timeout, or redirect error: denied by default.

The plugin protects the local Codex tool paths covered by the current hooks contract (including shell, patch/edit, MCP and local function tools). Hosted tools and specialized paths that opt out of hooks are outside the enforcement boundary. Hooks are useful defense-in-depth, not a complete system boundary; Codex may continue a call if a hook is disabled, untrusted, or fails at the host/runtime level. Review and trust the hook in Codex before use.

Codex currently supplies no universal execution-status field in `PostToolUse` (and has no documented `PostToolUseFailure` hook). The adapter marks explicit structured errors as `failure`; where a result has no reliable status signal—especially shell output—it sets `metadata.completionStatus` to `unknown` and `errorCategory` to `host_status_unavailable`. For compatibility with the current Aurels telemetry API enum, `outcome.status` remains `success` in that indeterminate case. Do not use `outcome.status` alone as proof a shell command exited zero; this requires a Codex status field or an Aurels API `unknown` outcome before the audit trail can be fully truthful.

The older `scripts/aurel-protected-mcp.mjs` launcher remains for setups that specifically need an MCP proxy; it is not required by the native hook plugin.

Policy JSON and decision metadata are validated; invalid decisions remain denied even with outage fail-open enabled. The command resolves `PLUGIN_ROOT` inside Node, so PowerShell does not misinterpret the plugin path. A real Codex 0.160.0 CLI session uses the packaged hook declarations with synthetic model/policy servers: allow creates a disposable fixture file; block, review and policy outage leave it absent. The test grants hook trust for its own fixture only. Marketplace installation, interactive hook-trust prompts, and interactions with other installed hooks still require deployment acceptance. See the [current Codex hook contract](https://developers.openai.com/codex/hooks) and the repository [validation matrix](../../../../../docs/SUPPORT-MATRIX.md) before deployment.
