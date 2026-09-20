# Aurels for OpenClaw

`@aurels/openclaw-plugin` is a standalone Node.js plugin that intercepts OpenClaw tool calls before execution. It calls the Aurels action-evaluation API directly; it does not expose an agent-visible security tool.

## Support contract

| Component | Supported version |
| --- | --- |
| Plugin | 0.2.0 |
| Node.js | 20 or newer |
| OpenClaw | 2026.3.2 or newer, with `before_tool_call` and `after_tool_call` hooks |
| Aurels API | `/api/v1/actions/evaluate` and `/api/v1/actions/telemetry` |

## Install

```bash
cd plugins/aurels-openclaw
npm test
openclaw plugins install . --link
openclaw plugins enable aurels
```

## Configure

Copy `.env.example` to your secret manager or environment. Use a dedicated key limited to action evaluation and telemetry; never use a workspace-admin key in an agent runtime.

```text
AURELS_API_URL=https://www.aurels.dev
AURELS_API_KEY=replace-with-a-scoped-plugin-key
AURELS_FAIL_MODE=closed
AURELS_TIMEOUT_MS=1500
AURELS_TELEMETRY_ENABLED=true
```

## Decision and outage contract

| Event | Result |
| --- | --- |
| `allow` | Tool executes unchanged. |
| `flag` | Tool does not execute. OpenClaw receives an approval-required block. |
| `block` / `quarantine` | Tool does not execute. |
| `rewrite` | Rewritten parameters execute only when the host declares `supportsParamRewrite`; otherwise the tool does not execute. |
| Timeout, network failure, 4xx/5xx, invalid JSON | Block by default (`failMode=closed`). |
| Same failures with `failMode=open` | Tool continues. This is for low-risk development use only. |

OpenClaw 2026.3.2 does not consume an approval directive in the documented pre-tool hook, so `flag` is deliberately returned as a block.

## What leaves the machine

The evaluation request contains the tool name, arguments, optional agent/session identifiers, and timestamp. Telemetry sends the tool name, redacted parameters, outcome, and Aurels trace ID. Keys named password, secret, token, API key, authorization, cookie, or credential are redacted in telemetry. Evaluation arguments are not redacted because the policy engine may need them; do not pass secrets as tool arguments.

## Verify and troubleshoot

```bash
npm run check
npm test
openclaw plugins info aurels --json
openclaw plugins doctor
```

If the plugin cannot register both hooks, it throws at startup rather than silently leaving the agent unprotected. See [docs/OPERATIONS.md](docs/OPERATIONS.md) for rollout, debugging, rotation, rollback, and removal.

## Security boundary

Protected: tool calls that reach OpenClaw's registered hooks. Not protected: native host actions that bypass these hooks, direct filesystem writes outside OpenClaw tools, or subprocesses launched before a tool call reaches the hook.

## License

MIT. See [LICENSE](LICENSE).
