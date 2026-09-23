# Aurels for OpenClaw

`@aurels/openclaw-plugin` is a standalone Node.js plugin that intercepts OpenClaw tool calls before execution. With no API key, it runs an offline deterministic policy and makes no network request. A key optionally enables remote Aurels evaluation.

## Support contract

| Component | Supported version |
| --- | --- |
| Plugin | 0.2.5 |
| Node.js | 20 or newer |
| OpenClaw | 2026.3.28 or newer, with `before_tool_call`, `after_tool_call` hooks and `requireApproval` support |
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
AURELS_MODE=remote
AURELS_TIMEOUT_MS=1500
AURELS_TELEMETRY_ENABLED=true
```

Leave `AURELS_API_KEY` empty and set `AURELS_MODE=local` for offline use. Local rules always run first: they block clearly destructive command patterns and flag every other action, including actions whose names merely look read-only. They are intentionally conservative and do not provide semantic analysis.

## Decision and outage contract

| Event | Result |
| --- | --- |
| Local deterministic `allow` | Tool executes unchanged; the model is not called. |
| Local deterministic `block` | Tool does not execute; a remote model cannot override it. |
| Ambiguous action | The configured model evaluates it and must return exactly `allow`, `flag`, or `block`. |
| `allow` | Tool executes unchanged. |
| `flag` | Tool does not execute. OpenClaw receives an approval-required block. |
| `block` | Tool does not execute. |
| Timeout, network failure, 4xx/5xx, invalid JSON, or another model output | `flag`: tool does not execute and requires human approval. |

OpenClaw 2026.3.2+ properly handles the approval directive returned by Aurels.

Remote mode requires an HTTPS API URL with no embedded credentials. Responses are limited to 1 MiB before JSON parsing.

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
