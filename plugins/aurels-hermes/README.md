# Aurels for Hermes

`aurels-hermes` is a standalone Python 3.11+ native Hermes guard. At startup it registers `pre_tool_call` and `post_tool_call`; a host missing either declared hook fails startup rather than silently running without protection. With no API key, it runs an offline deterministic policy and makes no network request.

## Support contract

| Component | Supported version |
| --- | --- |
| Plugin | 0.2.0 |
| Python | 3.11 or newer |
| Hermes host | Any host adapter able to call synchronous pre- and post-action hooks |
| Aurels API | `/api/v1/actions/evaluate` and `/api/v1/actions/telemetry` |

## Install and verify

```bash
cd plugins/aurels-hermes
python -m venv .venv
.venv\Scripts\activate
python -m pip install .
python -m unittest discover -s tests
```

On macOS/Linux, activate with `source .venv/bin/activate`.

## Hermes adapter example

```python
from aurels_hermes import AurelsHermesPlugin

guard = AurelsHermesPlugin()

def run_tool(name, arguments, context):
    preflight = guard.before_action(name, arguments, context)
    if not preflight["allow"]:
        return {"status": "approval_required_or_blocked", "reason": preflight["reason"]}
    result = execute_tool(name, preflight.get("arguments", arguments))
    guard.after_action(name, arguments, {**context, "action_id": preflight["action_id"]}, success=True)
    return result
```

`before_action` and the exact tool execution must be adjacent. Do not mutate arguments after evaluation unless you use the `arguments` returned for an Aurels `rewrite` decision. For native registration, call `guard.register(hermes_host)` during host startup.

## Configure

```text
AURELS_API_URL=https://www.aurels.dev
AURELS_API_KEY=replace-with-a-scoped-plugin-key
AURELS_FAIL_MODE=closed
AURELS_TIMEOUT_MS=1500
AURELS_TELEMETRY_ENABLED=true
```

You can instead pass a mapping to `AurelsHermesPlugin`, for example `{"api_key": runtime_secret, "fail_mode": "closed"}`. Runtime mapping values take precedence over the environment.

For fully offline use, leave `AURELS_API_KEY` empty. Local mode allows read-only actions, blocks clearly destructive command patterns, and returns approval-required for every other action. It is deliberately conservative and is not semantic analysis.

## Decision and outage contract

| Event | `before_action` result |
| --- | --- |
| `allow` | `allow: true`; execute the handler once. |
| `rewrite` with object arguments | `allow: true` and replacement arguments. |
| `flag` | `allow: false`; do not execute; return approval-required to the caller. |
| `block` / `quarantine` | `allow: false`; do not execute. |
| Timeout, DNS failure, 4xx/5xx, invalid response | `allow: false` by default. |
| Those failures with `fail_mode=open` | `allow: true, degraded: true`; development-only choice. |

The library never calls a protected handler itself. The hosting adapter must respect `allow: false`; the included tests exercise that security boundary.

## Data handling

Evaluation sends action name, arguments, optional agent/session IDs, and timestamp to Aurels. Telemetry sends the action name, outcome, trace ID, and redacted arguments. Telemetry keys matching password, secret, token, API key, authorization, cookie, or credential are replaced with `[REDACTED]`. Keep secrets out of action arguments because policy evaluation receives the original arguments.

## Operations

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for production rollout, failure behavior, key rotation, rollback, and scope boundaries.

## License

MIT. See [LICENSE](LICENSE).
