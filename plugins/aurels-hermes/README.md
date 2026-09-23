# Aurels for Hermes

`aurels-hermes` is a standalone Python 3.11+ native Hermes guard. At startup it registers `pre_tool_call` and `post_tool_call`; a host missing either declared hook fails startup rather than silently running without protection. With no API key, it runs an offline deterministic policy and makes no network request.

## Support contract

| Component | Supported version |
| --- | --- |
| Plugin | 0.2.5 |
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
    if preflight["action"] == "block":
        return {"status": "blocked", "reason": preflight["message"]}
    if preflight["action"] == "approve":
        return {"status": "approval_required", "reason": preflight["message"]}
    result = execute_tool(name, arguments)
    guard.after_action(name, arguments, {**context, "action_id": preflight.get("action_id")}, status="success")
    return result
```

`before_action` and the exact tool execution must be adjacent. Do not mutate arguments after evaluation unless you use the `arguments` returned for an Aurels `rewrite` decision. For native registration, call `guard.register(hermes_host)` during host startup.

## Configure

```text
AURELS_API_URL=https://www.aurels.dev
AURELS_API_KEY=replace-with-a-scoped-plugin-key
AURELS_MODE=remote
AURELS_TIMEOUT_MS=1500
AURELS_TELEMETRY_ENABLED=true
```

You can instead pass a mapping to `AurelsHermesPlugin`, for example `{"api_key": runtime_secret, "mode": "remote"}`. Runtime mapping values take precedence over the environment.

For fully offline use, leave `AURELS_API_KEY` empty. Local rules always run first: they block clearly destructive command patterns and return approval-required for every other action, including actions whose names merely look read-only. They are deliberately conservative and are not semantic analysis.

## Decision and outage contract

| Event | `before_action` result |
| --- | --- |
| Local deterministic `allow` | `{"action": "allow"}`; execute the handler once without a model call. |
| Local deterministic `block` | `{"action": "block", "message": "..."}`; a remote model cannot override it. |
| Ambiguous action | The configured model evaluates it and must return exactly `allow`, `flag`, or `block`. |
| `allow` | `{"action": "allow"}`; execute the handler once. |
| `flag` | `{"action": "approve", "message": "..."}`; do not execute; return approval-required to the caller. |
| `block` | `{"action": "block", "message": "..."}`; do not execute. |
| Timeout, DNS failure, 4xx/5xx, invalid response, or another model output | `{"action": "approve", "message": "..."}`; no execution. |

The library never calls a protected handler itself. The hosting adapter must respect `{"action": "block"}`; the included tests exercise that security boundary.

Remote mode requires an HTTPS API URL with no embedded credentials. Responses are limited to 1 MiB before JSON parsing.

## Data handling

Evaluation sends action name, arguments, optional agent/session IDs, and timestamp to Aurels. Telemetry sends the action name, outcome, trace ID, and redacted arguments. Telemetry keys matching password, secret, token, API key, authorization, cookie, or credential are replaced with `[REDACTED]`. Keep secrets out of action arguments because policy evaluation receives the original arguments.

## Operations

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for production rollout, failure behavior, key rotation, rollback, and scope boundaries.

## License

MIT. See [LICENSE](LICENSE).
