# Aurels for Hermes

`aurels-hermes` is a standalone Python 3.11+ native Hermes plugin. In `remote` mode it registers `pre_tool_call` and `post_tool_call` for Aurels API enforcement. In `local` mode it runs offline deterministic checks and blocks ambiguous actions because Hermes' native hook cannot pause for approval. In the separately opt-in `retrospective` mode it lets tools run and asks Hermes' already-configured model to review a bounded, redacted action summary at session end; this is advisory and is not an execution guard.

## Support contract

| Component | Supported version |
| --- | --- |
| Plugin | 0.2.6 |
| Python | 3.11 or newer |
| Hermes host | Hermes Agent v0.15.1+ native plugin runtime; native pre-tool hooks must honor `{"action":"block"}` |
| Aurels API | `/api/v1/actions/evaluate` and `/api/v1/actions/telemetry` in `remote` mode only |

## Install and verify

```bash
cd plugins/aurels-hermes
python -m venv .venv
.venv\Scripts\activate
python -m pip install .
python -m unittest discover -s tests
```

On macOS/Linux, activate with `source .venv/bin/activate`.

For a wheel installed into the Hermes environment, add the package name to
`plugins.enabled` in the Hermes configuration and restart Hermes:

```yaml
plugins:
  enabled:
    - aurels-hermes
```

`hermes plugins enable` only manages Git-cloned directory plugins; it does not
activate Python entry-point packages. This native integration uses Hermes'
pre-tool hook contract: only a nonempty `action: "block"` response stops
dispatch; `approve` is not a supported pause/resume result. See the host-runtime
E2E (`npm run test:e2e:hermes-host`) for the pinned Hermes executor test.

## Hermes adapter example

```python
from aurels_hermes import AurelsHermesPlugin, AurelsToolBlockedError

guard = AurelsHermesPlugin()

def run_tool(name, arguments, context):
    try:
        return guard.run_protected(
            name, arguments,
            lambda checked: execute_tool(name, checked),
            context,
        )
    except AurelsToolBlockedError as error:
        return {"status": "blocked", "reason": str(error)}
```

`run_protected` is for a trusted, synchronous dispatcher owned by your application. It snapshots strict JSON arguments before evaluation and passes that snapshot directly to the handler. The handler must execute those supplied arguments. A refusal, an approval requirement, a policy outage, or invalid arguments prevents dispatch; a handler exception records failure and is re-raised. Awaitable handlers are rejected: use this helper only for synchronous tools. It does not require native hook-order trust because evaluation and execution happen at this boundary. In `retrospective` mode it remains advisory. For native registration, call `guard.register(hermes_host)` during host startup; ordinary enforcement does not need the optional host LLM facade.

**Native-hook integrity limitation:** Hermes passes a mutable argument mapping through `pre_tool_call` callbacks in sequence, then dispatches the resulting mapping. Aurels can block in its callback, but the native hook contract does not let this plugin replace or freeze the final mapping, nor re-check it immediately before dispatch. A later plugin callback could therefore change arguments after Aurels returns `allow`. Do not treat native Hermes `allow` as bound to the exact dispatched arguments when other plugins can mutate them. For consequential tools, control hook ordering and ensure no later hook rewrites arguments, or put an Aurels check in a trusted adapter immediately adjacent to execution. A host-provided immutable final-invocation context/permit check is required to remove this limitation generally; cloning arguments inside this plugin alone would not fix the host's dispatched mapping.

## Configure

Create a workspace API key in [Aurels API Keys](https://www.aurels.dev/dashboard/api-keys) with the least-privilege `operator` role, then copy it once into your secret manager. API keys are workspace-scoped (not endpoint-scoped), so never use an admin key in an agent runtime. Do not use a Supabase publishable/anon key or `service_role` key as `AURELS_API_KEY`.

```text
AURELS_API_URL=https://www.aurels.dev
AURELS_API_KEY=replace-with-a-scoped-plugin-key
AURELS_MODE=remote
AURELS_TIMEOUT_MS=1500
AURELS_TELEMETRY_ENABLED=true
AURELS_TELEMETRY_DURABLE=false
```

You can instead pass a mapping to `AurelsHermesPlugin`, for example `{"api_key": runtime_secret, "mode": "remote"}`. Runtime mapping values take precedence over the environment.

For offline enforcement, leave `AURELS_API_KEY` empty and set `AURELS_MODE=local`. Local rules block a few clearly destructive command patterns and treat every other action, including actions whose names merely look read-only, as requiring human approval. Since Hermes' native `pre_tool_call` contract only supports a `block` directive (it silently ignores `approve`), the plugin converts that approval-required outcome into an explicit block. No ambiguous action reaches dispatch. These deliberately conservative checks are not semantic analysis. A custom adapter using `before_action()` directly can instead implement an actual approval/resume flow.

In native Hermes `remote` mode, a remote `allow` is also blocked by default because Hermes passes mutable arguments through hooks in sequence and Aurels cannot bind its decision to the final dispatch arguments. Only set `AURELS_HERMES_TRUST_NATIVE_HOOK_ORDER=true` after verifying and controlling hook ordering so no later plugin or host hook can rewrite arguments. This is an explicit operator trust decision, not cryptographic protection; keep consequential tools blocked unless that ordering is controlled. The custom `before_action()` API remains usable when its caller checks and executes the exact same argument snapshot.

For post-action model review using the model/provider and authentication already configured in Hermes, use `AURELS_MODE=retrospective` with no Aurels key. The plugin calls Hermes' host-owned `ctx.llm.complete_structured` API and does not receive provider credentials. This is disconnected from the Aurels API key, not necessarily offline: if Hermes is configured with OpenAI or another cloud model, the redacted action summaries are sent to that provider and consume its normal usage/quota. The plugin makes one bounded review call at session finalization, keeps at most 100 action summaries per session and 64 unfinished sessions in memory, purges inactive summaries after one hour when another hook runs (or on finalization), omits tool results and the user's full conversation, and writes the structured review to the Hermes plugin log. If the host model call fails, the log recommends checking Hermes provider authentication without logging the raw provider error. Because session goals and tool results are not provided to this hook, the model can assess the action sequence for apparent risk but cannot reliably judge task success or intent-alignment. Treat its findings as suggestions, never as proof or authorization.

## Decision and outage contract

| Event | Direct `before_action` result | Registered Hermes hook |
| --- | --- |
| Local deterministic `allow` | `{"action": "approve"}` for ambiguous inputs | Explicit block; Hermes ignores approval requests |
| Local deterministic `block` | `{"action": "block", "message": "..."}` | Explicit block |
| `retrospective` mode | `{"action": "allow"}`; advisory only | Explicit allow; tools execute |
| Remote `allow` | `{"action": "allow"}` | Block by default; executes only with explicit native hook-order trust |
| Remote `flag` | `{"action": "approve", "message": "..."}` | Explicit block; native Hermes cannot pause for approval |
| Remote `block` | `{"action": "block", "message": "..."}` | Explicit block |
| HTTP 429 rate limit | `{"action": "block", "message": "..."}` | Explicit block; respect `Retry-After` |
| Timeout, DNS failure, 4xx/5xx, invalid response, or unexpected output | `{"action": "approve", "message": "..."}` | Explicit block; no fail-open dispatch |

`before_action` alone never calls a handler; `run_protected` owns synchronous dispatch. The native hook converts every status other than an explicit `allow` or valid `block` into a nonempty host `block` response; tests exercise this through Hermes' real sequential dispatcher. Native Hermes hooks do not support interactive approval/resume. The pre-hook returns its generated `action_id`; native Hermes adapters should pass the host `tool_call_id` through both callbacks when available. When it is absent, the plugin correlates by task/session and a canonical fingerprint of tool name and arguments with a bounded TTL.

Remote mode requires an HTTPS API URL with no embedded credentials. Responses are limited to 1 MiB before JSON parsing.

The current API quota is 600 requests per minute per workspace, shared by integrations. A 429 response includes `Retry-After` and standard `X-RateLimit-*` headers. The Free Supabase project does not provide an isolated staging database; a key created in the current Aurels workspace reaches its live policies and data.

## Data handling

Evaluation sends action name, arguments, optional agent/session IDs, and timestamp to Aurels. Telemetry sends the action name, outcome, trace ID, and redacted arguments. Telemetry keys matching password, secret, token, API key, authorization, cookie, or credential are replaced with `[REDACTED]`; common embedded formats (Bearer values, `sk-…` keys, AWS access-key IDs, GitHub tokens, JWTs, and PEM private-key headers) are also detected inside ordinary text fields such as `content`, `message`, and `payload`. This is heuristic redaction, not DLP: novel formats, split/encoded secrets, and arbitrary personal or confidential text may pass through. Keep secrets out of action arguments because policy evaluation receives the original arguments.

Durable telemetry is opt-in (`AURELS_TELEMETRY_DURABLE=true`). It writes already-redacted events to an OS-local Aurels state directory before returning from the hook, then retries them on startup, subsequent events, and a capped exponential schedule (1 second to 60 seconds) while the process remains online. Enqueue uses a short cross-process filesystem lock so simultaneous plugin instances cannot exceed the queue cap; lock contention times out as best-effort telemetry rather than changing enforcement. The outbox is capped at 1,000 events, 8 MiB total, 64 KiB per event, and seven days of event retention; abandoned staging files older than 24 hours are pruned. Successful API ingestion removes an event, and the API's event-hash upsert makes exact retries idempotent. Events remain plaintext on disk, protected by local directory permissions (Windows inherits the user's LocalAppData ACL). Redaction is heuristic and cannot guarantee removal of every sensitive value. If the disk is unavailable or the queue is full, a warning is logged and enforcement still works, but that audit event is best effort. Keep this disabled if local retention is not acceptable.

## Operations

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for production rollout, failure behavior, key rotation, rollback, and scope boundaries.

## License

MIT. See [LICENSE](LICENSE).
