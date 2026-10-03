# Aurels for OpenClaw

`@aurels/aurels` is a standalone Node.js plugin that intercepts OpenClaw tool calls before execution. With no API key, it runs an offline deterministic policy and makes no network request. A key optionally enables remote Aurels evaluation.

## Support contract

| Component | Supported version |
| --- | --- |
| Plugin | 0.2.6 |
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

Create a workspace API key in [Aurels API Keys](https://www.aurels.dev/dashboard/api-keys) with the least-privilege `operator` role, then copy it once into your secret manager. API keys are workspace-scoped (not endpoint-scoped), so never use an admin key in an agent runtime. Do not use a Supabase publishable/anon key or `service_role` key as `AURELS_API_KEY`.

```text
AURELS_API_URL=https://www.aurels.dev
AURELS_API_KEY=replace-with-a-scoped-plugin-key
AURELS_MODE=remote
AURELS_TIMEOUT_MS=1500
AURELS_TELEMETRY_ENABLED=true
AURELS_TELEMETRY_DURABLE=false
```

Leave `AURELS_API_KEY` empty and set `AURELS_MODE=local` for offline use. Local rules always run first: they block clearly destructive command patterns and flag every other action, including actions whose names merely look read-only. They are intentionally conservative and do not provide semantic analysis.

### Optional local retrospective

On OpenClaw versions that expose the host-owned `api.runtime.llm.complete` capability (available in the current 2026.9.x runtime, not the minimum supported 2026.3.28 runtime), you can opt in to a post-run retrospective without an Aurels key or Aurels API request:

```json5
{
  plugins: {
    entries: {
      aurels: {
        config: { mode: "local", retrospectiveEnabled: true },
        hooks: { allowConversationAccess: true },
        llm: { allowedCompletionModels: ["openai/<your-configured-model>"] }
      }
    }
  }
}
```

The host's configured model reviews a bounded set of redacted tool names, arguments, and outcomes after the run. It does not receive tool results or the conversation transcript. Arguments may still contain confidential text that heuristic redaction misses, and the selected model provider may receive this review request; enable it only if that data flow is acceptable. The review is advisory, time-limited, and cannot allow, block, or change an action—the offline deterministic policy remains the only pre-execution control. If the host lacks the completion capability, the plugin warns and leaves its security hooks enabled; it does not fall back to an Aurels API call.

## Decision and outage contract

| Event | Result |
| --- | --- |
| Local deterministic `block` | Tool does not execute; a remote model cannot override it. |
| Local ambiguous action | OpenClaw requests one-shot human approval; the action is not sent to Aurels and does not execute unless the user chooses `allow-once`. |
| Remote ambiguous action | The Aurels API evaluates it and must return exactly `allow`, `flag`, or `block`. |
| `allow` | OpenClaw requests one-shot human confirmation and freezes the exact parameters Aurels evaluated before lower-priority plugin hooks run. Only `allow-once` executes that snapshot. |
| `flag` | OpenClaw requests one-shot human approval for the exact evaluated parameters; denial, timeout, cancellation, or no approval route means no execution. |
| `block` | Tool does not execute. |
| HTTP 429 rate limit | Block the tool call and show the `Retry-After` wait; it is not silently retried or sent for approval. |
| Timeout, network failure, other 4xx/5xx, invalid JSON, or another model output | `flag`: tool does not execute and requires human approval. |

OpenClaw 2026.3.28+ is required for the approval directive returned by Aurels. The plugin reads the host version at startup; on older or unknown hosts it hard-blocks decisions that require an approval or parameter freeze rather than letting unsupported fields be ignored. This PC currently has OpenClaw 2026.3.2: it can load the plugin, but is below the supported minimum, so policy-allowed remote actions are also blocked. Upgrade OpenClaw before using the integration.

Remote mode requires an HTTPS API URL with no embedded credentials. Responses are limited to 1 MiB before JSON parsing.

Rate-limit responses block immediately and display the server's `Retry-After` interval. Other outages and malformed responses require human approval on a supported host, or hard-block on a host version that cannot safely present an approval request. Every remote `allow` also requires one-shot confirmation: OpenClaw runs Aurels at the highest ordinary-hook priority, and its approval freezes the exact evaluated parameter snapshot so lower-priority hooks cannot rewrite it. This adds an approval step to every call; keep the integration enabled only on a host build with the documented approval contract.

The current API quota is 600 requests per minute per workspace, shared by integrations. A 429 response includes `Retry-After` and standard `X-RateLimit-*` headers. The Free Supabase project does not provide an isolated staging database; a key created in the current Aurels workspace reaches its live policies and data.

## What leaves the machine

The evaluation request contains the tool name, arguments, optional agent/session identifiers, and timestamp. Telemetry sends the tool name, redacted parameters, outcome, and Aurels trace ID. Keys named password, secret, token, API key, authorization, cookie, or credential are redacted in telemetry; common embedded forms (Bearer values, `sk-…` keys, AWS access-key IDs, GitHub tokens, JWTs, and PEM private-key headers) are also detected in ordinary text fields. This is heuristic redaction, not DLP: novel, split, or encoded secrets and arbitrary confidential text may pass through. Evaluation arguments are not redacted because the policy engine may need them; do not pass secrets as tool arguments. Authenticated API requests reject HTTP redirects so the workspace key cannot be forwarded to another origin.

Durable telemetry is opt-in (`AURELS_TELEMETRY_DURABLE=true`). It writes already-redacted telemetry events to an OS-local Aurels state directory before the hook returns, then retries them on startup, subsequent events, and a capped exponential schedule (1 second to 60 seconds) while the process remains online. Enqueue uses a short cross-process filesystem lock so simultaneous plugin instances cannot exceed the queue cap; lock contention times out as best-effort telemetry rather than changing enforcement. The outbox is capped at 1,000 events, 8 MiB total, 64 KiB per event, and seven days of event retention; abandoned staging files older than 24 hours are pruned. Successful API ingestion removes an event, and the API's event-hash upsert makes exact retries idempotent. Events remain plaintext on disk, protected by local directory permissions (Windows inherits the user's LocalAppData ACL). Redaction is heuristic and cannot guarantee removal of every sensitive value. If the disk is unavailable or the queue is full, a warning is logged and enforcement still works, but that audit event is best effort. Keep this disabled if local retention is not acceptable.

## Verify and troubleshoot

```bash
npm run check
npm test
openclaw plugins info aurels --json
openclaw plugins doctor
```

If the plugin cannot register both hooks, it throws at startup rather than silently leaving the agent unprotected. See [docs/OPERATIONS.md](docs/OPERATIONS.md) for rollout, debugging, rotation, rollback, and removal.

## Security boundary

Protected: ordinary OpenClaw tool calls that reach the registered hook chain and use the supported approval flow. Not protected: native host actions that bypass these hooks, direct filesystem writes outside OpenClaw tools, subprocesses launched before a tool call reaches the hook, or host-trusted policies that run outside the ordinary plugin hook chain. Codex native hook relays in report mode may translate plugin approval into a deny instead of an interactive prompt; verify the actual host path before deployment.

## License

MIT. See [LICENSE](LICENSE).
