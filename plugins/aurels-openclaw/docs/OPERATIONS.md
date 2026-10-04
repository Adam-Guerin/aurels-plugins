# OpenClaw operations guide

## Safe rollout

1. Start with `AURELS_MODE=local` or a non-production Aurels workspace with `AURELS_MODE=remote`. Do not point a test key at the production workspace: the Free Supabase project does not provide isolated staging data.
2. Run `npm test` and confirm `openclaw plugins doctor` finds the plugin.
3. Execute synthetic benign, flagged, and blocked tool calls. Confirm only an explicitly allowed call reaches the handler; the blocked/flagged handler never runs. Never use real accounts, secrets, payments, or irreversible operations for this check.
4. Observe telemetry without enabling result collection or placing secrets in tool arguments.
5. Promote only after confirming the OpenClaw hook API version in use.

## Failures

Timeout, DNS/network failure, malformed or oversized response, unexpected decision, or unsupported approval path never silently allows the action: the plugin requests host approval where supported and otherwise blocks. A remote `allow` also requests one-shot approval to freeze the evaluated parameter snapshot against lower-priority plugin rewrites. HTTP 429 is stricter: it blocks immediately, displays the `Retry-After` interval, and does not ask for approval or retry automatically. Hermes' native `pre_tool_call` hook has no approval/resume result, so Aurels translates `flag`, offline ambiguous actions, and evaluation errors into explicit blocks; only remote `allow` and the separately opted-in retrospective advisory mode dispatch.

This protects only ordinary tool calls that reach the plugin's hooks and supported approval path. Aurels registers at the highest ordinary-hook priority and returns the evaluated parameters with its approval request; OpenClaw freezes that snapshot, so lower-priority hook rewrites do not reach dispatch. It cannot protect host-native actions that bypass the hooks or host-trusted policy layers outside them. Telemetry is best-effort and is not a durable audit log.

Remote endpoints must use HTTPS and must not contain embedded credentials. Response bodies are capped at 1 MiB before parsing.

## Key rotation

Store the API key outside the repository. Replace the runtime secret, restart or reload OpenClaw, test one benign call, then revoke the previous key. Use a plugin-specific, least-privilege key.

## Rollback and removal

Disable the plugin to stop interception:

```bash
openclaw plugins disable aurels
openclaw plugins uninstall aurels
```

Disabling removes this plugin's protection. Record that change through your change-management process and retain audit evidence before rolling back.
