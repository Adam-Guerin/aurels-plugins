# OpenClaw operations guide

## Safe rollout

1. Start in a non-production workspace with `AURELS_FAIL_MODE=closed`.
2. Run `npm test` and confirm `openclaw plugins doctor` finds the plugin.
3. Execute one benign tool call and one policy-blocked tool call. Confirm the blocked handler never runs.
4. Observe telemetry without enabling result collection or placing secrets in tool arguments.
5. Promote only after confirming the OpenClaw hook API version in use.

## Failures

`closed` is the production default: API outages, DNS failures, timeout, malformed responses, and unexpected decisions block execution. `open` allows execution after those failures and should only be selected through a documented risk decision.

## Key rotation

Store the API key outside the repository. Replace the runtime secret, restart or reload OpenClaw, test one benign call, then revoke the previous key. Use a plugin-specific, least-privilege key.

## Rollback and removal

Disable the plugin to stop interception:

```bash
openclaw plugins disable aurels
openclaw plugins uninstall aurels
```

Disabling removes this plugin's protection. Record that change through your change-management process and retain audit evidence before rolling back.
