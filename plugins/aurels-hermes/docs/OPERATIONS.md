# Hermes operations guide

## Safe rollout

1. Install in a non-production Hermes environment with `AURELS_MODE=remote`.
2. Run `python -m unittest discover -s tests`.
3. Test an allowed action and a known blocked action. Assert that the action handler is not called in the blocked case.
4. Verify telemetry does not contain keys or values that should remain local.
5. Document the supported Hermes adapter point and promote the same configuration through environments.

## Failure handling

Any unavailable, malformed, oversized, or non-success Aurels response becomes `{"action": "approve", "message": "..."}`; no action should run.

Remote endpoints must use HTTPS and must not contain embedded credentials. Response bodies are capped at 1 MiB before parsing.

## Credential rotation

Use a dedicated Aurels key scoped to evaluate actions and write telemetry only. Store it in the host's secret manager. Update the secret, restart the worker, verify an allowed request, and only then revoke the former key.

## Rollback and removal

Remove the plugin from the host's pre-action path or uninstall it with `python -m pip uninstall aurels-hermes`. This removes the guard; record the change and retain the related audit evidence.

## Scope boundary

Only actions routed through the adapter's `before_action` call are protected. Direct side effects, subprocesses, or filesystem operations outside that path are out of scope and need separate controls.
