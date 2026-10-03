# Plugin hardening — October 2026

Branch: `codex/plugins-production-hardening`. This pass preserves the existing unreleased adapter work and favors refusing an uncertain action over executing it. Packages retain their current versions; this branch does not publish a new release.

## Changes

- **Hermes:** Windows process liveness checks use a non-destructive native probe. Python's Windows `os.kill(pid, 0)` must not be used for lock-owner checks because it can terminate that process. Queue-cap regressions exercise independent processes. Native remote allow requires explicit hook-order trust; unsupported approval directives become real host refusals. A synchronous `run_protected` dispatcher now snapshots strict JSON arguments, evaluates a separate copy, executes the checked snapshot, and reports actual handler success/failure. Normal enforcement registration does not depend on an optional model facade.
- **OpenClaw:** fail-closed privileged outage handling, guarded one-shot approval arguments, redacted bounded telemetry, and bounded durable outbox delivery are included. Runtime checks cover supported hook runners and refusal on older approval-incompatible hosts.
- **CrewAI:** synchronous and asynchronous BaseTool paths are both guarded. Approval handlers receive independent copies and must return the literal boolean `True`; callback mutations cannot alter the approved dispatch. Mixed positional/keyword invocations preserve both argument sets, including in rewrites. Awaited tool failures/cancellation do not emit premature success. Telemetry worker startup failures do not cause a successful action to be retried, and transport error logs omit raw upstream messages.
- **Shared TypeScript guards:** injected clients receive the same strict decision validation as HTTP clients. Malformed decisions and missing rewrite payloads never become fail-open allow. Cancellation is checked after policy evaluation and before dispatch, including when an injected client ignores its signal.
- **MCP:** standard newline stdio replaces legacy framing as the default. The proxy now works with an official SDK client and server, processes cancellation during evaluation, bounds active calls, validates tool call shapes, handles shutdown, and classifies `isError` tool results as failures. Legacy Content-Length framing is explicit opt-in for matching legacy endpoints.
- **Claude Code / Codex:** malformed JSON and invalid decision metadata remain refusals even with outage fail-open enabled. Codex approval and rewrite remain conservative refusals. Native hook-format archives are tested, but full client sessions are not yet validated.
- **Packaging:** independent wheels/npm archives include their executable code and shared clients. Tests install clean artifacts, repeat actual LangGraph/Agents/MCP dispatch scenarios, and validate archive hashes, manifests, and marketplace paths. Experimental source snapshots under `legacy/` are excluded from maintained plugin claims.
- **CI:** Windows checks cover Hermes enforcement and queue behavior. CrewAI 1.15.23 runs in a separate environment against an installed guard wheel. Release validation provisions that host before running the complete suite. Framework SDK versions are locked for reproducible checks.

## Validation scope

| Runtime | Check |
| --- | --- |
| OpenClaw 2026.3.28 and 2026.9.6 | Real hook-runner integration; 2026.3.2 refuses unsupported approval dispatch |
| Hermes | Real sequential native executor plus maintained package unit/structure tests and installed wheel |
| CrewAI 1.15.23 | 14 real sync/async dispatch scenarios: allow, block, approval absent/denied/granted, rewrite, outage |
| LangGraph 1.4.18 / core 1.2.13 | Compiled graphs: allow, block, approval-required, rewrite |
| OpenAI Agents SDK 0.18.0 | Real Runner with synthetic model: allow, block, approval-required, rewrite |
| MCP SDK 1.32.0 | Real stdio negotiation, Unicode arguments, refusal/approval/rewrite, cancellation, pending-call cap, structured host error |
| Claude Code / Codex | Hook scripts against local synthetic API, invalid protocol, native archive layout |
| Ollama | Preset and marketplace/archive validation; no model inference |

Tests use local synthetic policy servers and synthetic tool handlers. No live model, production account, or destructive operation is needed. Installed npm archive checks repeat 12 actual SDK scenarios. Extracted Claude/Codex archives and the installed MCP command repeat the command-hook/proxy suite. The wheel and process-isolation checks are additional coverage.

## Reproduce

Local validation on October 3, 2026 completed successfully: **294 reported tests**, plus six Hermes native-dispatch scenarios and fourteen CrewAI native-dispatch scenarios. Nested artifact checks also repeat twelve real SDK scenarios and thirty-eight command-hook/proxy tests from installed/extracted packages. The CrewAI host scenarios passed again with the newly built wheel installed. `npm audit --audit-level=high` reported zero vulnerabilities in the locked JavaScript dependencies. Workflow YAML and the staged diff passed their structural checks; remote GitHub Actions has not been run for this branch.

Use Node.js 22+ and Python 3.11+. Install the pinned host runtimes into separate environments; do not overwrite a production agent installation.

```bash
npm ci --prefix plugins/aurels-integrations
npm install --prefix .ci/openclaw --no-save --ignore-scripts openclaw@2026.3.28
python -m venv .ci/crewai-host
.ci/crewai-host/bin/python -m pip install crewai==1.15.23
# Provide a separately installed Hermes checkout/runtime to the variables below.
OPENCLAW_PACKAGE_ROOT="$PWD/.ci/openclaw/node_modules/openclaw" \
HERMES_SOURCE_DIR="/path/to/hermes-agent" \
HERMES_PYTHON="/path/to/hermes-venv/bin/python" \
CREWAI_PYTHON="$PWD/.ci/crewai-host/bin/python" npm test
npm audit --audit-level=high --prefix plugins/aurels-integrations
```

On Windows, set the same variables in PowerShell and use each virtual environment's `Scripts/python.exe`. The supported-runtime CI additionally checks current OpenClaw with its required Node runtime. GitHub workflow execution remains to be confirmed after pushing this branch; local success is not a claim that remote CI has run.

## Deployment constraints

This pass improves correctness at the tested boundaries. It does not make every integration universally production-ready:

1. **Hermes native hooks:** later callbacks can still mutate host-owned arguments. Default remote allow is refused; explicit ordering trust requires an operator to control the complete callback chain. Use the application-owned synchronous dispatcher when you need snapshot-bound execution. Local mode is intentionally restrictive; retrospective mode is advisory.
2. **Claude Code and Codex:** host enablement, hook trust, later-hook rewrites, runtime hook failures, and opt-out execution paths remain host responsibilities. Full agent-session acceptance is still required before consequential deployments. The [Claude hook contract](https://code.claude.com/docs/en/hooks) and [Codex hook contract](https://developers.openai.com/codex/hooks) define these boundaries.
3. **OpenClaw:** trusted/native execution paths outside the ordinary approval chain remain outside this plugin. Full gateway interaction and approval lifecycle acceptance are separate from hook-runner tests.
4. **Framework guards and MCP:** only wrapped tools/proxied calls are guarded. Already-dispatched cancellation depends on the tool host. Preflight requests use bounded timeouts and are not retried; durable telemetry is best effort when disks, locks, queues, or connectivity fail.
5. **Policies and secrets:** redaction is heuristic. Evaluation sees original arguments. Live policy quality, API compatibility under production load, credential provisioning, and model inference need deployment validation. An explicit include list narrows protection; disabling a guard disables its protection.

The [support matrix](SUPPORT-MATRIX.md) separates supported packages from experimental adapters and records what was actually tested.
