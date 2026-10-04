# Aurel for CrewAI

Use your own Jev key or local Laya/Ollama model with the [self-hosted evaluator](../../../aurels-evaluator/README.md). The guide generates the local URL/token configuration; this adapter retains its existing enforcement and approval contract.

CrewAI task guardrails validate task outputs. For pre-tool security, Aurel wraps CrewAI tools so the check runs before synchronous `_run`, asynchronous `_arun`, or a callable tool executes. Coroutine callables remain asynchronous; completion telemetry waits for their actual result.

## Usage

```python
from aurel_crewai import protect_tool

safe_tool = protect_tool(existing_tool)
```

Set:

```text
AUREL_API_URL=https://your-aurel.example.com
AUREL_API_KEY=...
AUREL_FAIL_MODE=closed
AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=block
AUREL_TIMEOUT_MS=1500
AUREL_TELEMETRY_ENABLED=true
AUREL_TELEMETRY_INCLUDE_RESULTS=false
AUREL_TELEMETRY_MAX_PAYLOAD_BYTES=32768
AUREL_REDACTION_ENABLED=true
AUREL_ENABLED=true
AUREL_TOOLS_INCLUDE=
AUREL_TOOLS_EXCLUDE= # legacy; exclusions no longer bypass preflight
```

`AUREL_TOOLS_INCLUDE` is a comma-separated allowlist of exact tool names; an empty list means evaluate every tool call. `AUREL_TOOLS_EXCLUDE` is retained as a deprecated configuration field but is ignored because exclusions bypass the security decision. To protect a subset, use the include list, understanding that non-included tools are deliberately outside Aurels' protection boundary.

If `AUREL_FAIL_MODE=open`, low-risk tools can proceed during an outage, but privileged tool names such as terminal/shell/process, browser/network, file mutation, messaging, database/cloud/package/schedule/delegation/MCP/API/finance/auth, and credential tools still fail closed by default. Set `AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=allow` only when pure fail-open behavior is intentional.

Wrapped callables and `_run` tools preserve their original invocation shape. Keyword calls remain keyword calls, a single positional mapping remains one mapping argument, and multi-positional calls remain positional.

Mixed positional/keyword calls are evaluated as `{"args": [...], "kwargs": {...}}` and dispatched with both parts. Rewrites for such calls must provide that complete shape; partial replacements are refused before calling the tool.

`block` and `quarantine` raise `AurelToolBlockedError` before the underlying tool runs. Because CrewAI has no portable native approval prompt at the wrapped tool boundary, `require_approval` emits `approval_requested` telemetry and stops execution by default. Hosts can pass `approval_handler` in `AurelCrewAIConfig`; the handler receives independent copies of the normalized action and decision. Only the literal boolean `True` permits execution; strings and other truthy values do not. Changes made by the callback cannot change the dispatched arguments. Approval decisions emit normalized resolution telemetry (`approval_allowed` or `approval_denied`); handler exceptions emit a sanitized `failure` outcome. `rewrite` uses validated replacement arguments before execution. Malformed policy JSON or decisions always block, including when outage fail-open is enabled.

```python
from aurel_crewai import AurelCrewAIConfig, AurelCrewAIGuard, protect_tool

def approve(action, decision):
    return human_review(action, decision)

guard = AurelCrewAIGuard(AurelCrewAIConfig(approval_handler=approve))
safe_tool = protect_tool(existing_tool, guard)
```

Telemetry includes the tool name, redacted argument metadata, and decision metadata for terminal pre-execution outcomes. Raw tool results are excluded by default; set `AUREL_TELEMETRY_INCLUDE_RESULTS=true` only when your policy allows result upload. Tool names are not treated as trusted Aurel identity: even an `aurel.*` name is evaluated. Aurel's decision client is an HTTP client, not a protected CrewAI tool, so there is no need for a name-based recursive bypass.

The Aurel API URL must be `http` or `https` and cannot contain embedded credentials. Query strings and fragments are stripped before endpoint paths are appended, oversized Aurel responses are rejected, and redirects are treated as errors so the API key is never forwarded to a redirect target. Rewrite telemetry records the arguments actually sent to the tool and redacted original arguments.

Policy evaluation is synchronous even for asynchronous tools, so it can briefly block the event loop up to the configured timeout. This favors a single checked dispatch path over throughput. Telemetry failures do not turn a completed tool action into an exception that might cause an unsafe retry.

The real-host regression suite covers CrewAI 1.15.23 `BaseTool.run` and `BaseTool.arun`: allow, deny, approval absent/denied/granted, rewrite, and policy outage. CI repeats these scenarios with an installed guard wheel. This is a dispatch compatibility check, not an end-to-end Crew execution with a live model.

## Packaging

Install the downloadable wheel from the latest GitHub release:

```bash
python -m pip install "https://github.com/Adam-Guerin/aurels-plugins/releases/latest/download/aurels_crewai-0.1.0-py3-none-any.whl"
```

Or install directly from this repository's source directory:

```bash
python -m pip install plugins/aurels-integrations/integrations/crewai
```

The distribution intentionally does not install CrewAI itself; install the CrewAI version supported by your application separately. The wheel contains the Aurels guard only and can also be installed with `python -m pip install --no-deps <wheel>`. This adapter remains experimental and is not included in the supported-plugin contract.
