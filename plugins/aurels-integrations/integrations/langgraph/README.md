# Aurel for LangGraph

LangGraph executes tools through `ToolNode` in graph workflows. Aurel wraps the tools before they are handed to `ToolNode`.

```ts
import { ToolNode } from "@langchain/langgraph/prebuilt";
import { wrapLangGraphTools } from "@aurels/langgraph-guard";

const protectedTools = wrapLangGraphTools(tools);
const toolNode = new ToolNode(protectedTools);
```

Install the standalone package from a GitHub release (install `@langchain/langgraph` and `@langchain/core` in your app as usual):

```bash
npm install "https://github.com/Adam-Guerin/aurels-plugins/releases/latest/download/aurels-langgraph-guard-0.1.0.tgz"
```

The archive contains the shared Aurels client/guard code; host SDKs remain peer dependencies.

The wrapper protects `invoke`, `call`, and `func` styles. It preserves run/session metadata from the LangGraph run config when available and reports post-tool telemetry after execution.

Configuration uses the shared Aurel tool guard config, including `enabled`, `failMode`, `failOpenPrivilegedActions`, `timeoutMs`, `telemetryEnabled`, `includeResults`, `maxPayloadBytes`, `redactionEnabled`, `approvalFallback`, and an exact tool `include` allowlist. The legacy `exclude` field and `AUREL_TOOLS_EXCLUDE` are ignored because they bypass the decision service. Environment fallback supports `AUREL_ENABLED`, `AUREL_API_URL`, `AUREL_API_KEY`, `AUREL_FAIL_MODE`, `AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS`, `AUREL_TIMEOUT_MS`, `AUREL_TELEMETRY_ENABLED`, `AUREL_TELEMETRY_INCLUDE_RESULTS`, `AUREL_TELEMETRY_MAX_PAYLOAD_BYTES`, `AUREL_REDACTION_ENABLED`, `AUREL_REWRITE_UNSUPPORTED_FALLBACK`, and `AUREL_TOOLS_INCLUDE`; `0`, `false`, `no`, and `off` disable boolean env flags.

If `AUREL_FAIL_MODE=open`, low-risk tools can proceed during an outage, but privileged tool names such as terminal/shell/process, browser/network, file mutation, messaging, database/cloud/package/schedule/delegation/MCP/API/finance/auth, and credential tools still stop before execution by default. Set `AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS=allow` only when pure fail-open behavior is intentional.

Decisions:

- `allow`: call the original tool.
- `block` / `quarantine`: throw a sanitized `AurelToolBlockedError`.
- `require_approval`: emit `approval_requested` telemetry and throw a sanitized approval-required error unless the app catches it and performs its own approval UX.
- `rewrite`: call the original tool with rewritten input.
