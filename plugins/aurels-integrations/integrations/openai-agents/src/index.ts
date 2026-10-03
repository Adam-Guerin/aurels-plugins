import {
  AurelToolBlockedError,
  createAurelToolGuard,
  type AurelToolCall,
  type AurelToolGuardClient,
  type AurelToolGuardConfig,
} from "../../shared/typescript/aurel-tool-guard.js";

export interface OpenAIAgentsToolLike {
  name: string;
  invoke?: (...args: any[]) => any;
  execute?: (input: unknown, context?: unknown, details?: unknown) => Promise<unknown> | unknown;
  inputGuardrails?: unknown[];
  outputGuardrails?: unknown[];
  [key: string]: unknown;
}

export function withAurelOpenAIAgentsTool<T extends OpenAIAgentsToolLike>(
  tool: T,
  config: Omit<AurelToolGuardConfig, "integration"> = {},
  client?: AurelToolGuardClient
): T {
  const guard = createAurelToolGuard({ ...config, integration: "openai-agents", rewriteSupported: true }, client);
  if (typeof tool.invoke === "function") {
    const originalInvoke = tool.invoke.bind(tool);
    return {
      ...tool,
      async invoke(runContext: unknown, input: string, details?: unknown) {
        const args = parseToolInput(input);
        const callId = contextValue(details, "toolCallId")
          ?? contextValue(details, "tool_call_id")
          ?? contextValue(contextValueObject(details, "toolCall"), "callId");
        return guard.runProtected(
          {
            id: callId,
            name: tool.name,
            arguments: args,
            agent: {
              id: contextValue(contextValueObject(runContext, "context"), "agentId"),
              sessionId: contextValue(contextValueObject(runContext, "context"), "sessionId"),
              runId: contextValue(contextValueObject(runContext, "context"), "runId"),
            },
            context: { metadata: { sdk: "@openai/agents", toolCallId: callId } },
          },
          (rewrittenArgs) => originalInvoke(runContext, JSON.stringify(rewrittenArgs), details),
        );
      },
    };
  }

  if (typeof tool.execute !== "function") {
    throw new TypeError("OpenAI Agents SDK function tool must expose invoke or execute");
  }
  const originalExecute = tool.execute.bind(tool);

  return {
    ...tool,
    async execute(input: unknown, context?: unknown, details?: unknown) {
      return guard.runProtected(
        {
          id: contextValue(details, "toolCallId") ?? contextValue(details, "tool_call_id") ?? contextValue(context, "toolCallId") ?? contextValue(context, "tool_call_id"),
          name: tool.name,
          arguments: input,
          agent: {
            id: contextValue(context, "agentId") ?? contextValue(context, "agent_name"),
            sessionId: contextValue(context, "sessionId"),
            runId: contextValue(context, "runId"),
          },
          context: { metadata: { sdk: "@openai/agents", toolCallId: contextValue(details, "toolCallId") } },
        },
        (args) => originalExecute(args, context, details)
      );
    },
  };
}

export function createAurelOpenAIToolInputGuardrail(
  toolName: string,
  config: Omit<AurelToolGuardConfig, "integration"> = {},
  client?: AurelToolGuardClient
) {
  const guard = createAurelToolGuard({ ...config, integration: "openai-agents", rewriteSupported: false }, client);
  return {
    type: "tool_input" as const,
    name: "aurel-tool-input-guardrail",
    async run({ context, toolCall }: {
      context: unknown;
      toolCall: { type?: string; callId: string; name: string; arguments: string };
    }) {
      const input = parseToolInput(toolCall.arguments);
      const call: AurelToolCall = {
        id: toolCall.callId,
        name: toolCall.name || toolName,
        arguments: input,
        agent: {},
        context: { metadata: { sdk: "@openai/agents", guardrail: true, toolCallId: toolCall.callId } },
      };
      const decision = await guard.preflight(call);
      if (decision.type === "allow") return { behavior: { type: "allow" as const } };
      void guard.postflight(decision.action, {
        status: decision.type === "require_approval" ? "approval_requested" : "blocked",
        preflightLatencyMs: decision.preflightLatencyMs,
        traceId: decision.decision?.traceId,
        args: input,
      }).catch((error) => {
        console.warn("[aurel-openai-agents] terminal telemetry failed:", error instanceof Error ? error.message : error);
      });
      return {
        behavior: {
          type: "rejectContent" as const,
          message: decision.type === "block"
            ? decision.message
            : "Aurel requires human approval before this action can run.",
        },
      };
    },
  };
}

export { AurelToolBlockedError };

function parseToolInput(input: string): unknown {
  try {
    return JSON.parse(input);
  } catch {
    throw new AurelToolBlockedError("Aurel security verification is unavailable.");
  }
}

function contextValue(context: unknown, key: string): string | undefined {
  if (!context || typeof context !== "object") return undefined;
  const value = (context as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function contextValueObject(context: unknown, key: string): unknown {
  if (!context || typeof context !== "object") return undefined;
  return (context as Record<string, unknown>)[key];
}
