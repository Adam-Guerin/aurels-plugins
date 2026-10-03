import {
  createAurelToolGuard,
  type AurelToolGuardClient,
  type AurelToolGuardConfig,
} from "../../shared/typescript/aurel-tool-guard.js";

export interface LangGraphToolLike {
  name?: string;
  lc_name?: string;
  invoke?: (...args: any[]) => any;
  call?: (...args: any[]) => any;
  func?: (...args: any[]) => any;
}

export function wrapLangGraphTool<T extends LangGraphToolLike>(
  tool: T,
  config: Omit<AurelToolGuardConfig, "integration"> = {},
  client?: AurelToolGuardClient
): T {
  const guard = createAurelToolGuard({ ...config, integration: "langgraph", rewriteSupported: true }, client);
  const name = tool.name ?? tool.lc_name ?? "unknown_langgraph_tool";
  const wrapped: LangGraphToolLike = { ...tool };

  if (typeof tool.invoke === "function") {
    const original = tool.invoke.bind(tool);
    wrapped.invoke = async (input: unknown, runConfig?: unknown) => {
      const toolCall = readToolCall(input);
      const action = call(name, toolCall?.args ?? input, runConfig, toolCall?.id);
      return guard.runProtected(action, (args) => original(
        toolCall ? { ...toolCall, args } : args,
        runConfig,
      ));
    };
  }
  if (typeof tool.call === "function") {
    const original = tool.call.bind(tool);
    wrapped.call = async (input: unknown, runConfig?: unknown) => {
      const toolCall = readToolCall(input);
      const action = call(name, toolCall?.args ?? input, runConfig, toolCall?.id);
      return guard.runProtected(action, (args) => original(
        toolCall ? { ...toolCall, args } : args,
        runConfig,
      ));
    };
  }
  if (typeof tool.func === "function") {
    const original = tool.func.bind(tool);
    wrapped.func = async (input: unknown, runConfig?: unknown) => {
      const toolCall = readToolCall(input);
      const action = call(name, toolCall?.args ?? input, runConfig, toolCall?.id);
      return guard.runProtected(action, (args) => original(
        toolCall ? { ...toolCall, args } : args,
        runConfig,
      ));
    };
  }

  return wrapped as T;
}

export function wrapLangGraphTools<T extends LangGraphToolLike>(
  tools: T[],
  config: Omit<AurelToolGuardConfig, "integration"> = {},
  client?: AurelToolGuardClient
): T[] {
  return tools.map((tool) => wrapLangGraphTool(tool, config, client));
}

function call(name: string, input: unknown, runConfig: unknown, toolCallId?: string) {
  return {
    name,
    id: toolCallId ?? readString(runConfig, "toolCallId") ?? readString(runConfig, "tool_call_id"),
    arguments: input,
    agent: {
      runId: readString(runConfig, "runId") ?? readString(runConfig, "thread_id"),
      sessionId: readString(runConfig, "sessionId"),
    },
    context: {
      metadata: {
        sdk: "langgraph",
        configurableThreadId: readNestedString(runConfig, ["configurable", "thread_id"]),
      },
    },
  };
}

function readToolCall(value: unknown): { id?: string; args: unknown; [key: string]: unknown } | undefined {
  if (!value || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  if (record.type !== "tool_call" || !("args" in record)) return undefined;
  return {
    ...record,
    id: typeof record.id === "string" ? record.id : undefined,
    args: record.args,
  };
}

function readString(value: unknown, key: string): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const candidate = (value as Record<string, unknown>)[key];
  return typeof candidate === "string" ? candidate : undefined;
}

function readNestedString(value: unknown, path: string[]): string | undefined {
  let current = value;
  for (const key of path) {
    if (!current || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === "string" ? current : undefined;
}
