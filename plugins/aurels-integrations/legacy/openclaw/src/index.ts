import { createAurelHttpClient, createOpenClawAurelHandlers, loadConfig } from "./security.js";

type OpenClawApi = {
  on?: (hook: string, handler: (...args: never[]) => unknown, options?: Record<string, unknown>) => void;
  registerHook?: (hook: string, handler: (...args: never[]) => unknown, options?: Record<string, unknown>) => void;
  registerCommand?: (command: Record<string, unknown>) => void;
  getConfig?: () => unknown;
  config?: unknown;
};

function readPluginConfig(api: unknown): unknown {
  if (api && typeof api === "object") {
    const candidate = api as { getConfig?: () => unknown; config?: unknown };
    if (typeof candidate.getConfig === "function") return candidate.getConfig();
    return candidate.config;
  }
  return {};
}

// OpenClaw 2026.3.2 loads linked TypeScript entries synchronously. Keep this
// entry plain data so it can be evaluated by that loader without top-level await.
const entry = {
  id: "aurel",
  name: "Aurel Security Middleware",
  description: "Intercept OpenClaw tool calls and enforce Aurel security policy before execution.",
  register(api: OpenClawApi) {
    const useLegacyRegisterHook = typeof api.on !== "function" && typeof api.registerHook === "function";
    const registerHook = typeof api.on === "function" ? api.on.bind(api) : typeof api.registerHook === "function" ? api.registerHook.bind(api) : undefined;
    if (!registerHook) {
      api.registerCommand?.({
        name: "aurel",
        description: "Show Aurel plugin status.",
        requireAuth: true,
        handler: () => ({
          text: [
            "Aurel: unavailable",
            "Protection: disabled",
            "Reason: this OpenClaw runtime does not expose api.on tool-call hooks.",
          ].join("\n"),
        }),
      });
      throw new Error("Aurel requires an OpenClaw runtime with api.on or registerHook tool-call hooks.");
    }

    const config = loadConfig(readPluginConfig(api));
    const client = createAurelHttpClient(config);
    const handlers = createOpenClawAurelHandlers(config, client);
    const options = {
      registrationId: "aurel-tool-security",
      priority: 100,
      timeoutMs: config.timeoutMs + 250,
      ...(config.tools.include.length > 0 ? { matcher: config.tools.include } : {}),
    };

    const beforeToolCall = useLegacyRegisterHook
      ? async (event: never, ctx?: never) => legacySafeBeforeToolCall(await handlers.beforeToolCall(event, ctx))
      : handlers.beforeToolCall;

    registerHook("before_tool_call", beforeToolCall as never, options);
    registerHook("after_tool_call", handlers.afterToolCall as never, options);

    api.registerCommand?.({
      name: "aurel",
      description: "Show Aurel plugin status.",
      requireAuth: true,
      handler: () => {
        const status = handlers.status();
        return {
          text: [
            `Aurel: ${config.apiKey ? "configured" : "missing api key"}`,
            `Protection: ${status.enabled ? "enabled" : "disabled"}`,
            `Fail mode: ${status.failMode}`,
            `Telemetry: ${status.telemetry ? "enabled" : "disabled"}`,
            `Last decision: ${status.lastDecision?.decision ?? "none"}`,
          ].join("\n"),
        };
      },
    });
  },
};

export default entry;

function legacySafeBeforeToolCall(result: unknown): unknown {
  if (result && typeof result === "object" && "requireApproval" in result) {
    return {
      block: true,
      blockReason: "Aurel requires human approval before this action can run.",
    };
  }
  return result;
}
