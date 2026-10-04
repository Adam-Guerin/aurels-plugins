import { createClient, createHandlers, loadConfig } from "./security.js";

export default {
  id: "aurels",
  name: "Aurels Security",
  register(api) {
    const register = api?.on;
    if (typeof register !== "function") throw new Error("Aurels requires OpenClaw before_tool_call and after_tool_call hooks.");
    if (!supportsPluginApprovals(api?.runtime?.version)) {
      throw new Error("Unsupported OpenClaw runtime: Aurels requires tested version 2026.3.28 or 2026.9.6. Refusing to register security hooks on an unverified host.");
    }
    const config = loadConfig(api.pluginConfig ?? api.getConfig?.() ?? api.config ?? {});
    const handlers = createHandlers(config, createClient(config), {
      requireApprovalSupported: supportsPluginApprovals(api?.runtime?.version),
      llmComplete: typeof api?.runtime?.llm?.complete === "function" ? api.runtime.llm.complete.bind(api.runtime.llm) : undefined,
      logger: api?.logger
    });
    // Run first so this approval freezes the exact parameters Aurels evaluated
    // before any ordinary plugin hook can rewrite them.
    register.call(api, "before_tool_call", handlers.beforeToolCall, { priority: Number.MAX_SAFE_INTEGER, timeoutMs: config.timeoutMs + 250 });
    register.call(api, "after_tool_call", handlers.afterToolCall, { priority: 100, timeoutMs: config.timeoutMs + 250 });
    if (config.retrospectiveEnabled) {
      const complete = api?.runtime?.llm?.complete;
      if (typeof complete === "function") {
        register.call(api, "agent_end", handlers.agentEnd, { timeoutMs: 12_000 });
      } else {
        api?.logger?.warn?.("Aurels retrospective is enabled but this OpenClaw runtime has no host model-completion API; enforcement remains active and no retrospective data was sent.");
      }
    }
  }
};

function supportsPluginApprovals(version) {
  return version === "2026.3.28" || version === "2026.9.6";
}

export { createClient, createHandlers, loadConfig } from "./security.js";
