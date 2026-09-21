import { createClient, createHandlers, loadConfig } from "./security.js";

export default {
  id: "aurels",
  name: "Aurels Security",
  register(api) {
    const register = api?.on;
    if (typeof register !== "function") throw new Error("Aurels requires OpenClaw before_tool_call and after_tool_call hooks.");
    const config = loadConfig(api.pluginConfig ?? api.getConfig?.() ?? api.config ?? {});
    const handlers = createHandlers(config, createClient(config));
    register.call(api, "before_tool_call", handlers.beforeToolCall, { priority: 100, timeoutMs: config.timeoutMs + 250 });
    register.call(api, "after_tool_call", handlers.afterToolCall, { priority: 100, timeoutMs: config.timeoutMs + 250 });
  }
};

export { createClient, createHandlers, loadConfig } from "./security.js";
