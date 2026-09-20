const BLOCKED = "Aurels blocked this action because it violates the active security policy.";
const UNAVAILABLE = "Aurels security verification is unavailable.";
const SECRET_KEY = /(?:password|secret|token|api[_-]?key|authorization|cookie|credential)/i;

export function loadConfig(raw = {}) {
  const env = process.env;
  const cfg = raw && typeof raw === "object" ? raw : {};
  const timeoutMs = Number(cfg.timeoutMs ?? env.AURELS_TIMEOUT_MS ?? 1500);
  return {
    enabled: cfg.enabled ?? env.AURELS_ENABLED !== "false",
    apiUrl: String(cfg.apiUrl ?? env.AURELS_API_URL ?? "https://www.aurels.dev").replace(/\/$/, ""),
    apiKey: String(cfg.apiKey ?? env.AURELS_API_KEY ?? ""),
    failMode: cfg.failMode ?? env.AURELS_FAIL_MODE ?? "closed",
    timeoutMs: Number.isFinite(timeoutMs) ? Math.min(Math.max(timeoutMs, 100), 30000) : 1500,
    telemetry: cfg.telemetry ?? env.AURELS_TELEMETRY_ENABLED !== "false"
  };
}

export function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, SECRET_KEY.test(key) ? "[REDACTED]" : redact(item)]));
}

export function createClient(config, fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== "function") throw new Error("A Fetch-compatible runtime is required.");
  async function request(path, payload) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.timeoutMs);
    try {
      const response = await fetchImpl(`${config.apiUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${config.apiKey}` },
        body: JSON.stringify(payload), signal: controller.signal
      });
      if (!response.ok) throw new Error(`Aurels returned HTTP ${response.status}`);
      return await response.json();
    } finally { clearTimeout(timer); }
  }
  return { evaluate: (action) => request("/api/v1/actions/evaluate", action), telemetry: (event) => request("/api/v1/actions/telemetry", event) };
}

export function createHandlers(config, client) {
  const traceByCall = new Map();
  return {
    async beforeToolCall(event = {}, context = {}) {
      if (!config.enabled || String(event.toolName || "").startsWith("aurels.")) return undefined;
      const action = { version: "1", integration: "openclaw", action: { id: event.toolCallId || crypto.randomUUID(), name: event.toolName, arguments: event.params ?? {} }, agent: { id: context.agentId, sessionId: context.sessionId, runId: context.runId }, timestamp: new Date().toISOString() };
      try {
        const decision = await client.evaluate(action);
        if (!decision || !["allow", "flag", "block", "quarantine", "rewrite"].includes(decision.decision)) throw new Error("Malformed Aurels decision");
        traceByCall.set(action.action.id, decision.traceId);
        if (decision.decision === "allow") return undefined;
        if (decision.decision === "rewrite" && event.supportsParamRewrite && decision.rewrittenArguments && typeof decision.rewrittenArguments === "object") return { params: decision.rewrittenArguments };
        void report(client, config, action, decision.traceId, "blocked", event);
        return { block: true, blockReason: decision.decision === "flag" ? "Aurels requires human approval before this action can run." : BLOCKED };
      } catch {
        return config.failMode === "open" ? undefined : { block: true, blockReason: UNAVAILABLE };
      }
    },
    async afterToolCall(event = {}, context = {}) {
      if (!config.telemetry || !event.toolName || String(event.toolName).startsWith("aurels.")) return;
      const actionId = event.toolCallId || "unknown";
      await report(client, config, { action: { id: actionId }, agent: { id: context.agentId, sessionId: context.sessionId } }, traceByCall.get(actionId), event.success === false ? "failure" : "success", event);
    },
    status: () => ({ enabled: config.enabled, failMode: config.failMode, telemetry: config.telemetry })
  };
}

async function report(client, config, action, traceId, status, event) {
  if (!config.telemetry) return;
  try { await client.telemetry({ version: "1", integration: "openclaw", actionId: action.action.id, traceId, agent: action.agent, outcome: { status }, metadata: { tool: event.toolName, params: redact(event.params ?? {}) }, timestamp: new Date().toISOString() }); } catch { /* telemetry never changes enforcement */ }
}
