const BLOCKED = "Aurels blocked this action because it violates the active security policy.";
const UNAVAILABLE = "Aurels security verification is unavailable.";
const SECRET_KEY = /(?:password|secret|token|api[_-]?key|authorization|cookie|credential)/i;
const PRIVILEGED = new Set(["bash", "shell", "terminal", "exec", "process", "spawn", "write", "delete", "patch", "git", "network", "browser", "http", "fetch", "email", "message", "database", "cloud", "package", "install", "schedule", "delegate", "mcp", "api", "payment", "finance", "auth", "credential"]);

export function loadConfig(raw = {}) {
  const env = process.env;
  const cfg = raw && typeof raw === "object" ? raw : {};
  const timeoutMs = Number(cfg.timeoutMs ?? env.AURELS_TIMEOUT_MS ?? 1500);
  return {
    enabled: cfg.enabled ?? env.AURELS_ENABLED !== "false",
    apiUrl: normalizeUrl(String(cfg.apiUrl ?? env.AURELS_API_URL ?? "https://www.aurels.dev")),
    apiKey: String(cfg.apiKey ?? env.AURELS_API_KEY ?? ""),
    mode: cfg.mode ?? env.AURELS_MODE ?? (String(cfg.apiKey ?? env.AURELS_API_KEY ?? "") ? "remote" : "local"),
    failMode: cfg.failMode ?? env.AURELS_FAIL_MODE ?? "closed",
    failOpenPrivilegedActions: cfg.failOpenPrivilegedActions ?? env.AURELS_FAIL_OPEN_PRIVILEGED_ACTIONS ?? "block",
    timeoutMs: Number.isFinite(timeoutMs) ? Math.min(Math.max(timeoutMs, 100), 30000) : 1500,
    telemetry: cfg.telemetry ?? env.AURELS_TELEMETRY_ENABLED !== "false"
  };
}

export function redact(value, seen = new WeakSet(), depth = 0) {
  if (!value || typeof value !== "object") return typeof value === "string" ? value.slice(0, 4096) : value;
  if (depth > 8) return "[MaxDepth]";
  if (seen.has(value)) return "[Circular]";
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.slice(0, 50).map((item) => redact(item, seen, depth + 1));
    const output = {};
    for (const key of Object.keys(value).slice(0, 100)) {
      try { output[key] = SECRET_KEY.test(key) ? "[REDACTED]" : redact(value[key], seen, depth + 1); } catch { output[key] = "[UnserializableProperty]"; }
    }
    return output;
  } finally { seen.delete(value); }
}

export function createClient(config, fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== "function") throw new Error("A Fetch-compatible runtime is required.");
  async function request(path, payload) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), config.timeoutMs);
    try {
      const response = await fetchImpl(`${config.apiUrl}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": config.apiKey, "idempotency-key": idempotencyKey(path, payload) },
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
        const decision = config.mode === "local" ? localDecision(event) : validateDecision(await client.evaluate(action));
        traceByCall.set(action.action.id, decision.traceId);
        if (decision.decision === "allow") return undefined;
        if (decision.decision === "rewrite" && event.supportsParamRewrite && decision.rewrittenArguments && typeof decision.rewrittenArguments === "object") return { params: decision.rewrittenArguments };
        void report(client, config, action, decision.traceId, "blocked", event);
        return { block: true, blockReason: decision.decision === "flag" ? "Aurels requires human approval before this action can run." : BLOCKED };
      } catch {
        return config.failMode === "open" && (config.failOpenPrivilegedActions === "allow" || !isPrivileged(event.toolName)) ? undefined : { block: true, blockReason: UNAVAILABLE };
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

function normalizeUrl(value) {
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol) || url.username || url.password) throw new Error("Aurels API URL must be http(s) and contain no credentials.");
  url.search = ""; url.hash = "";
  return url.toString().replace(/\/$/, "");
}

function isPrivileged(name) {
  const normalized = String(name ?? "").toLowerCase().replace(/[^a-z0-9]/g, "_");
  return normalized.split("_").some((part) => PRIVILEGED.has(part)) || /(?:write|remove|delete|unlink|rename|chmod|filesystem|fs|terminal|exec|shell|spawn|network|http|browser|email|message|database|cloud|package|install|auth|credential)/.test(normalized);
}

function idempotencyKey(path, payload) {
  const id = path.endsWith("/evaluate") ? payload?.action?.id : payload?.actionId;
  const status = payload?.outcome?.status;
  return `${path.endsWith("/evaluate") ? "action-evaluate" : "action-telemetry"}:${encodeURIComponent(String(id ?? "unknown"))}${status ? `:${status}` : ""}`;
}

function validateDecision(value) {
  if (!value || typeof value !== "object" || !["allow", "flag", "block", "quarantine", "rewrite"].includes(value.decision)) throw new Error("Malformed Aurels decision");
  if (value.riskScore !== undefined && (typeof value.riskScore !== "number" || !Number.isFinite(value.riskScore) || value.riskScore < 0 || value.riskScore > 100)) throw new Error("Invalid Aurels risk score");
  if (value.ruleIds !== undefined && (!Array.isArray(value.ruleIds) || value.ruleIds.some((id) => typeof id !== "string"))) throw new Error("Invalid Aurels rule IDs");
  if (value.decision === "rewrite" && (!value.rewrittenArguments || typeof value.rewrittenArguments !== "object" || Array.isArray(value.rewrittenArguments))) throw new Error("Invalid Aurels rewrite");
  return value;
}

function localDecision(event) {
  const name = String(event.toolName ?? "").toLowerCase();
  const command = String(event.params?.command ?? event.params?.script ?? "").toLowerCase();
  if (/(rm\s+-[^\n]*r|del\s+\/|format\s|drop\s+table|curl[^\n]*\|\s*(sh|bash)|chmod\s+777)/.test(command)) return { decision: "block" };
  if (/^(read|list|get|search|inspect|status)[._:-]/.test(name) || /read_file|list_files|status/.test(name)) return { decision: "allow" };
  return { decision: "flag" };
}
