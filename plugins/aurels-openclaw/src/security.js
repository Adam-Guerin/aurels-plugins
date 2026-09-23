const BLOCKED = "Aurels blocked this action because it violates the active security policy.";
const SECRET_KEY = /(?:password|secret|token|api[_-]?key|authorization|cookie|credential)/i;
const SECRET_VALUE = /(?:bearer\s+[a-z0-9\-_.=]+|(?:api[_-]?key|token|password|secret)\s*[:=]\s*\S+|-----BEGIN [A-Z ]+PRIVATE KEY-----)/i;
import { createHash } from "node:crypto";

const MAX_RESPONSE_BYTES = 1024 * 1024;
const TRACE_TTL_MS = 10 * 60 * 1000;

export function loadConfig(raw = {}) {
  const env = process.env;
  const cfg = raw && typeof raw === "object" ? raw : {};
  const timeoutMs = Number(cfg.timeoutMs ?? env.AURELS_TIMEOUT_MS ?? 1500);
  const apiKey = String(cfg.apiKey ?? env.AURELS_API_KEY ?? "");
  const mode = String(cfg.mode ?? env.AURELS_MODE ?? (apiKey ? "remote" : "local"));
  if (!["local", "remote"].includes(mode)) throw new Error("AURELS_MODE must be 'local' or 'remote'.");
  return {
    enabled: cfg.enabled ?? env.AURELS_ENABLED !== "false",
    apiUrl: normalizeUrl(String(cfg.apiUrl ?? env.AURELS_API_URL ?? "https://www.aurels.dev")),
    apiKey,
    mode,
    timeoutMs: Number.isFinite(timeoutMs) ? Math.min(Math.max(timeoutMs, 100), 30000) : 1500,
    telemetry: cfg.telemetry ?? env.AURELS_TELEMETRY_ENABLED !== "false"
  };
}

export function redact(value, seen = new WeakSet(), depth = 0) {
  if (!value || typeof value !== "object") return typeof value === "string" ? redactString(value) : value;
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
      const declaredLength = Number(response.headers?.get?.("content-length"));
      if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) throw new Error("Aurels response exceeds the maximum allowed size.");
      const body = await readLimitedText(response);
      return JSON.parse(body);
    } finally { clearTimeout(timer); }
  }
  return { evaluate: (action) => request("/api/v1/actions/evaluate", action), telemetry: (event) => request("/api/v1/actions/telemetry", event) };
}

export function createHandlers(config, client) {
  const traceByCall = new Map();
  const rememberTrace = (callId, traceId) => {
    if (!callId || !traceId) return;
    const entry = { traceId };
    traceByCall.set(callId, entry);
    setTimeout(() => {
      if (traceByCall.get(callId) === entry) traceByCall.delete(callId);
    }, TRACE_TTL_MS).unref?.();
  };
  return {
    async beforeToolCall(event = {}, context = {}) {
      if (!config.enabled) return undefined;
      const hostCallId = event.toolCallId;
      const actionId = hostCallId ?? crypto.randomUUID();
      const action = { version: "1", integration: "openclaw", action: { id: actionId, name: event.toolName, arguments: event.params ?? {} }, agent: { id: context.agentId, sessionId: context.sessionId, runId: context.runId }, timestamp: new Date().toISOString() };
      const local = localDecision(event);
      if (local.decision === "allow") return undefined;
      if (local.decision === "block") {
        void report(client, config, action, undefined, "blocked", event);
        return { block: true, blockReason: BLOCKED };
      }
      try {
        if (config.mode === "local" || !config.apiKey) return flagged(client, config, action, event, context);
        const decision = validateDecision(await client.evaluate(action));
        if (decision.decision === "allow") rememberTrace(hostCallId, decision.traceId);
        if (decision.decision === "allow") return undefined;
        void report(client, config, action, decision.traceId, "blocked", event);
        if (decision.decision === "flag") return flagged(client, config, action, event, context);
        return { block: true, blockReason: BLOCKED };
      } catch {
        return flagged(client, config, action, event, context);
      }
    },
    async afterToolCall(event = {}, context = {}) {
      if (!config.enabled || !event.toolName) return;
      const actionId = event.toolCallId;
      if (!actionId) return;
      try {
        await report(client, config, { action: { id: actionId }, agent: { id: context.agentId, sessionId: context.sessionId } }, traceByCall.get(actionId)?.traceId, event.success === false ? "failure" : "success", event);
      } finally {
        traceByCall.delete(actionId);
      }
    },
    status: () => ({ enabled: config.enabled, mode: config.mode, telemetry: config.telemetry })
  };
}

async function readLimitedText(response) {
  if (!response.body?.getReader) {
    const body = await response.text();
    if (new TextEncoder().encode(body).byteLength > MAX_RESPONSE_BYTES) throw new Error("Aurels response exceeds the maximum allowed size.");
    return body;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) { await reader.cancel(); throw new Error("Aurels response exceeds the maximum allowed size."); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(bytes);
}

async function flagged(client, config, action, event, context) {
  void report(client, config, action, undefined, "blocked", event);
  return {
    requireApproval: {
      title: "Aurels Security Review",
      description: "Aurels requires human approval before this action can run.",
      severity: "warning",
      allowedDecisions: ["allow-once", "deny"]
    }
  };
}

async function report(client, config, action, traceId, status, event) {
  if (!shouldSendTelemetry(config)) return;
  try { await client.telemetry({ version: "1", integration: "openclaw", actionId: action.action.id, traceId, agent: action.agent, outcome: { status }, metadata: { tool: event.toolName, params: redact(event.params ?? {}) }, timestamp: new Date().toISOString() }); } catch { /* telemetry never changes enforcement */ }
}

function normalizeUrl(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password) throw new Error("Aurels API URL must use HTTPS and contain no credentials.");
  url.search = ""; url.hash = "";
  return url.toString().replace(/\/$/, "");
}

function idempotencyKey(path, payload) {
  const id = path.endsWith("/evaluate") ? payload?.action?.id : payload?.actionId;
  const status = payload?.outcome?.status;
  const prefix = path.endsWith("/evaluate") ? "action-evaluate" : "action-telemetry";
  if (path.endsWith("/evaluate")) {
    const fingerprint = createHash("sha256").update(JSON.stringify(payload?.action ?? {})).digest("hex");
    return `${prefix}:${encodeURIComponent(String(id ?? "unknown"))}:${fingerprint}`;
  }
  return `${prefix}:${encodeURIComponent(String(id ?? "unknown"))}${status ? `:${status}` : ""}`;
}

function validateDecision(value) {
  if (!value || typeof value !== "object" || !["allow", "flag", "block"].includes(value.decision)) throw new Error("Malformed Aurels decision");
  if (value.riskScore !== undefined && (typeof value.riskScore !== "number" || !Number.isFinite(value.riskScore) || value.riskScore < 0 || value.riskScore > 100)) throw new Error("Invalid Aurels risk score");
  if (value.ruleIds !== undefined && (!Array.isArray(value.ruleIds) || value.ruleIds.some((id) => typeof id !== "string"))) throw new Error("Invalid Aurels rule IDs");
  return value;
}

function localDecision(event) {
  const name = String(event.toolName ?? "").toLowerCase();
  const command = String(event.params?.command ?? event.params?.script ?? "").toLowerCase();
  if (/(rm\s+-[^\n]*r|del\s+\/|format\s|drop\s+table|curl[^\n]*\|\s*(sh|bash)|chmod\s+777)/.test(command)) return { decision: "block" };
  return { decision: "ambiguous" };
}

function redactString(value) {
  const clipped = value.slice(0, 4096);
  return SECRET_VALUE.test(clipped) ? "[REDACTED]" : clipped;
}

function shouldSendTelemetry(config) {
  return config.enabled && config.telemetry && config.mode !== "local" && Boolean(config.apiKey);
}
