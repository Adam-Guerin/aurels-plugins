#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import process from "node:process";

const BLOCKED_MESSAGE = "Aurel blocked this action because it violates the active security policy.";
const UNAVAILABLE_MESSAGE = "Aurel security verification is unavailable.";
const INVALID_MCP_MESSAGE = "Invalid MCP message.";
const MAX_MCP_FRAME_BYTES = clampSize(Number(process.env.AUREL_MCP_MAX_FRAME_BYTES ?? 1_048_576), 1024, 16 * 1024 * 1024);
const PENDING_TTL_MS = clampSize(Number(process.env.AUREL_MCP_PENDING_TTL_MS ?? 10 * 60 * 1000), 1000, 60 * 60 * 1000);
const MAX_TELEMETRY_PAYLOAD_BYTES = clampSize(Number(process.env.AUREL_TELEMETRY_MAX_PAYLOAD_BYTES ?? 32_768), 1024, 262_144);
const MAX_AUREL_RESPONSE_BYTES = 1024 * 1024;
const MAX_AUREL_REQUEST_BYTES = 1024 * 1024;
const MAX_AUREL_STRING_CHARS = 65_536;
const MAX_AUREL_ARRAY_ITEMS = 512;
const MAX_AUREL_OBJECT_KEYS = 512;
const MAX_PENDING_CALLS = clampSize(Number(process.env.AUREL_MCP_MAX_PENDING ?? 1024), 1, 4096);
const TRANSPORT = process.env.AUREL_MCP_TRANSPORT ?? "newline";
if (!["newline", "content-length"].includes(TRANSPORT)) {
  console.error("AUREL_MCP_TRANSPORT must be newline or content-length");
  process.exit(64);
}

class ExactActionPayloadError extends Error {}
class AurelProtocolError extends ExactActionPayloadError {}

const splitIndex = process.argv.indexOf("--");
if (splitIndex < 0 || splitIndex === process.argv.length - 1) {
  console.error("Usage: node aurel-mcp-proxy.mjs -- <upstream-command> [args...]");
  process.exit(64);
}

const upstream = spawn(process.argv[splitIndex + 1], process.argv.slice(splitIndex + 2), {
  stdio: ["pipe", "pipe", "inherit"],
  env: process.env,
});

const pending = new Map();
const evaluating = new Map();
const telemetryInFlight = new Set();
const stdinParser = createMcpParser((message) => {
  if (message?.method === "notifications/cancelled") {
    const id = message.params?.requestId;
    evaluating.get(id)?.controller.abort(new Error("MCP request cancelled"));
    if (pending.has(id)) writeMcp(upstream.stdin, message);
    return;
  }
  if (message?.method !== "tools/call") {
    writeMcp(upstream.stdin, message);
    return;
  }
  const id = message.id;
  if (message.jsonrpc !== "2.0" || !(typeof id === "string" || (typeof id === "number" && Number.isFinite(id)))
    || !message.params || typeof message.params.name !== "string" || !message.params.name.trim()
    || message.params.name.length > 512 || (message.params.arguments !== undefined
      && (!message.params.arguments || typeof message.params.arguments !== "object" || Array.isArray(message.params.arguments)))) {
    writeMcp(process.stdout, jsonRpcError(id ?? null, -32600, INVALID_MCP_MESSAGE));
    return;
  }
  if (evaluating.has(id) || pending.has(id)) {
    writeMcp(process.stdout, jsonRpcError(id, -32600, "Duplicate MCP request ID."));
    return;
  }
  if (new Set([...evaluating.keys(), ...pending.keys()]).size >= MAX_PENDING_CALLS) {
    writeMcp(process.stdout, jsonRpcError(id, -32052, "MCP proxy is busy; retry after outstanding calls complete."));
    return;
  }
  const state = { controller: new AbortController(), promise: undefined };
  evaluating.set(id, state);
  state.promise = handleHostMessage(message, state.controller.signal).catch(() => {
    writeMcp(process.stdout, jsonRpcError(id, -32051, UNAVAILABLE_MESSAGE));
  }).finally(() => evaluating.delete(id));
}, {
  onError(error) {
    console.error("[aurel-mcp] invalid host message.");
    writeMcp(process.stdout, jsonRpcError(null, -32700, INVALID_MCP_MESSAGE));
  },
});

async function handleHostMessage(message, signal) {
  if (message?.method !== "tools/call") {
    writeMcp(upstream.stdin, message);
    return;
  }

const toolName = String(message.params?.name ?? "unknown");
  if (!shouldInterceptTool(toolName)) {
    writeMcp(upstream.stdin, message);
    return;
  }

  const action = {
    version: "1",
    integration: process.env.AUREL_MCP_INTEGRATION ?? "mcp",
    action: {
      id: String(message.id ?? randomId("mcp-call")),
      name: toolName,
      type: "mcp.tools/call",
      arguments: message.params?.arguments ?? {},
    },
    agent: {
      sessionId: process.env.AUREL_SESSION_ID,
      runId: process.env.AUREL_RUN_ID,
    },
    context: {
      metadata: {
        upstreamCommand: process.argv[splitIndex + 1],
      },
    },
    timestamp: new Date().toISOString(),
  };

  const started = performance.now();
  let decision;
  try {
    decision = useExecutionPermits()
      ? await authorizeMcpExecution(toolName, message.params?.arguments ?? {}, action, signal)
      : parseDecision(await aurelPost("/api/v1/actions/evaluate", action, signal));
    if (signal.aborted) return;
  } catch (error) {
    if (signal.aborted) return;
    if (!(error instanceof ExactActionPayloadError) && (process.env.AUREL_FAIL_MODE ?? "closed") === "open" && !shouldBlockFailOpenOutage(toolName, message.params?.arguments)) {
      console.error("[aurel-mcp] fail-open: evaluation unavailable.");
      setPending(message.id, { action, preflightLatencyMs: elapsed(started) });
      writeMcp(upstream.stdin, message);
      return;
    }
    writeMcp(process.stdout, jsonRpcError(message.id, -32051, UNAVAILABLE_MESSAGE));
    return;
  }

  const preflightLatencyMs = elapsed(started);
  if (decision.decision === "allow") {
    setPending(message.id, { action, traceId: decision.traceId, preflightLatencyMs });
    writeMcp(upstream.stdin, message);
    return;
  }

  if (decision.decision === "rewrite" && decision.rewrittenArguments !== undefined) {
    setPending(message.id, {
      action,
      traceId: decision.traceId,
      preflightLatencyMs,
      executedArguments: decision.rewrittenArguments,
      originalArguments: action.action.arguments,
      rewriteApplied: true,
    });
    writeMcp(upstream.stdin, {
      ...message,
      params: {
        ...message.params,
        arguments: decision.rewrittenArguments,
      },
    });
    return;
  }

  trackTelemetry(sendOutcome(
    action,
    decision.traceId,
    decision.decision === "require_approval" ? "approval_requested" : "blocked",
    preflightLatencyMs,
    undefined,
    { decision }
  ));
  const reason =
    decision.decision === "require_approval"
      ? "Aurel requires human approval before this MCP tool can run."
      : BLOCKED_MESSAGE;
  writeMcp(process.stdout, jsonRpcError(message.id, -32050, reason));
}

const upstreamParser = createMcpParser(async (message) => {
  const state = takePending(message?.id);
  if (state) {
    trackTelemetry(sendOutcome(
      state.action,
      state.traceId,
      message?.error || message?.result?.isError === true ? "failure" : "success",
      state.preflightLatencyMs,
      message?.error || message?.result?.isError === true ? "mcp_error" : undefined,
      state
    ));
  }
  writeMcp(process.stdout, message);
}, {
  onError(error) {
    console.error("[aurel-mcp] invalid upstream message.");
  },
});

// Await each frame before reading more input. This bounds memory and prevents
// concurrent parser callbacks from racing pending IDs or policy evaluation.
async function pump(stream, parser) {
  try {
    for await (const chunk of stream) await parser.push(chunk);
  } catch (error) {
    console.error("[aurel-mcp] stream failed.");
  }
}
const upstreamPump = pump(upstream.stdout, upstreamParser);
void pump(process.stdin, stdinParser).then(() => {
  const shutdown = setTimeout(() => upstream.kill(), 3000);
  shutdown.unref();
  void Promise.allSettled([...evaluating.values()].map((state) => state.promise)).then(() => upstream.stdin.end());
});
upstream.stdin.on("error", () => {}); // EPIPE during upstream shutdown
upstream.on("error", (error) => {
  console.error(`[aurel-mcp] upstream could not start: ${error.code ?? "unknown"}`);
  process.exit(1);
});
for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => upstream.kill());
upstream.on("close", async (code) => {
  await upstreamPump;
  await Promise.allSettled([...telemetryInFlight]);
  process.exit(code ?? 0);
});

function trackTelemetry(promise) {
  telemetryInFlight.add(promise);
  void promise.finally(() => telemetryInFlight.delete(promise));
}

async function sendOutcome(action, traceId, status, preflightLatencyMs, errorCategory, state = {}) {
  if (!envBool("AUREL_TELEMETRY_ENABLED", true)) return;
  const postStarted = performance.now();
  try {
    await retryTelemetry(() => aurelPost("/api/v1/actions/telemetry", {
      version: "1",
      integration: action.integration,
      actionId: action.action.id,
      traceId,
      agent: action.agent,
      outcome: { status, errorCategory },
      timings: {
        aurelPreflightLatencyMs: preflightLatencyMs,
        aurelPostflightLatencyMs: elapsed(postStarted),
      },
      metadata: {
        tool: action.action.name,
        args: redact(state.executedArguments ?? action.action.arguments),
        originalArgs: state.rewriteApplied ? redact(state.originalArguments) : undefined,
        rewriteApplied: state.rewriteApplied === true,
        resultIncluded: false,
        decision: state.decision?.decision,
        riskScore: state.decision?.riskScore,
        category: state.decision?.category,
        ruleIds: state.decision?.ruleIds,
      },
      timestamp: new Date().toISOString(),
    }));
  } catch (error) {
    console.error("[aurel-mcp] telemetry failed.");
  }
}

/** V1 turns the proxy into the enforcement point: it consumes the one-time permit
 * before forwarding the exact MCP call to its upstream server. */
async function authorizeMcpExecution(toolName, argumentsValue, legacyAction, signal) {
  const request = normalizedAuthorizationRequest(toolName, argumentsValue, legacyAction);
  const response = await aurelPost("/api/v1/authorize", request, signal);
  const map = { ALLOW: "allow", BLOCK: "block", REQUIRE_APPROVAL: "require_approval" };
  const decision = { ...response, decision: map[response?.decision] ?? response?.decision, riskScore: response?.risk_score, traceId: response?.audit_id, ruleIds: response?.matched_policies?.map((policy) => policy.id) };
  if (!map[response?.decision]) throw new Error("Aurel v1 returned an unsupported decision");
  if (decision.decision === "allow") {
    if (!response.execution_permit) throw new Error("Aurel allowed an MCP call without an execution permit");
    const permit = await aurelPost("/api/v1/permits/verify", { permit: response.execution_permit, request }, signal);
    if (permit?.valid !== true) throw new Error("Aurel execution permit verification failed");
  }
  return decision;
}

function normalizedAuthorizationRequest(toolName, argumentsValue, action) {
  const provider = toolName.split(/[._:-]/)[0] || "mcp";
  const isGithub = provider.toLowerCase() === "github";
  return {
    request_id: action.action.id,
    agent: { id: process.env.AUREL_AGENT_ID ?? action.agent.sessionId ?? "mcp-agent", owner: process.env.AUREL_AGENT_OWNER, environment: process.env.AUREL_AGENT_ENVIRONMENT ?? "production", trust_level: Number(process.env.AUREL_AGENT_TRUST_LEVEL ?? 50) },
    action: { provider, operation: normalizeMcpOperation(toolName), category: isGithub ? "infrastructure" : "mcp", resource: String(argumentsValue?.repo ?? argumentsValue?.resource ?? ""), parameters: argumentsValue && typeof argumentsValue === "object" ? argumentsValue : {} },
    context: { session_id: action.agent.sessionId, workflow_id: action.agent.runId, metadata: { mcp_tool: toolName, mcp_server_id: process.env.AURELS_MCP_SERVER_ID ?? process.env.AUREL_MCP_SERVER_ID, permit_audience: "aurels-github-gateway" } },
  };
}

function normalizeMcpOperation(toolName) {
  const normalized = String(toolName).toLowerCase();
  if (/github[._:-].*(delete.*repo|repos.*delete)/.test(normalized)) return "repository.delete";
  if (/github[._:-].*(update.*repo|repos.*update)/.test(normalized)) return "repository.visibility.update";
  if (/github[._:-].*(merge.*pull|pulls.*merge)/.test(normalized)) return "pull_request.merge";
  return normalized;
}

function useExecutionPermits() { return envBool("AURELS_MCP_EXECUTION_PERMITS", envBool("AUREL_MCP_EXECUTION_PERMITS", false)); }

function setPending(id, state) {
  const existing = pending.get(id);
  if (existing?.timer) clearTimeout(existing.timer);
  const timer = setTimeout(() => pending.delete(id), PENDING_TTL_MS);
  timer.unref?.();
  pending.set(id, { ...state, timer });
}

function takePending(id) {
  const state = pending.get(id);
  if (!state) return undefined;
  pending.delete(id);
  if (state.timer) clearTimeout(state.timer);
  const cleanState = { ...state };
  delete cleanState.timer;
  return cleanState;
}

async function retryTelemetry(fn) {
  const delays = [50, 150, 350];
  let lastError;
  for (let index = 0; index < delays.length; index += 1) {
    try {
      await fn();
      return;
    } catch (error) {
      lastError = error;
      if (index + 1 < delays.length) await new Promise((resolve) => setTimeout(resolve, delays[index]));
    }
  }
  throw lastError;
}

function createMcpParser(onMessage, options = {}) {
  let buffer = Buffer.alloc(0);
  let discardingLine = false;
  return {
    async push(chunk) {
      buffer = Buffer.concat([buffer, chunk]);
      while (true) {
        if (TRANSPORT === "newline") {
          const lineEnd = buffer.indexOf(10);
          if (lineEnd < 0) {
            if (buffer.length > MAX_MCP_FRAME_BYTES) {
              if (!discardingLine) options.onError?.(new Error("MCP frame body exceeded maximum size"));
              discardingLine = true;
              buffer = Buffer.alloc(0);
            }
            return;
          }
          const line = buffer.subarray(0, lineEnd);
          buffer = buffer.subarray(lineEnd + 1);
          if (discardingLine) { discardingLine = false; continue; }
          if (!line.length) continue;
          try {
            if (line.length > MAX_MCP_FRAME_BYTES) throw new Error("MCP frame body exceeded maximum size");
            const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(line));
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("MCP frame body must be a JSON object");
            await onMessage(parsed);
          } catch (error) {
            options.onError?.(error);
          }
          continue;
        }
        const headerEnd = buffer.indexOf("\r\n\r\n");
        if (headerEnd < 0) {
          if (buffer.length > MAX_MCP_FRAME_BYTES) {
            options.onError?.(new Error("MCP frame header exceeded maximum size"));
            buffer = Buffer.alloc(0);
          }
          return;
        }
        try {
          const header = buffer.slice(0, headerEnd).toString("ascii");
          const match = /content-length:\s*(\d+)/i.exec(header);
          if (!match) throw new Error("MCP frame is missing Content-Length");
          const length = Number(match[1]);
          if (!Number.isSafeInteger(length) || length < 0) throw new Error("MCP frame has invalid Content-Length");
          if (length > MAX_MCP_FRAME_BYTES) throw new Error("MCP frame body exceeded maximum size");
          const bodyStart = headerEnd + 4;
          const bodyEnd = bodyStart + length;
          if (buffer.length < bodyEnd) return;
          const body = buffer.slice(bodyStart, bodyEnd).toString("utf8");
          buffer = buffer.slice(bodyEnd);
          const parsed = JSON.parse(body);
          if (!parsed || typeof parsed !== "object") throw new Error("MCP frame body must be a JSON object");
          await onMessage(parsed);
        } catch (error) {
          buffer = Buffer.alloc(0);
          options.onError?.(error);
          return;
        }
      }
    },
  };
}

function writeMcp(stream, message) {
  const body = Buffer.from(JSON.stringify(message), "utf8");
  if (TRANSPORT === "newline") {
    stream.write(Buffer.concat([body, Buffer.from("\n")]));
    return;
  }
  stream.write(`Content-Length: ${body.length}\r\n\r\n`);
  stream.write(body);
}

async function aurelPost(path, payload, signal) {
  const apiUrl = normalizeApiUrl(process.env.AURELS_API_URL ?? process.env.AUREL_API_URL ?? process.env.INTENTGUARD_API_URL ?? "https://www.aurels.dev");
  const apiKey = process.env.AURELS_API_KEY ?? process.env.AUREL_API_KEY ?? process.env.INTENTGUARD_API_KEY;
  if (!apiKey) throw new Error("Aurel API key is not configured");
  const timeoutMs = clampTimeout(Number(process.env.AUREL_TIMEOUT_MS ?? 1500));
  const controller = new AbortController();
  const cancel = () => controller.abort(signal.reason);
  if (signal?.aborted) cancel();
  else signal?.addEventListener("abort", cancel, { once: true });
  const timeoutError = new Error(`Aurel request timed out after ${timeoutMs}ms`);
  let timeout;
  const timeoutPromise = new Promise((_, reject) => {
    timeout = setTimeout(() => {
      controller.abort(timeoutError);
      reject(timeoutError);
    }, timeoutMs);
  });
  try {
    const response = await Promise.race([
      fetch(`${apiUrl}${path}`, {
        method: "POST",
        redirect: "error",
        signal: controller.signal,
        headers: {
          "content-type": "application/json",
          "x-api-key": apiKey,
          "idempotency-key": idempotencyKeyFor(path, payload),
          "user-agent": "aurel-mcp-proxy/0.1.0",
        },
        body: path === "/api/v1/actions/telemetry" ? stringifyAurelPayload(payload) : stringifyExactAurelPayload(payload),
      }),
      timeoutPromise,
    ]);
    const body = await readJsonResponse(response, timeoutPromise);
    if (!response.ok) throw new Error(`Aurel HTTP ${response.status}`);
    if (!body || typeof body !== "object") throw new AurelProtocolError("Aurel returned invalid JSON");
    return body;
  } catch (error) {
    if (controller.signal.aborted) throw controller.signal.reason instanceof Error ? controller.signal.reason : timeoutError;
    throw error;
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", cancel);
  }
}

function stringifyExactAurelPayload(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new ExactActionPayloadError("Aurel action payload is not losslessly JSON-serializable");
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_AUREL_REQUEST_BYTES) {
    throw new ExactActionPayloadError("Aurel action payload exceeded maximum size; exact arguments were not evaluated");
  }
  return serialized;
}

function jsonRpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

async function readJsonResponse(response, timeoutPromise) {
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_AUREL_RESPONSE_BYTES) {
    throw new AurelProtocolError("Aurel response exceeded maximum size");
  }

  const text = await readLimitedText(response, timeoutPromise);
  if (!text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function readLimitedText(response, timeoutPromise) {
  if (!response.body) {
    const text = await Promise.race([response.text(), timeoutPromise]);
    if (new TextEncoder().encode(text).length > MAX_AUREL_RESPONSE_BYTES) {
      throw new AurelProtocolError("Aurel response exceeded maximum size");
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), timeoutPromise]);
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > MAX_AUREL_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new AurelProtocolError("Aurel response exceeded maximum size");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const buffer = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(buffer);
}

function stringifyAurelPayload(value) {
  const serialized = JSON.stringify(toSerializable(value, new WeakSet(), 0));
  if (Buffer.byteLength(serialized, "utf8") <= MAX_AUREL_REQUEST_BYTES) return serialized;
  const fallback = JSON.stringify(toSerializable(boundActionArguments(value), new WeakSet(), 0));
  if (Buffer.byteLength(fallback, "utf8") <= MAX_AUREL_REQUEST_BYTES) return fallback;
  throw new Error("Aurel request payload exceeded maximum size");
}

function toSerializable(value, seen, depth) {
  if (value === null || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") return truncatePayloadString(value);
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "undefined") return null;
  if (typeof value === "function" || typeof value === "symbol") return `[${typeof value}]`;
  if (depth > 12) return "[MaxDepth]";
  if (typeof value !== "object") return String(value);
  if (seen.has(value)) return "[Circular]";
  seen.add(value);
  if (Array.isArray(value)) {
    try {
      const entries = value.slice(0, MAX_AUREL_ARRAY_ITEMS).map((entry) => toSerializable(entry, seen, depth + 1));
      if (value.length > MAX_AUREL_ARRAY_ITEMS) entries.push(`[${value.length - MAX_AUREL_ARRAY_ITEMS} items truncated]`);
      return entries;
    } finally {
      seen.delete(value);
    }
  }
  try {
    const output = Object.create(null);
    let keys;
    try {
      keys = Object.keys(value);
    } catch {
      return "[UnserializableObject]";
    }
    for (const key of keys.slice(0, MAX_AUREL_OBJECT_KEYS)) {
      let entry;
      try {
        entry = value[key];
      } catch {
        output[key] = "[UnserializableProperty]";
        continue;
      }
      output[key] = toSerializable(entry, seen, depth + 1);
    }
    if (keys.length > MAX_AUREL_OBJECT_KEYS) output.__truncatedKeys = keys.length - MAX_AUREL_OBJECT_KEYS;
    return output;
  } finally {
    seen.delete(value);
  }
}

function truncatePayloadString(value) {
  return value.length > MAX_AUREL_STRING_CHARS ? `${value.slice(0, MAX_AUREL_STRING_CHARS)}...[truncated]` : value;
}

function boundActionArguments(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return { truncated: true, reason: "payload_limit" };
  if (!value.action || typeof value.action !== "object" || Array.isArray(value.action)) {
    return { truncated: true, reason: "payload_limit" };
  }
  return {
    ...value,
    action: {
      ...value.action,
      arguments: { truncated: true, reason: "payload_limit" },
    },
  };
}

function parseDecision(body) {
  if (!body || typeof body !== "object" || typeof body.decision !== "string") {
    throw new AurelProtocolError("Aurel returned a malformed decision");
  }
  const normalized = body.decision === "flag" ? { ...body, decision: "require_approval" } : body;
  if (!["allow", "block", "require_approval", "rewrite", "quarantine"].includes(normalized.decision)) {
    throw new AurelProtocolError("Aurel returned an unsupported decision");
  }
  try { validateDecisionMetadata(normalized); }
  catch { throw new AurelProtocolError("Aurel returned invalid decision metadata"); }
  if (normalized.decision === "rewrite" && (!normalized.rewrittenArguments || typeof normalized.rewrittenArguments !== "object" || Array.isArray(normalized.rewrittenArguments))) {
    throw new AurelProtocolError("Aurel returned a rewrite without valid MCP arguments");
  }
  return normalized;
}

function validateDecisionMetadata(body) {
  if (body.riskScore !== undefined && (typeof body.riskScore !== "number" || !Number.isFinite(body.riskScore) || body.riskScore < 0 || body.riskScore > 100)) {
    throw new Error("Aurel returned an invalid risk score");
  }
  for (const field of ["reason", "category", "traceId", "policyVersion"]) {
    const value = body[field];
    if (value !== undefined && (typeof value !== "string" || value.length > 4096)) {
      throw new Error(`Aurel returned an invalid ${field}`);
    }
  }
  if (
    body.ruleIds !== undefined &&
    (!Array.isArray(body.ruleIds) || body.ruleIds.length > 128 || body.ruleIds.some((ruleId) => typeof ruleId !== "string" || ruleId.length > 512))
  ) {
    throw new Error("Aurel returned invalid rule IDs");
  }
}

function elapsed(start) {
  return Math.round(performance.now() - start);
}

function randomId(prefix) {
  return `${prefix}-${crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`}`;
}

function idempotencyKeyFor(path, payload) {
  if (path.endsWith("/evaluate") && payload && typeof payload === "object" && payload.action && typeof payload.action.id === "string") {
    return idempotencyKey("action-evaluate", payload.action.id, fingerprint(JSON.stringify(payload.action)));
  }
  if (path.endsWith("/telemetry") && payload && typeof payload === "object" && typeof payload.actionId === "string") {
    const status = payload.outcome && typeof payload.outcome.status === "string" ? payload.outcome.status : "unknown";
    return idempotencyKey("action-telemetry", payload.actionId, status, fingerprint(JSON.stringify(payload)));
  }
  return idempotencyKey("aurel-request", path);
}

function fingerprint(value) {
  return createHash("sha256").update(value).digest("hex");
}

function idempotencyKey(prefix, ...parts) {
  return [prefix, ...parts.map((part) => encodeURIComponent(String(part)).slice(0, 256))].join(":");
}

function shouldInterceptTool(toolName) {
  if (!envBool("AUREL_ENABLED", true)) return false;
  const include = envList("AUREL_TOOLS_INCLUDE");
  return include.length === 0 || include.includes(toolName);
}

function shouldBlockFailOpenOutage(toolName, args) {
  if (process.env.AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS === "allow") return false;
  return isPrivilegedToolName(toolName) || inputHasDestructiveContent(toolName, args);
}

function inputHasDestructiveContent(toolName, args) {
  let serialized = "";
  try { serialized = JSON.stringify(args ?? ""); } catch { return true; }
  return /(?:rm\s+-[a-z]*r[a-z]*f|remove-item\s+.*-recurse|format\s+[a-z]:|drop\s+(?:database|table|schema)|truncate\s+table|delete\s+from|\b(?:send|transfer|pay|purchase|delete|destroy|overwrite|chmod|chown)\b)/i.test(`${toolName} ${serialized}`);
}

function isPrivilegedToolName(toolName) {
  return /(?:^|[._:-])(?:bash|shell|terminal|exec|execute|process|spawn|run_command|file_write|write_file|delete_file|remove_file|patch|apply_patch|git_push|network|browser|http|fetch|email|send_email|message|database|db|sql|cloud|package|install|schedule|subagent|delegate|mcp|api|payment|finance|permission|auth|credential)(?:$|[._:-])/i.test(
    toolName
  );
}

function envList(name) {
  return String(process.env[name] ?? "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function envBool(name, fallback) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  if (/^(1|true|yes|on)$/i.test(value)) return true;
  if (/^(0|false|no|off)$/i.test(value)) return false;
  return fallback;
}

function redact(value, seen = new WeakSet(), depth = 0) {
  const shouldRedact = envBool("AUREL_REDACTION_ENABLED", true);
  return bound(redactValue(value, shouldRedact, seen, depth));
}

function redactValue(value, shouldRedact, seen = new WeakSet(), depth = 0) {
  if (value === null || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "string") return redactText(clean(value, 4096), shouldRedact);
  if (typeof value === "undefined") return null;
  if (depth > 8) return "[MaxDepth]";
  if (typeof value !== "object") return `[${typeof value}]`;
  if (seen.has(value)) return "[Circular]";
  seen.add(value);
  if (Array.isArray(value)) {
    try {
      return value.slice(0, 50).map((item) => redactValue(item, shouldRedact, seen, depth + 1));
    } finally {
      seen.delete(value);
    }
  }
  try {
    const out = Object.create(null);
    let keys;
    try {
      keys = Object.keys(value);
    } catch {
      return "[UnserializableObject]";
    }
    for (const key of keys.slice(0, 100)) {
      const safeKey = clean(key, 256);
      if (shouldRedact && /password|passwd|secret|token|api[_-]?key|apikey|authorization|cookie|session|private[_-]?key|credential|access[_-]?token|refresh[_-]?token/i.test(key)) {
        out[safeKey] = "[REDACTED]";
        continue;
      }
      let item;
      try {
        item = value[key];
      } catch {
        out[safeKey] = "[UnserializableProperty]";
        continue;
      }
      out[safeKey] = redactValue(item, shouldRedact, seen, depth + 1);
    }
    return bound(out);
  } finally {
    seen.delete(value);
  }
}

function bound(value) {
  const encoded = Buffer.from(JSON.stringify(value) ?? "null", "utf8");
  if (encoded.length <= MAX_TELEMETRY_PAYLOAD_BYTES) return value;
  return { truncated: true, reason: "payload_limit", preview: encoded.subarray(0, Math.min(4096, MAX_TELEMETRY_PAYLOAD_BYTES)).toString("utf8") };
}

function clean(value, maxLength) {
  const sanitized = String(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "\uFFFD");
  return sanitized.length > maxLength ? `${sanitized.slice(0, maxLength)}...[truncated]` : sanitized;
}

function redactText(value, enabled) {
  if (!enabled) return value;
  return value
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\b(?:sk-(?:ant|proj)-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]");
}

function normalizeApiUrl(value) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new AurelProtocolError("Invalid evaluator endpoint"); }
  const localHttp = parsed.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if ((parsed.protocol !== "https:" && !localHttp) || parsed.username || parsed.password) throw new AurelProtocolError("Evaluator endpoint requires HTTPS or loopback HTTP without credentials");
  parsed.hash = "";
  parsed.search = "";
  return parsed.toString().replace(/\/+$/, "");
}

function clampTimeout(value) {
  return Math.min(30_000, Math.max(100, Number.isFinite(value) ? value : 1500));
}

function clampSize(value, min, max) {
  return Math.min(max, Math.max(min, Number.isFinite(value) ? value : 1_048_576));
}
