#!/usr/bin/env node

import { createHash } from "node:crypto";
import process from "node:process";
import { mkdir, open, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

const BLOCKED_MESSAGE = "Aurel blocked this action because it violates the active security policy.";
const UNAVAILABLE_MESSAGE = "Aurel security verification is unavailable.";
const MAX_STDIN_BYTES = clampSize(Number(process.env.AUREL_HOOK_MAX_STDIN_BYTES ?? 1_048_576), 1024, 16 * 1024 * 1024);
const MAX_TELEMETRY_PAYLOAD_BYTES = clampSize(Number(process.env.AUREL_TELEMETRY_MAX_PAYLOAD_BYTES ?? 32_768), 1024, 262_144);
const MAX_AUREL_RESPONSE_BYTES = 1024 * 1024;
const MAX_AUREL_REQUEST_BYTES = 1024 * 1024;
const MAX_PENDING_CORRELATION_FILES = 1024;
const MAX_AUREL_STRING_CHARS = 65_536;
const MAX_AUREL_ARRAY_ITEMS = 512;
const MAX_AUREL_OBJECT_KEYS = 512;
class AurelProtocolError extends Error {}

main().catch((error) => {
  console.error(`[aurel-claude-code] hook failed before tool context was available: ${error instanceof Error ? error.message : String(error)}`);
  deny(UNAVAILABLE_MESSAGE);
});

async function main() {
  const input = JSON.parse(await readStdin());
  if (!input || typeof input !== "object") throw new Error("Claude hook input must be a JSON object");
  const event = input.hook_event_name;
  if (event === "PreToolUse") {
    await preToolUse(input);
    return;
  }
  if (event === "PostToolUse" || event === "PostToolUseFailure") {
    await postToolUse(input);
    return;
  }
  process.exit(0);
}

async function preToolUse(input) {
  const toolName = String(input.tool_name ?? "unknown");
  if (!shouldInterceptTool(toolName)) process.exit(0);

  const action = normalizeClaudeCodeAction(input);
  const started = performance.now();
  let decision;
  try {
    decision = parseDecision(await aurelPost("/api/v1/actions/evaluate", action));
  } catch (error) {
    if (!(error instanceof AurelProtocolError) && (process.env.AUREL_FAIL_MODE ?? "closed") === "open") {
      if (shouldBlockFailOpenOutage(toolName, action.action.arguments)) {
        console.error(`[aurel-claude-code] fail-open privileged block: ${error instanceof Error ? error.message : String(error)}`);
        deny(UNAVAILABLE_MESSAGE);
      }
      console.error(`[aurel-claude-code] fail-open: ${error instanceof Error ? error.message : String(error)}`);
      allow();
    }
    deny(UNAVAILABLE_MESSAGE);
    return;
  }

  const latency = Math.round(performance.now() - started);
  process.env.AUREL_LAST_PREFLIGHT_LATENCY_MS = String(latency);
  await rememberPreflight(action.action.id, {
    actionId: action.action.id,
    traceId: decision.traceId,
    agent: action.agent,
    preflightLatencyMs: latency,
  });

  switch (decision.decision) {
    case "allow":
      allow();
      return;
    case "block":
    case "quarantine":
      await sendPreExecutionOutcome(action, decision, latency, "blocked");
      deny(BLOCKED_MESSAGE);
      return;
    case "require_approval":
      await sendPreExecutionOutcome(action, decision, latency, "approval_requested");
      ask("Aurel requires human approval before this action can run.");
      return;
    case "rewrite":
      if ((process.env.AUREL_REWRITE_UNSUPPORTED_FALLBACK ?? "approval") === "block") {
        await sendPreExecutionOutcome(action, decision, latency, "blocked");
        deny(BLOCKED_MESSAGE);
      } else {
        await sendPreExecutionOutcome(action, decision, latency, "approval_requested");
        ask("Aurel requires approval because Claude Code hooks cannot safely rewrite this tool call.");
      }
      return;
    default:
      await sendPreExecutionOutcome(action, decision, latency, "blocked");
      deny(BLOCKED_MESSAGE);
  }
}

async function postToolUse(input) {
  if (!envBool("AUREL_TELEMETRY_ENABLED", true)) process.exit(0);
  const actionId = String(input.tool_use_id ?? randomId("claude-tool"));
  const state = await consumePreflight(actionId);
  const telemetry = {
    version: "1",
    integration: "claude-code",
    actionId,
    traceId: state?.traceId,
    agent: state?.agent ?? {
      sessionId: stringOrUndefined(input.session_id),
      runId: stringOrUndefined(input.prompt_id),
    },
    outcome: {
      status: input.hook_event_name === "PostToolUseFailure" ? "failure" : "success",
      durationMs: typeof input.duration_ms === "number" ? input.duration_ms : undefined,
      errorCategory: input.hook_event_name === "PostToolUseFailure" ? "tool_error" : undefined,
    },
    timings: {
      aurelPreflightLatencyMs: state?.preflightLatencyMs,
      toolExecutionLatencyMs: typeof input.duration_ms === "number" ? input.duration_ms : undefined,
      aurelPostflightLatencyMs: 0,
    },
    metadata: {
      tool: input.tool_name,
      cwd: input.cwd,
      args: redact(input.tool_input),
      resultIncluded: false,
    },
    timestamp: new Date().toISOString(),
  };
  try {
    const postStarted = performance.now();
    await retryTelemetry(() => {
      telemetry.timings.aurelPostflightLatencyMs = elapsed(postStarted);
      return aurelPost("/api/v1/actions/telemetry", telemetry);
    });
  } catch (error) {
    console.error(`[aurel-claude-code] telemetry failed: ${error instanceof Error ? error.message : String(error)}`);
  }
  process.exit(0);
}

async function sendPreExecutionOutcome(action, decision, preflightLatencyMs, status) {
  if (!envBool("AUREL_TELEMETRY_ENABLED", true)) return;
  const telemetry = {
    version: "1",
    integration: "claude-code",
    actionId: action.action.id,
    traceId: decision.traceId,
    agent: action.agent,
    outcome: { status },
    timings: {
      aurelPreflightLatencyMs: preflightLatencyMs,
      aurelPostflightLatencyMs: 0,
    },
    metadata: {
      tool: action.action.name,
      args: redact(action.action.arguments),
      resultIncluded: false,
      decision: decision.decision,
      riskScore: decision.riskScore,
      category: decision.category,
      ruleIds: decision.ruleIds,
    },
    timestamp: new Date().toISOString(),
  };
  try {
    const postStarted = performance.now();
    await retryTelemetry(() => {
      telemetry.timings.aurelPostflightLatencyMs = elapsed(postStarted);
      return aurelPost("/api/v1/actions/telemetry", telemetry);
    });
  } catch (error) {
    console.error(`[aurel-claude-code] blocked telemetry failed: ${error instanceof Error ? error.message : String(error)}`);
  }
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

function normalizeClaudeCodeAction(input) {
  return {
    version: "1",
    integration: "claude-code",
    action: {
      id: String(input.tool_use_id ?? randomId("claude-tool")),
      name: String(input.tool_name ?? "unknown"),
      type: String(input.hook_event_name ?? "PreToolUse"),
      arguments: input.tool_input ?? {},
    },
    agent: {
      sessionId: stringOrUndefined(input.session_id),
      runId: stringOrUndefined(input.prompt_id),
    },
    context: {
      workingDirectory: stringOrUndefined(input.cwd),
      targetPaths: derivedPaths(input.tool_input),
      metadata: {
        permissionMode: input.permission_mode,
        transcriptPath: input.transcript_path,
      },
    },
    timestamp: new Date().toISOString(),
  };
}

async function aurelPost(path, payload) {
  const apiUrl = normalizeApiUrl(process.env.AURELS_API_URL ?? process.env.AUREL_API_URL ?? process.env.INTENTGUARD_API_URL ?? "https://www.aurels.dev");
  const apiKey = process.env.AURELS_API_KEY ?? process.env.AUREL_API_KEY ?? process.env.INTENTGUARD_API_KEY;
  if (!apiKey) throw new Error("Aurel API key is not configured");
  const timeoutMs = clampTimeout(Number(process.env.AUREL_TIMEOUT_MS ?? 1500));
  const controller = new AbortController();
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
          "user-agent": "aurel-claude-code-hook/0.1.0",
        },
        body: path === "/api/v1/actions/evaluate" ? stringifyExactAurelPayload(payload) : stringifyAurelPayload(payload),
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
  }
}

function stringifyExactAurelPayload(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new AurelProtocolError("Aurel action payload is not losslessly JSON-serializable");
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_AUREL_REQUEST_BYTES) {
    throw new AurelProtocolError("Aurel action payload exceeded maximum size; exact arguments were not evaluated");
  }
  return serialized;
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

function allow() {
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } }));
  process.exit(0);
}

function ask(message) {
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: message } }));
  process.exit(0);
}

function deny(message) {
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: message } }));
  process.exit(0);
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

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;
    process.stdin.on("data", (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > MAX_STDIN_BYTES) {
        reject(new Error("Claude hook input exceeded maximum size"));
        process.stdin.destroy();
        return;
      }
      chunks.push(chunk);
    });
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", reject);
  });
}

async function rememberPreflight(actionId, state) {
  if (!state.traceId) return;
  try {
    const dir = stateDir();
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const file = join(dir, stateFile(actionId));
    await withStateLock(dir, async () => {
      await prunePendingState(dir, file);
      await writeFile(file, JSON.stringify(state), { encoding: "utf8", flag: "w", mode: 0o600 });
    });
  } catch (error) {
    console.error(`[aurel-claude-code] unable to persist preflight correlation: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function withStateLock(directory, operation) {
  const lockPath = join(directory, ".aurel-state.lock");
  const deadline = Date.now() + 10_000;
  let lock;
  while (!lock) {
    try { lock = await open(lockPath, "wx", 0o600); }
    catch (error) {
      if (error?.code !== "EEXIST") throw error;
      if (Date.now() >= deadline) throw new Error("Timed out waiting for Claude Code correlation state lock");
      const lockInfo = await stat(lockPath).catch(() => undefined);
      if (!lockInfo || Date.now() - lockInfo.mtimeMs > 30_000) {
        await rm(lockPath, { force: true }).catch(() => undefined);
      } else {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }
  }
  try { return await operation(); }
  finally {
    await lock.close().catch(() => undefined);
    await rm(lockPath, { force: true }).catch(() => undefined);
  }
}

async function prunePendingState(directory, currentFile) {
  const entries = (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.isFile() && entry.name.endsWith(".json"));
  const currentExists = entries.some((entry) => join(directory, entry.name) === currentFile);
  const excess = entries.length + (currentExists ? 0 : 1) - MAX_PENDING_CORRELATION_FILES;
  if (excess <= 0) return;
  const candidates = (await Promise.all(entries
    .map((entry) => join(directory, entry.name))
    .filter((path) => path !== currentFile)
    .map(async (path) => {
      try { return { path, mtimeMs: (await stat(path)).mtimeMs }; }
      catch { return undefined; }
    })))
    .filter(Boolean)
    .sort((left, right) => left.mtimeMs - right.mtimeMs);
  for (const candidate of candidates.slice(0, excess)) {
    await rm(candidate.path, { force: true }).catch(() => undefined);
  }
}

async function consumePreflight(actionId) {
  const file = join(stateDir(), stateFile(actionId));
  try {
    const raw = await readFile(file, "utf8");
    await rm(file, { force: true });
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function stateDir() {
  return process.env.AUREL_STATE_DIR || join(tmpdir(), "aurel-claude-code");
}

function stateFile(actionId) {
  return `${fingerprint(String(actionId))}.json`;
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

function derivedPaths(toolInput) {
  if (!toolInput || typeof toolInput !== "object") return undefined;
  const values = [];
  for (const key of ["file_path", "path", "notebook_path"]) {
    const value = toolInput[key];
    if (typeof value === "string") values.push(value);
  }
  return values.length ? values : undefined;
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
    return out;
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

function normalizeApiUrl(value) {
  const parsed = new URL(value);
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Aurel API URL must use http or https");
  if (parsed.username || parsed.password) throw new Error("Aurel API URL must not contain credentials");
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

function elapsed(start) {
  return Math.round(performance.now() - start);
}

function stringOrUndefined(value) {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function randomId(prefix) {
  return `${prefix}-${crypto.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`}`;
}
