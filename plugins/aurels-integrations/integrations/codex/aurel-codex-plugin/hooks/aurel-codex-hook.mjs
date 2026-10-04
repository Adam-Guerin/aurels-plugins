#!/usr/bin/env node
import { createHash, randomUUID } from "node:crypto";
import { mkdir, open, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const MAX_INPUT = 1_048_576;
const MAX_RESPONSE_BYTES = 1_048_576;
const MAX_PENDING_CORRELATION_FILES = 1024;
const DENY = "Aurels blocked this action or could not verify it.";
class AurelProtocolError extends Error {}

main().catch(() => deny(DENY));

async function main() {
  const input = JSON.parse(await readStdin());
  if (!input || typeof input !== "object") return deny(DENY);
  if (input.hook_event_name === "PostToolUse") return postToolUse(input);
  if (input.hook_event_name !== "PreToolUse") return process.exit(0);
  const tool = String(input.tool_name ?? "unknown");
  const args = input.tool_input ?? {};
  if (!envBool("AUREL_ENABLED", true) || !included(tool)) return allow();
  const action = {
    version: "1",
    integration: "codex",
    action: { id: String(input.tool_use_id ?? randomUUID()), name: tool, type: "PreToolUse", arguments: args },
    agent: { sessionId: input.session_id, runId: input.turn_id },
    context: { workingDirectory: input.cwd, metadata: { permissionMode: input.permission_mode, model: input.model } },
    timestamp: new Date().toISOString(),
  };
  let decision;
  const started = performance.now();
  try {
    decision = await aurelPost("/api/v1/actions/evaluate", action);
    validateDecision(decision);
  } catch (error) {
    if (!(error instanceof AurelProtocolError) && process.env.AUREL_FAIL_MODE === "open" && !mustBlockOnOutage(tool, args)) return allow();
    return deny(DENY);
  }

  if (decision.decision !== "allow") {
    await telemetry(action, decision, "blocked");
    const note = decision.decision === "require_approval" || decision.decision === "flag"
      ? "Aurels requires human approval. This Codex hook cannot safely open an approval prompt, so the tool was denied."
      : decision.decision === "rewrite"
        ? "Aurels requested an argument rewrite that this adapter cannot safely apply, so the tool was denied."
        : DENY;
    return deny(note);
  }
  await saveState(action, decision, Math.round(performance.now() - started));
  return allow();
}

function validateDecision(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !["allow", "block", "flag", "require_approval", "rewrite", "quarantine"].includes(value.decision)) {
    throw new AurelProtocolError("Invalid Aurels decision");
  }
  if (value.riskScore !== undefined && (typeof value.riskScore !== "number" || !Number.isFinite(value.riskScore) || value.riskScore < 0 || value.riskScore > 100)) {
    throw new AurelProtocolError("Invalid Aurels risk score");
  }
  for (const field of ["traceId", "reason", "policyVersion", "category"]) {
    if (value[field] !== undefined && (typeof value[field] !== "string" || value[field].length > 4096)) {
      throw new AurelProtocolError("Invalid Aurels metadata");
    }
  }
  if (value.ruleIds !== undefined && (!Array.isArray(value.ruleIds) || value.ruleIds.length > 128
    || value.ruleIds.some((id) => typeof id !== "string" || id.length > 512))) {
    throw new AurelProtocolError("Invalid Aurels rule IDs");
  }
}

async function postToolUse(input) {
  const id = String(input.tool_use_id ?? "");
  const state = id ? await consumeState(id) : undefined;
  if (!state || !envBool("AUREL_TELEMETRY_ENABLED", true)) return process.exit(0);
  const completionStatus = classifyToolResponse(input.tool_response);
  try {
    const telemetryPayload = {
      version: "1",
      integration: "codex",
      actionId: state.actionId,
      traceId: state.traceId,
      agent: state.agent,
      outcome: {
        status: completionStatus === "failure" ? "failure" : "success",
        errorCategory: completionStatus === "failure" ? "tool_error" : completionStatus === "unknown" ? "host_status_unavailable" : undefined,
      },
      timings: { aurelPreflightLatencyMs: state.preflightLatencyMs, aurelPostflightLatencyMs: 0 },
      metadata: { tool: input.tool_name, args: redact(input.tool_input), resultIncluded: false, completionStatus },
      timestamp: new Date().toISOString(),
    };
    await aurelPost("/api/v1/actions/telemetry", telemetryPayload);
  } catch (error) {
    console.error(`[aurels-codex] telemetry failed: ${safeError(error)}`);
  }
  process.exit(0);
}

async function telemetry(action, decision, status) {
  if (!envBool("AUREL_TELEMETRY_ENABLED", true)) return;
  try {
    await aurelPost("/api/v1/actions/telemetry", {
      version: "1", integration: "codex", actionId: action.action.id, traceId: decision.traceId,
      agent: action.agent, outcome: { status },
      metadata: { tool: action.action.name, args: redact(action.action.arguments), decision: decision.decision, resultIncluded: false },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error(`[aurels-codex] blocked telemetry failed: ${safeError(error)}`);
  }
}

async function aurelPost(path, payload) {
  const apiKey = process.env.AURELS_API_KEY ?? process.env.AUREL_API_KEY;
  if (!apiKey) throw new Error("Aurels API key is not configured");
  let base;
  try { base = new URL(process.env.AURELS_API_URL ?? process.env.AUREL_API_URL ?? "https://www.aurels.dev"); } catch { throw new AurelProtocolError("Invalid evaluator endpoint"); }
  const localHttp = base.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(base.hostname);
  if ((base.protocol !== "https:" && !localHttp) || base.username || base.password) throw new AurelProtocolError("Evaluator endpoint requires HTTPS or loopback HTTP without credentials");
  base.search = ""; base.hash = "";
  const timeout = Math.min(30_000, Math.max(100, Number(process.env.AUREL_TIMEOUT_MS ?? 1500)));
  const response = await fetch(`${base.toString().replace(/\/+$/, "")}${path}`, {
    method: "POST", redirect: "error", signal: AbortSignal.timeout(timeout),
    headers: { "content-type": "application/json", "x-api-key": apiKey, "idempotency-key": idempotencyKey(path, payload) },
    body: JSON.stringify(payload),
  });
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) throw new AurelProtocolError("Aurels response too large");
  const text = await readLimitedText(response);
  if (!response.ok) throw new Error(`Aurels HTTP ${response.status}`);
  try { return JSON.parse(text); }
  catch { throw new AurelProtocolError("Aurels returned invalid JSON"); }
}

async function readLimitedText(response) {
  if (!response.body || typeof response.body.getReader !== "function") {
    throw new Error("Aurels response stream is unsupported");
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new AurelProtocolError("Aurels response too large");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total).toString("utf8");
}

function idempotencyKey(path, payload) {
  const action = payload?.action ?? { id: payload?.actionId };
  const fingerprint = createHash("sha256").update(JSON.stringify(payload)).digest("hex");
  return `aurels:${path.endsWith("/evaluate") ? "evaluate" : "telemetry"}:${encodeURIComponent(String(action?.id ?? "unknown")).slice(0, 128)}:${fingerprint}`;
}

function allow() {
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" } }));
  process.exit(0);
}
function deny(reason) {
  console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: reason } }));
  process.exit(0);
}
function included(tool) {
  const list = String(process.env.AUREL_TOOLS_INCLUDE ?? "").split(",").map((v) => v.trim()).filter(Boolean);
  return list.length === 0 || list.includes(tool);
}
function mustBlockOnOutage(tool, args) {
  if (process.env.AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS === "allow") return false;
  let text;
  try { text = JSON.stringify(args); } catch { return true; }
  return /(?:bash|shell|terminal|exec|process|write|delete|remove|patch|network|browser|email|message|database|sql|cloud|package|install|schedule|delegate|mcp|api|payment|finance|auth|credential)/i.test(tool)
    || /(?:rm\s+-[a-z]*r[a-z]*f|drop\s+(?:database|table|schema)|truncate\s+table|delete\s+from|\b(?:send|transfer|pay|purchase|delete|destroy|overwrite|chmod|chown)\b)/i.test(text);
}
function redact(value, depth = 0) {
  if (depth > 8) return "[MaxDepth]";
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  if (value && typeof value === "object") {
    const output = Object.create(null);
    for (const [key, item] of Object.entries(value).slice(0, 100)) {
      output[key] = /password|secret|token|api[_-]?key|authorization|cookie|credential/i.test(key) ? "[REDACTED]" : redact(item, depth + 1);
    }
    return output;
  }
  if (typeof value === "string") return value.slice(0, 4096)
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\b(?:sk-(?:ant|proj)-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]");
  return value;
}
function statePath(id) { return join(process.env.AUREL_STATE_DIR || join(tmpdir(), "aurels-codex"), `${createHash("sha256").update(id).digest("hex")}.json`); }
async function saveState(action, decision, preflightLatencyMs) {
  if (!envBool("AUREL_TELEMETRY_ENABLED", true)) return;
  if (!action.action.id) return;
  const file = statePath(action.action.id);
  const directory = dirname(file);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await withStateLock(directory, async () => {
    await prunePendingState(directory, file);
    await writeFile(file, JSON.stringify({ actionId: action.action.id, traceId: decision.traceId, agent: action.agent, preflightLatencyMs }), { encoding: "utf8", mode: 0o600 });
  });
}
async function withStateLock(directory, operation) {
  const lockPath = join(directory, ".aurels-state.lock");
  const deadline = Date.now() + 10_000;
  let lock;
  while (!lock) {
    try { lock = await open(lockPath, "wx", 0o600); }
    catch (error) {
      if (error?.code !== "EEXIST") throw error;
      if (Date.now() >= deadline) throw new Error("Timed out waiting for the Aurels correlation state lock");
      const lockInfo = await stat(lockPath).catch(() => undefined);
      if (!lockInfo) {
        // The owner may have released the lock between open(EEXIST) and stat.
        // Never unlink a path we did not observe: a new owner may already hold it.
        await new Promise((resolve) => setTimeout(resolve, 10));
      } else if (Date.now() - lockInfo.mtimeMs > 30_000) {
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
function classifyToolResponse(value) {
  if (!value || typeof value !== "object") return "unknown";
  if (value.isError === true || value.ok === false || value.success === false || value.error) return "failure";
  if (value.isError === false || value.ok === true || value.success === true) return "success";
  const exitCode = value.exit_code ?? value.exitCode;
  if (typeof exitCode === "number") return exitCode === 0 ? "success" : "failure";
  if (typeof value.status === "string" && /^(failed|failure|error)$/i.test(value.status)) return "failure";
  if (typeof value.status === "string" && /^(success|succeeded|ok|completed)$/i.test(value.status)) return "success";
  return "unknown";
}
async function consumeState(id) {
  const file = statePath(id);
  try {
    const value = JSON.parse(await readFile(file, "utf8"));
    await rm(file, { force: true });
    return value;
  } catch { return undefined; }
}
function envBool(name, fallback) { const v = process.env[name]; return v === undefined ? fallback : /^(1|true|yes|on)$/i.test(v); }
function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = []; let bytes = 0;
    process.stdin.on("data", (chunk) => { bytes += chunk.length; if (bytes > MAX_INPUT) { reject(new Error("hook input too large")); process.stdin.destroy(); } else chunks.push(chunk); });
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    process.stdin.on("error", reject);
  });
}
function safeError(error) { return error instanceof Error ? error.message.slice(0, 256) : "unknown"; }
