import { createHash } from "node:crypto";

export type AurelDecision = "allow" | "block" | "require_approval" | "rewrite" | "quarantine";
export type FailMode = "open" | "closed";

export interface OpenClawAurelConfig {
  enabled: boolean;
  apiUrl: string;
  apiKey: string;
  failMode: FailMode;
  failOpenPrivilegedActions: "block" | "allow";
  timeoutMs: number;
  logLevel: "silent" | "error" | "warn" | "info" | "debug";
  telemetry: {
    enabled: boolean;
    includeResults: boolean;
    maxPayloadBytes: number;
  };
  approval: {
    enabled: boolean;
    nativeDirective: boolean;
    timeoutMs: number;
  };
  rewrite: {
    enabled: boolean;
    unsupportedFallback: "approval" | "block";
    unsupportedTools: string[];
  };
  tools: {
    include: string[];
    exclude: string[];
  };
  redaction: {
    enabled: boolean;
  };
}

export interface AurelActionRequest {
  version: "1";
  integration: "openclaw";
  action: {
    id: string;
    name: string;
    type?: string;
    arguments: unknown;
  };
  agent: {
    id?: string;
    sessionId?: string;
    runId?: string;
  };
  requester?: {
    channel?: string;
    accountId?: string;
    senderId?: string;
    isOwner?: boolean;
    roleIds?: string[];
  };
  context?: {
    workingDirectory?: string;
    targetPaths?: string[];
    parentActionId?: string;
    metadata?: Record<string, unknown>;
  };
  timestamp: string;
}

export interface AurelSecurityDecision {
  decision: AurelDecision;
  reason?: string;
  riskScore?: number;
  ruleIds?: string[];
  category?: string;
  rewrittenArguments?: unknown;
  traceId?: string;
  policyVersion?: string;
}

export interface AurelActionTelemetry {
  version: "1";
  integration: "openclaw";
  actionId: string;
  traceId?: string;
  agent?: AurelActionRequest["agent"];
  outcome: {
    status: "success" | "failure" | "blocked" | "approval_requested" | "approval_allowed" | "approval_denied";
    durationMs?: number;
    errorCategory?: string;
  };
  timings?: {
    aurelPreflightLatencyMs?: number;
    toolExecutionLatencyMs?: number;
    aurelPostflightLatencyMs?: number;
  };
  metadata?: Record<string, unknown>;
  timestamp: string;
}

export interface OpenClawBeforeToolEvent {
  toolName: string;
  params?: unknown;
  toolKind?: string;
  toolInputKind?: string;
  derivedPaths?: string[];
  runId?: string | number;
  toolCallId?: string;
  supportsParamRewrite?: boolean;
}

export interface OpenClawAfterToolEvent extends OpenClawBeforeToolEvent {
  result?: unknown;
  error?: unknown;
  durationMs?: number;
  success?: boolean;
}

export interface OpenClawHookContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string | number;
  toolKind?: string;
  toolInputKind?: string;
  abortSignal?: AbortSignal;
  requester?: {
    channel?: string;
    accountId?: string;
    senderId?: string;
    senderIsOwner?: boolean;
    roleIds?: string[];
  };
  trace?: unknown;
  cwd?: string;
}

export interface BeforeToolResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
  requireApproval?: {
    title: string;
    description: string;
    severity?: "info" | "warning" | "critical";
    timeoutMs?: number;
    allowedDecisions?: Array<"allow-once" | "allow-always" | "deny">;
    onResolution?: (decision: "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled") => Promise<void> | void;
  };
}

export interface AurelHttpClient {
  evaluateAction(action: AurelActionRequest, signal?: AbortSignal): Promise<AurelSecurityDecision>;
  recordTelemetry(telemetry: AurelActionTelemetry, signal?: AbortSignal): Promise<void>;
}

const BLOCKED_MESSAGE = "Aurel blocked this action because it violates the active security policy.";
const UNAVAILABLE_MESSAGE = "Aurel security verification is unavailable.";
const MAX_AUREL_RESPONSE_BYTES = 1024 * 1024;
const MAX_AUREL_REQUEST_BYTES = 1024 * 1024;
const MAX_AUREL_STRING_CHARS = 65_536;
const MAX_AUREL_ARRAY_ITEMS = 512;
const MAX_AUREL_OBJECT_KEYS = 512;
const SENSITIVE_KEY_PATTERN =
  /(?:password|passwd|secret|token|api[_-]?key|apikey|authorization|cookie|session|private[_-]?key|credential|access[_-]?token|refresh[_-]?token)/i;

interface ActionState {
  actionId: string;
  traceId?: string;
  agent: AurelActionRequest["agent"];
  preflightLatencyMs?: number;
  reported?: boolean;
}

export function loadConfig(raw: unknown = {}): OpenClawAurelConfig {
  const cfg = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  return {
    enabled: readBoolean(cfg.enabled, readEnvBoolean("AUREL_ENABLED", true)),
    apiUrl: readString(cfg.apiUrl, process.env.AURELS_API_URL ?? process.env.AUREL_API_URL ?? process.env.INTENTGUARD_API_URL ?? "https://www.aurels.dev"),
    apiKey: readString(cfg.apiKey, process.env.AURELS_API_KEY ?? process.env.AUREL_API_KEY ?? process.env.INTENTGUARD_API_KEY ?? ""),
    failMode: readEnum(cfg.failMode, ["open", "closed"], process.env.AUREL_FAIL_MODE === "open" ? "open" : "closed"),
    failOpenPrivilegedActions: readEnum(
      cfg.failOpenPrivilegedActions,
      ["block", "allow"],
      process.env.AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS === "allow" ? "allow" : "block"
    ),
    timeoutMs: readNumber(cfg.timeoutMs, readEnvNumber("AUREL_TIMEOUT_MS", 1500), 100, 30_000),
    logLevel: readLogLevel(cfg.logLevel),
    telemetry: {
      enabled: readBoolean(readObject(cfg.telemetry).enabled, readEnvBoolean("AUREL_TELEMETRY_ENABLED", true)),
      includeResults: readBoolean(readObject(cfg.telemetry).includeResults, readEnvBoolean("AUREL_TELEMETRY_INCLUDE_RESULTS", false)),
      maxPayloadBytes: readNumber(readObject(cfg.telemetry).maxPayloadBytes, readEnvNumber("AUREL_TELEMETRY_MAX_PAYLOAD_BYTES", 32_768), 1024, 262_144),
    },
    approval: {
      enabled: readBoolean(readObject(cfg.approval).enabled, true),
      nativeDirective: readBoolean(readObject(cfg.approval).nativeDirective, readEnvBoolean("AUREL_OPENCLAW_NATIVE_APPROVAL", false)),
      timeoutMs: readNumber(readObject(cfg.approval).timeoutMs, 60_000, 1000, 3_600_000),
    },
    rewrite: {
      enabled: readBoolean(readObject(cfg.rewrite).enabled, true),
      unsupportedFallback: readEnum(
        readObject(cfg.rewrite).unsupportedFallback,
        ["approval", "block"],
        process.env.AUREL_REWRITE_UNSUPPORTED_FALLBACK === "block" ? "block" : "approval"
      ),
      unsupportedTools: readStringArray(readObject(cfg.rewrite).unsupportedTools),
    },
    tools: {
      include: readStringArray(readObject(cfg.tools).include, readEnvList("AUREL_TOOLS_INCLUDE")),
      exclude: readStringArray(readObject(cfg.tools).exclude, readEnvList("AUREL_TOOLS_EXCLUDE")),
    },
    redaction: {
      enabled: readBoolean(readObject(cfg.redaction).enabled, readEnvBoolean("AUREL_REDACTION_ENABLED", true)),
    },
  };
}

export function createAurelHttpClient(config: OpenClawAurelConfig, fetchImpl: typeof fetch = fetch): AurelHttpClient {
  const baseUrl = validateBaseUrl(config.apiUrl);
  return {
    async evaluateAction(action, signal) {
      const body = await requestJson<AurelSecurityDecision>(
        fetchImpl,
        baseUrl,
        "/api/v1/actions/evaluate",
        config,
        action,
        signal
      );
      return parseDecision(body);
    },
    async recordTelemetry(telemetry, signal) {
      await retryTelemetry(async () => {
        await requestJson(fetchImpl, baseUrl, "/api/v1/actions/telemetry", config, telemetry, signal);
      });
    },
  };
}

export function createOpenClawAurelHandlers(config: OpenClawAurelConfig, client: AurelHttpClient) {
  const stateByToolCall = new Map<string, ActionState>();
  // Keep only a short-lived correlation tombstone after finalization. This avoids
  // duplicate post-hook telemetry without retaining a decision or action payload.
  const finalizedToolCalls = new Set<string>();
  let lastDecision: AurelSecurityDecision | undefined;

  return {
    async beforeToolCall(event: OpenClawBeforeToolEvent, ctx: OpenClawHookContext = {}): Promise<BeforeToolResult | undefined> {
      if (!shouldIntercept(event.toolName, config)) return undefined;
      const started = now();
      const action = normalizeOpenClawAction(event, ctx);

      try {
        const decision = await client.evaluateAction(action, ctx.abortSignal);
        lastDecision = decision;
        const state: ActionState = {
          actionId: action.action.id,
          traceId: decision.traceId,
          agent: action.agent,
          preflightLatencyMs: elapsed(started),
        };
        const key = toolCallKey(event, ctx);
        stateByToolCall.set(key, state);
        // A host may reuse an ID after a completed call. A new preflight starts a
        // new lifecycle and must not inherit the previous completion tombstone.
        finalizedToolCalls.delete(key);
        scheduleStateCleanup(stateByToolCall, key, state);

        const result = mapDecision(event, decision, config, client, state);
        // A blocked action has no reliable post-hook. Its state must therefore be
        // finalized here rather than retained until the TTL expires.
        if (result?.block) {
          stateByToolCall.delete(key);
          markFinalized(finalizedToolCalls, key);
        }
        return result;
      } catch (error) {
        log(config, config.failMode === "closed" ? "error" : "warn", "Aurel preflight failed", error);
        if (config.failMode === "closed" || shouldBlockFailOpenOutage(action, config)) {
          return { block: true, blockReason: UNAVAILABLE_MESSAGE };
        }
        return undefined;
      }
    },

    async afterToolCall(event: OpenClawAfterToolEvent, ctx: OpenClawHookContext = {}): Promise<void> {
      if (!shouldIntercept(event.toolName, config)) return;
      const key = toolCallKey(event, ctx);
      if (finalizedToolCalls.has(key)) return;
      const state = stateByToolCall.get(key);
      // Cleanup is independent of telemetry. Otherwise disabling telemetry makes
      // every completed call survive until its expiry timer.
      stateByToolCall.delete(key);
      markFinalized(finalizedToolCalls, key);
      if (!config.telemetry.enabled) return;

      const actionId = state?.actionId ?? event.toolCallId ?? randomId("oc-act");
      const postStarted = now();
      const success = event.success ?? event.error === undefined;
      const metadata: Record<string, unknown> = {
        tool: event.toolName,
        toolKind: event.toolKind ?? ctx.toolKind,
        toolInputKind: event.toolInputKind ?? ctx.toolInputKind,
        params: redact(event.params, config),
      };
      if (config.telemetry.includeResults) {
        metadata.result = redact(event.result, config);
      }

      const telemetry: AurelActionTelemetry = {
        version: "1",
        integration: "openclaw",
        actionId,
        traceId: state?.traceId,
        agent: state?.agent ?? {
          id: ctx.agentId,
          sessionId: ctx.sessionId ?? ctx.sessionKey,
          runId: stringifyId(ctx.runId ?? event.runId),
        },
        outcome: {
          status: success ? "success" : "failure",
          durationMs: readOptionalNumber(event.durationMs),
          errorCategory: success ? undefined : classifyError(event.error),
        },
        timings: {
          aurelPreflightLatencyMs: state?.preflightLatencyMs,
          toolExecutionLatencyMs: readOptionalNumber(event.durationMs),
          aurelPostflightLatencyMs: elapsed(postStarted),
        },
        metadata,
        timestamp: new Date().toISOString(),
      };

      void client.recordTelemetry(telemetry, ctx.abortSignal).catch((error) => {
        log(config, "warn", "Aurel postflight telemetry failed", error);
      });
    },

    status() {
      return {
        enabled: config.enabled,
        failMode: config.failMode,
        telemetry: config.telemetry.enabled,
        lastDecision,
        pendingActions: stateByToolCall.size,
      };
    },
  };
}

export function normalizeOpenClawAction(event: OpenClawBeforeToolEvent, ctx: OpenClawHookContext = {}): AurelActionRequest {
  const actionId = event.toolCallId ?? traceString(ctx.trace, "toolCallId") ?? randomId("oc-act");
  return {
    version: "1",
    integration: "openclaw",
    action: {
      id: actionId,
      name: safeName(event.toolName),
      type: event.toolKind ?? ctx.toolKind,
      arguments: event.params ?? {},
    },
    agent: {
      id: ctx.agentId,
      sessionId: ctx.sessionId ?? ctx.sessionKey,
      runId: stringifyId(ctx.runId ?? event.runId),
    },
    requester: ctx.requester
      ? {
          channel: ctx.requester.channel,
          accountId: ctx.requester.accountId,
          senderId: ctx.requester.senderId,
          isOwner: ctx.requester.senderIsOwner,
          roleIds: Array.isArray(ctx.requester.roleIds) ? ctx.requester.roleIds : undefined,
        }
      : undefined,
    context: {
      workingDirectory: ctx.cwd,
      targetPaths: Array.isArray(event.derivedPaths) ? event.derivedPaths : undefined,
      parentActionId: traceString(ctx.trace, "parentActionId"),
      metadata: {
        toolInputKind: event.toolInputKind ?? ctx.toolInputKind,
      },
    },
    timestamp: new Date().toISOString(),
  };
}

function mapDecision(
  event: OpenClawBeforeToolEvent,
  decision: AurelSecurityDecision,
  config: OpenClawAurelConfig,
  client: AurelHttpClient,
  state: ActionState
): BeforeToolResult | undefined {
  switch (decision.decision) {
    case "allow":
      return undefined;
    case "block":
    case "quarantine":
      recordPreExecutionOutcome(client, config, state, event, "blocked", decision);
      return { block: true, blockReason: BLOCKED_MESSAGE };
    case "require_approval":
      if (!config.approval.enabled || !config.approval.nativeDirective) {
        recordPreExecutionOutcome(client, config, state, event, "blocked", decision);
        return { block: true, blockReason: BLOCKED_MESSAGE };
      }
      return approvalResult(event, decision, config, client, state);
    case "rewrite":
      if (canRewrite(event, decision, config)) {
        return { params: decision.rewrittenArguments as Record<string, unknown> };
      }
      if (config.rewrite.unsupportedFallback === "block" || !config.approval.enabled || !config.approval.nativeDirective) {
        recordPreExecutionOutcome(client, config, state, event, "blocked", decision);
        return { block: true, blockReason: BLOCKED_MESSAGE };
      }
      return approvalResult(
        event,
        { ...decision, reason: "Aurel requested a parameter rewrite that this OpenClaw tool runtime cannot apply safely." },
        config,
        client,
        state
      );
    default:
      recordPreExecutionOutcome(client, config, state, event, "blocked", decision);
      return { block: true, blockReason: BLOCKED_MESSAGE };
  }
}

function recordPreExecutionOutcome(
  client: AurelHttpClient,
  config: OpenClawAurelConfig,
  state: ActionState,
  event: OpenClawBeforeToolEvent,
  status: AurelActionTelemetry["outcome"]["status"],
  decision: AurelSecurityDecision
): void {
  if (!config.telemetry.enabled || state.reported) return;
  const postStarted = now();
  state.reported = true;
  void client.recordTelemetry({
    version: "1",
    integration: "openclaw",
    actionId: state.actionId,
    traceId: state.traceId,
    agent: state.agent,
    outcome: { status },
    timings: {
      aurelPreflightLatencyMs: state.preflightLatencyMs,
      aurelPostflightLatencyMs: elapsed(postStarted),
    },
    metadata: {
      tool: event.toolName,
      toolKind: event.toolKind,
      toolInputKind: event.toolInputKind,
      params: redact(event.params, config),
      decision: decision.decision,
      riskScore: decision.riskScore,
      category: decision.category,
      ruleIds: decision.ruleIds,
    },
    timestamp: new Date().toISOString(),
  }).catch((error) => {
    log(config, "warn", "Aurel terminal pre-execution telemetry failed", error);
  });
}

function approvalResult(
  event: OpenClawBeforeToolEvent,
  decision: AurelSecurityDecision,
  config: OpenClawAurelConfig,
  client: AurelHttpClient,
  state: ActionState
): BeforeToolResult {
  recordApprovalRequested(client, config, state, event, decision);
  return {
    requireApproval: {
      title: "Aurel approval required",
      description: "Aurel requires human approval before this action can run.",
      severity: severityFor(decision.riskScore),
      timeoutMs: config.approval.timeoutMs,
      allowedDecisions: ["allow-once", "deny"],
      onResolution: async (resolution) => {
        if (!config.telemetry.enabled) return;
        await client.recordTelemetry({
          version: "1",
          integration: "openclaw",
          actionId: state.actionId,
          traceId: state.traceId,
          agent: state.agent,
          outcome: {
            status: resolution === "allow-once" || resolution === "allow-always" ? "approval_allowed" : "approval_denied",
          },
          metadata: {
            approvalResolution: resolution,
          },
          timestamp: new Date().toISOString(),
        });
      },
    },
  };
}

function recordApprovalRequested(
  client: AurelHttpClient,
  config: OpenClawAurelConfig,
  state: ActionState,
  event: OpenClawBeforeToolEvent,
  decision: AurelSecurityDecision
): void {
  if (!config.telemetry.enabled) return;
  const postStarted = now();
  void client.recordTelemetry({
    version: "1",
    integration: "openclaw",
    actionId: state.actionId,
    traceId: state.traceId,
    agent: state.agent,
    outcome: { status: "approval_requested" },
    timings: {
      aurelPreflightLatencyMs: state.preflightLatencyMs,
      aurelPostflightLatencyMs: elapsed(postStarted),
    },
    metadata: {
      tool: event.toolName,
      toolKind: event.toolKind,
      toolInputKind: event.toolInputKind,
      params: redact(event.params, config),
      decision: decision.decision,
      riskScore: decision.riskScore,
      category: decision.category,
      ruleIds: decision.ruleIds,
    },
    timestamp: new Date().toISOString(),
  }).catch((error) => {
    log(config, "warn", "Aurel approval-request telemetry failed", error);
  });
}

function canRewrite(event: OpenClawBeforeToolEvent, decision: AurelSecurityDecision, config: OpenClawAurelConfig): boolean {
  return (
    config.rewrite.enabled &&
    decision.rewrittenArguments !== undefined &&
    isRecord(decision.rewrittenArguments) &&
    event.supportsParamRewrite !== false &&
    !config.rewrite.unsupportedTools.includes(event.toolName)
  );
}

function shouldIntercept(toolName: string, config: OpenClawAurelConfig): boolean {
  if (!config.enabled) return false;
  if (!config.apiKey) return config.failMode === "closed";
  if (config.tools.exclude.includes(toolName)) return false;
  return config.tools.include.length === 0 || config.tools.include.includes(toolName);
}

function shouldBlockFailOpenOutage(action: AurelActionRequest, config: OpenClawAurelConfig): boolean {
  return config.failMode === "open" && config.failOpenPrivilegedActions === "block" && isPrivilegedToolName(action.action.name);
}

function isPrivilegedToolName(toolName: string): boolean {
  return /(?:^|[._:-])(?:bash|shell|terminal|exec|execute|process|spawn|run_command|file_write|write_file|delete_file|remove_file|patch|apply_patch|git_push|network|browser|http|fetch|email|send_email|message|database|db|sql|cloud|package|install|schedule|subagent|delegate|mcp|api|payment|finance|permission|auth|credential)(?:$|[._:-])/i.test(
    toolName
  );
}

function parseDecision(body: unknown): AurelSecurityDecision {
  if (!isRecord(body) || typeof body.decision !== "string") {
    throw new Error("Malformed Aurel decision response");
  }
  const normalized = body.decision === "flag" ? { ...body, decision: "require_approval" } : body;
  if (!["allow", "block", "require_approval", "rewrite", "quarantine"].includes(normalized.decision as string)) {
    throw new Error(`Unsupported Aurel decision: ${body.decision}`);
  }
  validateDecisionMetadata(normalized);
  return normalized as unknown as AurelSecurityDecision;
}

function validateDecisionMetadata(body: Record<string, unknown>): void {
  if (body.riskScore !== undefined) {
    const riskScore = body.riskScore;
    if (typeof riskScore !== "number" || !Number.isFinite(riskScore) || riskScore < 0 || riskScore > 100) {
      throw new Error("Aurel returned an invalid risk score");
    }
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

async function requestJson<T>(
  fetchImpl: typeof fetch,
  baseUrl: string,
  path: string,
  config: OpenClawAurelConfig,
  payload: unknown,
  upstreamSignal?: AbortSignal
): Promise<T> {
  if (!config.apiKey) throw new Error("Aurel API key is not configured");
  const controller = new AbortController();
  const timeoutError = new Error(`Aurel request timed out after ${config.timeoutMs}ms`);
  let timeout: ReturnType<typeof setTimeout>;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => {
      controller.abort(timeoutError);
      reject(timeoutError);
    }, config.timeoutMs);
  });
  const cleanup = linkSignal(controller, upstreamSignal);
  try {
    const response = await Promise.race([
      fetchImpl(`${baseUrl}${path}`, {
        method: "POST",
        signal: controller.signal,
        headers: {
          "content-type": "application/json",
          "x-api-key": config.apiKey,
          "idempotency-key": idempotencyKeyFor(path, payload),
          "user-agent": "aurel-openclaw-plugin/0.1.0",
        },
        body: path === "/api/v1/actions/evaluate" ? stringifyExactAurelPayload(payload) : stringifyAurelPayload(payload),
      }),
      timeoutPromise,
    ]);
    const body = await readJsonResponse(response, timeoutPromise);
    if (!response.ok) throw new Error(`Aurel HTTP ${response.status}`);
    return body as T;
  } catch (error) {
    if (controller.signal.aborted) {
      throw controller.signal.reason instanceof Error ? controller.signal.reason : timeoutError;
    }
    throw error;
  } finally {
    clearTimeout(timeout!);
    cleanup();
  }
}

function stringifyExactAurelPayload(value: unknown): string {
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new Error("Aurel action payload is not losslessly JSON-serializable");
  }
  if (new TextEncoder().encode(serialized).length > MAX_AUREL_REQUEST_BYTES) {
    throw new Error("Aurel action payload exceeded maximum size; exact arguments were not evaluated");
  }
  return serialized;
}

function stringifyAurelPayload(value: unknown): string {
  const serialized = JSON.stringify(toSerializable(value, new WeakSet<object>(), 0));
  if (new TextEncoder().encode(serialized).length <= MAX_AUREL_REQUEST_BYTES) return serialized;
  const bounded = boundActionArguments(value);
  const fallback = JSON.stringify(toSerializable(bounded, new WeakSet<object>(), 0));
  if (new TextEncoder().encode(fallback).length <= MAX_AUREL_REQUEST_BYTES) return fallback;
  throw new Error("Aurel request payload exceeded maximum size");
}

function toSerializable(value: unknown, seen: WeakSet<object>, depth: number): unknown {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : "[NonFiniteNumber]";
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
    const output: Record<string, unknown> = Object.create(null);
    let keys: string[];
    try {
      keys = Object.keys(value as Record<string, unknown>);
    } catch {
      return "[UnserializableObject]";
    }
    for (const key of keys.slice(0, MAX_AUREL_OBJECT_KEYS)) {
      let entry: unknown;
      try {
        entry = (value as Record<string, unknown>)[key];
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

function truncatePayloadString(value: string): string {
  return value.length > MAX_AUREL_STRING_CHARS ? `${value.slice(0, MAX_AUREL_STRING_CHARS)}...[truncated]` : value;
}

function boundActionArguments(value: unknown): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return { truncated: true, reason: "payload_limit" };
  const envelope = value as Record<string, unknown>;
  if (!envelope.action || typeof envelope.action !== "object" || Array.isArray(envelope.action)) {
    return { truncated: true, reason: "payload_limit" };
  }
  return {
    ...envelope,
    action: {
      ...(envelope.action as Record<string, unknown>),
      arguments: { truncated: true, reason: "payload_limit" },
    },
  };
}

async function readJsonResponse(response: Response, timeoutPromise: Promise<never>): Promise<unknown> {
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_AUREL_RESPONSE_BYTES) {
    throw new Error("Aurel response exceeded maximum size");
  }

  const text = await readLimitedText(response, timeoutPromise);
  if (!text.trim()) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function readLimitedText(response: Response, timeoutPromise: Promise<never>): Promise<string> {
  if (!response.body) {
    const text = await Promise.race([response.text(), timeoutPromise]);
    if (new TextEncoder().encode(text).length > MAX_AUREL_RESPONSE_BYTES) {
      throw new Error("Aurel response exceeded maximum size");
    }
    return text;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), timeoutPromise]);
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > MAX_AUREL_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new Error("Aurel response exceeded maximum size");
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

async function retryTelemetry(fn: () => Promise<void>): Promise<void> {
  const delays = [50, 150, 350];
  let lastError: unknown;
  for (let index = 0; index < delays.length; index += 1) {
    try {
      await fn();
      return;
    } catch (error) {
      lastError = error;
      if (index + 1 < delays.length) {
        await new Promise((resolve) => setTimeout(resolve, delays[index]));
      }
    }
  }
  throw lastError;
}

function redact(value: unknown, config: OpenClawAurelConfig): unknown {
  return redactValue(value, new WeakSet<object>(), 0, config);
}

function redactValue(value: unknown, seen: WeakSet<object>, depth: number, config: OpenClawAurelConfig): unknown {
  if (!config.redaction.enabled) return boundPayload(value, config.telemetry.maxPayloadBytes);
  if (value === null || typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string") return truncate(value, 4096);
  if (typeof value === "undefined") return null;
  if (typeof value === "function" || typeof value === "symbol") return `[${typeof value}]`;
  if (depth > 8) return "[MaxDepth]";
  if (seen.has(value)) return "[Circular]";
  seen.add(value);
  if (Array.isArray(value)) {
    try {
      return value.slice(0, 50).map((entry) => redactValue(entry, seen, depth + 1, config));
    } finally {
      seen.delete(value);
    }
  }
  try {
    const out: Record<string, unknown> = Object.create(null);
    let keys: string[];
    try {
      keys = Object.keys(value as Record<string, unknown>);
    } catch {
      return "[UnserializableObject]";
    }
    for (const key of keys) {
      const safeKey = truncate(key, 256);
      if (SENSITIVE_KEY_PATTERN.test(key)) {
        out[safeKey] = "[REDACTED]";
        continue;
      }
      let entry: unknown;
      try {
        entry = (value as Record<string, unknown>)[key];
      } catch {
        out[safeKey] = "[UnserializableProperty]";
        continue;
      }
      out[safeKey] = redactValue(entry, seen, depth + 1, config);
    }
    return boundPayload(out, config.telemetry.maxPayloadBytes);
  } finally {
    seen.delete(value);
  }
}

function boundPayload(value: unknown, maxBytes: number): unknown {
  const json = safeStringify(value);
  if (new TextEncoder().encode(json).length <= maxBytes) return value;
  return { truncated: true, reason: "payload_limit", preview: truncate(json, Math.min(4096, maxBytes)) };
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "null";
  } catch {
    return '"[Unserializable]"';
  }
}

function truncate(value: string, maxLength: number): string {
  const sanitized = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "\uFFFD");
  return sanitized.length > maxLength ? `${sanitized.slice(0, maxLength)}...[truncated]` : sanitized;
}

function idempotencyKeyFor(path: string, payload: unknown): string {
  if (isRecord(payload) && path.endsWith("/evaluate") && isRecord(payload.action) && typeof payload.action.id === "string") {
    // Do not let a reused invocation ID deduplicate a different action.
    return idempotencyKey("action-evaluate", payload.action.id, actionFingerprint(payload.action));
  }
  if (isRecord(payload) && path.endsWith("/telemetry") && typeof payload.actionId === "string") {
    const status = isRecord(payload.outcome) && typeof payload.outcome.status === "string" ? payload.outcome.status : "unknown";
    return idempotencyKey("action-telemetry", payload.actionId, status, createHash("sha256").update(stringifyAurelPayload(payload)).digest("hex"));
  }
  return idempotencyKey("aurel-request", safeStringify(payload).slice(0, 128));
}

function actionFingerprint(action: Record<string, unknown>): string {
  // Reuse the bounded, circular-safe transport serialization so the key binds
  // to exactly the envelope that will be sent to the decision service.
  return createHash("sha256").update(stringifyAurelPayload({ action })).digest("hex");
}

function idempotencyKey(prefix: string, ...parts: string[]): string {
  return [prefix, ...parts.map((part) => encodeURIComponent(part).slice(0, 256))].join(":");
}

function severityFor(riskScore = 0): "info" | "warning" | "critical" {
  if (riskScore >= 85) return "critical";
  if (riskScore >= 50) return "warning";
  return "info";
}

function validateBaseUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Aurel API URL must use http or https");
  }
  if (url.username || url.password) {
    throw new Error("Aurel API URL must not include embedded credentials");
  }
  url.hash = "";
  url.search = "";
  return url.toString().replace(/\/+$/, "");
}

function linkSignal(controller: AbortController, upstream?: AbortSignal): () => void {
  if (!upstream) return () => undefined;
  if (upstream.aborted) {
    controller.abort(upstream.reason);
    return () => undefined;
  }
  const onAbort = () => controller.abort(upstream.reason);
  upstream.addEventListener("abort", onAbort, { once: true });
  return () => upstream.removeEventListener("abort", onAbort);
}

function toolCallKey(event: OpenClawBeforeToolEvent, ctx: OpenClawHookContext): string {
  const explicitId = event.toolCallId ?? traceString(ctx.trace, "toolCallId");
  const sessionId = ctx.sessionId ?? ctx.sessionKey ?? "unknown-session";
  const runId = stringifyId(ctx.runId ?? event.runId);
  const agentId = ctx.agentId ?? "unknown-agent";
  // JSON encoding avoids delimiter collisions from externally supplied identity
  // strings. Without a call ID, run/tool is the strongest stable correlation the
  // OpenClaw hook contract provides; never use our random action ID as a key
  // because the post-hook cannot reproduce it.
  return JSON.stringify([agentId, sessionId, runId ?? "unknown-run", explicitId ? "action" : "tool", explicitId ?? event.toolName]);
}

function scheduleStateCleanup(map: Map<string, ActionState>, key: string, state: ActionState): void {
  setTimeout(() => {
    if (map.get(key) === state) {
      map.delete(key);
    }
  }, 10 * 60 * 1000).unref?.();
}

function markFinalized(finalized: Set<string>, key: string): void {
  finalized.add(key);
  setTimeout(() => finalized.delete(key), 10 * 60 * 1000).unref?.();
}

function classifyError(error: unknown): string | undefined {
  if (!error) return undefined;
  if (error instanceof Error) return error.name || "Error";
  if (typeof error === "object" && error !== null && "name" in error && typeof error.name === "string") return error.name;
  return "unknown";
}

function traceString(trace: unknown, key: string): string | undefined {
  if (!isRecord(trace)) return undefined;
  const value = trace[key];
  return typeof value === "string" ? value : undefined;
}

function stringifyId(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}

function safeName(value: unknown): string {
  return typeof value === "string" && value.trim() ? value.slice(0, 256) : "unknown";
}

function randomId(prefix: string): string {
  return `${prefix}_${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}_${Math.random().toString(16).slice(2)}`}`;
}

function now(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

function elapsed(start: number): number {
  return Math.round(now() - start);
}

function readObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function readString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function readStringArray(value: unknown, fallback: string[] = []): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string" && entry.length > 0) : fallback;
}

function readNumber(value: unknown, fallback: number, min: number, max: number): number {
  const n = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  return Math.max(min, Math.min(max, n));
}

function readEnum<const T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === "string" && allowed.includes(value as T) ? (value as T) : fallback;
}

function readOptionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : undefined;
}

function readEnvNumber(name: string, fallback: number): number {
  const value = process.env[name];
  if (!value) return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function readEnvBoolean(name: string, fallback: boolean): boolean {
  const value = process.env[name];
  if (!value) return fallback;
  if (["1", "true", "yes", "on"].includes(value.toLowerCase())) return true;
  if (["0", "false", "no", "off"].includes(value.toLowerCase())) return false;
  return fallback;
}

function readEnvList(name: string): string[] {
  const value = process.env[name];
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function readLogLevel(value: unknown): OpenClawAurelConfig["logLevel"] {
  return value === "silent" || value === "error" || value === "warn" || value === "info" || value === "debug"
    ? value
    : readEnum(process.env.AUREL_LOG_LEVEL, ["silent", "error", "warn", "info", "debug"], "warn");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function log(config: OpenClawAurelConfig, level: "error" | "warn" | "info" | "debug", message: string, error?: unknown): void {
  const order = ["silent", "error", "warn", "info", "debug"];
  if (order.indexOf(config.logLevel) < order.indexOf(level)) return;
  const logger = console[level] ?? console.warn;
  logger(`[aurel-openclaw] ${message}`, error instanceof Error ? error.message : error ?? "");
}
