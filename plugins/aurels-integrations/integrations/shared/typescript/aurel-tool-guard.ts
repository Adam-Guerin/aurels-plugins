import {
  createAurelClient,
  AurelProtocolError,
  normalizeAurelDecision,
  type AurelActionRequest,
  type AurelActionTelemetry,
  type AurelSecurityDecision,
  type IntentGuardClient,
} from "../sdk/index.js";
import { redactForTelemetry } from "../actions/redaction.js";

export type IntegrationName = "openai-agents" | "langgraph" | "mcp" | "codex" | "claude-code" | string;
export type ToolDecision =
  | { type: "allow"; decision: AurelSecurityDecision; action: AurelActionRequest; preflightLatencyMs: number; intercepted?: boolean }
  | { type: "block"; message: string; decision?: AurelSecurityDecision; action: AurelActionRequest; preflightLatencyMs: number; intercepted?: boolean }
  | { type: "require_approval"; message: string; decision: AurelSecurityDecision; action: AurelActionRequest; preflightLatencyMs: number; intercepted?: boolean }
  | { type: "rewrite"; arguments: unknown; decision: AurelSecurityDecision; action: AurelActionRequest; preflightLatencyMs: number; intercepted?: boolean };

export interface AurelToolGuardConfig {
  integration: IntegrationName;
  enabled?: boolean;
  apiUrl?: string;
  apiKey?: string;
  timeoutMs?: number;
  failMode?: "open" | "closed";
  failOpenPrivilegedActions?: "block" | "allow";
  telemetryEnabled?: boolean;
  includeResults?: boolean;
  maxPayloadBytes?: number;
  redactionEnabled?: boolean;
  approvalFallback?: "block" | "approval";
  rewriteSupported?: boolean;
  tools?: {
    include?: string[];
    exclude?: string[];
  };
}

export interface AurelToolCall {
  id?: string;
  name: string;
  type?: string;
  arguments: unknown;
  agent?: AurelActionRequest["agent"];
  requester?: AurelActionRequest["requester"];
  context?: AurelActionRequest["context"];
}

export class AurelToolBlockedError extends Error {
  constructor(public readonly publicMessage: string, public readonly decision?: AurelSecurityDecision) {
    super(publicMessage);
    this.name = "AurelToolBlockedError";
  }
}

export interface AurelToolGuardClient {
  evaluateAction(action: AurelActionRequest, signal?: AbortSignal): Promise<AurelSecurityDecision>;
  recordActionTelemetry(telemetry: AurelActionTelemetry, signal?: AbortSignal): Promise<void>;
}

const SANITIZED_BLOCK = "Aurel blocked this action because it violates the active security policy.";
const SANITIZED_UNAVAILABLE = "Aurel security verification is unavailable.";

export function createAurelToolGuard(config: AurelToolGuardConfig, client?: AurelToolGuardClient) {
  const resolved = resolveConfig(config);
  const aurel = client ?? createAurelClient({
    apiKey: resolved.apiKey,
    baseUrl: resolved.apiUrl,
    timeoutMs: resolved.timeoutMs,
  });

  return {
    async preflight(call: AurelToolCall, signal?: AbortSignal): Promise<ToolDecision> {
      const started = now();

      if (!shouldIntercept(call.name, resolved)) {
        const action = normalizeToolCall(call, resolved.integration, false);
        return { type: "allow", decision: { decision: "allow" }, action, preflightLatencyMs: elapsed(started), intercepted: false };
      }

      const action = normalizeToolCall(call, resolved.integration);
      try {
        if (signal?.aborted) throw new AurelToolBlockedError(SANITIZED_UNAVAILABLE);
        const decision = normalizeAurelDecision(await aurel.evaluateAction(action, signal));
        if (signal?.aborted) throw new AurelToolBlockedError(SANITIZED_UNAVAILABLE);
        return mapDecision(decision, action, elapsed(started), resolved);
      } catch (error) {
        if (error instanceof AurelProtocolError || error instanceof AurelToolBlockedError || signal?.aborted
          || resolved.failMode === "closed" || shouldBlockFailOpenOutage(action, resolved)) {
          return { type: "block", message: SANITIZED_UNAVAILABLE, action, preflightLatencyMs: elapsed(started), intercepted: true };
        }
        console.warn("[aurel] preflight failed in fail-open mode:", error instanceof Error ? error.message : error);
        return { type: "allow", decision: { decision: "allow", reason: "Aurel fail-open fallback" }, action, preflightLatencyMs: elapsed(started), intercepted: true };
      }
    },

    async runProtected<T>(
      call: AurelToolCall,
      execute: (args: unknown) => Promise<T> | T,
      signal?: AbortSignal
    ): Promise<T> {
      const preflight = await this.preflight(call, signal);
      if (signal?.aborted) throw new AurelToolBlockedError(SANITIZED_UNAVAILABLE);
      if (preflight.intercepted === false) {
        return await execute(call.arguments);
      }
      if (preflight.type === "block") {
        reportPostflight(this.postflight(preflight.action, {
          status: "blocked",
          preflightLatencyMs: preflight.preflightLatencyMs,
          traceId: preflight.decision?.traceId,
          args: preflight.action.action.arguments,
          signal,
        }));
        throw new AurelToolBlockedError(preflight.message, preflight.decision);
      }
      if (preflight.type === "require_approval") {
        reportPostflight(this.postflight(preflight.action, {
          status: "approval_requested",
          preflightLatencyMs: preflight.preflightLatencyMs,
          traceId: preflight.decision.traceId,
          args: preflight.action.action.arguments,
          signal,
        }));
        throw new AurelToolBlockedError(preflight.message, preflight.decision);
      }

      const evaluatedArguments = preflight.action.action.arguments;
      const args = preflight.type === "rewrite" ? preflight.arguments : evaluatedArguments;
      const toolStarted = now();
      try {
        const result = await execute(args);
        reportPostflight(this.postflight(preflight.action, {
          status: "success",
          durationMs: elapsed(toolStarted),
          result: resolved.includeResults ? result : undefined,
          preflightLatencyMs: preflight.preflightLatencyMs,
          traceId: preflight.decision.traceId,
          args,
          originalArgs: preflight.type === "rewrite" ? evaluatedArguments : undefined,
          rewriteApplied: preflight.type === "rewrite",
          signal,
        }));
        return result;
      } catch (error) {
        reportPostflight(this.postflight(preflight.action, {
          status: "failure",
          durationMs: elapsed(toolStarted),
          errorCategory: error instanceof Error ? error.name : "unknown",
          preflightLatencyMs: preflight.preflightLatencyMs,
          traceId: preflight.decision.traceId,
          args,
          originalArgs: preflight.type === "rewrite" ? evaluatedArguments : undefined,
          rewriteApplied: preflight.type === "rewrite",
          signal,
        }));
        throw error;
      }
    },

    async postflight(
      action: AurelActionRequest,
      outcome: {
        status: "success" | "failure" | "blocked" | "approval_requested" | "approval_allowed" | "approval_denied";
        durationMs?: number;
        errorCategory?: string;
        result?: unknown;
        args?: unknown;
        originalArgs?: unknown;
        rewriteApplied?: boolean;
        traceId?: string;
        preflightLatencyMs?: number;
        signal?: AbortSignal;
      }
    ): Promise<void> {
      if (!resolved.telemetryEnabled) return;
      const postStarted = now();
      await aurel.recordActionTelemetry(
        {
          version: "1",
          integration: resolved.integration,
          actionId: action.action.id,
          traceId: outcome.traceId,
          agent: action.agent,
          outcome: {
            status: outcome.status,
            durationMs: outcome.durationMs,
            errorCategory: outcome.errorCategory,
          },
          timings: {
            aurelPreflightLatencyMs: outcome.preflightLatencyMs,
            toolExecutionLatencyMs: outcome.durationMs,
            aurelPostflightLatencyMs: elapsed(postStarted),
          },
          metadata: {
            tool: action.action.name,
            args: redactForTelemetry(outcome.args ?? action.action.arguments, {
              enabled: resolved.redactionEnabled,
              maxBytes: resolved.maxPayloadBytes,
            }),
            result: outcome.result === undefined
              ? undefined
              : redactForTelemetry(outcome.result, { enabled: resolved.redactionEnabled, maxBytes: resolved.maxPayloadBytes }),
            resultIncluded: outcome.result !== undefined,
            rewriteApplied: outcome.rewriteApplied ?? false,
            originalArgs: outcome.originalArgs === undefined
              ? undefined
              : redactForTelemetry(outcome.originalArgs, { enabled: resolved.redactionEnabled, maxBytes: resolved.maxPayloadBytes }),
          },
          timestamp: new Date().toISOString(),
        },
        outcome.signal
      );
    },
  };
}

function reportPostflight(promise: Promise<void>): void {
  void promise.catch((error) => {
    console.warn("[aurel] postflight telemetry failed:", error instanceof Error ? error.message : error);
  });
}

export function createDefaultAurelClient(config: AurelToolGuardConfig): IntentGuardClient {
  const resolved = resolveConfig(config);
  return createAurelClient({ apiKey: resolved.apiKey, baseUrl: resolved.apiUrl, timeoutMs: resolved.timeoutMs });
}

function normalizeToolCall(call: AurelToolCall, integration: string, snapshotArguments = true): AurelActionRequest {
  return {
    version: "1",
    integration,
    action: {
      id: call.id ?? randomId(`${integration}-act`),
      name: call.name,
      ...(call.type === undefined ? {} : { type: call.type }),
      arguments: snapshotArguments ? structuredClone(call.arguments) : call.arguments,
    },
    agent: call.agent ?? {},
    requester: call.requester,
    context: call.context,
    timestamp: new Date().toISOString(),
  };
}

function mapDecision(
  decision: AurelSecurityDecision,
  action: AurelActionRequest,
  preflightLatencyMs: number,
  config: RequiredAurelToolGuardConfig
): ToolDecision {
  if (decision.decision === "allow") return { type: "allow", decision, action, preflightLatencyMs, intercepted: true };
  if (decision.decision === "block" || decision.decision === "quarantine") {
    return { type: "block", message: SANITIZED_BLOCK, decision, action, preflightLatencyMs, intercepted: true };
  }
  if (decision.decision === "require_approval") {
    return { type: "require_approval", message: "Aurel requires human approval before this action can run.", decision, action, preflightLatencyMs, intercepted: true };
  }
  if (decision.decision === "rewrite") {
    if (config.rewriteSupported && decision.rewrittenArguments !== undefined) {
      return { type: "rewrite", arguments: decision.rewrittenArguments, decision, action, preflightLatencyMs, intercepted: true };
    }
    if (config.approvalFallback === "block") {
      return { type: "block", message: SANITIZED_BLOCK, decision, action, preflightLatencyMs, intercepted: true };
    }
    return { type: "require_approval", message: "Aurel requires approval because this integration cannot safely rewrite the tool call.", decision, action, preflightLatencyMs, intercepted: true };
  }
  return { type: "block", message: SANITIZED_BLOCK, decision, action, preflightLatencyMs, intercepted: true };
}

type RequiredAurelToolGuardConfig = Required<Omit<AurelToolGuardConfig, "tools">> & {
  tools: { include: string[]; exclude: string[] };
};

function resolveConfig(config: AurelToolGuardConfig): RequiredAurelToolGuardConfig {
  const timeoutMs = readNumber(config.timeoutMs, readEnvNumber("AUREL_TIMEOUT_MS", 1500), 100, 30_000);
  return {
    integration: config.integration,
    enabled: config.enabled ?? readEnvBoolean("AUREL_ENABLED", true),
    apiUrl: config.apiUrl ?? process.env.AURELS_API_URL ?? process.env.AUREL_API_URL ?? process.env.INTENTGUARD_API_URL ?? "https://www.aurels.dev",
    apiKey: config.apiKey ?? process.env.AURELS_API_KEY ?? process.env.AUREL_API_KEY ?? process.env.INTENTGUARD_API_KEY ?? "",
    timeoutMs,
    failMode: config.failMode ?? (process.env.AUREL_FAIL_MODE === "open" ? "open" : "closed"),
    failOpenPrivilegedActions: config.failOpenPrivilegedActions ?? (process.env.AUREL_FAIL_OPEN_PRIVILEGED_ACTIONS === "allow" ? "allow" : "block"),
    telemetryEnabled: config.telemetryEnabled ?? readEnvBoolean("AUREL_TELEMETRY_ENABLED", true),
    includeResults: config.includeResults ?? readEnvBoolean("AUREL_TELEMETRY_INCLUDE_RESULTS", false),
    maxPayloadBytes: readNumber(config.maxPayloadBytes, readEnvNumber("AUREL_TELEMETRY_MAX_PAYLOAD_BYTES", 32_768), 1024, 262_144),
    redactionEnabled: config.redactionEnabled ?? readEnvBoolean("AUREL_REDACTION_ENABLED", true),
    approvalFallback: config.approvalFallback ?? (process.env.AUREL_REWRITE_UNSUPPORTED_FALLBACK === "block" ? "block" : "approval"),
    rewriteSupported: config.rewriteSupported ?? false,
    tools: {
      include: config.tools?.include ?? readEnvList("AUREL_TOOLS_INCLUDE"),
      exclude: config.tools?.exclude ?? readEnvList("AUREL_TOOLS_EXCLUDE"),
    },
  };
}

function shouldIntercept(toolName: string, config: RequiredAurelToolGuardConfig): boolean {
  if (!config.enabled) return false;
  return config.tools.include.length === 0 || config.tools.include.includes(toolName);
}

function shouldBlockFailOpenOutage(action: AurelActionRequest, config: RequiredAurelToolGuardConfig): boolean {
  return config.failMode === "open" && config.failOpenPrivilegedActions === "block" && (
    isPrivilegedToolName(action.action.name) || containsDestructiveContent(action.action.arguments)
  );
}

function containsDestructiveContent(value: unknown): boolean {
  let serialized: string;
  try {
    serialized = JSON.stringify(value) ?? "";
  } catch {
    return true;
  }
  return /(?:rm\s+-[a-z]*r[a-z]*f|remove-item\s+.*-recurse|format\s+[a-z]:|drop\s+(?:database|table|schema)|truncate\s+table|delete\s+from|\b(?:send|transfer|pay|purchase|delete|destroy|overwrite|chmod|chown)\b)/i.test(serialized);
}

function isPrivilegedToolName(toolName: string): boolean {
  return /(?:^|[._:-])(?:bash|shell|terminal|exec|execute|process|spawn|run_command|file_write|write_file|delete_file|remove_file|patch|apply_patch|git_push|network|browser|http|fetch|email|send_email|message|database|db|sql|cloud|package|install|schedule|subagent|delegate|mcp|api|payment|finance|permission|auth|credential)(?:$|[._:-])/i.test(
    toolName
  );
}

function randomId(prefix: string): string {
  return `${prefix}_${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}_${Math.random().toString(16).slice(2)}`}`;
}

function elapsed(start: number): number {
  return Math.round(now() - start);
}

function now(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

function readNumber(value: unknown, fallback: number, min: number, max: number): number {
  const candidate = typeof value === "number" && Number.isFinite(value) ? value : fallback;
  return Math.max(min, Math.min(max, candidate));
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
    .map((item) => item.trim())
    .filter(Boolean);
}
