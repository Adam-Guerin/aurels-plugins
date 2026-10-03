import { createHash } from "node:crypto";

export type IntentGuardDecision = "allow" | "flag" | "block";
export type AurelDecision = "allow" | "block" | "require_approval" | "rewrite" | "quarantine";

export interface IntentGuardClientOptions {
  apiKey: string;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface AurelActionRequest {
  version: "1";
  integration: "openclaw" | "hermes" | string;
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
  auditSignature?: string;
  auditSignatureVersion?: string;
  evaluatedAt?: string;
}

export interface AurelActionTelemetry {
  version: "1";
  integration: string;
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

const MAX_AUREL_RESPONSE_BYTES = 1024 * 1024;
const MAX_AUREL_REQUEST_BYTES = 1024 * 1024;
const MAX_AUREL_STRING_CHARS = 65_536;
const MAX_AUREL_ARRAY_ITEMS = 512;
const MAX_AUREL_OBJECT_KEYS = 512;

export interface VerifyIntentInput {
  intent_id: string;
  agent_id: string;
  amount: number;
  currency: string;
  recipient: string;
  merchant_id?: string;
  agent_context?: string;
  metadata?: Record<string, unknown>;
}

export interface VerifyIntentResult {
  decision: IntentGuardDecision;
  reason: string;
  triggered_rule?: string;
  risk_score: number;
  evaluated_at: string;
  intent_id: string;
  audit_signature?: string;
  audit_signature_version?: string;
}

export interface AuditDecisionRecord {
  workspace_id: string;
  intent_id: string;
  agent_id: string;
  recipient: string;
  merchant_id: string | null;
  amount: number;
  currency: string;
  decision: string;
  triggered_rule: string | null;
  risk_score: number;
  evaluated_at: string;
}

export interface AuditVerificationResult {
  valid: boolean;
  audit_signature_version: string;
  reason?: string;
  id?: string;
  intent_id?: string;
  audit_signature?: string;
  record?: AuditDecisionRecord;
}

export interface ActionAuditRecord {
  workspace_id: string;
  action_id: string;
  integration: string;
  agent_id: string | null;
  decision: AurelDecision;
  reason: string | null;
  risk_score: number;
  rule_ids: string[];
  policy_version: string | null;
  trace_id: string | null;
  payload_hash: string;
  evaluated_at: string;
}

export class IntentGuardError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly body: unknown
  ) {
    super(message);
    this.name = "IntentGuardError";
  }
}

export class AurelTimeoutError extends Error {
  constructor(
    public readonly operation: string,
    public readonly timeoutMs: number
  ) {
    super(`Aurels ${operation} exceeded ${timeoutMs}ms`);
    this.name = "AurelTimeoutError";
  }
}

export class AurelProtocolError extends Error {
  constructor(message: string, public readonly body: unknown) {
    super(message);
    this.name = "AurelProtocolError";
  }
}

export class IntentGuardClient {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(options: IntentGuardClientOptions) {
    this.apiKey = options.apiKey;
    this.baseUrl = normalizeBaseUrl(options.baseUrl ?? "https://www.aurels.dev");
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.timeoutMs = clampTimeout(options.timeoutMs ?? 1500);
  }

  async verify(input: VerifyIntentInput): Promise<VerifyIntentResult> {
    return this.request<VerifyIntentResult>("/api/v1/verify", {
      method: "POST",
      body: stringifyAurelPayload(input),
    });
  }

  async getSettings<T = Record<string, unknown>>(): Promise<T> {
    const data = await this.request<{ settings: T }>("/api/v1/workspace/settings");
    return data.settings;
  }

  async updateSettings<T extends Record<string, unknown>>(settings: T): Promise<void> {
    await this.request<{ success: boolean }>("/api/v1/workspace/settings", {
      method: "PATCH",
      body: stringifyAurelPayload(settings),
    });
  }

  async exportAuditLogs(format: "json" | "csv" = "json", limit = 500): Promise<unknown> {
    const path = `/api/v1/workspace/audit-export?format=${encodeURIComponent(format)}&limit=${limit}`;
    if (format === "csv") return this.requestText(path);
    return this.request(path);
  }

  async evaluateAction(input: AurelActionRequest, signal?: AbortSignal): Promise<AurelSecurityDecision> {
    const serializedInput = stringifyExactAurelPayload(input);
    const serializedAction = JSON.stringify(toExactJsonValue(input.action, new WeakSet<object>(), 0));
    const result = await this.request<AurelSecurityDecision>(
      "/api/v1/actions/evaluate",
      {
        method: "POST",
        headers: {
          "idempotency-key": idempotencyKey("action-evaluate", input.action.id, fingerprint(serializedAction)),
        },
        body: serializedInput,
      },
      { signal, operation: "action evaluation" }
    );
    return normalizeAurelDecision(result);
  }

  async recordActionTelemetry(input: AurelActionTelemetry, signal?: AbortSignal): Promise<void> {
    await retryTelemetry(async () => {
      await this.request<{ accepted: boolean }>(
        "/api/v1/actions/telemetry",
        {
          method: "POST",
          headers: {
            "idempotency-key": idempotencyKey("action-telemetry", input.actionId, input.outcome.status, fingerprint(stringifyAurelPayload(input))),
          },
          body: stringifyAurelPayload(input),
        },
        { signal, operation: "action telemetry" }
      );
    });
  }

  async verifyStoredAuditLog(params: { intent_id?: string; id?: string }): Promise<AuditVerificationResult> {
    const search = new URLSearchParams();
    if (params.intent_id) search.set("intent_id", params.intent_id);
    if (params.id) search.set("id", params.id);
    return this.request<AuditVerificationResult>(`/api/v1/workspace/audit-verify?${search.toString()}`);
  }

  async verifyAuditRecord(input: {
    record: AuditDecisionRecord;
    audit_signature: string;
    audit_signature_version?: string;
  }): Promise<AuditVerificationResult> {
    return this.request<AuditVerificationResult>("/api/v1/audit/verify", {
      method: "POST",
      body: stringifyAurelPayload(input),
    });
  }

  async exportActionAuditLogs(format: "json" | "csv" = "json", limit = 500): Promise<unknown> {
    const path = `/api/v1/workspace/action-audit-export?format=${encodeURIComponent(format)}&limit=${limit}`;
    if (format === "csv") return this.requestText(path);
    return this.request(path);
  }

  async verifyActionAuditRecord(input: {
    record: ActionAuditRecord;
    audit_signature: string;
    audit_signature_version?: string;
  }): Promise<AuditVerificationResult> {
    return this.request<AuditVerificationResult>("/api/v1/audit/action-verify", {
      method: "POST",
      body: stringifyAurelPayload(input),
    });
  }

  private async request<T>(
    path: string,
    init: RequestInit = {},
    options: { signal?: AbortSignal; operation?: string } = {}
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutError = new AurelTimeoutError(options.operation ?? path, this.timeoutMs);
    let timeout: ReturnType<typeof setTimeout>;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        controller.abort(timeoutError);
        reject(timeoutError);
      }, this.timeoutMs);
    });
    const cleanup = linkAbortSignals(controller, options.signal);

    try {
      const res = await Promise.race([
        this.fetchImpl(`${this.baseUrl}${path}`, {
          ...init,
          redirect: "error",
          signal: controller.signal,
          headers: {
            "Content-Type": "application/json",
            "x-api-key": this.apiKey,
            ...init.headers,
          },
        }),
        timeoutPromise,
      ]);
      const body = await readJsonResponse(res, timeoutPromise);
      if (!res.ok) {
        const message =
          body && typeof body === "object" && "error" in body && typeof body.error === "string"
            ? body.error
            : `IntentGuard request failed with HTTP ${res.status}`;
        throw new IntentGuardError(message, res.status, body);
      }
      return body as T;
    } catch (error) {
      if (controller.signal.aborted) {
        throw controller.signal.reason instanceof Error
          ? controller.signal.reason
          : new AurelTimeoutError(options.operation ?? path, this.timeoutMs);
      }
      throw error;
    } finally {
      clearTimeout(timeout!);
      cleanup();
    }
  }

  private async requestText(path: string): Promise<string> {
    const controller = new AbortController();
    const timeoutError = new AurelTimeoutError(path, this.timeoutMs);
    let timeout: ReturnType<typeof setTimeout>;
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeout = setTimeout(() => {
        controller.abort(timeoutError);
        reject(timeoutError);
      }, this.timeoutMs);
    });
    try {
      const res = await Promise.race([
        this.fetchImpl(`${this.baseUrl}${path}`, {
          redirect: "error",
          signal: controller.signal,
          headers: { "x-api-key": this.apiKey },
        }),
        timeoutPromise,
      ]);
      const body = await Promise.race([res.text(), timeoutPromise]);
      if (!res.ok) throw new IntentGuardError(body || `HTTP ${res.status}`, res.status, body);
      return body;
    } catch (error) {
      if (controller.signal.aborted) {
        throw controller.signal.reason instanceof Error ? controller.signal.reason : timeoutError;
      }
      throw error;
    } finally {
      clearTimeout(timeout!);
    }
  }
}

export function createIntentGuardClient(options: IntentGuardClientOptions): IntentGuardClient {
  return new IntentGuardClient(options);
}

export function createAurelClient(options: IntentGuardClientOptions): IntentGuardClient {
  return new IntentGuardClient(options);
}

/** The public Aurels SDK factory. */
export function createAurelsClient(options: IntentGuardClientOptions): IntentGuardClient {
  return new IntentGuardClient(options);
}

export function normalizeAurelDecision(body: AurelSecurityDecision): AurelSecurityDecision {
  if (!body || typeof body !== "object") {
    throw new AurelProtocolError("Aurels returned a non-object decision", body);
  }
  const decision = (body as { decision?: unknown }).decision;
  const normalized = decision === "flag" ? ({ ...body, decision: "require_approval" } as AurelSecurityDecision) : body;
  const normalizedDecision = (normalized as { decision?: unknown }).decision;
  validateDecisionMetadata(normalized);
  if (
    normalizedDecision !== "allow" &&
    normalizedDecision !== "block" &&
    normalizedDecision !== "require_approval" &&
    normalizedDecision !== "rewrite" &&
    normalizedDecision !== "quarantine"
  ) {
    throw new AurelProtocolError("Aurels returned an unsupported decision", body);
  }
  if (normalizedDecision === "rewrite" && normalized.rewrittenArguments === undefined) {
    throw new AurelProtocolError("Aurels returned a rewrite without replacement arguments", body);
  }
  return normalized;
}

function stringifyAurelPayload(value: unknown): string {
  const serialized = JSON.stringify(toSerializable(value, new WeakSet<object>(), 0));
  if (new TextEncoder().encode(serialized).length <= MAX_AUREL_REQUEST_BYTES) return serialized;
  const bounded = boundActionArguments(value);
  const fallback = JSON.stringify(toSerializable(bounded, new WeakSet<object>(), 0));
  if (new TextEncoder().encode(fallback).length <= MAX_AUREL_REQUEST_BYTES) return fallback;
  throw new AurelProtocolError("Aurels request payload exceeded maximum size", null);
}

function stringifyExactAurelPayload(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new AurelProtocolError("Aurels action payload is not losslessly JSON-serializable", null);
  }
  const envelope = toSerializable(value, new WeakSet<object>(), 0) as Record<string, unknown>;
  const action = (value as Record<string, unknown>).action;
  if (!action || typeof action !== "object") {
    throw new AurelProtocolError("Aurels action payload is missing its action envelope", null);
  }
  envelope.action = toExactJsonValue(action, new WeakSet<object>(), 0);
  const serialized = JSON.stringify(envelope);
  if (new TextEncoder().encode(serialized).length > MAX_AUREL_REQUEST_BYTES) {
    throw new AurelProtocolError("Aurels action payload exceeded maximum size; exact arguments were not evaluated", null);
  }
  return serialized;
}

function toExactJsonValue(value: unknown, ancestors: WeakSet<object>, depth: number): unknown {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "object" || depth > 64) {
    throw new AurelProtocolError("Aurels action arguments are not losslessly JSON-serializable", null);
  }
  if (ancestors.has(value)) throw new AurelProtocolError("Aurels action arguments contain a cycle", null);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const output: unknown[] = [];
      for (let index = 0; index < value.length; index += 1) {
        if (!Object.hasOwn(value, index)) throw new AurelProtocolError("Aurels action arguments contain a sparse array", null);
        output.push(toExactJsonValue(value[index], ancestors, depth + 1));
      }
      return output;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new AurelProtocolError("Aurels action arguments contain a non-JSON object", null);
    }
    const output: Record<string, unknown> = Object.create(null);
    for (const key of Reflect.ownKeys(value)) {
      if (typeof key !== "string") throw new AurelProtocolError("Aurels action arguments contain a non-JSON key", null);
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new AurelProtocolError("Aurels action arguments contain a non-JSON property", null);
      }
      output[key] = toExactJsonValue(descriptor.value, ancestors, depth + 1);
    }
    return output;
  } catch (error) {
    if (error instanceof AurelProtocolError) throw error;
    throw new AurelProtocolError("Aurels action arguments are not losslessly JSON-serializable", null);
  } finally {
    ancestors.delete(value);
  }
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
    throw new AurelProtocolError("Aurels response exceeded maximum size", null);
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
      throw new AurelProtocolError("Aurels response exceeded maximum size", null);
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
        throw new AurelProtocolError("Aurels response exceeded maximum size", null);
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

function validateDecisionMetadata(body: AurelSecurityDecision): void {
  if (body.riskScore !== undefined && (!Number.isFinite(body.riskScore) || body.riskScore < 0 || body.riskScore > 100)) {
    throw new AurelProtocolError("Aurels returned an invalid risk score", body);
  }
  for (const field of ["reason", "category", "traceId", "policyVersion"] as const) {
    const value = body[field];
    if (value !== undefined && (typeof value !== "string" || value.length > 4096)) {
      throw new AurelProtocolError(`Aurels returned an invalid ${field}`, body);
    }
  }
  if (body.ruleIds !== undefined) {
    if (!Array.isArray(body.ruleIds) || body.ruleIds.length > 128 || body.ruleIds.some((ruleId) => typeof ruleId !== "string" || ruleId.length > 512)) {
      throw new AurelProtocolError("Aurels returned invalid rule IDs", body);
    }
  }
}

function linkAbortSignals(controller: AbortController, upstream?: AbortSignal): () => void {
  if (!upstream) return () => undefined;
  if (upstream.aborted) {
    controller.abort(upstream.reason);
    return () => undefined;
  }
  const onAbort = () => controller.abort(upstream.reason);
  upstream.addEventListener("abort", onAbort, { once: true });
  return () => upstream.removeEventListener("abort", onAbort);
}

async function retryTelemetry(fn: () => Promise<void>): Promise<void> {
  const delays = [50, 150, 350];
  let lastError: unknown;
  for (let attempt = 0; attempt < delays.length; attempt += 1) {
    try {
      await fn();
      return;
    } catch (error) {
      lastError = error;
      if (attempt < delays.length - 1) {
        await new Promise((resolve) => setTimeout(resolve, delays[attempt]));
      }
    }
  }
  throw lastError;
}

function normalizeBaseUrl(value: string): string {
  const url = new URL(value);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new IntentGuardError("Aurels API URL must use http or https", 0, null);
  }
  if (url.username || url.password) {
    throw new IntentGuardError("Aurels API URL must not contain credentials", 0, null);
  }
  url.hash = "";
  url.search = "";
  return url.toString().replace(/\/+$/, "");
}

function clampTimeout(value: number): number {
  if (!Number.isFinite(value)) return 1500;
  return Math.max(100, Math.min(30_000, value));
}

function idempotencyKey(prefix: string, ...parts: string[]): string {
  return [prefix, ...parts.map((part) => encodeURIComponent(part).slice(0, 256))].join(":");
}

function fingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
