const SENSITIVE_KEY_PATTERN =
  /(?:password|passwd|secret|token|api[_-]?key|apikey|authorization|cookie|session|private[_-]?key|credential|access[_-]?token|refresh[_-]?token)/i;

export interface RedactionOptions {
  enabled?: boolean;
  maxDepth?: number;
  maxArrayItems?: number;
  maxStringLength?: number;
  maxBytes?: number;
}

const DEFAULTS: Required<RedactionOptions> = {
  enabled: true,
  maxDepth: 8,
  maxArrayItems: 50,
  maxStringLength: 4096,
  maxBytes: 32_768,
};

export function redactForTelemetry(value: unknown, options: RedactionOptions = {}): unknown {
  const config = { ...DEFAULTS, ...options };
  if (!config.enabled) return boundValue(value, config);

  const seen = new WeakSet<object>();
  return boundValue(redactValue(value, config, seen, 0), config);
}

function redactValue(
  value: unknown,
  config: Required<RedactionOptions>,
  seen: WeakSet<object>,
  depth: number
): unknown {
  if (value === null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "string") return redactSensitiveText(truncateControlSafe(value, config.maxStringLength));
  if (typeof value === "undefined") return null;
  if (typeof value === "function" || typeof value === "symbol") return `[${typeof value}]`;

  if (depth >= config.maxDepth) return "[MaxDepth]";
  if (seen.has(value)) return "[Circular]";
  seen.add(value);

  if (Array.isArray(value)) {
    try {
      return value
        .slice(0, config.maxArrayItems)
        .map((entry) => redactValue(entry, config, seen, depth + 1));
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
      const safeKey = truncateControlSafe(key, 256);
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
      out[safeKey] = redactValue(entry, config, seen, depth + 1);
    }
    return out;
  } finally {
    seen.delete(value);
  }
}

function boundValue(value: unknown, config: Required<RedactionOptions>): unknown {
  const json = safeStringify(value);
  if (byteLength(json) <= config.maxBytes) return value;
  return {
    truncated: true,
    reason: "payload_limit",
    original_bytes: byteLength(json),
    preview: truncateControlSafe(json, Math.min(config.maxStringLength, config.maxBytes)),
  };
}

export function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? "null";
  } catch {
    return JSON.stringify(redactForTelemetry(value, { maxDepth: 4, maxBytes: 4096 })) ?? "null";
  }
}

function truncateControlSafe(value: string, maxLength: number): string {
  const sanitized = value.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "\uFFFD");
  return sanitized.length > maxLength ? `${sanitized.slice(0, maxLength)}...[truncated]` : sanitized;
}

function redactSensitiveText(value: string): string {
  return value
    .replace(/\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\b(?:sk-(?:ant|proj)-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]");
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).length;
}
