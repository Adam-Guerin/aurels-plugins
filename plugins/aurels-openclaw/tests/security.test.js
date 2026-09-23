import test from "node:test";
import assert from "node:assert/strict";
import { createClient, createHandlers, loadConfig, redact } from "../src/security.js";
import plugin from "../src/index.js";

const config = loadConfig({ apiUrl: "https://example.test", apiKey: "test", telemetry: false });
test("allows an allowed action", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "allow" }) });
  assert.equal(await handlers.beforeToolCall({ toolName: "read_file", toolCallId: "a" }), undefined);
});
test("evaluates an action when OpenClaw omits its optional toolCallId", async () => {
  let evaluations = 0;
  const handlers = createHandlers(config, { evaluate: async () => { evaluations += 1; return { decision: "block" }; }, telemetry: async () => {} });
  assert.equal((await handlers.beforeToolCall({ toolName: "exec", params: { command: "rm -rf /" } }))?.block, true);
  assert.equal(evaluations, 0, "local deterministic blocking remains the first boundary");
  const ambiguous = await handlers.beforeToolCall({ toolName: "send_email", params: { to: "x@example.test" } });
  assert.ok(ambiguous?.requireApproval);
});
test("evaluates an Aurels-prefixed tool instead of trusting its name", async () => {
  let evaluations = 0;
  const handlers = createHandlers(config, { evaluate: async () => { evaluations += 1; return { decision: "block" }; }, telemetry: async () => {} });
  const result = await handlers.beforeToolCall({ toolName: "aurels.exec", toolCallId: "prefix-bypass" });
  assert.equal(result?.block, true);
  assert.equal(evaluations, 1);
});
test("does not execute blocked or flagged actions", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "block" }), telemetry: async () => {} });
  assert.equal((await handlers.beforeToolCall({ toolName: "exec", toolCallId: "block" }))?.block, true);
  const flagHandlers = createHandlers(config, { evaluate: async () => ({ decision: "flag" }), telemetry: async () => {} });
  assert.ok((await flagHandlers.beforeToolCall({ toolName: "exec", toolCallId: "flag" }))?.requireApproval);
});
test("fails closed when the service is unavailable", async () => {
  const handlers = createHandlers(config, { evaluate: async () => { throw new Error("offline"); } });
  assert.ok((await handlers.beforeToolCall({ toolName: "exec", toolCallId: "failure-1" }))?.requireApproval);
  assert.ok((await handlers.beforeToolCall({ toolName: "filesystem.writeFile", toolCallId: "failure-2" }))?.requireApproval);
});
test("keeps privileged actions blocked during a fail-open outage", async () => {
  const handlers = createHandlers({ ...config }, { evaluate: async () => { throw new Error("offline"); } });
  assert.ok((await handlers.beforeToolCall({ toolName: "exec", toolCallId: "fail-open" }))?.requireApproval);
});
test("fails closed on malformed allow decisions and safely redacts cycles", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "allow", riskScore: 101 }) });
  assert.ok((await handlers.beforeToolCall({ toolName: "exec", toolCallId: "malformed" }))?.requireApproval);
});
test("adapter conformance: only allow reaches the simulated tool handler", async () => {
  for (const [decision, expectedCalls] of [["allow", 1], ["flag", 0], ["block", 0]]) {
    let calls = 0;
    const handlers = createHandlers(config, { evaluate: async () => ({ decision }), telemetry: async () => {} });
    const preflight = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: `conformance-${decision}` });
    if (!preflight?.block && !preflight?.requireApproval) calls += 1;
    assert.equal(calls, expectedCalls, `${decision} must execute ${expectedCalls} time(s)`);
  }
});
test("adapter conformance: an outage never reaches a privileged handler", async () => {
  let calls = 0;
  const handlers = createHandlers({ ...config }, { evaluate: async () => { throw new Error("offline"); } });
  const preflight = await handlers.beforeToolCall({ toolName: "filesystem.writeFile", toolCallId: "outage-privileged" });
  if (!preflight?.block && !preflight?.requireApproval) calls += 1;
  assert.equal(calls, 0);
});
test("local mode flags a benign read without an API key", async () => {
  const handlers = createHandlers(loadConfig({ apiKey: "", telemetry: false }), { evaluate: async () => { throw new Error("network must not be used"); } });
  assert.ok((await handlers.beforeToolCall({ toolName: "read_file", toolCallId: "local-flag", params: { path: "README.md" } }))?.requireApproval);
});
test("does not trust an action merely because its name sounds read-only", async () => {
  let evaluations = 0;
  const handlers = createHandlers(config, { evaluate: async () => { evaluations += 1; return { decision: "flag" }; } });
  assert.ok((await handlers.beforeToolCall({ toolName: "read.execute", toolCallId: "read-only-trust", params: { command: "send secrets" } }))?.requireApproval);
  assert.equal(evaluations, 1);
});
test("local mode blocks destructive commands without an API key", async () => {
  const handlers = createHandlers(loadConfig({ apiKey: "", telemetry: false }), { evaluate: async () => { throw new Error("network must not be used"); } });
  assert.equal((await handlers.beforeToolCall({ toolName: "exec", toolCallId: "local-block", params: { command: "rm -rf /" } }))?.block, true);
});
test("local deterministic blocks take priority over a model allow", async () => {
  let evaluations = 0;
  const handlers = createHandlers(config, { evaluate: async () => { evaluations += 1; return { decision: "allow" }; }, telemetry: async () => {} });
  const result = await handlers.beforeToolCall({ toolName: "exec", toolCallId: "local-deterministic", params: { command: "rm -rf /" } });
  assert.equal(result?.block, true);
  assert.equal(evaluations, 0);
});

test("blocks destructive commands even without toolCallId", async () => {
  const handlers = createHandlers(loadConfig({ apiKey: "", telemetry: false }), { evaluate: async () => { throw new Error("network must not be used"); } });
  const result = await handlers.beforeToolCall({ toolName: "exec", params: { command: "rm -rf /" } });
  assert.equal(result?.block, true);
});
test("only an ambiguous action reaches the model and accepts its strict decisions", async () => {
  let evaluations = 0;
  const handlers = createHandlers(config, { evaluate: async () => { evaluations += 1; return { decision: "allow" }; } });
  const result = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: "ambiguous" });
  assert.equal(result, undefined);
  assert.equal(evaluations, 1);
});
test("a model failure flags an ambiguous action without executing it", async () => {
  const handlers = createHandlers({ ...config }, { evaluate: async () => { throw new Error("timeout"); } });
  const result = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: "failure" });
  assert.ok(result?.requireApproval);
});
test("rejects non-strict model decisions", async () => {
  for (const decision of ["rewrite", "quarantine"]) {
    const handlers = createHandlers(config, { evaluate: async () => ({ decision }) });
    assert.ok((await handlers.beforeToolCall({ toolName: "send_email", toolCallId: decision }))?.requireApproval);
  }
});
test("rejects non-HTTPS API endpoints before sending an API key", () => {
  assert.throws(() => loadConfig({ apiUrl: "http://aurels.test", apiKey: "secret" }), /HTTPS/i);
});
test("bounds remote response bodies before parsing JSON", async () => {
  const client = createClient(loadConfig({ apiKey: "test", telemetry: false }), async () => ({
    ok: true,
    status: 200,
    headers: new Headers(),
    text: async () => "x".repeat(1024 * 1024 + 1)
  }));
  await assert.rejects(() => client.evaluate({ action: { id: "a" } }), /response exceeds/i);
});
test("binds evaluation idempotency keys to evaluated arguments", async () => {
  const keys = [];
  const client = createClient(loadConfig({ apiUrl: "https://example.test", apiKey: "test" }), async (_url, init) => {
    keys.push(new Headers(init.headers).get("idempotency-key"));
    return { ok: true, headers: new Headers(), text: async () => JSON.stringify({ decision: "allow" }) };
  });
  await client.evaluate({ action: { id: "same-call", name: "exec", arguments: { command: "echo safe" } } });
  await client.evaluate({ action: { id: "same-call", name: "exec", arguments: { command: "rm -rf /" } } });
  assert.notEqual(keys[0], keys[1]);
});
test("fails startup when OpenClaw only exposes the legacy hook registrar", () => {
  const api = {
    getConfig: () => ({ apiUrl: "https://example.test", apiKey: "test", telemetry: false }),
    registerHook: () => true
  };
  assert.throws(() => plugin.register(api), /before_tool_call/i);
});
test("uses the documented OpenClaw registrar even when it returns undefined", () => {
  const calls = [];
  const api = {
    getConfig: () => ({ apiUrl: "https://example.test", apiKey: "test", telemetry: false }),
    on: (...args) => { calls.push(args); }
  };
  plugin.register(api);
  assert.deepEqual(calls.map(([name]) => name), ["before_tool_call", "after_tool_call"]);
});
test("prefers api.pluginConfig over legacy config accessors", () => {
  const api = {
    pluginConfig: { apiUrl: "https://example.test", apiKey: "", mode: "local", telemetry: false },
    getConfig: () => ({ apiUrl: "https://legacy.test", apiKey: "test" }),
    on: () => {}
  };
  assert.doesNotThrow(() => plugin.register(api));
});
test("local mode with no key does not emit telemetry network calls", async () => {
  let telemetryCalls = 0;
  const handlers = createHandlers(loadConfig({ apiKey: "", mode: "local", telemetry: true }), {
    evaluate: async () => ({ decision: "allow" }),
    telemetry: async () => { telemetryCalls += 1; }
  });
  await handlers.beforeToolCall({ toolName: "read_file", toolCallId: "offline" });
  await handlers.afterToolCall({ toolName: "read_file", toolCallId: "offline", success: true });
  assert.equal(telemetryCalls, 0);
});
test("enabled=false disables post tool telemetry processing", async () => {
  let telemetryCalls = 0;
  const handlers = createHandlers(loadConfig({ enabled: false, apiKey: "test", telemetry: true }), {
    evaluate: async () => ({ decision: "allow" }),
    telemetry: async () => { telemetryCalls += 1; }
  });
  await handlers.afterToolCall({ toolName: "read_file", toolCallId: "disabled", success: true });
  assert.equal(telemetryCalls, 0);
});
test("flagged actions return requireApproval object", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "flag" }), telemetry: async () => {} });
  const result = await handlers.beforeToolCall(
    { toolName: "send_email", toolCallId: "flag-approved", params: { to: "a@example.test" } }
  );
  assert.ok(result?.requireApproval);
  assert.equal(result.requireApproval.title, "Aurels Security Review");
  assert.equal(result.requireApproval.severity, "warning");
  assert.ok(result.requireApproval.allowedDecisions.includes("allow-once"));
  assert.ok(result.requireApproval.allowedDecisions.includes("deny"));
});
test("cleans trace state after post-tool telemetry", async () => {
  const calls = [];
  const handlers = createHandlers({ ...config, telemetry: true }, {
    evaluate: async () => ({ decision: "allow", traceId: "trace-123" }),
    telemetry: async (payload) => { calls.push(payload); }
  });
  await handlers.beforeToolCall({ toolName: "read_file", toolCallId: "trace-cleanup" });
  await handlers.afterToolCall({ toolName: "read_file", toolCallId: "trace-cleanup", success: true });
  await handlers.afterToolCall({ toolName: "read_file", toolCallId: "trace-cleanup", success: true });
  assert.equal(calls[0]?.traceId, "trace-123");
  assert.equal(calls[1]?.traceId, undefined);
});
test("redacts sensitive values embedded in strings", () => {
  assert.equal(redact("Authorization: Bearer secret-token"), "[REDACTED]");
  assert.equal(redact({ command: "token=abc123" }).command, "[REDACTED]");
  assert.equal(redact("safe-value"), "safe-value");
});
test("validates and normalizes mode configuration", () => {
  assert.equal(loadConfig({ mode: "local", apiKey: "" }).mode, "local");
  assert.equal(loadConfig({ mode: "remote", apiKey: "x" }).mode, "remote");
  assert.equal(loadConfig({ apiKey: "x" }).mode, "remote");
  assert.equal(loadConfig({ apiKey: "" }).mode, "local");
  assert.throws(() => loadConfig({ mode: "invalid" }), /AURELS_MODE/);
});
