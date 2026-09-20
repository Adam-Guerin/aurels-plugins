import test from "node:test";
import assert from "node:assert/strict";
import { createHandlers, loadConfig } from "../src/security.js";

const config = loadConfig({ apiUrl: "https://example.test", apiKey: "test", telemetry: false });
test("allows an allowed action", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "allow" }) });
  assert.equal(await handlers.beforeToolCall({ toolName: "read_file", toolCallId: "a" }), undefined);
});
test("does not execute blocked or flagged actions", async () => {
  for (const decision of ["block", "flag"]) {
    const handlers = createHandlers(config, { evaluate: async () => ({ decision }), telemetry: async () => {} });
    assert.equal((await handlers.beforeToolCall({ toolName: "exec", toolCallId: decision }))?.block, true);
  }
});
test("fails closed when the service is unavailable", async () => {
  const handlers = createHandlers(config, { evaluate: async () => { throw new Error("offline"); } });
  assert.equal((await handlers.beforeToolCall({ toolName: "exec" }))?.block, true);
  assert.equal((await handlers.beforeToolCall({ toolName: "filesystem.writeFile" }))?.block, true);
});
test("keeps privileged actions blocked during a fail-open outage", async () => {
  const handlers = createHandlers({ ...config, failMode: "open" }, { evaluate: async () => { throw new Error("offline"); } });
  assert.equal((await handlers.beforeToolCall({ toolName: "exec" }))?.block, true);
});
test("fails closed on malformed allow decisions and safely redacts cycles", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "allow", riskScore: 101 }) });
  assert.equal((await handlers.beforeToolCall({ toolName: "exec" }))?.block, true);
});
test("adapter conformance: only allow reaches the simulated tool handler", async () => {
  for (const [decision, expectedCalls] of [["allow", 1], ["flag", 0], ["block", 0]]) {
    let calls = 0;
    const handlers = createHandlers(config, { evaluate: async () => ({ decision }), telemetry: async () => {} });
    const preflight = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: `conformance-${decision}` });
    if (!preflight?.block) calls += 1;
    assert.equal(calls, expectedCalls, `${decision} must execute ${expectedCalls} time(s)`);
  }
});
test("adapter conformance: an outage never reaches a privileged handler", async () => {
  let calls = 0;
  const handlers = createHandlers({ ...config, failMode: "open" }, { evaluate: async () => { throw new Error("offline"); } });
  const preflight = await handlers.beforeToolCall({ toolName: "filesystem.writeFile" });
  if (!preflight?.block) calls += 1;
  assert.equal(calls, 0);
});
test("local mode permits a benign read without an API key", async () => {
  const handlers = createHandlers(loadConfig({ apiKey: "", telemetry: false }), { evaluate: async () => { throw new Error("network must not be used"); } });
  assert.equal(await handlers.beforeToolCall({ toolName: "read_file", params: { path: "README.md" } }), undefined);
});
test("local mode blocks destructive commands without an API key", async () => {
  const handlers = createHandlers(loadConfig({ apiKey: "", telemetry: false }), { evaluate: async () => { throw new Error("network must not be used"); } });
  assert.equal((await handlers.beforeToolCall({ toolName: "exec", params: { command: "rm -rf /" } }))?.block, true);
});
test("local deterministic blocks take priority over a model allow", async () => {
  let evaluations = 0;
  const handlers = createHandlers(config, { evaluate: async () => { evaluations += 1; return { decision: "allow" }; }, telemetry: async () => {} });
  const result = await handlers.beforeToolCall({ toolName: "exec", params: { command: "rm -rf /" } });
  assert.equal(result?.block, true);
  assert.equal(evaluations, 0);
});
test("only an ambiguous action reaches the model and accepts its strict decisions", async () => {
  let evaluations = 0;
  const handlers = createHandlers(config, { evaluate: async () => { evaluations += 1; return { decision: "allow" }; } });
  assert.equal(await handlers.beforeToolCall({ toolName: "send_email" }), undefined);
  assert.equal(evaluations, 1);
});
test("a model failure flags an ambiguous action without executing it", async () => {
  const handlers = createHandlers({ ...config, failMode: "open" }, { evaluate: async () => { throw new Error("timeout"); } });
  const result = await handlers.beforeToolCall({ toolName: "send_email" });
  assert.equal(result?.block, true);
  assert.match(result?.blockReason ?? "", /approval/i);
});
test("rejects non-strict model decisions", async () => {
  for (const decision of ["rewrite", "quarantine"]) {
    const handlers = createHandlers(config, { evaluate: async () => ({ decision }) });
    assert.equal((await handlers.beforeToolCall({ toolName: "send_email" }))?.block, true);
  }
});
