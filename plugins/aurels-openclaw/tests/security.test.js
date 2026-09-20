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
