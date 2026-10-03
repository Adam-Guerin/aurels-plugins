import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { mkdtemp, readFile, readdir, rm, utimes, writeFile } from "node:fs/promises";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { AurelsRateLimitError, createClient, createHandlers, loadConfig, redact } from "../src/security.js";
import { MAX_OUTBOX_BYTES, TelemetryOutbox } from "../src/telemetry-outbox.js";
import plugin from "../src/index.js";

const config = loadConfig({ apiUrl: "https://example.test", apiKey: "test", telemetry: false });
const redactionCorpus = JSON.parse(readFileSync(new URL("../../aurels-integrations/tests/fixtures/redaction-corpus.json", import.meta.url), "utf8"));

test("self-hosted evaluator endpoints allow loopback HTTP while public plaintext remains refused", () => {
  for (const apiUrl of ["http://127.0.0.1:8788", "http://localhost:8788", "http://[::1]:8788"]) {
    assert.equal(loadConfig({ apiUrl, apiKey: "local-access-token" }).apiUrl, apiUrl);
  }
  for (const apiUrl of ["http://localhost.evil.test:8788", "http://192.168.1.2:8788", "http://user:secret@127.0.0.1:8788"]) {
    assert.throws(() => loadConfig({ apiUrl, apiKey: "local-access-token" }));
  }
});

test("durable telemetry expires stale local events without sending them", async () => {
  const spoolDir = await mkdtemp(join(tmpdir(), "aurels-openclaw-expiry-"));
  try {
    const outbox = new TelemetryOutbox(spoolDir);
    const path = await outbox.enqueue({ actionId: "expired-event" });
    const expiredAt = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000);
    await utimes(path, expiredAt, expiredAt);
    const sent = [];
    assert.equal(await outbox.flush(async (event) => sent.push(event)), 0);
    assert.deepEqual(sent, []);
    assert.deepEqual((await readdir(spoolDir)).filter((name) => name.endsWith(".json")), []);
  } finally {
    await rm(spoolDir, { recursive: true, force: true });
  }
});

test("durable telemetry prunes abandoned staging files but preserves recent writers", async () => {
  const spoolDir = await mkdtemp(join(tmpdir(), "aurels-openclaw-stale-temp-"));
  try {
    const abandoned = join(spoolDir, ".pending-crashed.tmp");
    const active = join(spoolDir, ".pending-active.tmp");
    await writeFile(abandoned, "interrupted event", "utf8");
    await writeFile(active, "active writer", "utf8");
    const staleAt = new Date(Date.now() - 25 * 60 * 60 * 1000);
    await utimes(abandoned, staleAt, staleAt);
    const outbox = new TelemetryOutbox(spoolDir);
    await outbox.enqueue({ actionId: "new-event" });
    const remaining = await readdir(spoolDir);
    assert.equal(remaining.includes(".pending-crashed.tmp"), false);
    assert.equal(remaining.includes(".pending-active.tmp"), true);
  } finally {
    await rm(spoolDir, { recursive: true, force: true });
  }
});

test("durable telemetry enforces the queue cap across concurrent outbox instances", async () => {
  const spoolDir = await mkdtemp(join(tmpdir(), "aurels-openclaw-concurrent-cap-"));
  try {
    const events = Array.from({ length: 16 }, (_, index) => ({ actionId: `concurrent-${index}` }));
    const eventBytes = Math.max(...events.map((event) => Buffer.byteLength(JSON.stringify(event), "utf8")));
    const fixtureBytes = MAX_OUTBOX_BYTES - 5 * eventBytes;
    await writeFile(join(spoolDir, "occupier.json"), Buffer.alloc(fixtureBytes, 0x78));
    const results = await Promise.allSettled(events.map((event) => new TelemetryOutbox(spoolDir).enqueue(event)));
    const accepted = results.filter((result) => result.status === "fulfilled");
    const queued = (await readdir(spoolDir)).filter((name) => name.endsWith(".json"));
    const totalBytes = (await Promise.all(queued.map(async (name) => (await readFile(join(spoolDir, name))).byteLength)))
      .reduce((sum, size) => sum + size, 0);
    assert.ok(accepted.length <= 5, `only five maximum-sized events fit, but ${accepted.length} were accepted`);
    assert.ok(totalBytes <= MAX_OUTBOX_BYTES, `queue byte cap exceeded with ${totalBytes} bytes`);
  } finally {
    await rm(spoolDir, { recursive: true, force: true });
  }
});

test("durable telemetry does not remove a replacement lock after a stale PID race", async () => {
  const spoolDir = await mkdtemp(join(tmpdir(), "aurels-openclaw-lock-replacement-"));
  const lockPath = join(spoolDir, ".enqueue.lock");
  const deadPid = 2_000_000_000;
  const originalKill = process.kill;
  await writeFile(lockPath, String(deadPid), "utf8");
  process.kill = (pid, signal) => {
    if (pid !== deadPid || signal !== 0) return originalKill(pid, signal);
    unlinkSync(lockPath);
    writeFileSync(lockPath, String(process.pid), "utf8");
    const error = new Error("simulated dead owner");
    error.code = "ESRCH";
    throw error;
  };

  try {
    await assert.rejects(
      new TelemetryOutbox(spoolDir).enqueue({ actionId: "must-not-steal-lock" }),
      /Telemetry queue is busy/,
    );
    assert.equal(await readFile(lockPath, "utf8"), String(process.pid));
  } finally {
    process.kill = originalKill;
    await rm(spoolDir, { recursive: true, force: true });
  }
});

test("durable telemetry retries a queued event after a temporary network outage", async () => {
  const spoolDir = await mkdtemp(join(tmpdir(), "aurels-openclaw-retry-"));
  try {
    const outbox = new TelemetryOutbox(spoolDir);
    await outbox.enqueue({ actionId: "retry-after-outage" });
    let online = false;
    const received = [];
    const sender = async (event) => {
      if (!online) throw new Error("network offline");
      received.push(event);
    };
    await outbox.flush(sender);
    online = true;
    for (let index = 0; index < 400 && received.length === 0; index += 1) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.deepEqual(received, [{ actionId: "retry-after-outage" }]);
    assert.deepEqual((await readdir(spoolDir)).filter((name) => name.endsWith(".json")), []);
  } finally {
    await rm(spoolDir, { recursive: true, force: true });
  }
});

test("durable telemetry persists a redacted blocked event before the hook returns", async () => {
  const spoolDir = await mkdtemp(join(tmpdir(), "aurels-openclaw-outbox-"));
  try {
    const durableConfig = loadConfig({
      apiUrl: "https://example.test", apiKey: "test", telemetry: true,
      telemetryDurable: true, telemetrySpoolDir: spoolDir,
    });
    const handlers = createHandlers(durableConfig, {
      evaluate: async () => ({ decision: "block" }),
      telemetry: async () => { throw new Error("network offline"); },
    });
    const result = await handlers.beforeToolCall({
      toolName: "send_email", toolCallId: "durable-blocked-call",
      params: { to: "person@example.test", api_key: "secret-value", content: "OpenAI key sk-proj-" + "C".repeat(32) },
    });
    assert.equal(result.block, true);
    const files = (await readdir(spoolDir)).filter((name) => name.endsWith(".json"));
    assert.equal(files.length, 1, "blocked event must be durable before hook returns");
    const event = JSON.parse(await readFile(join(spoolDir, files[0]), "utf8"));
    assert.equal(event.metadata.params.api_key, "[REDACTED]");
    assert.equal(event.metadata.params.content, "[REDACTED]");
  } finally {
    await rm(spoolDir, { recursive: true, force: true });
  }
});

test("durable telemetry replays pending events after a handler restart and removes them only after success", async () => {
  const spoolDir = await mkdtemp(join(tmpdir(), "aurels-openclaw-replay-"));
  try {
    const durableConfig = loadConfig({
      apiUrl: "https://example.test", apiKey: "test", telemetry: true,
      telemetryDurable: true, telemetrySpoolDir: spoolDir,
    });
    let finishOffline;
    const offlineAttempted = new Promise((resolve) => { finishOffline = resolve; });
    const first = createHandlers(durableConfig, {
      evaluate: async () => ({ decision: "block" }),
      telemetry: async () => { finishOffline(); throw new Error("network offline"); },
    });
    await first.beforeToolCall({ toolName: "send_email", toolCallId: "replay-call", params: { to: "person@example.test" } });
    await offlineAttempted;
    for (let index = 0; index < 100 && (await readdir(spoolDir)).some((name) => name.endsWith(".tmp")); index += 1) await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal((await readdir(spoolDir)).filter((name) => name.endsWith(".json")).length, 1);

    let finishOnline;
    const delivered = new Promise((resolve) => { finishOnline = resolve; });
    const received = [];
    createHandlers(durableConfig, {
      evaluate: async () => ({ decision: "allow" }),
      telemetry: async (event) => { received.push(event); finishOnline(); return { accepted: true }; },
    });
    await delivered;
    for (let index = 0; index < 100 && (await readdir(spoolDir)).some((name) => name.endsWith(".json")); index += 1) await new Promise((resolve) => setTimeout(resolve, 5));
    assert.equal(received.length, 1);
    assert.equal(received[0].actionId, "replay-call");
    assert.deepEqual((await readdir(spoolDir)).filter((name) => name.endsWith(".json")), []);
  } finally {
    await rm(spoolDir, { recursive: true, force: true });
  }
});

async function loadOpenClawHookRuntime(openclawRoot, { resolve, pathToFileURL }) {
  const sdkDirectory = resolve(openclawRoot, "dist/plugin-sdk");
  const candidates = [
    resolve(sdkDirectory, "plugin-runtime.js"),
    resolve(sdkDirectory, "hook-runtime.js"),
    resolve(openclawRoot, "dist/plugins/hook-runner-global.js"),
  ];
  for (const name of await readdir(sdkDirectory)) {
    if (!/\.m?js$/i.test(name)) continue;
    const candidate = resolve(sdkDirectory, name);
    let source;
    try { source = await readFile(candidate, "utf8"); } catch { continue; }
    if (source.includes("function initializeGlobalHookRunner") && source.includes("function getGlobalHookRunner")) {
      candidates.push(candidate);
    }
  }
  for (const candidate of candidates) {
    try {
      const runtime = await import(pathToFileURL(candidate));
      if (typeof runtime.initializeGlobalHookRunner === "function" && typeof runtime.getGlobalHookRunner === "function") return runtime;
      if (typeof runtime.A === "function" && typeof runtime.k === "function") {
        return {
          initializeGlobalHookRunner: runtime.A,
          getGlobalHookRunner: runtime.k,
          resetGlobalHookRunner: () => runtime.A({ hooks: [], typedHooks: [] }),
        };
      }
    } catch (error) {
      if (candidate === candidates.at(-1)) throw error;
    }
  }
  throw new Error(`No OpenClaw hook runner implementation found under ${sdkDirectory}`);
}

test("allows an allowed action", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "allow" }) });
  const result = await handlers.beforeToolCall({ toolName: "read_file", toolCallId: "a", params: { path: "README.md" } });
  assert.deepEqual(result.params, { path: "README.md" });
  assert.deepEqual(result.requireApproval.allowedDecisions, ["allow-once", "deny"]);
});
test("local retrospective reviews only bounded redacted tool actions through the host model", async () => {
  const localConfig = loadConfig({ mode: "local", apiKey: "", telemetry: false, retrospectiveEnabled: true });
  const completions = [];
  const logs = [];
  const clientCalls = [];
  const handlers = createHandlers(localConfig, {
    evaluate: async (...args) => { clientCalls.push(["evaluate", ...args]); },
    telemetry: async (...args) => { clientCalls.push(["telemetry", ...args]); },
  }, {
    llmComplete: async (request) => {
      completions.push(request);
      return { text: JSON.stringify({ assessment: "mixed", rationale: "The result should be checked.", suggestion: "Verify the output." }) };
    },
    logger: { info: (message) => logs.push(message), warn: (message) => logs.push(message) },
  });

  await handlers.afterToolCall({
    toolName: "exec",
    toolCallId: "retrospective-call",
    params: { command: "cat notes.txt", apiKey: "sk-proj-test-secret-value" },
    success: true,
    result: { content: [{ text: "private tool output" }] },
  }, { agentId: "main", sessionId: "session-retro", sessionKey: "agent:main:session-retro" });
  await handlers.agentEnd({ success: true }, { agentId: "main", sessionId: "session-retro", sessionKey: "agent:main:session-retro" });

  assert.equal(completions.length, 1);
  assert.equal(completions[0].purpose, "aurels.retrospective");
  assert.equal(completions[0].agentId, "main");
  assert.match(completions[0].messages[0].content, /cat notes\.txt/);
  assert.doesNotMatch(completions[0].messages[0].content, /sk-proj-test-secret-value|private tool output/);
  assert.equal(clientCalls.length, 0, "local retrospective must not call the Aurels API");
  assert.match(logs.join("\n"), /mixed/);
});

test("local retrospective bounds argument traversal before serializing hostile-width inputs", async () => {
  const localConfig = loadConfig({ mode: "local", apiKey: "", telemetry: false, retrospectiveEnabled: true });
  const completions = [];
  const handlers = createHandlers(localConfig, { evaluate: async () => ({ decision: "allow" }) }, {
    llmComplete: async (request) => { completions.push(request); return { text: "{\"assessment\":\"uncertain\",\"rationale\":\"bounded\",\"suggestion\":\"none\"}" }; }
  });
  const params = Object.fromEntries(Array.from({ length: 10_000 }, (_, index) => [`field${index}`, "x".repeat(1000)]));
  await handlers.afterToolCall({ toolName: "inspect", toolCallId: "wide-input-call", params, success: true }, { sessionId: "wide-input" });
  await handlers.agentEnd({ success: true }, { sessionId: "wide-input" });
  const payload = JSON.parse(completions[0].messages[0].content);
  assert.ok(payload.toolActions[0].arguments.length <= 4000);
  assert.deepEqual(JSON.parse(payload.toolActions[0].arguments)["[Truncated]"], true, "projection must mark omitted source fields before stringification");
});
test("evaluates an action when OpenClaw omits its optional toolCallId", async () => {
  let evaluations = 0;
  const handlers = createHandlers(config, { evaluate: async () => { evaluations += 1; return { decision: "block" }; }, telemetry: async () => {} });
  assert.equal((await handlers.beforeToolCall({ toolName: "exec", params: { command: "rm -rf /" } }))?.block, true);
  assert.equal(evaluations, 0, "local deterministic blocking remains the first boundary");
  const ambiguous = await handlers.beforeToolCall({ toolName: "send_email", params: { to: "x@example.test" } });
  assert.equal(ambiguous?.block, true);
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

test("fails closed when an unexpected hook error occurs before evaluation", async () => {
  const config = loadConfig({ mode: "local", apiKey: "", telemetry: false });
  const handler = createHandlers(config, {});
  const params = Object.defineProperty({}, "command", { enumerable: true, get() { throw new Error("malformed host params"); } });
  const result = await handler.beforeToolCall({ toolName: "exec", params });
  assert.ok(result?.block || result?.requireApproval);
  assert.notEqual(result?.decision, "allow");
});
test("keeps privileged actions blocked during a fail-open outage", async () => {
  const handlers = createHandlers({ ...config }, { evaluate: async () => { throw new Error("offline"); } });
  assert.ok((await handlers.beforeToolCall({ toolName: "exec", toolCallId: "fail-open" }))?.requireApproval);
});
test("fails closed on malformed allow decisions and safely redacts cycles", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "allow", riskScore: 101 }) });
  assert.ok((await handlers.beforeToolCall({ toolName: "exec", toolCallId: "malformed" }))?.requireApproval);
});
test("adapter conformance: allow requires one-shot approval before the frozen action reaches the handler", async () => {
  for (const [decision, expectedCalls] of [["allow", 1], ["flag", 0], ["block", 0]]) {
    let calls = 0;
    const handlers = createHandlers(config, { evaluate: async () => ({ decision }), telemetry: async () => {} });
    const params = { to: "recipient@example.test", body: "synthetic" };
    const preflight = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: `conformance-${decision}`, params });
    if (preflight?.requireApproval && decision === "allow") {
      const approvedDecision = "allow-once";
      if (approvedDecision === "allow-once") calls += 1;
      assert.deepEqual(preflight.params, params);
    } else if (!preflight?.block && !preflight?.requireApproval) calls += 1;
    assert.equal(calls, expectedCalls, `${decision} must execute ${expectedCalls} time(s)`);
  }
});

test("documents the OpenClaw hook TOCTOU boundary when a later plugin replaces params", async () => {
  const evaluated = [];
  const aurels = createHandlers(config, { evaluate: async (action) => { evaluated.push(action); return { decision: "allow" }; } });
  const initial = { command: "echo safe" };
  const aurelsResult = await aurels.beforeToolCall({ toolName: "exec", toolCallId: "mutated-params", params: initial });
  assert.deepEqual(aurelsResult.params, initial);
  assert.ok(aurelsResult.requireApproval);

  // OpenClaw freezes the accumulated parameter snapshot when the first approval
  // is requested, so later handlers may block but cannot replace the approved data.
  const laterPluginResult = { params: { command: "rm -rf /" } };
  const aurelsApproval = { ...aurelsResult.requireApproval, pluginId: "aurels" };
  const accumulated = { ...aurelsResult, requireApproval: aurelsApproval };
  const finalDispatchParams = accumulated.requireApproval.pluginId !== "mutator"
    ? accumulated.params
    : laterPluginResult.params;
  assert.deepEqual(evaluated[0].action.arguments, { command: "echo safe" });
  assert.deepEqual(finalDispatchParams, { command: "echo safe" });
  assert.notDeepEqual(laterPluginResult.params, finalDispatchParams);
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
  assert.equal((await handlers.beforeToolCall({ toolName: "read.execute", toolCallId: "read-only-trust", params: { command: "send secrets" } }))?.block, true);
  assert.equal(evaluations, 0);
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
test("offline scanner finds destructive text in nested arbitrary argument fields", async () => {
  const handlers = createHandlers(loadConfig({ apiKey: "", telemetry: false }), { evaluate: async () => { throw new Error("network must not be used"); } });
  for (const [toolName, params] of [
    ["write_file", { content: "drop table customers" }],
    ["task", { payload: { body: "chmod 777 /srv/app" } }],
    ["aurels.exec", { steps: [{ message: "transfer funds now" }] }],
    ["task", { cmd: "remove-item C:\\data -recurse" }],
  ]) {
    assert.equal((await handlers.beforeToolCall({ toolName, toolCallId: `offline-${toolName}`, params }))?.block, true);
  }
});
test("offline scanner bounds hostile input and treats cycles/getters as ambiguous, never allow", async () => {
  const handlers = createHandlers(loadConfig({ apiKey: "", telemetry: false }), { evaluate: async () => { throw new Error("network must not be used"); } });
  const cyclic = {}; cyclic.self = cyclic;
  const throwing = Object.defineProperty({}, "payload", { enumerable: true, get() { throw new Error("hostile getter"); } });
  const huge = { payload: "x".repeat(70 * 1024) + " drop table customers" };
  for (const params of [cyclic, throwing, huge]) {
    const result = await handlers.beforeToolCall({ toolName: "read_file", params });
    assert.ok(result?.block || result?.requireApproval, "uncertain input must not become an allow result");
    assert.notEqual(result?.decision, "allow");
  }
});
test("only an ambiguous action reaches the model and accepts its strict decisions", async () => {
  let evaluations = 0;
  const handlers = createHandlers(config, { evaluate: async () => { evaluations += 1; return { decision: "allow" }; } });
  const result = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: "ambiguous" });
  assert.ok(result?.requireApproval);
  assert.deepEqual(result.params, {});
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
test("rejects oversized action requests before any network call", async () => {
  let fetchCalls = 0;
  const oversizedConfig = loadConfig({ apiKey: "test", telemetry: false });
  const client = createClient(oversizedConfig, async () => { fetchCalls += 1; throw new Error("must not reach network"); });
  await assert.rejects(
    () => client.evaluate({ action: { id: "oversized", arguments: { content: "x".repeat(1024 * 1024) } } }),
    /request exceeds/i,
  );
  const handlers = createHandlers(oversizedConfig, { evaluate: (action) => client.evaluate(action) });
  const result = await handlers.beforeToolCall({ toolName: "write_file", toolCallId: "oversized-hook", params: { content: "x".repeat(1024 * 1024) } });
  assert.ok(result?.block || result?.requireApproval, "oversized actions must stay on a non-allow path");
  assert.equal(fetchCalls, 0);
});
test("rate-limited evaluation blocks without retrying or sending telemetry", async () => {
  let telemetryCalls = 0;
  const client = createClient(loadConfig({ apiKey: "test", telemetry: true }), async () => ({
    ok: false,
    status: 429,
    headers: new Headers({ "retry-after": "12" }),
    text: async () => "",
  }));
  const handlers = createHandlers(loadConfig({ apiKey: "test", telemetry: true }), {
    evaluate: (action) => client.evaluate(action),
    telemetry: async () => { telemetryCalls += 1; },
  });
  const result = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: "limited-call" });
  assert.equal(result.block, true);
  assert.match(result.blockReason, /12 seconds/);
  assert.equal(telemetryCalls, 0);
  await assert.rejects(
    () => client.evaluate({ action: { id: "limited-call", name: "send_email", arguments: {} } }),
    (error) => error instanceof AurelsRateLimitError && error.retryAfterSeconds === 12,
  );
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
test("binds telemetry idempotency keys to event content", async () => {
  const keys = [];
  const client = createClient(loadConfig({ apiUrl: "https://example.test", apiKey: "test" }), async (_url, init) => {
    keys.push(new Headers(init.headers).get("idempotency-key"));
    return { ok: true, headers: new Headers(), text: async () => JSON.stringify({ accepted: true }) };
  });
  const base = { actionId: "same-call", outcome: { status: "success" }, metadata: { path: "safe.txt" } };
  await client.telemetry(base);
  await client.telemetry(base);
  await client.telemetry({ ...base, metadata: { path: "different.txt" } });
  assert.equal(keys[0], keys[1], "retrying the same event must reuse its key");
  assert.notEqual(keys[0], keys[2], "different event content must not collide");
});
test("API client rejects redirects before a key can reach another origin", async (t) => {
  let receivedApiKey = false;
  const destination = createServer((req, res) => { receivedApiKey = Boolean(req.headers["x-api-key"]); res.end('{"decision":"allow"}'); });
  destination.listen(0, "127.0.0.1");
  await once(destination, "listening");
  t.after(() => destination.close());
  const target = `http://127.0.0.1:${destination.address().port}/collect`;
  const redirector = createServer((_req, res) => { res.writeHead(303, { location: target }); res.end(); });
  redirector.listen(0, "127.0.0.1");
  await once(redirector, "listening");
  t.after(() => redirector.close());
  const client = createClient({ apiUrl: `http://127.0.0.1:${redirector.address().port}`, apiKey: "synthetic-redirect-secret", timeoutMs: 1000 });
  await assert.rejects(() => client.evaluate({ action: { id: "redirect", name: "read_file", arguments: {} } }));
  assert.equal(receivedApiKey, false);
});
test("API client timeout covers a response body that stalls after headers", async (t) => {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.flushHeaders();
    const timer = setTimeout(() => { if (!res.destroyed) res.end('{"decision":"allow"}'); }, 5000);
    res.once("close", () => clearTimeout(timer));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const client = createClient({ apiUrl: `http://127.0.0.1:${server.address().port}`, apiKey: "synthetic-body-timeout-key", timeoutMs: 100 });
  await assert.rejects(() => client.evaluate({ action: { id: "body-timeout", name: "read_file", arguments: {} } }));
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
  assert.equal(calls[0][2].priority, Number.MAX_SAFE_INTEGER, "Aurels approval must freeze params before ordinary lower-priority hooks");
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
  assert.equal(result.requireApproval.title, "Confirm Aurels-checked action");
  assert.equal(result.requireApproval.severity, "warning");
  assert.ok(result.requireApproval.allowedDecisions.includes("allow-once"));
  assert.ok(result.requireApproval.allowedDecisions.includes("deny"));
});

test("blocks flagged actions when the installed OpenClaw host lacks approval support", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "flag" }), telemetry: async () => {} }, { requireApprovalSupported: false });
  const result = await handlers.beforeToolCall({ toolName: "exec", toolCallId: "unsupported-host" });
  assert.equal(result.block, true);
  assert.match(result.blockReason, /execution was blocked/i);
  assert.equal(result.requireApproval, undefined);
});

test("records an approval denial as blocked, but does not call an approved action blocked", async () => {
  const events = [];
  const handlers = createHandlers({ ...config, telemetry: true }, {
    evaluate: async () => ({ decision: "flag", traceId: "trace-flagged" }),
    telemetry: async (event) => events.push(event),
  });
  const denied = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: "denied-approval", params: { to: "user@example.test" } });
  assert.equal(events.length, 0, "an unresolved approval is not yet a blocked execution");
  denied.requireApproval.onResolution("deny");
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(events.length, 1);
  assert.equal(events[0].outcome.status, "blocked");
  assert.equal(events[0].traceId, "trace-flagged");

  const allowed = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: "allowed-approval", params: { to: "user@example.test" } });
  allowed.requireApproval.onResolution("allow-once");
  await handlers.afterToolCall({ toolName: "send_email", toolCallId: "allowed-approval", params: allowed.params, success: true });
  assert.equal(events[1].outcome.status, "success");
});

test("real OpenClaw hook runner freezes approved params or blocks when approval freezing is unavailable", async () => {
  const openclawRoot = process.env.OPENCLAW_PACKAGE_ROOT;
  if (!openclawRoot) {
    if (process.env.AURELS_SKIP_OPENCLAW_RUNTIME_E2E === "1") {
      console.log("SKIP OpenClaw runtime hook-runner E2E: OPENCLAW_PACKAGE_ROOT is not configured");
      return;
    }
    throw new Error("Set OPENCLAW_PACKAGE_ROOT to a supported OpenClaw package root or AURELS_SKIP_OPENCLAW_RUNTIME_E2E=1");
  }
  const { pathToFileURL } = await import("node:url");
  const { resolve } = await import("node:path");
  const runtimeModule = await loadOpenClawHookRuntime(openclawRoot, { resolve, pathToFileURL });
  const hostVersion = JSON.parse(await readFile(resolve(openclawRoot, "package.json"), "utf8")).version;
  const requireApprovalSupported = supportsTestedApprovalContract(hostVersion);
  const hooks = [];
  const client = { evaluate: async () => ({ decision: "allow", traceId: "trace-final-params" }), telemetry: async () => {} };
  const config = loadConfig({ apiUrl: "https://example.test", apiKey: "test", telemetry: false });
  const handlers = createHandlers(config, client, { requireApprovalSupported });
  const registry = {
    hooks: [
      { pluginId: "aurels", entry: { hook: { name: "aurels-guard" } }, events: ["before_tool_call"], source: "aurels" },
      { pluginId: "rewrite", entry: { hook: { name: "rewrite-hook" } }, events: ["before_tool_call"], source: "rewrite" },
    ],
    typedHooks: [
      { hookName: "before_tool_call", pluginId: "aurels", priority: Number.MAX_SAFE_INTEGER, handler: handlers.beforeToolCall },
      { hookName: "before_tool_call", pluginId: "rewrite", priority: 10, handler: async () => ({ params: { command: "rm -rf /different" } }) },
    ],
  };
  runtimeModule.resetGlobalHookRunner();
  runtimeModule.initializeGlobalHookRunner(registry);
  try {
    const result = await runtimeModule.getGlobalHookRunner().runBeforeToolCall(
      { toolName: "exec", toolCallId: "rewrite-after-allow", params: { command: "echo safe" } },
      { toolName: "exec", toolCallId: "rewrite-after-allow", runId: "run-1" },
    );
    if (requireApprovalSupported) {
      assert.equal(result.params.command, "echo safe");
      assert.ok(result.requireApproval);
      assert.deepEqual(result.requireApproval.allowedDecisions, ["allow-once", "deny"]);
    } else {
      assert.equal(result.block, true, `OpenClaw ${hostVersion} must block instead of accepting an unfreezable authorization`);
      assert.equal(result.requireApproval, undefined);
    }
  } finally {
    runtimeModule.resetGlobalHookRunner();
  }
});

function supportsTestedApprovalContract(version) {
  const actual = String(version).split(".").map(Number);
  const minimum = [2026, 3, 28];
  for (let index = 0; index < minimum.length; index += 1) {
    if (actual[index] !== minimum[index]) return actual[index] > minimum[index];
  }
  return true;
}

test("blocks Aurels allow when the host cannot freeze approved parameters", async () => {
  const handlers = createHandlers(config, { evaluate: async () => ({ decision: "allow" }) }, { requireApprovalSupported: false });
  const result = await handlers.beforeToolCall({ toolName: "send_email", toolCallId: "unsupported-allow", params: { to: "recipient@example.test" } });
  assert.equal(result.block, true);
  assert.match(result.blockReason, /cannot freeze its approved parameters/i);
});

test("plugin registration detects approval support from the real host runtime version", () => {
  const handlers = [];
  plugin.register({
    pluginConfig: { mode: "local", apiKey: "", telemetry: false },
    runtime: { version: "2026.3.2" },
    on(name, handler) { handlers.push([name, handler]); }
  });
  const result = handlers.find(([name]) => name === "before_tool_call")[1]({ toolName: "read_file", params: {} });
  return Promise.resolve(result).then((decision) => {
    assert.equal(decision.block, true);
    assert.equal(decision.requireApproval, undefined);
  });
});

test("local retrospective hook is opt-in and capability-gated", async () => {
  const currentHooks = [];
  const currentLogger = { warn() {}, info() {} };
  plugin.register({
    pluginConfig: { mode: "local", apiKey: "", telemetry: false, retrospectiveEnabled: true },
    runtime: { version: "2026.9.6", llm: { complete: async () => ({ text: "{}" }) } },
    logger: currentLogger,
    on(name, handler) { currentHooks.push([name, handler]); }
  });
  assert.deepEqual(currentHooks.map(([name]) => name), ["before_tool_call", "after_tool_call", "agent_end"]);

  const legacyHooks = [];
  const warnings = [];
  plugin.register({
    pluginConfig: { mode: "local", apiKey: "", telemetry: false, retrospectiveEnabled: true },
    runtime: { version: "2026.3.28" },
    logger: { warn(message) { warnings.push(message); }, info() {} },
    on(name, handler) { legacyHooks.push([name, handler]); }
  });
  assert.deepEqual(legacyHooks.map(([name]) => name), ["before_tool_call", "after_tool_call"]);
  assert.equal(warnings.length, 1);
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

test("bounds trace correlation memory when post-tool callbacks are missing", async () => {
  // The map is intentionally private; the first item's eviction is observable
  // because its later callback cannot recover the trace ID, unlike the newest.
  const calls = [];
  const tracedHandlers = createHandlers({ ...config, telemetry: true }, {
    evaluate: async (action) => ({ decision: "allow", traceId: `trace-${action.action.id}` }),
    telemetry: async (event) => calls.push(event),
  });
  for (let index = 0; index < 1100; index += 1) {
    await tracedHandlers.beforeToolCall({ toolName: "read_file", toolCallId: `bounded-trace-${index}`, params: { index } });
  }
  await tracedHandlers.afterToolCall({ toolName: "read_file", toolCallId: "bounded-trace-0" });
  await tracedHandlers.afterToolCall({ toolName: "read_file", toolCallId: "bounded-trace-1099" });
  assert.equal(calls[0].traceId, undefined);
  assert.equal(calls[1].traceId, "trace-bounded-trace-1099");
});

test("reports host-reported tool errors as failure telemetry", async () => {
  const events = [];
  const handlers = createHandlers({ ...config, telemetry: true }, {
    evaluate: async () => ({ decision: "allow", traceId: "trace-failure" }),
    telemetry: async (event) => events.push(event)
  });
  await handlers.beforeToolCall({ toolName: "read_file", toolCallId: "failed-call", params: { path: "missing" } });
  await handlers.afterToolCall({ toolName: "read_file", toolCallId: "failed-call", error: "ENOENT", params: { path: "missing" } });
  assert.equal(events[0].outcome.status, "failure");
});

test("reports host ToolResult isError as failure telemetry", async () => {
  const events = [];
  const handlers = createHandlers({ ...config, telemetry: true }, {
    evaluate: async () => ({ decision: "allow", traceId: "trace-tool-result-error" }),
    telemetry: async (event) => events.push(event),
  });
  const approval = await handlers.beforeToolCall({ toolName: "read_file", toolCallId: "result-error", params: { path: "missing" } });
  approval.requireApproval.onResolution("allow-once");
  await handlers.afterToolCall({ toolName: "read_file", toolCallId: "result-error", result: { isError: true, content: [] } });
  assert.equal(events[0].outcome.status, "failure");
});
test("redacts sensitive values embedded in strings", () => {
  assert.equal(redact("Authorization: Bearer secret-token"), "[REDACTED]");
  assert.equal(redact({ command: "token=abc123" }).command, "[REDACTED]");
  assert.equal(redact("safe-value"), "safe-value");
});
test("redacts common secret formats in ordinary telemetry fields", () => {
  const cases = [
    ["content", "sk-proj-" + "C".repeat(32)],
    ["message", "AWS key AKIAIOSFODNN7EXAMPLE"],
    ["payload", "GitHub token ghp_" + "b".repeat(36)],
    ["body", "JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl"],
  ];
  for (const [field, secret] of cases) assert.equal(redact({ [field]: secret })[field], "[REDACTED]", field);
});
test("OpenClaw redaction passes the shared cross-language credential corpus", () => {
  for (const item of redactionCorpus) {
    assert.equal(JSON.stringify(redact({ message: item.input })).includes(item.secret), false, item.name);
  }
});
test("validates and normalizes mode configuration", () => {
  assert.equal(loadConfig({ mode: "local", apiKey: "" }).mode, "local");
  assert.equal(loadConfig({ mode: "remote", apiKey: "x" }).mode, "remote");
  assert.equal(loadConfig({ apiKey: "x" }).mode, "remote");
  assert.equal(loadConfig({ apiKey: "" }).mode, "local");
  assert.equal(loadConfig({ apiKey: "x" }).telemetryDurable, false);
  assert.equal(loadConfig({ apiKey: "x", telemetryDurable: true, telemetrySpoolDir: "C:/aurels-spool" }).telemetryDurable, true);
  assert.equal(loadConfig({ apiKey: "x", telemetrySpoolDir: "C:/aurels-spool" }).telemetrySpoolDir, "C:/aurels-spool");
  assert.throws(() => loadConfig({ mode: "invalid" }), /AURELS_MODE/);
});
