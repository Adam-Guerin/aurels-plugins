import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { createAurelToolGuard, AurelToolBlockedError, type AurelToolGuardClient } from "../integrations/shared/typescript/aurel-tool-guard";
import { redactForTelemetry } from "../integrations/shared/actions/redaction";
import { IntentGuardClient } from "../integrations/shared/sdk/index";

const redactionCorpus = JSON.parse(readFileSync("tests/fixtures/redaction-corpus.json", "utf8")) as Array<{ name: string; input: string; secret: string }>;

test("custom evaluator mutations cannot change the protected dispatch", async () => {
  const client: AurelToolGuardClient = {
    async evaluateAction(action) { (action.action.arguments as { path: string }).path = "unchecked.txt"; return { decision: "allow" }; },
    async recordActionTelemetry() {},
  };
  const guard = createAurelToolGuard({ integration: "langgraph", telemetryEnabled: false }, client);
  const result = await guard.runProtected({ name: "read_file", arguments: { path: "checked.txt" } }, (args) => args);
  assert.deepEqual(result, { path: "checked.txt" });
});

test("non-JSON arguments cannot bypass payload validation through a custom evaluator", async () => {
  let evaluations = 0, executions = 0;
  const client: AurelToolGuardClient = { async evaluateAction() { evaluations++; return { decision: "allow" }; }, async recordActionTelemetry() {} };
  const guard = createAurelToolGuard({ integration: "langgraph", failMode: "open", telemetryEnabled: false }, client);
  for (const args of [{ value: NaN }, { value: new Date() }, Object.defineProperty({}, "hidden", { value: "secret" }), { [Symbol("hidden")]: "secret" }]) {
    await assert.rejects(guard.runProtected({ name: "read_file", arguments: args }, () => { executions++; }), AurelToolBlockedError);
  }
  assert.equal(evaluations, 0);
  assert.equal(executions, 0);
});

test("SDK refuses remote plaintext endpoints before accepting credentials", () => {
  for (const baseUrl of ["http://api.example", "http://192.0.2.1", "http://localhost.example", "https://user:secret@example.com"]) assert.throws(() => new IntentGuardClient({ baseUrl, apiKey: "private-key" }));
  for (const baseUrl of ["https://api.example", "http://127.0.0.1:8000", "http://localhost:8000", "http://[::1]:8000"]) assert.doesNotThrow(() => new IntentGuardClient({ baseUrl, apiKey: "local-token" }));
});

test("custom provider errors are never copied into guard logs", async () => {
  const lines: unknown[][] = [];
  const original = console.warn;
  console.warn = (...values) => { lines.push(values); };
  try {
    const client: AurelToolGuardClient = { async evaluateAction() { throw new Error("Bearer synthetic-private-key"); }, async recordActionTelemetry() {} };
    const guard = createAurelToolGuard({ integration: "langgraph", failMode: "open", telemetryEnabled: false }, client);
    await guard.runProtected({ name: "read_file", arguments: {} }, () => "fixture");
    assert.doesNotMatch(JSON.stringify(lines), /synthetic-private-key/);
  } finally { console.warn = original; }
});

test("shared guard rejects invalid protocol responses even with fail-open explicitly enabled", async () => {
  for (const response of [{ decision: "allow", riskScore: NaN }, { decision: "allow", riskScore: true },
    { decision: "rewrite" }, { decision: "unknown" }]) {
    const client = { async evaluateAction() { return response; }, async recordActionTelemetry() {} } as unknown as AurelToolGuardClient;
    const guard = createAurelToolGuard({ integration: "langgraph", failMode: "open", rewriteSupported: true }, client);
    let dispatches = 0;
    await assert.rejects(guard.runProtected({ name: "read_file", arguments: {} }, () => { dispatches++; }), AurelToolBlockedError);
    assert.equal(dispatches, 0);
  }
});

test("shared guard never executes an aborted action after an in-flight allow returns", async () => {
  const controller = new AbortController();
  const client: AurelToolGuardClient = {
    async evaluateAction() { controller.abort(); return { decision: "allow" }; },
    async recordActionTelemetry() {},
  };
  const guard = createAurelToolGuard({ integration: "langgraph", failMode: "open" }, client);
  let dispatches = 0;
  await assert.rejects(guard.runProtected({ name: "read_file", arguments: {} }, () => { dispatches++; }, controller.signal), AurelToolBlockedError);
  assert.equal(dispatches, 0);
});

test("shared TypeScript redaction passes the cross-language credential corpus", () => {
  for (const item of redactionCorpus) {
    const result = JSON.stringify(redactForTelemetry({ message: item.input }));
    assert.equal(result.includes(item.secret), false, item.name);
  }
});

function fakeClient(decision: "allow" | "block" | "require_approval" | "rewrite", fail = false) {
  const seen: string[] = [];
  const client: AurelToolGuardClient = {
    async evaluateAction(action) {
      seen.push(action.action.name);
      if (fail) throw new Error("synthetic Aurel outage");
      return { decision, traceId: "synthetic-trace" };
    },
    async recordActionTelemetry() {},
  };
  return { client, seen };
}

test("shared TypeScript guard evaluates Aurel-prefixed names and ignores legacy excludes", async () => {
  const fake = fakeClient("block");
  const guard = createAurelToolGuard({
    integration: "langgraph",
    tools: { exclude: ["aurel.exec"] },
  }, fake.client);
  let executed = false;

  await assert.rejects(
    guard.runProtected({ name: "aurel.exec", arguments: { command: "rm -rf /synthetic" } }, () => {
      executed = true;
    }),
    AurelToolBlockedError,
  );
  assert.deepEqual(fake.seen, ["aurel.exec"]);
  assert.equal(executed, false);
});

test("shared TypeScript guard executes the exact argument snapshot evaluated before async policy returns", async () => {
  let releaseEvaluation!: (decision: { decision: "allow" }) => void;
  let evaluatedArguments: unknown;
  let executedArguments: unknown;
  const client: AurelToolGuardClient = {
    async evaluateAction(action) {
      evaluatedArguments = structuredClone(action.action.arguments);
      return await new Promise((resolve) => { releaseEvaluation = resolve; });
    },
    async recordActionTelemetry() {},
  };
  const guard = createAurelToolGuard({ integration: "langgraph" }, client);
  const call = { name: "task", arguments: { command: "echo safe" } };

  const execution = guard.runProtected(call, (args) => {
    executedArguments = args;
    return "done";
  });
  call.arguments.command = "rm -rf /synthetic";
  releaseEvaluation({ decision: "allow" });
  await execution;

  assert.deepEqual(evaluatedArguments, { command: "echo safe" });
  assert.deepEqual(executedArguments, evaluatedArguments);
});

test("shared TypeScript guard does not clone arguments for tools outside the include list", async () => {
  const fake = fakeClient("block");
  const guard = createAurelToolGuard({ integration: "langgraph", tools: { include: ["read_file"] } }, fake.client);
  const argumentsValue = { callback: () => "not JSON" };
  let executedArguments: unknown;

  const result = await guard.runProtected({ name: "write_file", arguments: argumentsValue }, (args) => {
    executedArguments = args;
    return "executed";
  });

  assert.equal(result, "executed");
  assert.equal(executedArguments, argumentsValue);
  assert.deepEqual(fake.seen, []);
});

test("shared TypeScript fail-open blocks destructive args behind a benign name", async () => {
  const fake = fakeClient("allow", true);
  const guard = createAurelToolGuard({
    integration: "openai-agents",
    failMode: "open",
    failOpenPrivilegedActions: "block",
  }, fake.client);
  let executed = false;

  await assert.rejects(
    guard.runProtected({ name: "task", arguments: { payload: { command: "rm -rf /synthetic" } } }, () => {
      executed = true;
    }),
    AurelToolBlockedError,
  );
  assert.deepEqual(fake.seen, ["task"]);
  assert.equal(executed, false);
});
