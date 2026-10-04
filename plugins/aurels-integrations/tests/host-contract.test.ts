import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { test } from "node:test";
import { AIMessage } from "@langchain/core/messages";
import { tool as langchainTool } from "@langchain/core/tools";
import { ToolNode } from "@langchain/langgraph/prebuilt";
import { invokeFunctionTool, runToolInputGuardrails, tool as openAIAgentTool } from "@openai/agents";
import { RunContext } from "@openai/agents";
import { z } from "zod";
import { IntentGuardClient } from "../integrations/shared/sdk/index";
import { wrapLangGraphTool } from "../integrations/langgraph/src/index";
import { createAurelOpenAIToolInputGuardrail, withAurelOpenAIAgentsTool } from "../integrations/openai-agents/src/index";
import type { AurelActionRequest, AurelActionTelemetry } from "../integrations/shared/sdk/index";
import type { AurelToolGuardClient } from "../integrations/shared/typescript/aurel-tool-guard";

function decisionClient(decision: "allow" | "block" | "rewrite") {
  const evaluated: AurelActionRequest[] = [];
  const telemetry: AurelActionTelemetry[] = [];
  const client: AurelToolGuardClient = {
    async evaluateAction(action) {
      evaluated.push(action);
      return {
        decision,
        traceId: "host-contract-trace",
        rewrittenArguments: decision === "rewrite" ? { path: "/synthetic/rewritten" } : undefined,
      };
    },
    async recordActionTelemetry(event) {
      telemetry.push(event);
    },
  };
  return { client, evaluated, telemetry };
}

test("shared SDK idempotency keys distinguish payloads but remain stable for exact telemetry retries", async () => {
  const keys: string[] = [];
  const client = new IntentGuardClient({
    apiKey: "synthetic-test-key",
    baseUrl: "https://aurels.invalid",
    fetchImpl: async (_input, init) => {
      keys.push(new Headers(init?.headers).get("idempotency-key") ?? "");
      return new Response(JSON.stringify({ accepted: true }), { status: 202, headers: { "content-type": "application/json" } });
    },
  });
  const base: AurelActionTelemetry = {
    version: "1", integration: "contract-test", actionId: "reused-call", outcome: { status: "success" },
    metadata: { path: "safe.txt" }, timestamp: "2026-09-27T00:00:00.000Z",
  };
  await client.recordActionTelemetry(base);
  await client.recordActionTelemetry(base);
  await client.recordActionTelemetry({ ...base, metadata: { path: "different.txt" } });
  assert.equal(keys[0], keys[1]);
  assert.notEqual(keys[0], keys[2]);
});

test("shared SDK rejects redirects for JSON and text requests without forwarding its key", async (t) => {
  const receivedKeys: string[] = [];
  const destination = createServer((req, res) => { receivedKeys.push(String(req.headers["x-api-key"] ?? "")); res.end("synthetic response"); });
  destination.listen(0, "127.0.0.1");
  await once(destination, "listening");
  t.after(() => destination.close());
  const target = `http://127.0.0.1:${(destination.address() as import("node:net").AddressInfo).port}/collect`;
  const redirector = createServer((_req, res) => { res.writeHead(303, { location: target }); res.end(); });
  redirector.listen(0, "127.0.0.1");
  await once(redirector, "listening");
  t.after(() => redirector.close());
  const client = new IntentGuardClient({
    apiKey: "synthetic-redirect-secret",
    baseUrl: `http://127.0.0.1:${(redirector.address() as import("node:net").AddressInfo).port}`,
    timeoutMs: 1000,
  });
  await assert.rejects(() => client.evaluateAction({ version: "1", integration: "redirect-test", action: { id: "redirect", name: "read_file", arguments: {} }, agent: {}, timestamp: "now" }));
  await assert.rejects(() => client.exportAuditLogs("csv"));
  assert.deepEqual(receivedKeys, []);
});

test("shared SDK timeout covers a response body that stalls after headers", async (t) => {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.flushHeaders();
    const timer = setTimeout(() => { if (!res.destroyed) res.end('{"decision":"allow"}'); }, 5000);
    res.once("close", () => clearTimeout(timer));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const client = new IntentGuardClient({
    apiKey: "synthetic-body-timeout-key",
    baseUrl: `http://127.0.0.1:${(server.address() as import("node:net").AddressInfo).port}`,
    timeoutMs: 100,
  });
  await assert.rejects(
    () => client.evaluateAction({ version: "1", integration: "timeout-test", action: { id: "body-timeout", name: "read_file", arguments: {} }, agent: {}, timestamp: "now" }),
    (error: unknown) => error instanceof Error && error.name === "AurelTimeoutError",
  );
});

test("shared SDK evaluates the exact action without silently truncating large arguments", async () => {
  const received: unknown[] = [];
  const client = new IntentGuardClient({
    apiKey: "synthetic-test-key",
    baseUrl: "https://aurels.invalid",
    fetchImpl: async (_input, init) => {
      received.push(JSON.parse(String(init?.body)));
      return new Response(JSON.stringify({ decision: "allow" }), { status: 200 });
    },
  });
  const longString = "x".repeat(65_537);
  const longArray = Array.from({ length: 513 }, (_, index) => index);
  const manyProperties = Object.fromEntries(Array.from({ length: 513 }, (_, index) => [`field${index}`, index]));
  const actions = [
    { id: "large-string", name: "write_file", arguments: { content: longString } },
    { id: "large-array", name: "batch", arguments: { items: longArray } },
    { id: "large-object", name: "update", arguments: manyProperties },
  ];
  for (const action of actions) {
    await client.evaluateAction({ version: "1", integration: "exact-action-test", action, agent: {}, timestamp: "now" });
  }
  assert.deepEqual(received.map((item) => (item as AurelActionRequest).action), actions);
});

test("current LangGraph ToolNode dispatches only after the Aurel wrapper allows it", async () => {
  const fake = decisionClient("allow");
  const executed: unknown[] = [];
  const original = langchainTool(async ({ path }) => {
    executed.push(path);
    return `read:${path}`;
  }, {
    name: "read_file",
    description: "Read a synthetic fixture",
    schema: z.object({ path: z.string() }),
  });
  const protectedTool = wrapLangGraphTool(original, { telemetryEnabled: false }, fake.client);
  const node = new ToolNode([protectedTool]);

  const result = await node.invoke({
    messages: [new AIMessage({
      content: "",
      tool_calls: [{ id: "lg-call-1", name: "read_file", args: { path: "/synthetic/fixture" }, type: "tool_call" }],
    })],
  });

  assert.deepEqual(executed, ["/synthetic/fixture"]);
  assert.equal(fake.evaluated.length, 1);
  assert.equal(fake.evaluated[0].action.name, "read_file");
  assert.deepEqual(fake.evaluated[0].action.arguments, { path: "/synthetic/fixture" });
  assert.equal(fake.evaluated[0].action.id, "lg-call-1");
  assert.equal(result.messages[0].content, "read:/synthetic/fixture");
});

test("current LangGraph ToolNode does not invoke the handler after Aurel blocks", async () => {
  const fake = decisionClient("block");
  let executed = false;
  const original = langchainTool(async () => {
    executed = true;
    return "UNSAFE_HANDLER_EXECUTED";
  }, {
    name: "mutate_record",
    description: "Synthetic mutating tool",
    schema: z.object({ command: z.string() }),
  });
  const node = new ToolNode([wrapLangGraphTool(original, { telemetryEnabled: false }, fake.client)]);

  const result = await node.invoke({
    messages: [new AIMessage({
      content: "",
      tool_calls: [{ id: "lg-call-2", name: "mutate_record", args: { command: "delete synthetic fixture" }, type: "tool_call" }],
    })],
  });

  assert.equal(fake.evaluated.length, 1);
  assert.equal(executed, false);
  assert.equal(result.messages[0].status, "error");
  assert.doesNotMatch(String(result.messages[0].content), /UNSAFE_HANDLER_EXECUTED/);
});

test("current LangGraph ToolNode dispatches rewritten args while preserving the ToolCall envelope", async () => {
  const fake = decisionClient("rewrite");
  const executed: unknown[] = [];
  const original = langchainTool(async ({ path }) => {
    executed.push(path);
    return `read:${path}`;
  }, {
    name: "read_file",
    description: "Read a synthetic fixture",
    schema: z.object({ path: z.string() }),
  });
  const node = new ToolNode([wrapLangGraphTool(original, { telemetryEnabled: false }, fake.client)]);
  const result = await node.invoke({
    messages: [new AIMessage({
      content: "",
      tool_calls: [{ id: "lg-call-rewrite", name: "read_file", args: { path: "/synthetic/original" }, type: "tool_call" }],
    })],
  });

  assert.deepEqual(fake.evaluated.map((action) => action.action.arguments), [{ path: "/synthetic/original" }]);
  assert.equal(fake.evaluated[0].action.id, "lg-call-rewrite");
  assert.deepEqual(executed, ["/synthetic/rewritten"]);
  assert.equal(result.messages[0].content, "read:/synthetic/rewritten");
});

test("current OpenAI Agents function-tool object remains callable through the Aurel wrapper", async () => {
  const fake = decisionClient("allow");
  const executed: unknown[] = [];
  const original = openAIAgentTool({
    name: "read_fixture",
    description: "Read synthetic fixture",
    parameters: z.object({ path: z.string() }),
    async execute({ path }) {
      executed.push(path);
      return `read:${path}`;
    },
  });
  assert.equal(original.type, "function");
  const protectedTool = withAurelOpenAIAgentsTool(original, { telemetryEnabled: false }, fake.client);
  assert.equal(typeof protectedTool.invoke, "function");
  const toolCall = { type: "function_call" as const, callId: "oa-call-1", name: "read_fixture", arguments: JSON.stringify({ path: "/synthetic/openai-fixture" }) };
  const result = await invokeFunctionTool({ tool: protectedTool, runContext: new RunContext({}), input: toolCall.arguments, details: { toolCall } });

  assert.deepEqual(executed, ["/synthetic/openai-fixture"]);
  assert.equal(fake.evaluated.length, 1);
  assert.equal(fake.evaluated[0].action.name, "read_fixture");
  assert.equal(fake.evaluated[0].action.id, "oa-call-1");
  assert.deepEqual(fake.evaluated[0].action.arguments, { path: "/synthetic/openai-fixture" });
  assert.equal(result, "read:/synthetic/openai-fixture");
});

test("current OpenAI Agents wrapper passes only Aurel's rewritten arguments to invokeFunctionTool", async () => {
  const fake = decisionClient("rewrite");
  const executed: unknown[] = [];
  const original = openAIAgentTool({
    name: "read_fixture",
    description: "Read synthetic fixture",
    parameters: z.object({ path: z.string() }),
    async execute({ path }) {
      executed.push(path);
      return `read:${path}`;
    },
  });
  const protectedTool = withAurelOpenAIAgentsTool(original, { telemetryEnabled: false }, fake.client);
  const toolCall = { type: "function_call" as const, callId: "oa-call-rewrite", name: "read_fixture", arguments: JSON.stringify({ path: "/synthetic/original" }) };
  const result = await invokeFunctionTool({ tool: protectedTool, runContext: new RunContext({}), input: toolCall.arguments, details: { toolCall } });

  assert.deepEqual(fake.evaluated.map((action) => action.action.arguments), [{ path: "/synthetic/original" }]);
  assert.equal(fake.evaluated[0].action.id, "oa-call-rewrite");
  assert.deepEqual(executed, ["/synthetic/rewritten"]);
  assert.equal(result, "read:/synthetic/rewritten");
});

test("current OpenAI Agents tool input guardrail uses the SDK run contract and blocks before dispatch", async () => {
  const fake = decisionClient("block");
  const guardrail = createAurelOpenAIToolInputGuardrail("mutate_record", { telemetryEnabled: false }, fake.client);
  const sdkTool = openAIAgentTool({
    name: "mutate_record",
    description: "Synthetic mutating tool",
    parameters: z.object({ command: z.string() }),
    inputGuardrails: [guardrail],
    async execute() {
      return "UNSAFE_HANDLER_EXECUTED";
    },
  });
  assert.equal(sdkTool.inputGuardrails?.[0], guardrail);
  const result = await runToolInputGuardrails({
    guardrails: sdkTool.inputGuardrails,
    context: new RunContext({}),
    toolCall: { type: "function_call", callId: "oa-call-2", name: "mutate_record", arguments: JSON.stringify({ command: "delete synthetic fixture" }) },
    agent: {} as never,
  });

  assert.deepEqual(fake.evaluated.map((action) => action.action.arguments), [{ command: "delete synthetic fixture" }]);
  assert.deepEqual(result, {
    type: "reject",
    message: "Aurel blocked this action because it violates the active security policy.",
  });
});
