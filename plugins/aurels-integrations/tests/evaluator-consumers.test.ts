import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Agent, Runner, Usage, tool, type Model } from "@openai/agents";
import { StateGraph, MessagesAnnotation, START, END } from "@langchain/langgraph";
import { ToolNode } from "@langchain/langgraph/prebuilt";
import { AIMessage } from "@langchain/core/messages";
import { tool as langchainTool } from "@langchain/core/tools";
import { z } from "zod";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const root = resolve(__dirname, "../../..");
const evaluatorModule = import(pathToFileURL(process.env.AURELS_EVALUATOR_MODULE ?? resolve(root, "plugins/aurels-evaluator/src/server.mjs")).href);
const adapters = Promise.all([
  import(process.env.AURELS_LG_ADAPTER_MODULE ? pathToFileURL(process.env.AURELS_LG_ADAPTER_MODULE).href : "../integrations/langgraph/src/index"),
  import(process.env.AURELS_OAI_ADAPTER_MODULE ? pathToFileURL(process.env.AURELS_OAI_ADAPTER_MODULE).href : "../integrations/openai-agents/src/index"),
]);
const token = "synthetic-local-evaluator-token";

async function serve(server: Server, run: (url: string) => Promise<void>) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try { await run(`http://127.0.0.1:${(server.address() as import("node:net").AddressInfo).port}`); }
  finally { server.closeAllConnections(); await new Promise<void>((done) => server.close(() => done())); }
}

async function withEvaluator(run: (url: string) => Promise<void>) {
  const evaluator = await evaluatorModule;
  await serve(createServer(async (req, res) => {
    assert.equal(req.headers.authorization, "Bearer owner-provider-key");
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const input = JSON.parse(raw);
    const decision = input.state.action.arguments.path;
    res.end(JSON.stringify({ answers: { decision: { type: "choice", choice: decision, confidence: .98,
      probabilities: Object.fromEntries(["allow", "block", "flag"].map((label) => [label, label === decision ? .98 : .01])) } } }));
  }), async (apiUrl) => {
    await serve(evaluator.createEvaluatorServer({ provider: "jev", apiUrl, apiKey: "owner-provider-key", token,
      model: "jev-latest", allowTools: ["read_fixture", "read_file"], timeoutMs: 1000 }), run);
  });
}

function child(command: string, args: string[], url: string, input?: unknown) {
  return new Promise<{ status: number | null; stdout: string; stderr: string }>((done, reject) => {
    const processChild = spawn(command, args, { cwd: root, env: { ...process.env,
      AURELS_API_URL: url, AUREL_API_URL: url, AURELS_API_KEY: token, AUREL_API_KEY: token,
      AURELS_MODE: "remote", AURELS_TIMEOUT_MS: "2000", AUREL_TIMEOUT_MS: "2000", AUREL_FAIL_MODE: "closed",
      AURELS_TELEMETRY_ENABLED: "false", AUREL_TELEMETRY_ENABLED: "false", AURELS_TELEMETRY_DURABLE: "false",
    } });
    let stdout = "", stderr = "";
    processChild.stdout.on("data", (chunk) => { stdout += chunk; });
    processChild.stderr.on("data", (chunk) => { stderr += chunk; });
    processChild.on("error", reject);
    processChild.on("close", (status) => done({ status, stdout, stderr }));
    processChild.stdin.end(input === undefined ? undefined : JSON.stringify(input));
  });
}

for (const decision of ["allow", "block", "flag"] as const) {
  test(`OpenAI Agents Runner uses the self-hosted HTTP evaluator for ${decision}`, async () => withEvaluator(async (apiUrl) => {
    const dispatched: string[] = [];
    const [, { withAurelOpenAIAgentsTool }] = await adapters;
    const protectedTool = withAurelOpenAIAgentsTool(tool({ name: "read_fixture", description: "Fixture",
      parameters: z.object({ path: z.string() }), errorFunction: null,
      execute: async ({ path }) => { dispatched.push(path); return path; },
    }), { apiUrl, apiKey: token, telemetryEnabled: false });
    const model: Model = {
      async getResponse() { return { usage: new Usage(), output: [{ type: "function_call", callId: "local-call", name: "read_fixture", arguments: JSON.stringify({ path: decision }) }] }; },
      async *getStreamedResponse() { throw new Error("Not streaming"); },
    };
    const run = new Runner({ tracingDisabled: true }).run(new Agent({ name: "fixture", model, tools: [protectedTool], toolUseBehavior: "stop_on_first_tool" }), "fixture", { maxTurns: 2 });
    if (decision === "allow") assert.equal((await run).finalOutput, "allow");
    else await assert.rejects(run);
    assert.deepEqual(dispatched, decision === "allow" ? ["allow"] : []);
  }));

  test(`compiled LangGraph uses the self-hosted HTTP evaluator for ${decision}`, async () => withEvaluator(async (apiUrl) => {
    const dispatched: string[] = [];
    const [{ wrapLangGraphTool }] = await adapters;
    const protectedTool = wrapLangGraphTool(langchainTool(async ({ path }) => { dispatched.push(path); return path; },
      { name: "read_fixture", description: "Fixture", schema: z.object({ path: z.string() }) }), { apiUrl, apiKey: token, telemetryEnabled: false });
    const graph = new StateGraph(MessagesAnnotation)
      .addNode("model", () => ({ messages: [new AIMessage({ content: "", tool_calls: [{ id: "local-call", name: "read_fixture", args: { path: decision }, type: "tool_call" }] })] }))
      .addNode("tools", new ToolNode([protectedTool])).addEdge(START, "model").addEdge("model", "tools").addEdge("tools", END).compile();
    await graph.invoke({ messages: [] });
    assert.deepEqual(dispatched, decision === "allow" ? ["allow"] : []);
  }));
}

test("native command hooks use the self-hosted evaluator without a cloud key", async () => withEvaluator(async (url) => {
  for (const host of ["claude-code", "codex"]) {
    const script = host === "claude-code" ? (process.env.AURELS_CLAUDE_HOOK_BIN ?? "plugins/aurels-integrations/integrations/claude-code/hooks/aurel-hook.mjs")
      : (process.env.AURELS_CODEX_HOOK_BIN ?? "plugins/aurels-integrations/integrations/codex/aurel-codex-plugin/hooks/aurel-codex-hook.mjs");
    for (const decision of ["allow", "block", "flag"]) {
      const result = await child(process.execPath, [script], url, { hook_event_name: "PreToolUse", tool_name: "read_file", tool_input: { path: decision } });
      assert.equal(result.status, 0, result.stderr);
      const expected = decision === "allow" ? "allow" : host === "claude-code" && decision === "flag" ? "ask" : "deny";
      assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, expected);
    }
  }
}));

test("Hermes and CrewAI Python guards call the self-hosted evaluator before dispatch", async () => withEvaluator(async (url) => {
  for (const host of ["hermes", "crewai"]) {
    const source = host === "hermes" ? `
from aurels_hermes import AurelsHermesPlugin, AurelsToolBlockedError
guard = AurelsHermesPlugin()
for decision in ('allow','block','flag'):
    dispatched=[]
    try:
        guard.run_protected('read_fixture', {'path':decision}, lambda args: dispatched.append(args['path']))
    except AurelsToolBlockedError:
        assert decision != 'allow'
    assert dispatched == (['allow'] if decision == 'allow' else [])
` : `
from aurel_crewai import AurelCrewAIGuard, AurelToolBlockedError
guard = AurelCrewAIGuard()
for decision in ('allow','block','flag'):
    dispatched=[]
    try:
        guard.run_protected(tool_name='read_fixture', args={'path':decision}, execute=lambda args: dispatched.append(args['path']))
    except AurelToolBlockedError:
        assert decision != 'allow'
    assert dispatched == (['allow'] if decision == 'allow' else [])
`;
    const path = resolve(root, host === "hermes" ? "plugins/aurels-hermes" : "plugins/aurels-integrations/integrations/crewai");
    const code = `import sys; sys.path.insert(0, ${JSON.stringify(path)})\n${source}`;
    const result = await child("python", ["-c", code], url);
    assert.equal(result.status, 0, `${host}: ${result.stdout} ${result.stderr}`);
  }
}));

test("OpenClaw preserves its one-shot approval contract with a self-hosted evaluator", async () => withEvaluator(async (apiUrl) => {
  const openclaw = await import(pathToFileURL(resolve(root, "plugins/aurels-openclaw/src/security.js")).href);
  const config = openclaw.loadConfig({ apiUrl, apiKey: token, telemetry: false, mode: "remote" });
  const hooks = openclaw.createHandlers(config, openclaw.createClient(config));
  const allowed = await hooks.beforeToolCall({ toolName: "read_file", toolCallId: "allow-call", params: { path: "allow" } });
  assert.deepEqual(allowed.params, { path: "allow" });
  assert.deepEqual(allowed.requireApproval.allowedDecisions, ["allow-once", "deny"]);
  const blocked = await hooks.beforeToolCall({ toolName: "read_file", toolCallId: "block-call", params: { path: "block" } });
  assert.equal(blocked.block, true);
}));

test("official MCP client dispatches only self-hosted evaluator-approved calls", async () => withEvaluator(async (url) => {
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [process.env.AUREL_MCP_PROXY_BIN ?? resolve(root, "plugins/aurels-integrations/integrations/mcp/src/aurel-mcp-proxy.mjs"), "--", process.execPath,
      resolve(__dirname, "fixtures/mcp-sdk-server.mjs")],
    env: { ...process.env, AURELS_API_URL: url, AUREL_API_URL: url, AURELS_API_KEY: token, AUREL_API_KEY: token,
      AUREL_MCP_TRANSPORT: "newline", AUREL_TELEMETRY_ENABLED: "false", AUREL_FAIL_MODE: "closed", AURELS_MCP_EXECUTION_PERMITS: "false" },
  });
  const client = new Client({ name: "local-evaluator-client", version: "1.0.0" });
  try {
    await client.connect(transport);
    const allowed = await client.callTool({ name: "read_file", arguments: { path: "allow" } });
    assert.equal(JSON.parse((allowed.content as { text: string }[])[0].text).path, "allow");
    for (const path of ["block", "flag"]) await assert.rejects(client.callTool({ name: "read_file", arguments: { path } }));
  } finally { await client.close(); }
}));
