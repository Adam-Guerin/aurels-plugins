import assert from "node:assert/strict";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { Agent, Runner, Usage, tool, type Model } from "@openai/agents";
import { StateGraph, MessagesAnnotation, START, END } from "@langchain/langgraph";
import { ToolNode } from "@langchain/langgraph/prebuilt";
import { AIMessage } from "@langchain/core/messages";
import { tool as langchainTool } from "@langchain/core/tools";
import { z } from "zod";
import type { AurelToolGuardClient } from "../integrations/shared/typescript/aurel-tool-guard";

const langgraphModule = import(process.env.AURELS_LG_ADAPTER_MODULE
  ? pathToFileURL(process.env.AURELS_LG_ADAPTER_MODULE).href : "../integrations/langgraph/src/index.ts");
const agentsModule = import(process.env.AURELS_OAI_ADAPTER_MODULE
  ? pathToFileURL(process.env.AURELS_OAI_ADAPTER_MODULE).href : "../integrations/openai-agents/src/index.ts");

for (const decision of ["allow", "block", "require_approval", "rewrite"] as const) {
  function client(): AurelToolGuardClient {
    return { async evaluateAction() { return { decision, rewrittenArguments: decision === "rewrite" ? { path: "rewritten.txt" } : undefined }; }, async recordActionTelemetry() {} };
  }

  test(`OpenAI Agents Runner enforces ${decision} at actual function dispatch`, async () => {
    const agents = await agentsModule;
    const dispatched: string[] = [];
    const protectedTool = agents.withAurelOpenAIAgentsTool(tool({
      name: "read_fixture", description: "Synthetic fixture", parameters: z.object({ path: z.string() }),
      execute: async ({ path }) => { dispatched.push(path); return `read:${path}`; },
      errorFunction: null,
    }), { telemetryEnabled: false }, client());
    const model: Model = {
      async getResponse() { return { usage: new Usage(), output: [{ type: "function_call", callId: "runner-call", name: "read_fixture", arguments: JSON.stringify({ path: "original.txt" }) }] }; },
      async *getStreamedResponse() { throw new Error("This test never streams"); },
    };
    const agent = new Agent({ name: "synthetic-agent", model, tools: [protectedTool], toolUseBehavior: "stop_on_first_tool" });
    const execution = new Runner({ tracingDisabled: true }).run(agent, "Read the fixture", { maxTurns: 2 });
    if (decision === "block" || decision === "require_approval") {
      await assert.rejects(execution, (error: Error) => error.name === "ToolCallError" && error.message.includes("AurelToolBlockedError"));
      assert.deepEqual(dispatched, []);
    } else {
      const expected = decision === "rewrite" ? "rewritten.txt" : "original.txt";
      assert.equal((await execution).finalOutput, `read:${expected}`);
      assert.deepEqual(dispatched, [expected]);
    }
  });

  test(`compiled LangGraph enforces ${decision} at actual ToolNode dispatch`, async () => {
    const langgraph = await langgraphModule;
    const dispatched: string[] = [];
    const protectedTool = langgraph.wrapLangGraphTool(langchainTool(async ({ path }) => {
      dispatched.push(path); return `read:${path}`;
    }, { name: "read_fixture", description: "Synthetic fixture", schema: z.object({ path: z.string() }) }), { telemetryEnabled: false }, client());
    const graph = new StateGraph(MessagesAnnotation)
      .addNode("synthetic-model", () => ({ messages: [new AIMessage({ content: "", tool_calls: [{ id: "graph-call", name: "read_fixture", args: { path: "original.txt" }, type: "tool_call" }] })] }))
      .addNode("tools", new ToolNode([protectedTool]))
      .addEdge(START, "synthetic-model").addEdge("synthetic-model", "tools").addEdge("tools", END).compile();
    const result = await graph.invoke({ messages: [] });
    if (decision === "block" || decision === "require_approval") {
      assert.deepEqual(dispatched, []);
      assert.match(String(result.messages.at(-1)?.content), /Aurel/);
    } else {
      const expected = decision === "rewrite" ? "rewritten.txt" : "original.txt";
      assert.deepEqual(dispatched, [expected]);
      assert.equal(result.messages.at(-1)?.content, `read:${expected}`);
    }
  });
}
