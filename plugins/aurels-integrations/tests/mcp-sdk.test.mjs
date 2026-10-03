import assert from "node:assert/strict";
import { test } from "node:test";
import { once } from "node:events";
import { resolve } from "node:path";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { createAurelHarnessServer } from "../integrations/dev-harness/mock-aurel-server.mjs";

const proxy = process.env.AUREL_MCP_PROXY_BIN ?? resolve(import.meta.dirname, "../integrations/mcp/src/aurel-mcp-proxy.mjs");
const fixture = resolve(import.meta.dirname, "fixtures/mcp-sdk-server.mjs");

async function withSdkProxy(options, run) {
  const temporary = await mkdtemp(resolve(tmpdir(), "aurels-mcp-sdk-"));
  const dispatchLog = resolve(temporary, "dispatch.jsonl");
  const api = createAurelHarnessServer(options);
  api.listen(0, "127.0.0.1");
  await once(api, "listening");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [proxy, "--", process.execPath, fixture],
    env: { ...process.env, AUREL_API_URL: `http://127.0.0.1:${api.address().port}`, AUREL_API_KEY: "synthetic-sdk-key",
      AUREL_FAIL_MODE: "closed", AUREL_TELEMETRY_ENABLED: "false", AUREL_ENABLED: "true", AUREL_TOOLS_INCLUDE: "", AUREL_MCP_TRANSPORT: "newline",
      AURELS_TEST_DISPATCH_LOG: dispatchLog, ...options.env },
    stderr: "pipe",
  });
  let stderr = "";
  transport.stderr?.on("data", (chunk) => { stderr += chunk; });
  const client = new Client({ name: "aurels-sdk-client-test", version: "1.0.0" });
  try {
    await client.connect(transport, { timeout: 4000 });
    await run(client, api, async () => {
      try { return (await readFile(dispatchLog, "utf8")).trim().split("\n").filter(Boolean).map((line) => JSON.parse(line)); }
      catch (error) { if (error.code === "ENOENT") return []; throw error; }
    });
  } catch (error) {
    error.message += `\nProxy stderr: ${stderr}`;
    throw error;
  } finally {
    await client.close();
    api.close();
    await once(api, "close");
    await rm(temporary, { recursive: true, force: true });
  }
}

test("MCP proxy initializes and dispatches through the official SDK's newline stdio transport", { timeout: 15000 }, async () => {
  await withSdkProxy({}, async (client) => {
    const listed = await client.listTools();
    assert.equal(listed.tools[0].name, "read_file");
    const args = { path: "fixture.txt", unicode: "été\nمرحبا" };
    const result = await client.callTool({ name: "read_file", arguments: args });
    assert.deepEqual(JSON.parse(result.content[0].text), args);
    await assert.rejects(client.callTool({ name: "read_file", arguments: { command: "rm -rf /synthetic" } }));
    await assert.rejects(client.callTool({ name: "send_email", arguments: { body: "synthetic" } }));
    const rewrite = await client.callTool({ name: "read_file", arguments: { path: "rewrite-me" } });
    assert.equal(JSON.parse(rewrite.content[0].text).rewritten_by, "aurel-harness");
  });
});

test("MCP cancellation during policy evaluation never dispatches the cancelled call", { timeout: 15000 }, async () => {
  await withSdkProxy({ delayMs: 300 }, async (client, api, dispatches) => {
    const controller = new AbortController();
    const cancelled = client.callTool({ name: "read_file", arguments: { path: "cancel-me" } }, undefined, { signal: controller.signal });
    const rejected = assert.rejects(cancelled);
    for (let attempt = 0; attempt < 100 && !api.receivedRequests.some((request) => request.path.endsWith("evaluate")); attempt++) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    controller.abort();
    await rejected;
    await new Promise((resolve) => setTimeout(resolve, 500));
    assert.deepEqual(await dispatches(), [], "cancelled requests must not reach the real SDK server");
    const result = await client.callTool({ name: "read_file", arguments: { path: "still-works" } });
    assert.equal(JSON.parse(result.content[0].text).path, "still-works");
  });
});

test("MCP rejects additional calls when its pending dispatch limit is reached", { timeout: 15000 }, async () => {
  await withSdkProxy({ env: { AUREL_MCP_MAX_PENDING: "1" } }, async (client, api, dispatches) => {
    const first = client.callTool({ name: "read_file", arguments: { path: "first", hostDelay: 800 } });
    for (let attempt = 0; attempt < 100 && !(await dispatches()).length; attempt++) await new Promise((resolve) => setTimeout(resolve, 10));
    await assert.rejects(client.callTool({ name: "read_file", arguments: { path: "overflow" } }));
    await first;
    assert.equal((await dispatches()).length, 1);
  });
});

test("MCP records a structured SDK tool error as failure telemetry", { timeout: 15000 }, async () => {
  await withSdkProxy({ env: { AUREL_TELEMETRY_ENABLED: "true" } }, async (client, api) => {
    const result = await client.callTool({ name: "read_file", arguments: { hostFailure: true } });
    assert.equal(result.isError, true);
    for (let attempt = 0; attempt < 100 && !api.receivedRequests.some((request) => request.path.endsWith("telemetry")); attempt++) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(api.receivedRequests.find((request) => request.path.endsWith("telemetry")).payload.outcome.status, "failure");
  });
});
