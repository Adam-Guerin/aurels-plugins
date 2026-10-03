import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdtemp, readdir, rm, utimes, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { createAurelHarnessServer } from "../integrations/dev-harness/mock-aurel-server.mjs";

const claudeHook = process.env.AURELS_CLAUDE_HOOK_BIN ?? fileURLToPath(new URL("../integrations/claude-code/hooks/aurel-hook.mjs", import.meta.url));
const mcpProxy = process.env.AUREL_MCP_PROXY_BIN
  ? resolve(process.env.AUREL_MCP_PROXY_BIN)
  : fileURLToPath(new URL("../integrations/mcp/src/aurel-mcp-proxy.mjs", import.meta.url));
const redactionCorpus = JSON.parse(readFileSync(new URL("./fixtures/redaction-corpus.json", import.meta.url), "utf8"));
const redactionInput = redactionCorpus.map(({ input }) => input).join(" | ");

async function withHarness(run) {
  const server = createAurelHarnessServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    await run(`http://127.0.0.1:${server.address().port}`, server);
  } finally {
    server.close();
    await once(server, "close");
  }
}

function testEnv(apiUrl, overrides = {}) {
  return {
    ...process.env,
    AUREL_API_URL: apiUrl,
    AUREL_API_KEY: "synthetic-test-key",
    AUREL_MCP_TRANSPORT: "content-length",
    AUREL_ENABLED: "true",
    AUREL_FAIL_MODE: "closed",
    AUREL_TELEMETRY_ENABLED: "false",
    AUREL_TOOLS_INCLUDE: "",
    AUREL_TOOLS_EXCLUDE: "",
    ...overrides,
  };
}

function runClaudeHook(apiUrl, input, overrides = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [claudeHook], { env: testEnv(apiUrl, overrides), stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => {
      if (code !== 0) return reject(new Error(`Claude hook exited ${code}: ${stderr}`));
      try { resolve(JSON.parse(stdout)); } catch (error) { reject(new Error(`Invalid Claude hook response: ${stdout} ${stderr}`, { cause: error })); }
    });
    child.stdin.end(typeof input === "string" ? input : JSON.stringify(input));
  });
}

function runClaudePostflight(apiUrl, input, overrides = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [claudeHook], { env: testEnv(apiUrl, overrides), stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve() : reject(new Error(`Claude postflight exited ${code}: ${stderr}`)));
    child.stdin.end(JSON.stringify(input));
  });
}

function frame(message) {
  const body = JSON.stringify(message);
  return `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
}

function firstFrame(stream, child) {
  return new Promise((resolve, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => reject(new Error("Timed out waiting for MCP response")), 4000);
    stream.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd < 0) return;
      const header = buffer.subarray(0, headerEnd).toString("ascii");
      const match = /content-length:\s*(\d+)/i.exec(header);
      if (!match) return reject(new Error(`Missing MCP Content-Length: ${header}`));
      const length = Number(match[1]);
      if (buffer.length < headerEnd + 4 + length) return;
      clearTimeout(timer);
      resolve(JSON.parse(buffer.subarray(headerEnd + 4, headerEnd + 4 + length).toString("utf8")));
    });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code) => {
      if (code !== 0) { clearTimeout(timer); reject(new Error(`MCP proxy exited ${code}`)); }
    });
  });
}

async function runMcpCall(apiUrl, name, args, envOverrides = {}) {
  const upstream = String.raw`
    let input = Buffer.alloc(0);
    process.stdin.on("data", chunk => {
      input = Buffer.concat([input, chunk]);
      const end = input.indexOf("\r\n\r\n");
      if (end < 0) return;
      const match = /content-length:\s*(\d+)/i.exec(input.subarray(0, end).toString("ascii"));
      if (!match) process.exit(3);
      const size = Number(match[1]);
      if (input.length < end + 4 + size) return;
      const message = JSON.parse(input.subarray(end + 4, end + 4 + size).toString("utf8"));
      const body = JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { content: [{ type: "text", text: JSON.stringify(message.params.arguments) }] } });
      process.stdout.write("Content-Length: " + Buffer.byteLength(body) + "\r\n\r\n" + body);
      process.exit(0);
    });
    setTimeout(() => process.exit(0), 2500);
  `;
  const child = spawn(process.execPath, [mcpProxy, "--", process.execPath, "-e", upstream], {
    env: testEnv(apiUrl, envOverrides),
    stdio: ["pipe", "pipe", "pipe"],
  });
  try {
    const responsePromise = firstFrame(child.stdout, child);
    const closePromise = once(child, "close");
    child.stdin.write(frame({ jsonrpc: "2.0", id: "dispatch-mcp-1", method: "tools/call", params: { name, arguments: args } }));
    const response = await responsePromise;
    await closePromise;
    return response;
  } finally {
    child.kill();
  }
}

test("Claude Code hook does not bypass Aurel for an aurel-prefixed tool name", async () => {
  await withHarness(async (apiUrl) => {
    const result = await runClaudeHook(apiUrl, {
      hook_event_name: "PreToolUse",
      tool_name: "aurel.exec",
      tool_use_id: "prefix-claude-1",
      tool_input: { command: "rm -rf /synthetic" },
      session_id: "synthetic-session",
      prompt_id: "synthetic-run",
    });
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  });
});

test("Claude Code rejects a malformed policy response even in fail-open mode", async () => {
  await withHarness(async (apiUrl) => {
    const result = await runClaudeHook(apiUrl, { hook_event_name: "PreToolUse", tool_name: "read_file",
      tool_input: { path: "invalid-response" }, tool_use_id: "protocol-claude" }, { AUREL_FAIL_MODE: "open" });
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  });
});

test("MCP rejects a malformed policy response even in fail-open mode", async () => {
  await withHarness(async (apiUrl) => {
    const response = await runMcpCall(apiUrl, "read_file", { path: "invalid-response" }, { AUREL_FAIL_MODE: "open" });
    assert.ok(response.error, "invalid protocol data must never authorize dispatch");
  });
});

test("Claude Code and MCP reject unreadable policy JSON even in fail-open mode", async () => {
  const server = createServer((req, res) => res.writeHead(200, { "content-type": "application/json" }).end("invalid JSON"));
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const url = `http://127.0.0.1:${server.address().port}`;
    const result = await runClaudeHook(url, { hook_event_name: "PreToolUse", tool_name: "read_file", tool_input: {} }, { AUREL_FAIL_MODE: "open" });
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
    const response = await runMcpCall(url, "read_file", {}, { AUREL_FAIL_MODE: "open" });
    assert.ok(response.error);
  } finally { server.close(); await once(server, "close"); }
});

test("Claude Code hook ignores the legacy exclusion bypass and blocks destructive input", async () => {
  await withHarness(async (apiUrl) => {
    const result = await runClaudeHook(apiUrl, {
      hook_event_name: "PreToolUse",
      tool_name: "Bash",
      tool_use_id: "exclude-claude-1",
      tool_input: { command: "rm -rf /synthetic" },
      session_id: "synthetic-session",
      prompt_id: "synthetic-run",
    }, { AUREL_TOOLS_EXCLUDE: "Bash" });
    assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  });
});

test("Claude Code rejects API redirects without forwarding the API key", async (t) => {
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
  const result = await runClaudeHook(`http://127.0.0.1:${redirector.address().port}`, {
    hook_event_name: "PreToolUse", tool_name: "Read", tool_use_id: "redirect-claude", tool_input: { file_path: "safe.txt" },
  });
  assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
  assert.equal(receivedApiKey, false);
});

test("Claude Code fails closed when the API stalls after response headers", async (t) => {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.flushHeaders();
    const timer = setTimeout(() => { if (!res.destroyed) res.end('{"decision":"allow"}'); }, 5000);
    res.once("close", () => clearTimeout(timer));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const result = await runClaudeHook(`http://127.0.0.1:${server.address().port}`, {
    hook_event_name: "PreToolUse", tool_name: "Read", tool_use_id: "body-timeout-claude", tool_input: { file_path: "safe.txt" },
  }, { AUREL_TIMEOUT_MS: "100" });
  assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
});

test("Claude Code evaluation idempotency binds a reused tool ID to its exact action", async () => {
  await withHarness(async (apiUrl, server) => {
    const base = { hook_event_name: "PreToolUse", tool_name: "Read", tool_use_id: "reused-claude-id", session_id: "synthetic-session" };
    await runClaudeHook(apiUrl, { ...base, tool_input: { file_path: "safe-a.txt" } });
    await runClaudeHook(apiUrl, { ...base, tool_input: { file_path: "safe-b.txt" } });
    const evaluations = server.receivedRequests.filter((request) => request.path === "/api/v1/actions/evaluate");
    assert.equal(evaluations.length, 2);
    assert.equal(evaluations[0].payload.action.id, evaluations[1].payload.action.id);
    assert.notEqual(evaluations[0].headers["idempotency-key"], evaluations[1].headers["idempotency-key"]);
  });
});

test("Claude Code sends the complete action arguments for policy evaluation", async () => {
  await withHarness(async (apiUrl, server) => {
    const toolInput = { file_path: "large.txt", content: "x".repeat(65_537) };
    await runClaudeHook(apiUrl, {
      hook_event_name: "PreToolUse", tool_name: "Write", tool_use_id: "large-claude", tool_input: toolInput,
    });
    const evaluation = server.receivedRequests.find((request) => request.path === "/api/v1/actions/evaluate");
    assert.deepEqual(evaluation?.payload.action.arguments, toolInput);
  });
});

test("Claude Code telemetry redacts credential formats embedded in ordinary fields", async () => {
  await withHarness(async (apiUrl, server) => {
    const id = `redaction-${Date.now()}`;
    const args = { message: redactionInput };
    await runClaudeHook(apiUrl, { hook_event_name: "PreToolUse", tool_name: "Read", tool_use_id: id, tool_input: args }, { AUREL_TELEMETRY_ENABLED: "true" });
    await runClaudePostflight(apiUrl, { hook_event_name: "PostToolUse", tool_name: "Read", tool_use_id: id, tool_input: args }, { AUREL_TELEMETRY_ENABLED: "true" });
    const telemetry = server.receivedRequests.find((request) => request.path === "/api/v1/actions/telemetry")?.payload;
    assert.ok(telemetry, "postflight telemetry should be sent");
    for (const { name, secret } of redactionCorpus) assert.equal(telemetry.metadata.args.message.includes(secret), false, name);
  });
});

test("MCP proxy sends complete action arguments to policy evaluation without truncating them", async () => {
  await withHarness(async (apiUrl, server) => {
    const argumentsValue = { content: "x".repeat(65_537) };
    await runMcpCall(apiUrl, "write_file", argumentsValue);
    const evaluations = server.receivedRequests.filter((request) => request.path === "/api/v1/actions/evaluate");
    assert.equal(evaluations.length, 1);
    assert.deepEqual(evaluations[0].payload.action.arguments, argumentsValue);
  });
});

test("Claude Code approval decisions return ask instead of executing the tool", async () => {
  await withHarness(async (apiUrl) => {
    const result = await runClaudeHook(apiUrl, {
      hook_event_name: "PreToolUse",
      tool_name: "send_email",
      tool_use_id: "approval-claude-1",
      tool_input: { to: "synthetic@example.test", body: "synthetic test only" },
      session_id: "synthetic-session",
      prompt_id: "synthetic-run",
    });
    assert.equal(result.hookSpecificOutput.permissionDecision, "ask");
  });
});

test("Claude Code fail-open still blocks destructive input behind a benign tool name", async () => {
  const result = await runClaudeHook("http://127.0.0.1:1", {
    hook_event_name: "PreToolUse",
    tool_name: "task",
    tool_use_id: "outage-claude-1",
    tool_input: { payload: { command: "rm -rf /synthetic" } },
    session_id: "synthetic-session",
    prompt_id: "synthetic-run",
  }, { AUREL_FAIL_MODE: "open", AUREL_TIMEOUT_MS: "100" });
  assert.equal(result.hookSpecificOutput.permissionDecision, "deny");
});

test("Claude Code bounds and serializes on-disk correlations across concurrent hooks", async () => {
  const stateDir = await mkdtemp(resolve(tmpdir(), "aurels-claude-state-cap-"));
  try {
    const ordinaryOld = new Date(Date.now() - 48 * 60 * 60 * 1000);
    const oldest = new Date(Date.now() - 72 * 60 * 60 * 1000);
    await Promise.all(Array.from({ length: 1024 }, async (_, index) => {
      const file = resolve(stateDir, `orphan-${index}.json`);
      await writeFile(file, "{}", "utf8");
      const mtime = index === 0 ? oldest : ordinaryOld;
      await utimes(file, mtime, mtime);
    }));
    await withHarness(async (apiUrl, server) => {
      const calls = Array.from({ length: 8 }, (_, index) => runClaudeHook(apiUrl, {
        hook_event_name: "PreToolUse", session_id: "concurrent-session", tool_name: "Read",
        tool_use_id: `claude-parallel-${index}`, tool_input: { file_path: `safe-${index}.txt` },
      }, { AUREL_STATE_DIR: stateDir }));
      const results = await Promise.all(calls);
      for (const result of results) assert.equal(result.hookSpecificOutput.permissionDecision, "allow");
      assert.equal(server.receivedRequests.filter((request) => request.path === "/api/v1/actions/evaluate").length, 8);
    });
    const entries = await readdir(stateDir);
    assert.equal(entries.length, 1024);
    assert.equal(entries.includes("orphan-0.json"), false, "oldest orphaned correlation should be evicted");
    for (let index = 0; index < 8; index++) {
      const id = createHash("sha256").update(`claude-parallel-${index}`).digest("hex");
      assert.equal(entries.includes(`${id}.json`), true, `fresh correlation ${index} should remain`);
    }
    assert.equal(entries.some((entry) => entry.includes("claude-parallel")), false, "tool call IDs must not appear in state filenames");
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("Claude Code recovers stale correlation locks after a crashed process", async () => {
  const stateDir = await mkdtemp(resolve(tmpdir(), "aurels-claude-stale-lock-"));
  try {
    const lockPath = resolve(stateDir, ".aurel-state.lock");
    await writeFile(lockPath, "", "utf8");
    const expired = new Date(Date.now() - 60_000);
    await utimes(lockPath, expired, expired);
    const callId = "claude-after-crash";
    await withHarness(async (apiUrl) => {
      const result = await runClaudeHook(apiUrl, {
        hook_event_name: "PreToolUse", session_id: "recovery-session", tool_name: "Read",
        tool_use_id: callId, tool_input: { file_path: "safe.txt" },
      }, { AUREL_STATE_DIR: stateDir });
      assert.equal(result.hookSpecificOutput.permissionDecision, "allow");
    });
    const entries = await readdir(stateDir);
    assert.equal(entries.includes(".aurel-state.lock"), false);
    assert.equal(entries.includes(`${createHash("sha256").update(callId).digest("hex")}.json`), true);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("MCP stdio proxy does not forward an aurel-prefixed blocked call upstream", async () => {
  await withHarness(async (apiUrl) => {
    const upstream = String.raw`
      let input = Buffer.alloc(0);
      process.stdin.on("data", chunk => {
        input = Buffer.concat([input, chunk]);
        const end = input.indexOf("\r\n\r\n");
        if (end < 0) return;
        const match = /content-length:\s*(\d+)/i.exec(input.subarray(0, end).toString("ascii"));
        if (!match) process.exit(3);
        const size = Number(match[1]);
        if (input.length < end + 4 + size) return;
        const message = JSON.parse(input.subarray(end + 4, end + 4 + size).toString("utf8"));
        const body = JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { content: [{ type: "text", text: "UPSTREAM_EXECUTED" }] } });
        process.stdout.write("Content-Length: " + Buffer.byteLength(body) + "\r\n\r\n" + body);
        process.exit(0);
      });
      setTimeout(() => process.exit(0), 2500);
    `;
    const child = spawn(process.execPath, [mcpProxy, "--", process.execPath, "-e", upstream], {
      env: testEnv(apiUrl),
      stdio: ["pipe", "pipe", "pipe"],
    });
    const responsePromise = firstFrame(child.stdout, child);
    child.stdin.write(frame({
      jsonrpc: "2.0",
      id: "prefix-mcp-1",
      method: "tools/call",
      params: { name: "aurel.exec", arguments: { command: "rm -rf /synthetic" } },
    }));
    const response = await responsePromise;
    assert.equal(response.id, "prefix-mcp-1");
    assert.equal(response.error.code, -32050);
    assert.doesNotMatch(JSON.stringify(response), /UPSTREAM_EXECUTED/);
    child.kill();
  });
});

test("MCP allow forwards the evaluated action to the real upstream dispatch seam unchanged", async () => {
  await withHarness(async (apiUrl) => {
    const args = { path: "/synthetic/readme.txt" };
    const response = await runMcpCall(apiUrl, "read_file", args);
    assert.equal(response.error, undefined);
    assert.deepEqual(JSON.parse(response.result.content[0].text), args);
  });
});

test("MCP telemetry redacts credential formats embedded in ordinary fields", async () => {
  await withHarness(async (apiUrl, server) => {
    const args = { message: redactionInput };
    const response = await runMcpCall(apiUrl, "read_file", args, { AUREL_TELEMETRY_ENABLED: "true" });
    assert.equal(response.error, undefined);
    const telemetry = server.receivedRequests.find((request) => request.path === "/api/v1/actions/telemetry")?.payload;
    assert.ok(telemetry, "MCP postflight telemetry should be sent");
    for (const { name, secret } of redactionCorpus) assert.equal(telemetry.metadata.args.message.includes(secret), false, name);
  });
});

test("MCP proxy rejects API redirects without forwarding the API key or dispatching upstream", async (t) => {
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
  const response = await runMcpCall(`http://127.0.0.1:${redirector.address().port}`, "read_file", { path: "safe.txt" });
  assert.equal(response.result, undefined);
  assert.ok(response.error, "failed preflight must prevent upstream dispatch");
  assert.equal(receivedApiKey, false);
});

test("MCP proxy times out while reading a stalled API body and never dispatches upstream", async (t) => {
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.flushHeaders();
    const timer = setTimeout(() => { if (!res.destroyed) res.end('{"decision":"allow"}'); }, 5000);
    res.once("close", () => clearTimeout(timer));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const response = await runMcpCall(`http://127.0.0.1:${server.address().port}`, "read_file", { path: "safe.txt" }, { AUREL_TIMEOUT_MS: "100" });
  assert.equal(response.result, undefined);
  assert.ok(response.error, "body timeout must fail closed before upstream dispatch");
});

test("MCP evaluation idempotency binds a reused JSON-RPC ID to its exact action", async () => {
  await withHarness(async (apiUrl, server) => {
    await runMcpCall(apiUrl, "read_file", { path: "safe-a.txt" });
    await runMcpCall(apiUrl, "read_file", { path: "safe-b.txt" });
    const evaluations = server.receivedRequests.filter((request) => request.path === "/api/v1/actions/evaluate");
    assert.equal(evaluations.length, 2);
    assert.equal(evaluations[0].payload.action.id, evaluations[1].payload.action.id);
    assert.notEqual(evaluations[0].headers["idempotency-key"], evaluations[1].headers["idempotency-key"]);
  });
});

test("MCP approval-required decisions never reach upstream dispatch", async () => {
  await withHarness(async (apiUrl) => {
    const response = await runMcpCall(apiUrl, "send_email", { to: "synthetic@example.test", body: "synthetic test only" });
    assert.equal(response.error.code, -32050);
    assert.match(response.error.message, /requires human approval/);
  });
});

test("MCP rewrite forwards only the replacement arguments to upstream dispatch", async () => {
  await withHarness(async (apiUrl) => {
    const response = await runMcpCall(apiUrl, "read_file", { path: "/synthetic/rewrite-me.txt" });
    assert.equal(response.error, undefined);
    assert.deepEqual(JSON.parse(response.result.content[0].text), {
      path: "/synthetic/rewrite-me.txt",
      rewritten_by: "aurel-harness",
    });
  });
});

test("MCP proxy ignores the legacy exclusion bypass and does not forward destructive calls", async () => {
  await withHarness(async (apiUrl) => {
    const upstream = String.raw`
      process.stdin.on("data", () => {
        const body = JSON.stringify({ jsonrpc: "2.0", id: "excluded-mcp-1", result: { content: [{ type: "text", text: "UPSTREAM_EXECUTED" }] } });
        process.stdout.write("Content-Length: " + Buffer.byteLength(body) + "\r\n\r\n" + body);
      });
      setTimeout(() => process.exit(0), 2500);
    `;
    const child = spawn(process.execPath, [mcpProxy, "--", process.execPath, "-e", upstream], {
      env: testEnv(apiUrl, { AUREL_TOOLS_EXCLUDE: "dangerous_tool" }),
      stdio: ["pipe", "pipe", "pipe"],
    });
    try {
      const responsePromise = firstFrame(child.stdout, child);
      child.stdin.write(frame({
        jsonrpc: "2.0",
        id: "excluded-mcp-1",
        method: "tools/call",
        params: { name: "dangerous_tool", arguments: { command: "rm -rf /synthetic" } },
      }));
      const response = await responsePromise;
      assert.equal(response.error.code, -32050);
      assert.doesNotMatch(JSON.stringify(response), /UPSTREAM_EXECUTED/);
    } finally {
      child.kill();
    }
  });
});

test("MCP fail-open still blocks destructive input behind a benign tool name", async () => {
  const upstream = String.raw`
    process.stdin.on("data", () => {
      const body = JSON.stringify({ jsonrpc: "2.0", id: "outage-mcp-1", result: { content: [{ type: "text", text: "UPSTREAM_EXECUTED" }] } });
      process.stdout.write("Content-Length: " + Buffer.byteLength(body) + "\r\n\r\n" + body);
    });
    setTimeout(() => process.exit(0), 2500);
  `;
  const child = spawn(process.execPath, [mcpProxy, "--", process.execPath, "-e", upstream], {
    env: testEnv("http://127.0.0.1:1", { AUREL_FAIL_MODE: "open", AUREL_TIMEOUT_MS: "100" }),
    stdio: ["pipe", "pipe", "pipe"],
  });
  try {
    const responsePromise = firstFrame(child.stdout, child);
    child.stdin.write(frame({
      jsonrpc: "2.0",
      id: "outage-mcp-1",
      method: "tools/call",
      params: { name: "task", arguments: { payload: { command: "rm -rf /synthetic" } } },
    }));
    const response = await responsePromise;
    assert.equal(response.error.code, -32051);
    assert.doesNotMatch(JSON.stringify(response), /UPSTREAM_EXECUTED/);
  } finally {
    child.kill();
  }
});
