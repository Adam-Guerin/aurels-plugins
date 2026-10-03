import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, readdir, rm, utimes, writeFile } from "node:fs/promises";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { after, test } from "node:test";
import { resolve } from "node:path";

const hook = process.env.AURELS_CODEX_HOOK_BIN ?? resolve(import.meta.dirname, "../integrations/codex/aurel-codex-plugin/hooks/aurel-codex-hook.mjs");
const redactionCorpus = JSON.parse(readFileSync(new URL("./fixtures/redaction-corpus.json", import.meta.url), "utf8"));
const redactionInput = redactionCorpus.map(({ input }) => input).join(" | ");
const defaultStateDir = mkdtempSync(resolve(tmpdir(), "aurels-codex-hooks-"));
after(() => rm(defaultStateDir, { recursive: true, force: true }));

async function withServer(handler, run) {
  const server = createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try { await run(`http://127.0.0.1:${port}`); }
  finally { await new Promise((resolve) => server.close(resolve)); }
}

function runHook(apiUrl, input, failMode, stateDir, overrides = {}) {
  return new Promise((done, reject) => {
    const child = spawn(process.execPath, [hook], {
      env: { ...process.env, AURELS_API_URL: apiUrl, AURELS_API_KEY: "e2e-fake-key", AUREL_STATE_DIR: stateDir ?? defaultStateDir, AUREL_TIMEOUT_MS: "1000", AUREL_TELEMETRY_ENABLED: "true", AUREL_FAIL_MODE: failMode, ...overrides },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (status) => done({ status, stdout, stderr }));
    child.stdin.end(typeof input === "string" ? input : JSON.stringify(input));
  });
}

function invoke(apiUrl, decision, toolName = "Bash", failMode, stateDir, toolUseId = "e2e-call-1", overrides) {
  return runHook(apiUrl, { hook_event_name: "PreToolUse", tool_name: toolName, tool_use_id: toolUseId, tool_input: { command: "echo harmless", testDecision: decision }, session_id: "e2e-session" }, failMode, stateDir, overrides);
}

test("Codex rejects malformed allow metadata and unsupported decisions even in fail-open mode", async () => {
  let response = { decision: "allow", riskScore: true };
  await withServer((req, res) => res.writeHead(200, { "content-type": "application/json" }).end(typeof response === "string" ? response : JSON.stringify(response)), async (url) => {
    for (const decision of [{ decision: "allow", riskScore: true }, { decision: "unknown" }, { decision: "allow", traceId: {} }, "invalid JSON"]) {
      response = decision;
      const result = await invoke(url, "allow", "read_file", "open");
      assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, "deny");
    }
  });
});

test("Codex PreToolUse allows only an explicit allow response", async () => {
  let responseDecision = "allow";
  await withServer((req, res) => {
    assert.equal(req.headers["x-api-key"], "e2e-fake-key");
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ decision: responseDecision }));
  }, async (url) => {
    const allowed = await invoke(url, "allow");
    assert.equal(allowed.status, 0, allowed.stderr);
    assert.equal(JSON.parse(allowed.stdout).hookSpecificOutput.permissionDecision, "allow", `${allowed.stdout} ${allowed.stderr}`);
    responseDecision = "block";
    const blocked = await invoke(url, "block");
    assert.equal(blocked.status, 0, blocked.stderr);
    assert.equal(JSON.parse(blocked.stdout).hookSpecificOutput.permissionDecision, "deny");
  });
});

test("Codex approval and rewrite decisions deny rather than fail open", async () => {
  let responseDecision = "flag";
  await withServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ decision: responseDecision }));
  }, async (url) => {
    for (const decision of ["flag", "require_approval", "rewrite", "quarantine"]) {
      responseDecision = decision;
      const result = await invoke(url, decision);
      assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, "deny", decision);
    }
  });
});

test("Codex denies malformed and oversized hook input before any policy request", async () => {
  const malformed = await runHook("http://127.0.0.1:1", "{broken-json");
  assert.equal(malformed.status, 0, malformed.stderr);
  assert.equal(JSON.parse(malformed.stdout).hookSpecificOutput.permissionDecision, "deny");

  const oversized = await runHook("http://127.0.0.1:1", {
    hook_event_name: "PreToolUse", tool_name: "Bash", tool_use_id: "too-large",
    tool_input: { body: "x".repeat(1_100_000) },
  });
  assert.equal(oversized.status, 0, oversized.stderr);
  assert.equal(JSON.parse(oversized.stdout).hookSpecificOutput.permissionDecision, "deny");
});

test("Codex rejects redirects and does not forward the API key", async () => {
  let redirected = false;
  const target = createServer((req, res) => { redirected = Boolean(req.headers["x-api-key"]); res.end("{}"); });
  await new Promise((resolve) => target.listen(0, "127.0.0.1", resolve));
  const port = target.address().port;
  try {
    await withServer((req, res) => {
      res.writeHead(303, { location: `http://127.0.0.1:${port}/steal` });
      res.end();
    }, async (url) => {
      const result = await invoke(url, "allow");
      assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, "deny");
      assert.equal(redirected, false);
    });
  } finally { await new Promise((resolve) => target.close(resolve)); }
});

test("Codex bounds a chunked oversized decision body while streaming", async () => {
  await withServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ decision: "allow", padding: "x".repeat(1_100_000) }));
  }, async (url) => {
    const result = await invoke(url, "allow");
    assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, "deny");
  });
});

test("Codex fails closed on outage and only permits benign fail-open fallback", async () => {
  const unavailable = createServer();
  await new Promise((resolve) => unavailable.listen(0, "127.0.0.1", resolve));
  const port = unavailable.address().port;
  await new Promise((resolve) => unavailable.close(resolve));
  const endpoint = `http://127.0.0.1:${port}`;

  const closed = await invoke(endpoint, "allow", "Bash");
  assert.equal(JSON.parse(closed.stdout).hookSpecificOutput.permissionDecision, "deny");
  const privilegedFailOpen = await invoke(endpoint, "allow", "Bash", "open");
  assert.equal(JSON.parse(privilegedFailOpen.stdout).hookSpecificOutput.permissionDecision, "deny");
  const benignFailOpen = await invoke(endpoint, "allow", "summarize", "open");
  assert.equal(JSON.parse(benignFailOpen.stdout).hookSpecificOutput.permissionDecision, "allow");
});

test("Codex keeps postflight correlation without traceId and classifies structured tool failures", async () => {
  const stateDir = await mkdtemp(resolve(tmpdir(), "aurels-codex-lifecycle-"));
  const received = [];
  try {
    await withServer((req, res) => {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const payload = JSON.parse(Buffer.concat(chunks).toString());
        received.push({ path: req.url, payload });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(req.url.endsWith("/evaluate") ? { decision: "allow" } : {}));
      });
    }, async (url) => {
      const before = await invoke(url, "allow", "Bash", undefined, stateDir);
      assert.equal(JSON.parse(before.stdout).hookSpecificOutput.permissionDecision, "allow");
      const after = await runHook(url, {
        hook_event_name: "PostToolUse", tool_name: "Bash", tool_use_id: "e2e-call-1",
        tool_input: { command: "synthetic-failing-tool" }, tool_response: { isError: true, message: "synthetic failure" },
      }, undefined, stateDir);
      assert.equal(after.status, 0, after.stderr);
    });
    assert.equal(received.length, 2);
    const event = received[1].payload;
    assert.equal(event.actionId, "e2e-call-1");
    assert.equal(event.traceId, undefined);
    assert.equal(event.outcome.status, "failure");
    assert.equal(event.outcome.errorCategory, "tool_error");
    assert.equal(event.metadata.completionStatus, "failure");
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("Codex marks unstructured post-tool responses as indeterminate in metadata", async () => {
  const stateDir = await mkdtemp(resolve(tmpdir(), "aurels-codex-indeterminate-"));
  const received = [];
  try {
    await withServer((req, res) => {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const payload = JSON.parse(Buffer.concat(chunks).toString());
        received.push(payload);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(req.url.endsWith("/evaluate") ? { decision: "allow", traceId: "trace-1" } : {}));
      });
    }, async (url) => {
      await invoke(url, "allow", "Bash", undefined, stateDir);
      await runHook(url, { hook_event_name: "PostToolUse", tool_name: "Bash", tool_use_id: "e2e-call-1", tool_input: { command: "sh -c exit-3", message: redactionInput }, tool_response: "" }, undefined, stateDir);
    });
    const event = received[1];
    assert.equal(event.outcome.status, "success");
    assert.equal(event.outcome.errorCategory, "host_status_unavailable");
    assert.equal(event.metadata.completionStatus, "unknown");
    for (const { name, secret } of redactionCorpus) assert.equal(event.metadata.args.message.includes(secret), false, name);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("Codex bounds persisted postflight correlation when PostToolUse callbacks are lost", async () => {
  const stateDir = await mkdtemp(resolve(tmpdir(), "aurels-codex-overflow-"));
  try {
    const oldTime = new Date(Date.now() - 48 * 60 * 60 * 1000);
    const newTime = new Date(Date.now() - 24 * 60 * 60 * 1000);
    for (let index = 0; index < 1024; index++) {
      const file = resolve(stateDir, `orphan-${index}.json`);
      await writeFile(file, "{}", "utf8");
      await utimes(file, index === 0 ? oldTime : newTime, index === 0 ? oldTime : newTime);
    }
    await withServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ decision: "allow" }));
    }, async (url) => {
      const result = await invoke(url, "allow", "Bash", undefined, stateDir);
      assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, "allow");
    });
    const entries = await readdir(stateDir);
    const current = `${createHash("sha256").update("e2e-call-1").digest("hex")}.json`;
    assert.equal(entries.length, 1024);
    assert.equal(entries.includes(current), true);
    assert.equal(entries.includes("orphan-0.json"), false);
    assert.equal(entries.includes("orphan-1023.json"), true);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("Codex enforces the persisted-state cap across concurrent PreToolUse processes", async () => {
  const stateDir = await mkdtemp(resolve(tmpdir(), "aurels-codex-concurrent-overflow-"));
  try {
    const oldTime = new Date(Date.now() - 48 * 60 * 60 * 1000);
    for (let index = 0; index < 1024; index++) {
      const file = resolve(stateDir, `orphan-${index}.json`);
      await writeFile(file, "{}", "utf8");
      await utimes(file, oldTime, oldTime);
    }
    await withServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ decision: "allow" }));
    }, async (url) => {
      const calls = Array.from({ length: 8 }, (_, index) => invoke(url, "allow", "Bash", undefined, stateDir, `parallel-${index}`, { AUREL_TIMEOUT_MS: "5000" }));
      const results = await Promise.all(calls);
      for (const result of results) {
        assert.equal(result.status, 0, result.stderr);
        assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, "allow", `${result.stdout} ${result.stderr}`);
      }
    });
    const entries = await readdir(stateDir);
    assert.equal(entries.length, 1024);
    for (let index = 0; index < 8; index++) {
      const id = createHash("sha256").update(`parallel-${index}`).digest("hex");
      assert.equal(entries.includes(`${id}.json`), true, `recent concurrent state ${index} should remain correlated`);
    }
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("Codex recovers a stale correlation lock after a hook process crashes", async () => {
  const stateDir = await mkdtemp(resolve(tmpdir(), "aurels-codex-stale-lock-"));
  const lockPath = resolve(stateDir, ".aurels-state.lock");
  const callId = "after-crash-recovery";
  try {
    await writeFile(lockPath, "", "utf8");
    const expired = new Date(Date.now() - 60_000);
    await utimes(lockPath, expired, expired);
    await withServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ decision: "allow", traceId: "recovered-trace" }));
    }, async (url) => {
      const result = await invoke(url, "allow", "Bash", undefined, stateDir, callId);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(JSON.parse(result.stdout).hookSpecificOutput.permissionDecision, "allow");
    });
    const entries = await readdir(stateDir);
    const correlation = `${createHash("sha256").update(callId).digest("hex")}.json`;
    assert.equal(entries.includes(".aurels-state.lock"), false);
    assert.equal(entries.includes(correlation), true);
  } finally {
    await rm(stateDir, { recursive: true, force: true });
  }
});

test("portable Codex and Claude plugin manifests point at packaged hooks", async () => {
  const codexRoot = resolve(import.meta.dirname, "../integrations/codex/aurel-codex-plugin");
  const codexManifest = JSON.parse(await readFile(resolve(codexRoot, "plugin.json"), "utf8"));
  const codexHooks = JSON.parse(await readFile(resolve(codexRoot, "hooks/hooks.json"), "utf8"));
  assert.equal(codexManifest.extensions["com.openai"].hooks, "./hooks/hooks.json");
  assert.equal(codexHooks.hooks.PreToolUse[0].hooks[0].command.includes("${PLUGIN_ROOT}"), true);

  const claudeRoot = resolve(import.meta.dirname, "../integrations/claude-code");
  const claudeManifest = JSON.parse(await readFile(resolve(claudeRoot, ".claude-plugin/plugin.json"), "utf8"));
  const claudeHooks = JSON.parse(await readFile(resolve(claudeRoot, "hooks/hooks.json"), "utf8"));
  assert.equal(claudeManifest.name, "aurels-claude-code");
  assert.equal(claudeHooks.hooks.PreToolUse[0].hooks[0].command.includes("${CLAUDE_PLUGIN_ROOT}"), true);
});
