import assert from "node:assert/strict";
import { test } from "node:test";
import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const cli = process.env.AURELS_EVALUATOR_BIN ?? resolve(import.meta.dirname, "../plugins/aurels-evaluator/src/cli.mjs");

test("setup writes plugin configuration without copying the provider key", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "aurels-evaluator-init-"));
  try {
    const result = spawnSync(process.execPath, [cli, "init", "--provider", "ollama", "--model", "fixture-model", "--directory", directory], {
      encoding: "utf8", env: { ...process.env, AURELS_MODEL_API_KEY: "synthetic-private-provider-key" },
    });
    assert.equal(result.status, 0, result.stderr);
    const config = JSON.parse(await readFile(resolve(directory, "config.json"), "utf8"));
    const environment = await readFile(resolve(directory, "plugin.env"), "utf8");
    assert.equal(config.provider, "ollama");
    assert.equal(config.model, "fixture-model");
    assert.ok(config.token.length >= 32);
    assert.match(environment, /AURELS_API_URL=http:\/\/127\.0\.0\.1:8788/);
    assert.match(environment, /AURELS_TELEMETRY_ENABLED=false/);
    assert.match(environment, /AUREL_TELEMETRY_ENABLED=false/);
    assert.match(environment, /AUREL_FAIL_MODE=closed/);
    assert.match(environment, new RegExp(`AURELS_API_KEY=${config.token}`));
    assert.doesNotMatch(JSON.stringify(config) + environment + result.stdout + result.stderr, /synthetic-private-provider-key/);
    assert.doesNotMatch(result.stdout, new RegExp(config.token));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("setup never overwrites an existing evaluator configuration", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "aurels-evaluator-preserve-"));
  try {
    const args = [cli, "init", "--provider", "laya", "--directory", directory];
    const initial = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.equal(initial.status, 0, initial.stderr);
    const original = await readFile(resolve(directory, "config.json"), "utf8");
    const retry = spawnSync(process.execPath, args, { encoding: "utf8" });
    assert.notEqual(retry.status, 0);
    assert.equal(await readFile(resolve(directory, "config.json"), "utf8"), original);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("installed CLI starts a loopback evaluator, checks health, and evaluates through the configured provider", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "aurels-evaluator-start-"));
  const provider = createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    assert.equal(req.url, "/api/chat");
    assert.equal(JSON.parse(raw).model, "fixture-model");
    res.end(JSON.stringify({ done: true, message: { content: JSON.stringify({ decision: "allow", confidence: .98 }) } }));
  });
  provider.listen(0, "127.0.0.1");
  await once(provider, "listening");
  const probe = createServer();
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const port = probe.address().port;
  await new Promise((done) => probe.close(done));
  let worker;
  try {
    const setup = spawnSync(process.execPath, [cli, "init", "--provider", "ollama", "--model", "fixture-model", "--api-url", `http://127.0.0.1:${provider.address().port}`, "--directory", directory, "--port", String(port)], { encoding: "utf8" });
    assert.equal(setup.status, 0, setup.stderr);
    const path = resolve(directory, "config.json");
    const config = JSON.parse(await readFile(path, "utf8"));
    worker = spawn(process.execPath, [cli, "start", "--config", path], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    const ready = new Promise((done, reject) => {
      worker.stdout.on("data", (chunk) => { output += chunk; if (output.includes("Evaluator listening")) done(); });
      worker.once("error", reject);
      worker.once("exit", (code) => reject(new Error(`CLI exited before ready: ${code}`)));
    });
    await Promise.race([ready, new Promise((_, reject) => { const deadline = setTimeout(() => reject(new Error("CLI did not start")), 5000); deadline.unref(); })]);
    const health = spawnSync(process.execPath, [cli, "check", "--config", path], { encoding: "utf8" });
    assert.equal(health.status, 0, health.stderr);
    assert.match(health.stdout, /Health check only/);
    const response = await fetch(`http://127.0.0.1:${port}/api/v1/actions/evaluate`, { method: "POST", headers: { "content-type": "application/json", "x-api-key": config.token }, body: JSON.stringify({ action: { id: "cli-call", name: "read_file", arguments: { path: "fixture" } } }) });
    assert.equal((await response.json()).decision, "allow");
    assert.doesNotMatch(output, new RegExp(config.token));
  } finally {
    if (worker && worker.exitCode === null) { const closed = once(worker, "close"); worker.kill(); await closed; }
    provider.closeAllConnections();
    await new Promise((done) => provider.close(done));
    await rm(directory, { recursive: true, force: true });
  }
});
