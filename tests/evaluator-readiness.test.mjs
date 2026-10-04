import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

const serverUrl = process.env.AURELS_EVALUATOR_MODULE ? pathToFileURL(process.env.AURELS_EVALUATOR_MODULE) : new URL("../plugins/aurels-evaluator/src/server.mjs", import.meta.url);
const { createEvaluatorServer } = await import(serverUrl.href);
const readiness = await import(new URL("./readiness.mjs", serverUrl).href).catch((error) => { if (error.code === "ERR_MODULE_NOT_FOUND") return null; throw error; });
const config = { provider: "ollama", model: "fixture", token: "local-readiness-test-token", apiKey: "", timeoutMs: 500 };

async function serve(server, run) {
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  try { await run(`http://127.0.0.1:${server.address().port}`); }
  finally { server.closeAllConnections(); await new Promise((done) => server.close(done)); }
}

async function fixture(providerReply, run) {
  await serve(createServer(async (req, res) => {
    let raw = ""; for await (const chunk of req) raw += chunk;
    const state = JSON.parse(JSON.parse(raw).messages[1].content);
    const answer = providerReply(state);
    res.end(JSON.stringify({ done: true, message: { content: JSON.stringify(answer) } }));
  }), (apiUrl) => serve(createEvaluatorServer({ ...config, apiUrl }), run));
}

test("deployment verification exercises safe and refused actions through authenticated model inference", async () => {
  assert.ok(readiness?.verifyEvaluator, "real inference verification must exist");
  const seen = [];
  await fixture((state) => { seen.push(state.action); return { decision: state.action.arguments.path.endsWith("public-readme.txt") ? "allow" : "block", confidence: .98 }; }, async (url) => {
    const report = await readiness.verifyEvaluator(url, config);
    assert.equal(report.passed, true);
    assert.ok(report.checks.length >= 5);
    assert.equal(seen.length, report.checks.length);
    assert.ok(report.checks.every((check) => check.passed));
    assert.doesNotMatch(JSON.stringify(report), /local-readiness-test-token|Bearer|fixture-private-secret/);
  });
});

test("an unavailable model cannot pass negative readiness checks by returning a transport block", async () => {
  assert.ok(readiness?.verifyEvaluator, "real inference verification must exist");
  await serve(createServer((req, res) => res.writeHead(503).end("fixture-private-secret")), (apiUrl) => serve(createEvaluatorServer({ ...config, apiUrl }), async (url) => {
    const report = await readiness.verifyEvaluator(url, config);
    assert.equal(report.passed, false);
    assert.ok(report.checks.every((check) => !check.passed));
    assert.doesNotMatch(JSON.stringify(report), /fixture-private-secret/);
  }));
});

test("a model that approves credential extraction cannot pass deployment verification", async () => {
  assert.ok(readiness?.verifyEvaluator, "real inference verification must exist");
  await fixture(() => ({ decision: "allow", confidence: .99 }), async (url) => {
    const report = await readiness.verifyEvaluator(url, config);
    assert.equal(report.passed, false);
    assert.ok(report.checks.some((check) => !check.passed && check.decision === "allow"));
  });
});

test("deployment verification refuses a different configured model and the wrong access token", async () => {
  assert.ok(readiness?.verifyEvaluator, "real inference verification must exist");
  await fixture(() => ({ decision: "block", confidence: .99 }), async (url) => {
    await assert.rejects(readiness.verifyEvaluator(url, { ...config, model: "another-model" }));
    const report = await readiness.verifyEvaluator(url, { ...config, token: "wrong-local-token" });
    assert.equal(report.passed, false);
    assert.ok(report.checks.every((check) => !check.passed));
  });
});
