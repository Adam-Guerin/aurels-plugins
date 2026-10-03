import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { test } from "node:test";
import { pathToFileURL } from "node:url";

const moduleUrl = process.env.AURELS_EVALUATOR_MODULE
  ? pathToFileURL(process.env.AURELS_EVALUATOR_MODULE).href : new URL("../plugins/aurels-evaluator/src/server.mjs", import.meta.url).href;
const implementation = await import(moduleUrl).catch((error) => {
  if (error.code === "ERR_MODULE_NOT_FOUND") return null;
  throw error;
});
const action = { version: "1", integration: "fixture", action: { id: "call-1", name: "read_file", arguments: { path: "été.txt" } }, timestamp: "2026-10-03T00:00:00Z" };
const choice = (decision = "allow", confidence = .97) => ({ answers: { decision: { type: "choice", choice: decision, confidence, probabilities: Object.fromEntries(["allow", "flag", "block"].map((label) => [label, label === decision ? confidence : (1 - confidence) / 2])) } } });

async function serve(server, run) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try { return await run(`http://127.0.0.1:${server.address().port}`); }
  finally { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
}

async function upstream(handler, run) {
  const requests = [];
  return serve(createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const request = { path: req.url, headers: req.headers, body: JSON.parse(raw) };
    requests.push(request);
    await handler(request, res);
  }), (url) => run(url, requests));
}

async function gateway(apiUrl, options, run) {
  assert.ok(implementation?.createEvaluatorServer, "the self-hosted evaluator must exist");
  return serve(implementation.createEvaluatorServer({ provider: "jev", apiUrl, apiKey: "provider-key", token: "fixture-local-token", model: "jev-latest", timeoutMs: 500, allowTools: ["read_file"], ...options }), run);
}

async function evaluate(url, input = action, token = "fixture-local-token") {
  const response = await fetch(`${url}/api/v1/actions/evaluate`, { method: "POST", headers: { "content-type": "application/json", "x-api-key": token }, body: typeof input === "string" ? input : JSON.stringify(input) });
  return { status: response.status, body: await response.json() };
}

test("Jev evaluation uses the owner's Bearer key and preserves the exact action without Aurels forwarding", async () => {
  await upstream((_, res) => res.end(JSON.stringify(choice())), async (apiUrl, requests) => {
    await gateway(apiUrl, {}, async (url) => {
      const result = await evaluate(url);
      assert.equal(result.body.decision, "allow");
      assert.equal(requests.length, 1);
      assert.equal(requests[0].path, "/v1/systemone");
      assert.equal(requests[0].headers.authorization, "Bearer provider-key");
      assert.equal(requests[0].headers["x-api-key"], undefined);
      assert.deepEqual(requests[0].body.state.action, action.action);
      assert.equal(requests[0].body.questions.decision.type, "choice");
      assert.deepEqual(Object.keys(requests[0].body.questions.decision.criteria).sort(), ["allow", "block", "flag"]);
      assert.equal(result.body.metadata.provider, "jev");
    });
  });
});

test("Laya uses its System One server and can run without a provider API key", async () => {
  await upstream((_, res) => res.end(JSON.stringify(choice("block"))), async (apiUrl, requests) => {
    await gateway(apiUrl, { provider: "laya", apiKey: "", model: "multilingual" }, async (url) => {
      assert.equal((await evaluate(url)).body.decision, "block");
      assert.equal(requests[0].path, "/v1/systemone");
      assert.equal(requests[0].body.model, "multilingual");
      assert.equal(requests[0].headers.authorization, undefined);
    });
  });
});

test("Ollama receives a non-streaming chat request with a decision schema", async () => {
  await upstream((_, res) => res.end(JSON.stringify({ message: { content: JSON.stringify({ decision: "allow", confidence: .98 }) } })), async (apiUrl, requests) => {
    await gateway(apiUrl, { provider: "ollama", model: "fixture-local-model", apiKey: "" }, async (url) => {
      assert.equal((await evaluate(url)).body.decision, "allow");
      assert.equal(requests[0].path, "/api/chat");
      assert.equal(requests[0].body.model, "fixture-local-model");
      assert.equal(requests[0].body.stream, false);
      assert.equal(requests[0].body.format.type, "object");
      assert.deepEqual(JSON.parse(requests[0].body.messages[1].content).action, action.action);
    });
  });
});

test("OpenAI-compatible local models use the configured base path and structured output", async () => {
  await upstream((_, res) => res.end(JSON.stringify({ choices: [{ message: { content: '{"decision":"flag","confidence":0.95}' } }] })), async (apiUrl, requests) => {
    await gateway(`${apiUrl}/v1`, { provider: "openai-compatible", model: "fixture-model" }, async (url) => {
      assert.equal((await evaluate(url)).body.decision, "flag");
      assert.equal(requests[0].path, "/v1/chat/completions");
      assert.equal(requests[0].body.response_format.type, "json_schema");
    });
  });
});

test("uncertain model allow and tools outside the local allowlist require approval", async () => {
  await upstream((_, res) => res.end(JSON.stringify(choice("allow", .6))), async (apiUrl) => {
    await gateway(apiUrl, {}, async (url) => assert.equal((await evaluate(url)).body.decision, "flag"));
  });
  await upstream((_, res) => res.end(JSON.stringify(choice())), async (apiUrl) => {
    await gateway(apiUrl, {}, async (url) => assert.equal((await evaluate(url, { ...action, action: { ...action.action, name: "send_email" } })).body.decision, "flag"));
  });
});

test("malformed model output and provider failures return an explicit block without fallback", async () => {
  for (const body of ["invalid JSON", JSON.stringify({ answers: {} }), JSON.stringify(choice("unexpected")), JSON.stringify(choice("allow", true))]) {
    await upstream((_, res) => res.end(body), async (apiUrl, requests) => {
      await gateway(apiUrl, {}, async (url) => {
        const result = await evaluate(url);
        assert.equal(result.status, 200);
        assert.equal(result.body.decision, "block");
        assert.equal(requests.length, 1);
      });
    });
  }
  await upstream((_, res) => res.writeHead(503).end("synthetic-sensitive-provider-error"), async (apiUrl) => {
    await gateway(apiUrl, {}, async (url) => {
      const result = await evaluate(url);
      assert.equal(result.body.decision, "block");
      assert.doesNotMatch(JSON.stringify(result), /sensitive|provider-key|fixture-local-token/);
    });
  });
});

test("authentication and invalid actions stop before any model request", async () => {
  await upstream((_, res) => res.end(JSON.stringify(choice())), async (apiUrl, requests) => {
    await gateway(apiUrl, {}, async (url) => {
      assert.equal((await evaluate(url, action, "wrong-token")).status, 401);
      assert.equal((await evaluate(url, { action: { name: "read_file", arguments: [] } })).body.decision, "block");
      assert.equal((await evaluate(url, "{broken-json")).body.decision, "block");
      assert.equal(requests.length, 0);
    });
  });
});

test("redirects never forward the provider key to another server", async () => {
  await upstream((_, res) => res.end(JSON.stringify(choice())), async (target, targetRequests) => {
    await upstream((_, res) => res.writeHead(307, { location: `${target}/collect` }).end(), async (apiUrl) => {
      await gateway(apiUrl, {}, async (url) => assert.equal((await evaluate(url)).body.decision, "block"));
    });
    assert.equal(targetRequests.length, 0);
  });
});

test("slow providers are aborted and block within the deadline", async () => {
  await upstream((_, res) => { setTimeout(() => res.end(JSON.stringify(choice())), 250).unref(); }, async (apiUrl) => {
    await gateway(apiUrl, { timeoutMs: 50 }, async (url) => {
      const started = Date.now();
      assert.equal((await evaluate(url)).body.decision, "block");
      assert.ok(Date.now() - started < 500);
    });
  });
});

test("telemetry remains local and reports that storage is disabled", async () => {
  await upstream((_, res) => res.end(JSON.stringify(choice())), async (apiUrl, requests) => {
    await gateway(apiUrl, {}, async (url) => {
      const response = await fetch(`${url}/api/v1/actions/telemetry`, { method: "POST", headers: { "x-api-key": "fixture-local-token", "content-type": "application/json" }, body: JSON.stringify({ actionId: "fixture" }) });
      assert.equal((await response.json()).accepted, false);
      assert.equal(requests.length, 0);
    });
  });
});

test("context budgets stop oversized actions and oversized provider streams are cancelled immediately", async () => {
  await upstream((_, res) => res.end(JSON.stringify(choice())), async (apiUrl, requests) => {
    await gateway(apiUrl, {}, async (url) => {
      assert.equal((await evaluate(url, { ...action, context: { data: "x".repeat(20_000) } })).body.decision, "block");
      assert.equal(requests.length, 0);
    });
  });
  let disconnected;
  const providerClosed = new Promise((done) => { disconnected = done; });
  await upstream((_, res) => {
    res.on("close", disconnected);
    res.writeHead(200, { "content-length": String(1024 * 1024 + 1), "content-type": "application/json" });
    res.write("{");
  }, async (apiUrl) => {
    await gateway(apiUrl, { timeoutMs: 2000 }, async (url) => {
      assert.equal((await evaluate(url)).body.decision, "block");
      await Promise.race([providerClosed, new Promise((_, reject) => { const deadline = setTimeout(() => reject(new Error("oversized provider stream left running")), 500); deadline.unref(); })]);
    });
  });
});

test("unsafe endpoint URLs and missing credentials cannot start an evaluator", () => {
  assert.ok(implementation?.createEvaluatorServer, "the self-hosted evaluator must exist");
  for (const options of [{ provider: "jev", apiKey: "" }, { provider: "unknown" }, { apiUrl: "http://public.example" }, { apiUrl: "https://user:password@example.com" }, { token: "" }]) {
    assert.throws(() => implementation.createEvaluatorServer({ provider: "jev", apiUrl: "https://api.typesafe.ai", apiKey: "fixture", token: "fixture-local-token", model: "jev-latest", ...options }));
  }
});

test("inconsistent typed probabilities cannot authorize an action", async () => {
  const inconsistent = { answers: { decision: { type: "choice", choice: "allow", confidence: .99, probabilities: { allow: .01, flag: .01, block: .98 } } } };
  await upstream((_, res) => res.end(JSON.stringify(inconsistent)), async (apiUrl) => {
    await gateway(apiUrl, {}, async (url) => assert.equal((await evaluate(url)).body.decision, "block"));
  });
});

test("Laya gates on the answer probability rather than entropy confidence", async () => {
  const result = choice("allow", .97);
  result.answers.decision.confidence = .79;
  result.answers.decision.answer_confidence = .97;
  result.usage = { truncated: false, state_tokens_dropped: 0 };
  await upstream((_, res) => res.end(JSON.stringify(result)), async (apiUrl, requests) => {
    await gateway(apiUrl, { provider: "laya", model: "multilingual", apiKey: "" }, async (url) => {
      assert.equal((await evaluate(url)).body.decision, "allow");
      assert.equal(requests[0].body.min_confidence, .85);
    });
  });
});

test("Jev normalizes its confidence independently of the selected probability", async () => {
  const result = choice("allow", .97);
  result.answers.decision.confidence = .955;
  await upstream((_, res) => res.end(JSON.stringify(result)), async (apiUrl) => {
    await gateway(apiUrl, {}, async (url) => assert.equal((await evaluate(url)).body.metadata.confidence, .97));
  });
});

test("unfinished chat responses and additional decision fields cannot authorize execution", async () => {
  const valid = '{"decision":"allow","confidence":0.99}';
  for (const [provider, result] of [
    ["ollama", { done: false, message: { content: valid } }],
    ["ollama", { message: { content: '{"decision":"allow","confidence":0.99,"rewrite":"unsafe"}' } }],
    ["openai-compatible", { choices: [{ finish_reason: "length", message: { content: valid } }] }],
    ["openai-compatible", { choices: [{ finish_reason: "stop", message: { content: valid, refusal: "declined" } }] }],
  ]) {
    await upstream((_, res) => res.end(JSON.stringify(result)), async (apiUrl) => {
      await gateway(apiUrl, { provider, apiKey: "", model: "fixture" }, async (url) => assert.equal((await evaluate(url)).body.decision, "block"));
    });
  }
});

test("truncated Laya input and abstained answers never authorize execution", async () => {
  for (const variant of ["truncated", "abstained", "hidden-truncation"]) {
    const result = choice();
    result.usage = { truncated: variant === "truncated", state_tokens_dropped: variant === "truncated" ? 50 : 0 };
    if (variant === "abstained") result.answers.decision.abstention = "abstained";
    if (variant === "hidden-truncation") delete result.usage;
    await upstream((_, res) => res.end(JSON.stringify(result)), async (apiUrl) => {
      await gateway(apiUrl, { provider: "laya", model: "multilingual", apiKey: "" }, async (url) => assert.notEqual((await evaluate(url)).body.decision, "allow"));
    });
  }
});

test("pending evaluations are bounded and client disconnect aborts the provider request", async () => {
  let started;
  let disconnected;
  const providerStarted = new Promise((done) => { started = done; });
  const providerDisconnected = new Promise((done) => { disconnected = done; });
  await upstream((_, res) => { started(); res.on("close", disconnected); }, async (apiUrl, requests) => {
    await gateway(apiUrl, { maxConcurrent: 1, timeoutMs: 2000 }, async (url) => {
      const controller = new AbortController();
      const first = fetch(`${url}/api/v1/actions/evaluate`, { method: "POST", signal: controller.signal,
        headers: { "x-api-key": "fixture-local-token" }, body: JSON.stringify(action) });
      const rejection = assert.rejects(first);
      await providerStarted;
      const overflow = await evaluate(url);
      assert.equal(overflow.body.decision, "block");
      assert.equal(overflow.body.category, "evaluator_busy");
      assert.equal(requests.length, 1);
      controller.abort();
      await rejection;
      await Promise.race([providerDisconnected, new Promise((_, reject) => setTimeout(() => reject(new Error("Provider was not cancelled")), 1000).unref())]);
    });
  });
});
