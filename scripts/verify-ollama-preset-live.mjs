// Optional real-weight smoke check: no tool executes and no cloud key is used.
import { randomUUID } from "node:crypto";
import { installPreset } from "../plugins/aurels-ollama/install.mjs";
import { createEvaluatorServer } from "../plugins/aurels-evaluator/src/server.mjs";
import { verifyEvaluator } from "../plugins/aurels-evaluator/src/readiness.mjs";
const apiUrl = process.env.AURELS_OLLAMA_URL ?? "http://127.0.0.1:11434";
const model = `aurels-preset-smoke-${randomUUID()}`;
const config = { provider: "ollama", apiUrl, model, token: randomUUID(), timeoutMs: 30_000 };
let installed = false;
let server;
try {
  const installation = await installPreset({ baseUrl: apiUrl, model });
  installed = true;
  server = createEvaluatorServer(config);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const report = await verifyEvaluator(`http://127.0.0.1:${server.address().port}`, config);
  console.log(JSON.stringify({ installation, verification: report }, null, 2));
  if (!report.passed) process.exitCode = 1;
} finally {
  if (server) await new Promise((resolve) => server.close(resolve));
  if (installed) {
    const response = await fetch(new URL("/api/delete", apiUrl), { method: "DELETE", redirect: "error", signal: AbortSignal.timeout(10_000), headers: { "content-type": "application/json" }, body: JSON.stringify({ model }) });
    if (!response.ok) throw new Error("Could not remove the disposable smoke-test model");
  }
}
