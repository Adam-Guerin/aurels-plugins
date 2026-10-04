#!/usr/bin/env node
import { parseArgs } from "node:util";
import { randomBytes } from "node:crypto";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createEvaluatorServer } from "./server.mjs";
import { resolveConfig } from "./config.mjs";
import { verifyEvaluator } from "./readiness.mjs";

const options = { provider: { type: "string" }, model: { type: "string" }, "api-url": { type: "string" },
  directory: { type: "string" }, config: { type: "string" }, port: { type: "string" }, help: { type: "boolean" } };
const pluginEnvironment = (config, port) => [
  "# Private local evaluator access token; this is NOT a cloud Aurels or model-provider key.",
  `AURELS_API_URL=http://127.0.0.1:${port}`, `AUREL_API_URL=http://127.0.0.1:${port}`,
  `AURELS_API_KEY=${config.token}`, `AUREL_API_KEY=${config.token}`, "AURELS_MODE=remote",
  "AURELS_TIMEOUT_MS=30000", "AUREL_TIMEOUT_MS=30000", "AUREL_FAIL_MODE=closed",
  "AURELS_TELEMETRY_ENABLED=false", "AUREL_TELEMETRY_ENABLED=false", "AURELS_TELEMETRY_DURABLE=false",
  "AURELS_MCP_EXECUTION_PERMITS=false", "AUREL_MCP_EXECUTION_PERMITS=false", "",
].join("\n");
const validPort = (value) => {
  const port = Number(value ?? 8788);
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error("Invalid port.");
  return port;
};

const initialize = async (values) => {
  const directory = resolve(values.directory ?? ".aurels-evaluator");
  const targets = [resolve(directory, "config.json"), resolve(directory, "plugin.env")];
  for (const target of targets) {
    try { await access(target); throw new Error("Configuration already exists; edit it instead."); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  const resolved = resolveConfig({ provider: values.provider ?? "jev", apiUrl: values["api-url"], model: values.model,
    token: randomBytes(32).toString("hex") }, { requireCredentials: false });
  const port = validPort(values.port);
  const config = { provider: resolved.provider, apiUrl: resolved.apiUrl, model: resolved.model,
    apiKeyEnv: resolved.provider === "jev" ? "TYPESAFE_API_KEY" : resolved.provider === "laya" ? "LAYA_API_KEY" : "AURELS_MODEL_API_KEY",
    token: resolved.token, port, policy: resolved.policy, allowTools: [...resolved.allowTools],
    timeoutMs: resolved.timeoutMs, minConfidence: resolved.minConfidence, maxConcurrent: resolved.maxConcurrent,
    maxActionBytes: resolved.maxActionBytes };
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(targets[0], JSON.stringify(config, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  await writeFile(targets[1], pluginEnvironment(config, port), { mode: 0o600, flag: "wx" });
  console.log(`Evaluator configuration saved to ${targets[0]}\nPlugin environment saved to ${targets[1]}\nProvider keys stay in the evaluator process environment.`);
};

const readConfig = async (values) => {
  const path = resolve(values.config ?? ".aurels-evaluator/config.json");
  const raw = await readFile(path);
  if (raw.byteLength > 65_536) throw new Error("Configuration too large.");
  const config = JSON.parse(raw.toString("utf8"));
  if (!config || typeof config !== "object" || Array.isArray(config) || "apiKey" in config) throw new Error("Keep provider keys in environment variables.");
  const keyName = config.apiKeyEnv ?? "AURELS_MODEL_API_KEY";
  if (typeof keyName !== "string" || !/^[A-Z][A-Z0-9_]*$/.test(keyName)) throw new Error("Invalid API key environment variable.");
  return { ...config, apiKey: process.env[keyName] ?? "", port: validPort(config.port) };
};

const start = async (values) => {
  const config = await readConfig(values);
  const server = createEvaluatorServer(config);
  await new Promise((done, reject) => { server.once("error", reject); server.listen(config.port, "127.0.0.1", done); });
  console.log(`Evaluator listening on http://127.0.0.1:${config.port} using ${config.provider}/${config.model}. No Aurels cloud forwarding.`);
  const stop = () => { server.close(); setTimeout(() => { server.closeAllConnections(); process.exit(0); }, 1000).unref(); };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
};

const main = async () => {
  const { values, positionals } = parseArgs({ options, allowPositionals: true });
  if (values.help || !positionals.length) {
    console.log("aurels-evaluator init --provider jev|laya|ollama|openai-compatible [--model NAME] [--api-url URL] [--directory PATH]\naurels-evaluator start [--config PATH]\naurels-evaluator check [--config PATH]\naurels-evaluator verify [--config PATH]");
    return;
  }
  if (positionals.length !== 1) throw new Error("Select one command.");
  if (positionals[0] === "init") return initialize(values);
  if (positionals[0] === "start") return start(values);
  if (positionals[0] === "verify") {
    const config = await readConfig(values);
    const report = await verifyEvaluator(`http://127.0.0.1:${config.port}`, resolveConfig(config, { requireCredentials: false }));
    console.log(JSON.stringify(report, null, 2));
    if (!report.passed) process.exitCode = 1;
    return;
  }
  if (positionals[0] === "check") {
    const config = await readConfig(values);
    const response = await fetch(`http://127.0.0.1:${config.port}/health`, { signal: AbortSignal.timeout(1500) });
    if (!response.ok) throw new Error("Evaluator not available.");
    const status = await response.json();
    console.log(`Evaluator ready: ${status.provider}/${status.model}. Health check only; model inference is checked when an action is evaluated.`);
    return;
  }
  throw new Error("Unknown command.");
};
main().catch(() => {
  console.error("Evaluator setup failed. Check the command, configuration, provider key environment, endpoint, and model; existing configurations are never overwritten.");
  process.exitCode = 1;
});
