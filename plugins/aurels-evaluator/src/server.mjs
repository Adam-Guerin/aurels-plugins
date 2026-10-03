import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import { resolveConfig } from "./config.mjs";
import { blockDecision, evaluateModel } from "./model.mjs";

const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const hash = (value) => createHash("sha256").update(value).digest();
const validAction = (input) => object(input) && object(input.action) && typeof input.action.id === "string" && input.action.id.length > 0
  && input.action.id.length <= 512 && typeof input.action.name === "string" && input.action.name.length > 0 && input.action.name.length <= 256
  && object(input.action.arguments);
const respond = (res, status, body) => {
  if (res.destroyed || res.writableEnded) return;
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" }).end(JSON.stringify(body));
};
const readBody = async (req, maxBytes) => {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.byteLength;
    if (bytes > maxBytes) throw new Error("Request too large.");
    chunks.push(chunk);
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
};

export const createEvaluatorServer = (options) => {
  const config = resolveConfig(options);
  const tokenHash = hash(config.token);
  let active = 0;
  const server = createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/health") return respond(res, 200, { ready: true, provider: config.provider, model: config.model });
    const token = req.headers["x-api-key"];
    if (typeof token !== "string" || token.length > 512 || !timingSafeEqual(tokenHash, hash(token))) return respond(res, 401, { error: "Invalid evaluator access token." });
    if (req.method !== "POST") return respond(res, 405, { error: "Method not supported." });
    if (req.url === "/api/v1/actions/telemetry") return respond(res, 202, { accepted: false, storage: "disabled", localOnly: true });
    if (req.url !== "/api/v1/actions/evaluate") return respond(res, 404, { error: "Endpoint not supported by the self-hosted evaluator." });
    if (active >= config.maxConcurrent) return respond(res, 200, blockDecision(config, "evaluator_busy"));
    active++;
    const controller = new AbortController();
    const cancel = () => { if (!res.writableEnded) controller.abort(); };
    res.on("close", cancel);
    const bodyDeadline = setTimeout(() => req.destroy(), 10_000);
    try {
      const input = await readBody(req, config.maxBodyBytes);
      clearTimeout(bodyDeadline);
      if (!validAction(input)) return respond(res, 200, blockDecision(config, "invalid_action"));
      respond(res, 200, await evaluateModel(config, input, controller.signal));
    } catch {
      respond(res, 200, blockDecision(config));
    } finally {
      controller.abort();
      clearTimeout(bodyDeadline);
      res.off("close", cancel);
      active--;
    }
  });
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.maxRequestsPerSocket = 100;
  return server;
};
