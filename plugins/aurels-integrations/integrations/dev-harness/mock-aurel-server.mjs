import http from "node:http";
import { fileURLToPath } from "node:url";

const port = Number(process.env.AUREL_HARNESS_PORT ?? 8787);
const delayMs = Number(process.env.AUREL_HARNESS_DELAY_MS ?? 0);

export function decisionFor(action) {
  const name = action?.action?.name ?? "";
  const args = action?.action?.arguments ?? {};
  const serialized = JSON.stringify(args).toLowerCase();

  if (serialized.includes("invalid-response")) return "invalid";
  if (serialized.includes("timeout")) return "timeout";
  if (serialized.includes("rm -rf") || serialized.includes("malicious-domain")) {
    return {
      decision: "block",
      reason: "Harness deny rule",
      riskScore: 100,
      ruleIds: ["harness.block"],
      traceId: `trace-${Date.now()}`,
    };
  }
  if (/send_email|message|payment|transfer/i.test(name)) {
    return {
      decision: "require_approval",
      reason: "Harness approval rule",
      riskScore: 75,
      ruleIds: ["harness.approval"],
      traceId: `trace-${Date.now()}`,
    };
  }
  if (serialized.includes("rewrite-me")) {
    return {
      decision: "rewrite",
      rewrittenArguments: { ...args, rewritten_by: "aurel-harness" },
      riskScore: 40,
      traceId: `trace-${Date.now()}`,
    };
  }
  return { decision: "allow", reason: "Harness allow rule", riskScore: 5, traceId: `trace-${Date.now()}` };
}

export function createAurelHarnessServer(options = {}) {
  const responseDelayMs = Number(options.delayMs ?? delayMs);
  const server = http.createServer((req, res) => {
    if (req.method !== "POST") {
      res.writeHead(405).end();
      return;
    }

    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const rawBody = Buffer.concat(chunks).toString("utf8");
      let receivedPayload;
      try { receivedPayload = JSON.parse(rawBody); } catch { receivedPayload = undefined; }
      server.receivedRequests.push({ path: req.url, headers: req.headers, payload: receivedPayload });
      const respond = () => {
        if (req.url === "/api/v1/actions/telemetry") {
          res.writeHead(202, { "content-type": "application/json" });
          res.end(JSON.stringify({ accepted: true }));
          return;
        }

        if (req.url !== "/api/v1/actions/evaluate") {
          res.writeHead(404).end();
          return;
        }

        const action = receivedPayload;
        if (!action) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "invalid json" }));
          return;
        }

        const decision = decisionFor(action);
        if (decision === "invalid") {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ decision: "not-a-real-decision" }));
          return;
        }
        if (decision === "timeout") {
          setTimeout(() => {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ decision: "allow", traceId: "late" }));
          }, 60_000);
          return;
        }

        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(decision));
      };

      if (responseDelayMs > 0) setTimeout(respond, responseDelayMs);
      else respond();
    });
  });
  server.receivedRequests = [];
  return server;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const server = createAurelHarnessServer();

  server.listen(port, () => {
    console.log(`Aurel mock harness listening on http://127.0.0.1:${port}`);
    console.log(`Use AUREL_API_URL=http://127.0.0.1:${port} and any non-empty AUREL_API_KEY.`);
  });
}
