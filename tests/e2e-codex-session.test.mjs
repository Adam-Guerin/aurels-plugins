import assert from "node:assert/strict";
import { test } from "node:test";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, mkdir, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, dirname } from "node:path";
import { gunzipSync, inflateSync, brotliDecompressSync } from "node:zlib";

const binary = process.env.AURELS_CODEX_CLI ?? "codex";
const commandBinary = binary.endsWith(".js") ? process.execPath : binary;
const commandPrefix = binary.endsWith(".js") ? [binary] : [];
const hook = process.env.AURELS_CODEX_HOOK_BIN ?? resolve(import.meta.dirname, "../plugins/aurels-integrations/integrations/codex/aurel-codex-plugin/hooks/aurel-codex-hook.mjs");

for (const decision of ["allow", "block", "flag", "outage"]) {
  test(`real Codex session enforces ${decision} before writing its disposable fixture`, { timeout: 60_000 }, async () => {
    const directory = await mkdtemp(resolve(tmpdir(), "aurels-codex-session-"));
    const requests = [], policies = [];
    const marker = resolve(directory, "dispatch-marker.txt");
    const command = process.platform === "win32" ? `Set-Content -LiteralPath '${marker.replaceAll("'", "''")}' -Value 'approved-fixture'` : `printf approved-fixture > '${marker.replaceAll("'", "'\\''")}'`;
    const server = createServer(async (req, res) => {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      let raw = Buffer.concat(chunks);
      if (req.headers["content-encoding"] === "gzip") raw = gunzipSync(raw);
      if (req.headers["content-encoding"] === "deflate") raw = inflateSync(raw);
      if (req.headers["content-encoding"] === "br") raw = brotliDecompressSync(raw);
      if (req.url === "/api/v1/actions/evaluate") {
        policies.push(JSON.parse(raw));
        if (decision === "outage") return res.writeHead(503).end("fixture outage");
        return res.end(JSON.stringify({ decision, traceId: "session-fixture" }));
      }
      if (req.url !== "/v1/responses") return res.writeHead(404).end("unknown fixture endpoint");
      const input = JSON.parse(raw);
      requests.push(input);
      const outputs = input.input?.filter((item) => item.type === "function_call_output") ?? [];
      const items = outputs.length ? [{ id: "msg-fixture", type: "message", role: "assistant", status: "completed", content: [{ type: "output_text", text: "Fixture finished.", annotations: [] }] }]
        : [{ id: "call-fixture", type: "function_call", status: "completed", call_id: "fixture-dispatch", name: "exec_command", arguments: JSON.stringify({ cmd: command, max_output_tokens: 1000 }) }];
      res.writeHead(200, { "content-type": "text/event-stream" });
      const send = (type, payload) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...payload })}\n\n`);
      send("response.created", { response: { id: "resp-fixture", object: "response", status: "in_progress", output: [] } });
      for (const [index, item] of items.entries()) send("response.output_item.done", { output_index: index, item });
      send("response.completed", { response: { id: "resp-fixture", object: "response", status: "completed", output: items, usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } } });
      res.end();
    });
    server.listen(0, "127.0.0.1"); await once(server, "listening");
    const url = `http://127.0.0.1:${server.address().port}`;
    try {
      const manifest = JSON.parse(await readFile(resolve(dirname(hook), "hooks.json"), "utf8"));
      const nativeHooks = structuredClone(manifest);
      for (const groups of Object.values(nativeHooks.hooks)) {
        for (const group of groups) for (const handler of group.hooks) {
          handler.command = process.platform === "win32" ? handler.commandWindows ?? handler.command : handler.command;
        }
      }
      const taskCodexHome = resolve(directory, "codex-home");
      await mkdir(taskCodexHome);
      await writeFile(resolve(taskCodexHome, "config.toml"), "[features]\nhooks = true\n");
      await writeFile(resolve(taskCodexHome, "hooks.json"), JSON.stringify(nativeHooks));
      const args = ["exec", "--ignore-rules", "--ephemeral", "--skip-git-repo-check", "--dangerously-bypass-hook-trust", "--json", "-C", directory,
        "-c", "model=\"aurels-session-fixture\"", "-c", "model_provider=\"fixture\"", "-c", "approval_policy=\"never\"", "-c", "sandbox_mode=\"danger-full-access\"",
        "-c", "features.plugins=false",
        "-c", `model_providers.fixture={name="Local test",base_url="${url}/v1",wire_api="responses",requires_openai_auth=false,stream_max_retries=0}`,
        "-c", `projects.${JSON.stringify(directory.replaceAll("\\", "/"))}.trust_level="trusted"`,
        "Run the one supplied fixture tool call, then stop. This is a deterministic local integration test."];
      const child = spawn(commandBinary, [...commandPrefix, ...args], { cwd: directory, env: { ...process.env, CODEX_HOME: taskCodexHome, PLUGIN_ROOT: dirname(dirname(hook)), AURELS_API_URL: url, AURELS_API_KEY: "local-fixture-key", AUREL_ENABLED: "true", AUREL_FAIL_MODE: "closed", AUREL_TELEMETRY_ENABLED: "false", AUREL_TIMEOUT_MS: "300", AUREL_TOOLS_INCLUDE: "" } });
      child.stdin.end();
      let stdout = "", stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; }); child.stderr.on("data", (chunk) => { stderr += chunk; });
      const deadline = setTimeout(() => child.kill(), 45_000);
      const [status] = await once(child, "close"); clearTimeout(deadline);
      assert.equal(status, 0, `${stdout}\n${stderr}`);
      assert.ok(requests.length >= 2, `model dispatch did not finish: ${stdout}\n${stderr}`);
      assert.equal(policies.length, 1, `native hook did not guard the call: ${stdout}\n${stderr}`);
      assert.equal(policies[0].action.arguments.command ?? policies[0].action.arguments.cmd, command);
      const written = await readFile(marker, "utf8").catch((error) => { if (error.code === "ENOENT") return null; throw error; });
      assert.equal(written?.trim() ?? null, decision === "allow" ? "approved-fixture" : null);
    } finally {
      server.closeAllConnections(); await new Promise((done) => server.close(done));
      await rm(directory, { recursive: true, force: true });
    }
  });
}
