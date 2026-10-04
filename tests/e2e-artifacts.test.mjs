import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { validateReleaseArtifacts } from "../scripts/e2e-artifacts.mjs";

const root = resolve(import.meta.dirname, "..");

test("release artifacts expose every marketplace plugin and verify their hashes", async () => {
  execFileSync("npm", ["run", "package:ollama"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  execFileSync("npm", ["run", "package:crewai"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  execFileSync("npm", ["run", "package:integrations"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  execFileSync("npm", ["run", "package:claude-code"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  execFileSync("npm", ["run", "package:codex"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  execFileSync("npm", ["run", "package:langgraph"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  execFileSync("npm", ["run", "package:openai-agents"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  execFileSync("npm", ["run", "package:mcp"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  execFileSync("npm", ["run", "package:evaluator"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  const untrackedProbe = `plugins/aurels-openclaw/.manifest-untracked-probe-${randomUUID()}.txt`;
  await writeFile(resolve(root, untrackedProbe), "must not enter the release manifest\n", "utf8");
  try {
    execFileSync("npm", ["run", "release:manifest"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
    const generated = JSON.parse(await readFile(join(root, "dist/MANIFEST.json"), "utf8"));
    assert.equal(generated.plugins.some((entry) => entry.path === untrackedProbe), false, "untracked local files must not enter release metadata");
    const sourceEntries = new Set(generated.plugins.map((entry) => entry.path));
    const trackedPaths = execFileSync("git", ["ls-files", "-z", "--", "plugins"], { cwd: root, encoding: "buffer" })
      .toString("utf8").split("\0").filter(Boolean);
    const omittedTrackedPaths = trackedPaths.filter((path) =>
      !/(?:^|\/)(?:node_modules|__pycache__|\.venv|venv|coverage|dist|build)(?:\/|$)|(?:\.pyc|\.tsbuildinfo)$|\.egg-info(?:\/|$)/.test(path)
      && !sourceEntries.has(path));
    assert.deepEqual(omittedTrackedPaths, [], "all tracked plugin source should be represented in release metadata");
  } finally {
    await rm(resolve(root, untrackedProbe), { force: true });
  }
  const report = await validateReleaseArtifacts(root);
  const manifest = JSON.parse(await readFile(join(root, "dist/MANIFEST.json"), "utf8"));
  assert.equal(manifest.plugins.some((entry) => /(^|\/)node_modules\//.test(entry.path)), false);
  assert.equal(manifest.plugins.some((entry) => /(?:\.egg-info\/|\/build\/)/.test(entry.path)), false);
  assert.equal(manifest.plugins.some((entry) => entry.path.endsWith("aurels-framework-integrations.zip")), false);
  assert.equal(manifest.plugins.some((entry) => /plugins\/[^/]+\/.*\.(?:tgz|whl)$/.test(entry.path)), false);

  assert.deepEqual(report.marketplacePlugins.sort(), ["aurels-codex-guard", "aurels-hermes", "aurels-ollama", "aurels-openclaw"]);
  assert.ok(report.archives.includes("dist/aurels-ollama-plugin.zip"));
  assert.ok(report.archives.includes("dist/aurels-framework-integrations.tar.gz"));
  assert.ok(report.archives.includes("dist/aurels_crewai-0.1.0-py3-none-any.whl"));
  assert.ok(report.archives.includes("dist/aurels-claude-code-plugin.zip"));
  assert.ok(report.archives.includes("dist/aurels-codex-guard-plugin.zip"));
  assert.ok(report.archives.includes("dist/aurels-langgraph-guard-0.1.0.tgz"));
  assert.ok(report.archives.includes("dist/aurels-openai-agents-guard-0.1.0.tgz"));
  assert.ok(report.archives.includes("dist/aurels-mcp-proxy-0.1.0.tgz"));
  assert.ok(report.archives.includes("dist/aurels-evaluator-0.1.0.tgz"));
  assert.deepEqual(
    execFileSync("tar", ["-tzf", "dist/aurels-framework-integrations.tar.gz"], { cwd: root, encoding: "utf8" })
      .split(/\r?\n/)
      .filter((entry) => /integrations\/(claude-code|codex|crewai|langgraph|mcp|openai-agents)\//.test(entry))
      .map((entry) => entry.replace(/^\.\//, "").split("/")[1])
      .filter((value, index, all) => all.indexOf(value) === index)
      .sort(),
    ["claude-code", "codex", "crewai", "langgraph", "mcp", "openai-agents"],
  );
  assert.equal(report.hashesVerified, true);
  const integrationEntries = execFileSync("tar", ["-tzf", "dist/aurels-framework-integrations.tar.gz"], { cwd: root, encoding: "utf8" });
  assert.doesNotMatch(integrationEntries, /(?:^|\/)(?:__pycache__|build|[^/]+\.egg-info)(?:\/|$)|\.pyc$|\.tsbuildinfo$/m);
  assert.doesNotMatch(integrationEntries, /(?:^|\/)dist\//m, "source bundle must not contain local compiled package artifacts");

  const packageRoot = await mkdtemp(join(tmpdir(), "aurels-js-adapters-e2e-"));
  try {
    const packages = [
      "dist/aurels-langgraph-guard-0.1.0.tgz",
      "dist/aurels-openai-agents-guard-0.1.0.tgz",
      "dist/aurels-mcp-proxy-0.1.0.tgz",
      "dist/aurels-evaluator-0.1.0.tgz",
    ].map((archive) => resolve(root, archive));
    execFileSync("npm", ["install", "--ignore-scripts", "--legacy-peer-deps", "--no-audit", "--no-fund", ...packages], {
      cwd: packageRoot, stdio: "inherit", shell: process.platform === "win32",
    });
    const checkInstalledAdapters = String.raw`
      import assert from 'node:assert/strict';
      import { readFileSync } from 'node:fs';
      const client = { evaluateAction: async () => ({ decision: 'block' }), recordActionTelemetry: async () => {} };
      const config = { apiKey: 'synthetic', telemetryEnabled: false };
      const langgraph = await import('@aurels/langgraph-guard');
      let langgraphExecuted = false;
      const protectedLanggraph = langgraph.wrapLangGraphTool({ name: 'task', async invoke() { langgraphExecuted = true; } }, config, client);
      await assert.rejects(() => protectedLanggraph.invoke({ delete: true }), langgraph.AurelToolBlockedError);
      assert.equal(langgraphExecuted, false, 'the packaged LangGraph adapter must block before dispatch');
      const agents = await import('@aurels/openai-agents-guard');
      let agentsExecuted = false;
      const protectedAgentTool = agents.withAurelOpenAIAgentsTool({ name: 'task', async execute() { agentsExecuted = true; } }, config, client);
      await assert.rejects(() => protectedAgentTool.execute({ delete: true }), agents.AurelToolBlockedError);
      assert.equal(agentsExecuted, false, 'the packaged OpenAI Agents adapter must block before dispatch');
      const mcp = JSON.parse(readFileSync('node_modules/@aurels/mcp-proxy/package.json', 'utf8'));
      assert.equal(mcp.bin['aurels-mcp-proxy'], 'src/aurel-mcp-proxy.mjs');
    `;
    execFileSync(process.execPath, ["--input-type=module", "-e", checkInstalledAdapters], { cwd: packageRoot, stdio: "inherit" });
    const installedEvaluator = spawnSync(process.execPath, ["--test", "tests/model-evaluator.test.mjs", "tests/evaluator-cli.test.mjs", "tests/evaluator-readiness.test.mjs"], {
      cwd: root, env: { ...process.env,
        AURELS_EVALUATOR_MODULE: resolve(packageRoot, "node_modules/@aurels/evaluator/src/server.mjs"),
        AURELS_EVALUATOR_BIN: resolve(packageRoot, "node_modules/@aurels/evaluator/src/cli.mjs") },
      encoding: "utf8", timeout: 30_000,
    });
    if (installedEvaluator.status !== 0) throw new Error(`Installed evaluator protocol/CLI failed:\n${installedEvaluator.stdout}\n${installedEvaluator.stderr}`);
    const packagedMcpProxy = resolve(packageRoot, "node_modules/@aurels/mcp-proxy/src/aurel-mcp-proxy.mjs");
    const packagedClaude = resolve(packageRoot, "claude-plugin");
    const packagedCodex = resolve(packageRoot, "codex-plugin");
    await mkdir(packagedClaude);
    await mkdir(packagedCodex);
    execFileSync("tar", ["-xf", "dist/aurels-claude-code-plugin.zip", "-C", packagedClaude], { cwd: root });
    execFileSync("tar", ["-xf", "dist/aurels-codex-guard-plugin.zip", "-C", packagedCodex], { cwd: root });
    const hookE2e = spawnSync(process.execPath, ["--test", "--test-concurrency=1",
      "plugins/aurels-integrations/tests/e2e-prefix-enforcement.test.mjs", "plugins/aurels-integrations/tests/codex-hook.test.mjs"], {
      cwd: root,
      env: { ...process.env, AUREL_MCP_PROXY_BIN: packagedMcpProxy,
        AURELS_CLAUDE_HOOK_BIN: resolve(packagedClaude, "hooks/aurel-hook.mjs"),
        AURELS_CODEX_HOOK_BIN: resolve(packagedCodex, "hooks/aurel-codex-hook.mjs") },
      encoding: "utf8", timeout: 60_000,
    });
    if (hookE2e.status !== 0) throw new Error(`Packaged native-hook/MCP E2E failed:\n${hookE2e.stdout}\n${hookE2e.stderr}`);
    if (process.env.AURELS_CODEX_CLI) {
      const nativeCodex = spawnSync(process.execPath, ["--test", "tests/e2e-codex-session.test.mjs"], {
        cwd: root, env: { ...process.env, AURELS_CODEX_HOOK_BIN: resolve(packagedCodex, "hooks/aurel-codex-hook.mjs") },
        encoding: "utf8", timeout: 60_000,
      });
      if (nativeCodex.status !== 0) throw new Error(`Packaged Codex native-session failed:\n${nativeCodex.stdout}\n${nativeCodex.stderr}`);
    }
    const nativeSdkTests = spawnSync(process.execPath, ["--import", "tsx", "--test", "tests/agent-runners.test.ts", "tests/mcp-sdk.test.mjs", "tests/evaluator-consumers.test.ts"], {
      cwd: resolve(root, "plugins/aurels-integrations"),
      env: { ...process.env, AUREL_MCP_PROXY_BIN: packagedMcpProxy,
        AURELS_EVALUATOR_MODULE: resolve(packageRoot, "node_modules/@aurels/evaluator/src/server.mjs"),
        AURELS_LG_ADAPTER_MODULE: resolve(packageRoot, "node_modules/@aurels/langgraph-guard/dist/langgraph/src/index.js"),
        AURELS_OAI_ADAPTER_MODULE: resolve(packageRoot, "node_modules/@aurels/openai-agents-guard/dist/openai-agents/src/index.js") },
      encoding: "utf8", timeout: 60_000,
    });
    if (nativeSdkTests.status !== 0) throw new Error(`Installed SDK adapter dispatch failed:\n${nativeSdkTests.stdout}\n${nativeSdkTests.stderr}`);
  } finally {
    await rm(packageRoot, { recursive: true, force: true });
  }
});

test("the packed OpenClaw plugin installs and imports in a clean npm environment", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aurels-openclaw-e2e-"));
  try {
    const pluginRoot = resolve(root, "plugins/aurels-openclaw");
    execFileSync("npm", ["pack", "--pack-destination", temporary], { cwd: pluginRoot, stdio: "inherit", shell: process.platform === "win32" });
    const archive = (await readdir(temporary)).find((file) => file.endsWith(".tgz"));
    assert.ok(archive, "npm pack should produce a tarball");
    execFileSync("npm", ["install", "--ignore-scripts", "--legacy-peer-deps", "--no-audit", "--no-fund", join(temporary, archive)], {
      cwd: temporary,
      stdio: "inherit",
      shell: process.platform === "win32",
    });
    await import(pathToFileURL(join(temporary, "node_modules/@aurels/aurels/src/index.js")).href);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
