import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";

const requiredOllamaFiles = ["Modelfile.aurels", "README.md", ".codex-plugin/plugin.json"];
const requiredIntegrationFiles = [
  "integrations/claude-code/hooks/aurel-hook.mjs",
  "integrations/codex/aurel-codex-plugin/scripts/aurel-protected-mcp.mjs",
  "integrations/crewai/aurel_crewai/guard.py",
  "integrations/crewai/pyproject.toml",
  "integrations/langgraph/src/index.ts",
  "integrations/mcp/src/aurel-mcp-proxy.mjs",
  "integrations/openai-agents/src/index.ts",
];

export async function validateReleaseArtifacts(root) {
  const marketplacePaths = [
    resolve(root, "marketplace.json"),
    resolve(root, ".agents/plugins/marketplace.json"),
  ];
  const marketplacePlugins = [];

  for (const marketplacePath of marketplacePaths) {
    const marketplace = JSON.parse(await readFile(marketplacePath, "utf8"));
    if (!Array.isArray(marketplace.plugins)) throw new Error(`${marketplacePath} must contain a plugins array`);
    const names = new Set();
    const sources = new Set();
    for (const plugin of marketplace.plugins) {
      if (typeof plugin.name !== "string" || !plugin.name.trim()) throw new Error(`${marketplacePath} contains a plugin without a name`);
      if (names.has(plugin.name)) throw new Error(`${marketplacePath} contains duplicate plugin name ${plugin.name}`);
      names.add(plugin.name);
      const source = plugin.source?.path;
      if (plugin.source?.source !== "local" || typeof source !== "string" || !source.startsWith("./plugins/")) {
        throw new Error(`Marketplace plugin ${plugin.name} must use a local ./plugins source path`);
      }
      if (sources.has(source)) throw new Error(`${marketplacePath} maps multiple plugin names to ${source}`);
      sources.add(source);
      const pluginRoot = resolve(root, source);
      const relativeSource = relative(resolve(root, "plugins"), pluginRoot);
      if (!relativeSource || relativeSource === ".." || relativeSource.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) || isAbsolute(relativeSource)) {
        throw new Error(`Marketplace plugin ${plugin.name} source escapes plugins/: ${source}`);
      }
      await access(pluginRoot);
      const manifests = [resolve(pluginRoot, ".codex-plugin/plugin.json"), resolve(pluginRoot, "plugin.json")];
      let manifest = null;
      for (const manifestPath of manifests) {
        try {
          manifest = JSON.parse(await readFile(manifestPath, "utf8"));
          break;
        } catch (error) {
          if (error.code !== "ENOENT" && !(error instanceof SyntaxError)) throw error;
          if (error instanceof SyntaxError) throw new Error(`Invalid plugin manifest ${manifestPath}: ${error.message}`);
        }
      }
      if (!manifest) throw new Error(`Marketplace plugin ${plugin.name} has no valid plugin manifest`);
      if (manifest.name !== plugin.name) throw new Error(`Marketplace identity ${plugin.name} does not match manifest identity ${manifest.name}`);
      if (marketplacePath === marketplacePaths[1]) marketplacePlugins.push(plugin.name);
    }
  }

  const ollamaArchive = resolve(root, "dist/aurels-ollama-plugin.zip");
  const archiveEntries = execFileSync("tar", ["-tf", ollamaArchive], { encoding: "utf8" }).split(/\r?\n/).filter(Boolean);
  for (const required of requiredOllamaFiles) {
    if (!archiveEntries.includes(required)) throw new Error(`Ollama archive is missing ${required}`);
  }

  const integrationsArchive = resolve(root, "dist/aurels-framework-integrations.tar.gz");
  const integrationEntries = execFileSync("tar", ["-tzf", integrationsArchive], { encoding: "utf8" }).split(/\r?\n/).filter(Boolean);
  for (const required of requiredIntegrationFiles) {
    if (!integrationEntries.some((entry) => entry.replace(/^\.\//, "").endsWith(required))) {
      throw new Error(`Framework integrations archive is missing ${required}`);
    }
  }
  if (integrationEntries.some((entry) => /(?:^|\/)(?:__pycache__|build|[^/]+\.egg-info)(?:\/|$)|\.pyc$|\.tsbuildinfo$/.test(entry))) {
    throw new Error("Framework integrations archive contains local Python or TypeScript build artifacts");
  }

  const crewaiWheel = resolve(root, "dist/aurels_crewai-0.1.0-py3-none-any.whl");
  const python = process.platform === "win32" ? "python" : "python3";
  execFileSync(python, ["-c", "import sys, zipfile; z=zipfile.ZipFile(sys.argv[1]); names=z.namelist(); assert any(name.startswith('aurel_crewai/') and name.endswith('.py') for name in names), names; assert any(name.endswith('.dist-info/METADATA') for name in names), names", crewaiWheel], { stdio: "inherit" });

  const claudeArchive = resolve(root, "dist/aurels-claude-code-plugin.zip");
  const claudeEntries = execFileSync("tar", ["-tf", claudeArchive], { encoding: "utf8" }).split(/\r?\n/).filter(Boolean);
  for (const required of [".claude-plugin/plugin.json", "hooks/hooks.json", "hooks/aurel-hook.mjs", "README.md"]) {
    if (!claudeEntries.includes(required)) throw new Error(`Claude Code plugin archive is missing ${required}`);
  }
  const codexArchive = resolve(root, "dist/aurels-codex-guard-plugin.zip");
  const codexEntries = execFileSync("tar", ["-tf", codexArchive], { encoding: "utf8" }).split(/\r?\n/).filter(Boolean);
  for (const required of ["plugin.json", "hooks/hooks.json", "hooks/aurel-codex-hook.mjs", "README.md"]) {
    if (!codexEntries.includes(required)) throw new Error(`Codex plugin archive is missing ${required}`);
  }
  const unpacked = await mkdtemp(join(tmpdir(), "aurels-native-plugins-"));
  try {
    execFileSync("tar", ["-xf", claudeArchive, "-C", unpacked]);
    execFileSync("node", ["--check", resolve(unpacked, "hooks/aurel-hook.mjs")]);
    JSON.parse(await readFile(resolve(unpacked, ".claude-plugin/plugin.json"), "utf8"));
    await rm(unpacked, { recursive: true, force: true });
  } catch (error) {
    await rm(unpacked, { recursive: true, force: true });
    throw error;
  }
  const codexUnpacked = await mkdtemp(join(tmpdir(), "aurels-codex-plugin-"));
  try {
    execFileSync("tar", ["-xf", codexArchive, "-C", codexUnpacked]);
    execFileSync("node", ["--check", resolve(codexUnpacked, "hooks/aurel-codex-hook.mjs")]);
    const pluginManifest = JSON.parse(await readFile(resolve(codexUnpacked, "plugin.json"), "utf8"));
    if (pluginManifest.name !== "aurels-codex-guard") throw new Error("Extracted Codex plugin manifest has the wrong identity");
  } catch (error) {
    await rm(codexUnpacked, { recursive: true, force: true });
    throw error;
  }
  await rm(codexUnpacked, { recursive: true, force: true });

  const evaluatorEntries = execFileSync("tar", ["-tzf", resolve(root, "dist/aurels-evaluator-0.1.0.tgz")], { encoding: "utf8" }).split(/\r?\n/).filter(Boolean);
  for (const required of ["package/package.json", "package/README.md", "package/src/cli.mjs", "package/src/config.mjs", "package/src/model.mjs", "package/src/server.mjs", "package/src/readiness.mjs"]) {
    if (!evaluatorEntries.includes(required)) throw new Error(`Evaluator archive is missing ${required}`);
  }
  if (evaluatorEntries.some((entry) => /(?:^|\/)(?:config\.json|plugin\.env|node_modules)(?:\/|$)/.test(entry))) throw new Error("Evaluator archive contains local configuration or dependencies.");

  const checksums = await readFile(resolve(root, "dist/SHA256SUMS"), "utf8");
  let hashesVerified = true;
  const checksumPaths = new Set();
  for (const line of checksums.trim().split(/\r?\n/)) {
    const match = line.match(/^([a-f0-9]{64})  (.+)$/);
    if (!match) throw new Error(`Invalid SHA256SUMS line: ${line}`);
    const [, expected, relativePath] = match;
    if (checksumPaths.has(relativePath)) throw new Error(`Duplicate checksum entry for ${relativePath}`);
    checksumPaths.add(relativePath);
    const actual = createHash("sha256").update(await readFile(resolve(root, relativePath))).digest("hex");
    if (actual !== expected) {
      hashesVerified = false;
      throw new Error(`Checksum mismatch for ${relativePath}`);
    }
  }
  for (const archive of ["dist/aurels-ollama-plugin.zip", "dist/aurels-framework-integrations.tar.gz", "dist/aurels_crewai-0.1.0-py3-none-any.whl", "dist/aurels-claude-code-plugin.zip", "dist/aurels-codex-guard-plugin.zip", "dist/aurels-langgraph-guard-0.1.0.tgz", "dist/aurels-openai-agents-guard-0.1.0.tgz", "dist/aurels-mcp-proxy-0.1.0.tgz", "dist/aurels-evaluator-0.1.0.tgz"]) {
    if (!checksumPaths.has(archive)) throw new Error(`Release checksum list is missing ${archive}`);
  }

  return { marketplacePlugins, archives: ["dist/aurels-ollama-plugin.zip", "dist/aurels-framework-integrations.tar.gz", "dist/aurels_crewai-0.1.0-py3-none-any.whl", "dist/aurels-claude-code-plugin.zip", "dist/aurels-codex-guard-plugin.zip", "dist/aurels-langgraph-guard-0.1.0.tgz", "dist/aurels-openai-agents-guard-0.1.0.tgz", "dist/aurels-mcp-proxy-0.1.0.tgz", "dist/aurels-evaluator-0.1.0.tgz"], hashesVerified };
}

if (import.meta.main) {
  const root = resolve(import.meta.dirname, "..");
  const report = await validateReleaseArtifacts(root);
  console.log(`Validated ${report.marketplacePlugins.length} marketplace plugins and release checksums.`);
}
