import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { access, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const requiredOllamaFiles = ["Modelfile.aurels", "README.md", ".codex-plugin/plugin.json"];

export async function validateReleaseArtifacts(root) {
  const marketplacePath = resolve(root, ".agents/plugins/marketplace.json");
  const marketplace = JSON.parse(await readFile(marketplacePath, "utf8"));
  const marketplacePlugins = [];

  for (const plugin of marketplace.plugins ?? []) {
    const source = plugin.source?.path;
    if (!source) throw new Error(`Marketplace plugin ${plugin.name} has no local source path`);
    const pluginRoot = resolve(dirname(marketplacePath), "..", "..", source);
    await access(pluginRoot);
    await access(resolve(pluginRoot, ".codex-plugin/plugin.json"));
    marketplacePlugins.push(plugin.name);
  }

  const ollamaArchive = resolve(root, "dist/aurels-ollama-plugin.zip");
  const archiveEntries = execFileSync("tar", ["-tf", ollamaArchive], { encoding: "utf8" }).split(/\r?\n/).filter(Boolean);
  for (const required of requiredOllamaFiles) {
    if (!archiveEntries.includes(required)) throw new Error(`Ollama archive is missing ${required}`);
  }

  const checksums = await readFile(resolve(root, "dist/SHA256SUMS"), "utf8");
  let hashesVerified = true;
  for (const line of checksums.trim().split(/\r?\n/)) {
    const match = line.match(/^([a-f0-9]{64})  (.+)$/);
    if (!match) throw new Error(`Invalid SHA256SUMS line: ${line}`);
    const [, expected, relativePath] = match;
    const actual = createHash("sha256").update(await readFile(resolve(root, relativePath))).digest("hex");
    if (actual !== expected) {
      hashesVerified = false;
      throw new Error(`Checksum mismatch for ${relativePath}`);
    }
  }

  return { marketplacePlugins, archives: ["dist/aurels-ollama-plugin.zip"], hashesVerified };
}

if (import.meta.main) {
  const root = resolve(import.meta.dirname, "..");
  const report = await validateReleaseArtifacts(root);
  console.log(`Validated ${report.marketplacePlugins.length} marketplace plugins and release checksums.`);
}
