import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { execFileSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const dist = join(root, "dist");
await mkdir(dist, { recursive: true });
await Promise.all(["MANIFEST.json", "SHA256SUMS", "PROVENANCE.json", "SBOM.spdx.json"].map((file) => rm(join(dist, file), { force: true })));
const trackedPluginPaths = execFileSync("git", ["ls-files", "-z", "--", "plugins"], { cwd: root, encoding: "buffer" })
  .toString("utf8")
  .split("\0")
  .filter(Boolean);
const files = trackedPluginPaths
  .filter((path) => !/(?:^|\/)(?:node_modules|__pycache__|\.venv|venv|coverage|dist|build)(?:\/|$)|(?:\.pyc|\.tsbuildinfo)$|\.egg-info(?:\/|$)/.test(path))
  .map((path) => join(root, path));
for (const file of await readdir(dist)) {
  if (["aurels-ollama-plugin.zip", "aurels-framework-integrations.tar.gz", "aurels_crewai-0.1.0-py3-none-any.whl", "aurels-claude-code-plugin.zip", "aurels-codex-guard-plugin.zip", "aurels-langgraph-guard-0.1.0.tgz", "aurels-openai-agents-guard-0.1.0.tgz", "aurels-mcp-proxy-0.1.0.tgz", "aurels-evaluator-0.1.0.tgz"].includes(file)) files.push(join(dist, file));
}
const entries = [];
for (const file of files.sort()) {
  const bytes = await readFile(file);
  entries.push({ path: relative(root, file).replaceAll("\\", "/"), sha256: createHash("sha256").update(bytes).digest("hex"), bytes: bytes.length });
}
const commit = safeGit("rev-parse", "HEAD");
const generatedAt = process.env.SOURCE_DATE_EPOCH ? new Date(Number(process.env.SOURCE_DATE_EPOCH) * 1000).toISOString() : safeGit("show", "-s", "--format=%cI", "HEAD");
const manifest = { schema: 1, generatedAt, commit, plugins: entries };
await writeFile(join(dist, "MANIFEST.json"), JSON.stringify(manifest, null, 2) + "\n");
await writeFile(join(dist, "SHA256SUMS"), entries.map((entry) => `${entry.sha256}  ${entry.path}`).join("\n") + "\n");
await writeFile(join(dist, "PROVENANCE.json"), JSON.stringify({ schema: 1, repository: "https://github.com/Adam-Guerin/aurels-plugins", commit, workflow: "GitHub Actions release-artifacts", generatedAt: manifest.generatedAt }, null, 2) + "\n");

const openclawVersion = JSON.parse(await readFile(join(root, "plugins", "aurels-openclaw", "package.json"), "utf8")).version;
const hermesPyproject = await readFile(join(root, "plugins", "aurels-hermes", "pyproject.toml"), "utf8");
const hermesVersion = hermesPyproject.match(/version\s*=\s*["']([^"']+)["']/)?.[1] || "0.0.0";
if (openclawVersion !== hermesVersion) {
  console.error(`Version mismatch: openclaw=${openclawVersion}, hermes=${hermesVersion}`);
  process.exit(1);
}
const sbomPackages = [
  ["aurels-openclaw", openclawVersion], ["aurels-hermes", hermesVersion],
  ["aurels-framework-integrations", "0.1.0"], ["aurels-crewai", "0.1.0"],
  ["@aurels/langgraph-guard", "0.1.0"], ["@aurels/openai-agents-guard", "0.1.0"], ["@aurels/mcp-proxy", "0.1.0"],
  ["aurels-claude-code", "0.1.0"], ["aurels-codex-guard", "0.1.0"], ["@aurels/evaluator", "0.1.0"],
].map(([name, version]) => ({ SPDXID: `SPDXRef-${name.replaceAll(/[^A-Za-z0-9.-]/g, "-")}`, name, versionInfo: version, downloadLocation: "NOASSERTION", licenseConcluded: "MIT" }));
await writeFile(join(dist, "SBOM.spdx.json"), JSON.stringify({ SPDXID: "SPDXRef-DOCUMENT", spdxVersion: "SPDX-2.3", name: "aurels-plugins", documentNamespace: `https://github.com/Adam-Guerin/aurels-plugins/releases/${commit}`, dataLicense: "CC0-1.0", creationInfo: { created: manifest.generatedAt, creators: ["Tool: aurels release manifest"] }, packages: sbomPackages }, null, 2) + "\n");
console.log(`Release metadata generated for ${entries.length} files at ${dist}`);

function safeGit(...args) { try { return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim(); } catch { return "unavailable"; } }
