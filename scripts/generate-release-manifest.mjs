import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { execFileSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const dist = join(root, "dist");
await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
const files = [];
for (const plugin of await readdir(join(root, "plugins"))) await collect(join(root, "plugins", plugin), files);
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
await writeFile(join(dist, "SBOM.spdx.json"), JSON.stringify({ SPDXID: "SPDXRef-DOCUMENT", spdxVersion: "SPDX-2.3", name: "aurels-plugins", documentNamespace: `https://github.com/Adam-Guerin/aurels-plugins/releases/${commit}`, creationInfo: { created: manifest.generatedAt, creators: ["Tool: aurels release manifest"] }, packages: ["aurels-openclaw", "aurels-hermes"].map((name) => ({ SPDXID: `SPDXRef-${name}`, name, versionInfo: "0.2.1", downloadLocation: "NOASSERTION", licenseConcluded: "MIT" })) }, null, 2) + "\n");
console.log(`Release metadata generated for ${entries.length} files at ${dist}`);

async function collect(path, output) {
  const info = await stat(path);
  if (info.isDirectory()) { for (const item of await readdir(path)) if (!item.startsWith("__pycache__")) await collect(join(path, item), output); return; }
  if (!path.includes(".codex-plugin") && !path.endsWith(".pyc")) output.push(path);
}
function safeGit(...args) { try { return execFileSync("git", args, { cwd: root, encoding: "utf8" }).trim(); } catch { return "unavailable"; } }
