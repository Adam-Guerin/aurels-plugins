import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");
const load = async (path) => JSON.parse(await read(path));
const version = (await load("package.json")).version;
for (const path of ["plugins/aurels-openclaw/package.json", "plugins/aurels-openclaw/openclaw.plugin.json", "plugins/aurels-openclaw/.codex-plugin/plugin.json", "plugins/aurels-hermes/.codex-plugin/plugin.json", "plugins/aurels-ollama/.codex-plugin/plugin.json"]) {
  assert.equal((await load(path)).version, version, `Release version differs in ${path}`);
}
assert.equal((await read("plugins/aurels-hermes/pyproject.toml")).match(/^version = "([^"]+)"/m)?.[1], version);
assert.equal((await read("plugins/aurels-hermes/plugin.yaml")).match(/^version: ([^\r\n]+)/m)?.[1], version);
if (process.env.GITHUB_REF_NAME?.startsWith("v")) assert.equal(process.env.GITHUB_REF_NAME, `v${version}`, "Release tag and packaged versions must match");
console.log(`Release versions consistent: ${version}`);
