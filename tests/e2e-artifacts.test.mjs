import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { validateReleaseArtifacts } from "../scripts/e2e-artifacts.mjs";

const root = resolve(import.meta.dirname, "..");

test("release artifacts expose every marketplace plugin and verify their hashes", async () => {
  execFileSync("npm", ["run", "package:ollama"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  execFileSync("npm", ["run", "release:manifest"], { cwd: root, stdio: "inherit", shell: process.platform === "win32" });
  const report = await validateReleaseArtifacts(root);

  assert.deepEqual(report.marketplacePlugins.sort(), ["aurels-hermes", "aurels-ollama", "aurels-openclaw"]);
  assert.ok(report.archives.includes("dist/aurels-ollama-plugin.zip"));
  assert.equal(report.hashesVerified, true);
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
