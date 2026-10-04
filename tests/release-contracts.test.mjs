import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import plugin from "../plugins/aurels-openclaw/src/index.js";

const root = new URL("../", import.meta.url);
test("both marketplace entry points expose exactly the same plugins and policies", async () => {
  const load = async (path) => JSON.parse(await readFile(new URL(path, root), "utf8"));
  assert.deepEqual(await load("marketplace.json"), await load(".agents/plugins/marketplace.json"));
});

test("OpenClaw refuses untested hosts before registering any security hooks", () => {
  for (const version of [undefined, "2026.3.2", "2026.6.5", "2026.9.7", "2027.1.1", "2026.9.6-beta.1", "2026.9.6garbage"]) {
    let registrations = 0;
    assert.throws(() => plugin.register({ runtime: { version }, on() { registrations++; } }), /unsupported OpenClaw/i, String(version));
    assert.equal(registrations, 0);
  }
  for (const version of ["2026.3.28", "2026.9.6"]) {
    const hooks = [];
    plugin.register({ runtime: { version }, pluginConfig: { mode: "local", telemetry: false }, on(name) { hooks.push(name); } });
    assert.deepEqual(hooks, ["before_tool_call", "after_tool_call"]);
  }
});
