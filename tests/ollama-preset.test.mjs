import assert from "node:assert/strict";
import { test } from "node:test";
import { installPreset, loadPreset } from "../plugins/aurels-ollama/install.mjs";

const preset = await loadPreset();
function host({ digest = preset.lock.manifestDigest, missing = false, noBlob = false, redirect = false } = {}) {
  const calls = [];
  let pulled = false;
  const fetchImpl = async (url, options = {}) => {
    const path = new URL(url).pathname;
    calls.push({ path, options });
    assert.equal(options.redirect, "error");
    if (redirect) throw new Error("redirect refused");
    if (path === "/api/tags") return Response.json({ models: missing && !pulled ? [] : [{ name: preset.lock.model, digest }] });
    if (path === "/api/pull") { pulled = true; return Response.json({ status: "success" }); }
    if (path.startsWith("/api/blobs/")) return new Response(null, { status: noBlob ? 404 : 200 });
    if (path === "/api/create") return Response.json({ status: "success" });
    if (path === "/api/show") return Response.json({ modelfile: `FROM /models/blobs/sha256-${preset.lock.modelDigest.slice(7)}` });
    throw new Error(`Unexpected request ${path}`);
  };
  return { calls, fetchImpl };
}

test("preset installs from immutable model bytes with its pinned template and license", async () => {
  const server = host({ missing: true });
  await installPreset({ preset, fetchImpl: server.fetchImpl, model: "aurels-test" });
  const create = JSON.parse(server.calls.find((call) => call.path === "/api/create").options.body);
  assert.equal(create.from, undefined, "creation must not resolve a mutable tag again");
  assert.deepEqual(create.files, { "qwen2.5.gguf": preset.lock.modelDigest });
  assert.equal(create.template, preset.template);
  assert.equal(create.license, preset.license);
  assert.equal(create.system, preset.system);
  assert.equal(create.parameters.temperature, 0);
  assert.equal(server.calls.filter((call) => call.path === "/api/pull").length, 1);
});
test("installer accepts Ollama's unprefixed SHA-256 inventory digest", async () => {
  const server = host({ digest: preset.lock.manifestDigest.slice(7) });
  await installPreset({ preset, fetchImpl: server.fetchImpl });
  assert.equal(server.calls.some((call) => call.path === "/api/create"), true);
});

for (const [label, settings] of [["changed manifest", { digest: "sha256:" + "0".repeat(64) }], ["missing pinned blob", { noBlob: true }], ["redirect", { redirect: true }]]) {
  test(`installer refuses ${label} before creating a preset`, async () => {
    const server = host(settings);
    await assert.rejects(installPreset({ preset, fetchImpl: server.fetchImpl }));
    assert.equal(server.calls.some((call) => call.path === "/api/create"), false);
  });
}
test("installer rejects remote endpoints and unsafe output model names before any request", async () => {
  const server = host();
  for (const options of [{ baseUrl: "http://evil.test" }, { baseUrl: "http://localhost@evil.test" }, { model: "qwen2.5:7b-instruct-q4_K_M" }, { model: "../outside" }]) {
    await assert.rejects(installPreset({ preset, fetchImpl: server.fetchImpl, ...options }));
  }
  assert.deepEqual(server.calls, []);
});
