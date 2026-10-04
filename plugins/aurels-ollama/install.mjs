import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export async function loadPreset(directory = new URL("./", import.meta.url)) {
  const read = (file) => readFile(new URL(file, directory), "utf8");
  const lock = JSON.parse(await read("model.lock.json"));
  const template = await read("model.template");
  const license = await read("MODEL-LICENSE.txt");
  for (const [content, digest] of [[template, lock.templateDigest], [license, lock.licenseDigest]]) {
    if (`sha256:${createHash("sha256").update(content).digest("hex")}` !== digest) throw new Error("Bundled model metadata does not match the model lock");
  }
  for (const field of ["manifestDigest", "modelDigest"]) {
    if (!/^sha256:[a-f0-9]{64}$/.test(lock[field])) throw new Error("Invalid model lock digest");
  }
  const modelfile = (await read("Modelfile.aurels")).replaceAll("\r\n", "\n");
  if (!modelfile.startsWith(`FROM ${lock.model}\n`)) throw new Error("Modelfile base differs from the model lock");
  const system = modelfile.match(/SYSTEM\s+"""\n([\s\S]*?)\n"""/)?.[1];
  if (!system) throw new Error("Preset is missing its system prompt");
  const parameters = Object.fromEntries([...modelfile.matchAll(/^PARAMETER (\w+) (\d+)$/gm)].map(([, name, value]) => [name, Number(value)]));
  return { lock, template, license, system, parameters };
}

export async function installPreset({ preset, baseUrl = "http://127.0.0.1:11434", model = "aurels-local", fetchImpl = fetch } = {}) {
  preset ??= await loadPreset();
  const base = new URL(baseUrl);
  if (!(["http:", "https:"].includes(base.protocol) && ["127.0.0.1", "localhost", "[::1]"].includes(base.hostname)) || base.username || base.password || base.pathname !== "/" || base.search || base.hash) {
    throw new Error("Preset installer requires a local loopback Ollama endpoint");
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]*(?::[a-zA-Z0-9._-]+)?$/.test(model) || model === preset.lock.model) throw new Error("Invalid output model name or attempted overwrite of the locked base");
  const request = async (path, body, method = body === undefined ? "GET" : "POST", timeout = 60_000) => {
    const response = await fetchImpl(new URL(path, base), {
      method, redirect: "error", signal: AbortSignal.timeout(timeout),
      ...(body === undefined ? {} : { headers: { "content-type": "application/json" }, body: JSON.stringify(body) }),
    });
    if (!response.ok) throw new Error(`Ollama ${path} failed (HTTP ${response.status})`);
    if (method === "HEAD") return;
    // Read bounded responses even when the server omits Content-Length.
    const chunks = [];
    let bytes = 0;
    for await (const chunk of response.body) {
      bytes += chunk.byteLength;
      if (bytes > 1024 * 1024) { await response.body.cancel().catch(() => {}); throw new Error("Ollama response exceeds 1 MiB"); }
      chunks.push(Buffer.from(chunk));
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  };
  let tags = await request("/api/tags");
  if (!Array.isArray(tags.models)) throw new Error("Invalid Ollama model inventory");
  if (!tags.models.some((entry) => entry.name === preset.lock.model)) {
    const pulled = await request("/api/pull", { model: preset.lock.model, stream: false }, "POST", 15 * 60_000);
    if (pulled.status !== "success") throw new Error("Ollama model pull did not complete");
    tags = await request("/api/tags");
  }
  const baseModel = tags.models?.find((entry) => entry.name === preset.lock.model);
  const manifestDigest = baseModel?.digest?.replace(/^sha256:/, "");
  if (`sha256:${manifestDigest}` !== preset.lock.manifestDigest) throw new Error("Ollama base manifest differs from the pinned digest; refusing preset creation");
  await request(`/api/blobs/${preset.lock.modelDigest}`, undefined, "HEAD");
  // Use the content-addressed GGUF, never resolve the mutable base tag during
  // create. Template and license bytes were independently checked above.
  const created = await request("/api/create", {
    model, files: { "qwen2.5.gguf": preset.lock.modelDigest }, template: preset.template,
    license: preset.license, system: preset.system, parameters: preset.parameters, stream: false,
  }, "POST", 120_000);
  if (created.status !== "success") throw new Error("Ollama preset creation did not complete");
  const installed = await request("/api/show", { model });
  const importedDigest = installed.modelfile?.match(/^FROM\s+.*sha256-([a-f0-9]{64})\s*$/m)?.[1];
  if (`sha256:${importedDigest}` !== preset.lock.modelDigest) throw new Error("Created preset does not reference the pinned model weights");
  return { model, baseModel: preset.lock.model, manifestDigest: preset.lock.manifestDigest, modelDigest: preset.lock.modelDigest };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length > 2) throw new Error("Usage: node install.mjs [output-model] [local-ollama-url]");
    console.log(JSON.stringify(await installPreset({ model: args[0], baseUrl: args[1] }), null, 2));
  } catch (error) {
    console.error(`Aurels preset installation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
