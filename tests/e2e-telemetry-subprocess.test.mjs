import test from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const NODE_OUTBOX = pathToFileURL(join(ROOT, "plugins/aurels-openclaw/src/telemetry-outbox.js")).href;
const PYTHON_OUTBOX_ROOT = join(ROOT, "plugins/aurels-hermes");

function runChild(command, args, env) {
  const child = spawn(command, args, { env, stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  return once(child, "close").then(([code, signal]) => ({ code, signal, stdout, stderr }));
}

async function seedNearlyFullQueue(directory, eventBytes, maxBytes) {
  const remainingSlots = 5;
  await writeFile(join(directory, "occupier.json"), Buffer.alloc(maxBytes - remainingSlots * eventBytes, 0x78));
}

async function assertQueueUnderCap(directory, maxBytes) {
  const files = (await readdir(directory)).filter((name) => name.endsWith(".json"));
  const bytes = (await Promise.all(files.map(async (name) => (await readFile(join(directory, name))).byteLength)))
    .reduce((sum, size) => sum + size, 0);
  assert.ok(bytes <= maxBytes, `subprocess contention exceeded the ${maxBytes}-byte cap with ${bytes} bytes`);
  return files.length;
}

test("OpenClaw telemetry outbox remains under its cap across independent Node processes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aurels-openclaw-process-cap-"));
  try {
    const events = Array.from({ length: 16 }, (_, index) => ({ actionId: `node-process-${index}` }));
    const eventBytes = Math.max(...events.map((event) => Buffer.byteLength(JSON.stringify(event), "utf8")));
    const { MAX_OUTBOX_BYTES } = await import(NODE_OUTBOX);
    await seedNearlyFullQueue(directory, eventBytes, MAX_OUTBOX_BYTES);
    const children = events.map((event) => runChild(process.execPath, ["--input-type=module", "-e", `
      import { TelemetryOutbox } from ${JSON.stringify(NODE_OUTBOX)};
      const outbox = new TelemetryOutbox(process.env.AURELS_TEST_SPOOL);
      try {
        await outbox.enqueue({ actionId: process.env.AURELS_TEST_EVENT });
        process.stdout.write("admitted");
      } catch (error) {
        process.stdout.write("rejected:" + error.message);
      }
    `], { ...process.env, AURELS_TEST_SPOOL: directory, AURELS_TEST_EVENT: event.actionId }));
    const results = await Promise.all(children);
    assert.deepEqual(results.filter((result) => result.code !== 0), [], JSON.stringify(results));
    const admitted = results.filter((result) => result.stdout === "admitted").length;
    assert.ok(admitted > 0 && admitted <= 5, `expected at least one and no more than five admitted writers; got ${admitted}`);
    assert.equal(results.filter((result) => result.stdout.startsWith("rejected:")).length, events.length - admitted, "every other writer must report why it was refused");
    assert.ok(results.filter((result) => result.stdout.startsWith("rejected:")).every((result) => /spool is full|queue is busy/.test(result.stdout)), JSON.stringify(results));
    assert.equal(await assertQueueUnderCap(directory, MAX_OUTBOX_BYTES), admitted + 1, "the queue should contain its occupier and only admitted events");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("Hermes telemetry outbox remains under its cap across independent Python processes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aurels-hermes-process-cap-"));
  try {
    // Eight independent interpreters are enough to contend for five slots;
    // keep Windows runners reliable without weakening the cross-process check.
    const events = Array.from({ length: 8 }, (_, index) => `python-process-${index}`);
    const eventBytes = Math.max(...events.map((actionId) => Buffer.byteLength(JSON.stringify({ actionId }))));
    const MAX_BYTES = 8 * 1024 * 1024;
    await seedNearlyFullQueue(directory, eventBytes, MAX_BYTES);
    const source = `
import os
from aurels_hermes.outbox import TelemetryOutbox
outbox = TelemetryOutbox(os.environ["AURELS_TEST_SPOOL"])
try:
    outbox.enqueue({"actionId": os.environ["AURELS_TEST_EVENT"]})
    print("admitted", end="")
except OSError as error:
    print(f"rejected:{error}", end="")
`;
    const children = events.map((event) => runChild(process.env.PYTHON || "python", ["-c", source], {
      ...process.env,
      PYTHONPATH: [PYTHON_OUTBOX_ROOT, process.env.PYTHONPATH].filter(Boolean).join(delimiter),
      AURELS_TEST_SPOOL: directory,
      AURELS_TEST_EVENT: event,
    }));
    const results = await Promise.all(children);
    assert.deepEqual(results.filter((result) => result.code !== 0), [], JSON.stringify(results));
    const admitted = results.filter((result) => result.stdout === "admitted").length;
    assert.ok(admitted > 0 && admitted <= 5, `expected at least one and no more than five admitted writers; got ${admitted}`);
    assert.equal(results.filter((result) => result.stdout.startsWith("rejected:")).length, events.length - admitted, "every other writer must report why it was refused");
    assert.ok(results.filter((result) => result.stdout.startsWith("rejected:")).every((result) => /spool is full|queue is busy/.test(result.stdout)), JSON.stringify(results));
    assert.equal(await assertQueueUnderCap(directory, MAX_BYTES), admitted + 1, "the queue should contain its occupier and only admitted events");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
