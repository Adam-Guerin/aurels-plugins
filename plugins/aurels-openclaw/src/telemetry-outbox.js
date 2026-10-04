import { createHash, randomUUID } from "node:crypto";
import { chmod, link, lstat, mkdir, open, readFile, readdir, rename, rm, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

export const MAX_OUTBOX_EVENTS = 1000;
export const MAX_OUTBOX_BYTES = 8 * 1024 * 1024;
export const MAX_OUTBOX_EVENT_BYTES = 64_000;
export const MAX_OUTBOX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const FLUSH_BATCH_SIZE = 20;
const INITIAL_RETRY_DELAY_MS = 1000;
const MAX_RETRY_DELAY_MS = 60_000;
const MAX_STAGING_AGE_MS = 24 * 60 * 60 * 1000;

export function defaultTelemetrySpoolDir(env = process.env, platform = process.platform) {
  if (env.AURELS_TELEMETRY_SPOOL_DIR) return env.AURELS_TELEMETRY_SPOOL_DIR;
  if (platform === "win32") return join(env.LOCALAPPDATA || join(homedir(), "AppData", "Local"), "Aurels", "plugins", "openclaw", "telemetry");
  if (platform === "darwin") return join(homedir(), "Library", "Application Support", "Aurels", "plugins", "openclaw", "telemetry");
  return join(env.XDG_STATE_HOME || join(homedir(), ".local", "state"), "aurels", "plugins", "openclaw", "telemetry");
}

export class TelemetryOutbox {
  constructor(directory = defaultTelemetrySpoolDir()) {
    this.directory = resolve(directory);
    this.flushing = null;
    this.retryTimer = null;
    this.retryDelayMs = INITIAL_RETRY_DELAY_MS;
  }

  async initialize() {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    const info = await lstat(this.directory);
    if (info.isSymbolicLink() || !info.isDirectory()) throw new Error("Telemetry spool path must be a real directory");
    if (process.platform !== "win32") await chmod(this.directory, 0o700);
  }

  async enqueue(event) {
    await this.initialize();
    return this.#withQueueLock(async () => {
      await this.#purgeExpired();
      const serialized = JSON.stringify(event);
      const bytes = Buffer.byteLength(serialized, "utf8");
      if (bytes > MAX_OUTBOX_EVENT_BYTES) throw new Error("Telemetry event exceeds the local spool limit");
      const fileName = `${createHash("sha256").update(serialized).digest("hex")}.json`;
      const destination = join(this.directory, fileName);
      try {
        await lstat(destination);
        return destination;
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }

      const entries = await readdir(this.directory, { withFileTypes: true });
      let count = 0;
      let totalBytes = 0;
      for (const entry of entries) {
        if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
        const info = await lstat(join(this.directory, entry.name));
        if (!info.isFile() || info.isSymbolicLink()) continue;
        count += 1;
        totalBytes += info.size;
      }
      if (count >= MAX_OUTBOX_EVENTS || totalBytes + bytes > MAX_OUTBOX_BYTES) {
        throw new Error("Telemetry spool is full; event was not persisted");
      }

      const temporary = join(this.directory, `.pending-${process.pid}-${randomUUID()}.tmp`);
      const handle = await open(temporary, "wx", 0o600);
      try {
        await handle.writeFile(serialized, "utf8");
        await handle.sync();
      } finally {
        await handle.close();
      }
      try {
        try {
          await link(temporary, destination);
        } catch (error) {
          if (error.code === "EEXIST") return destination;
          if (!new Set(["EPERM", "ENOTSUP", "EOPNOTSUPP"]).has(error.code)) throw error;
          try { await lstat(destination); return destination; }
          catch (existsError) { if (existsError.code !== "ENOENT") throw existsError; }
          await rename(temporary, destination);
        }
        return destination;
      } finally {
        await rm(temporary, { force: true });
      }
    });
  }

  async flush(sender) {
    if (this.retryTimer) {
      clearTimeout(this.retryTimer);
      this.retryTimer = null;
    }
    if (this.flushing) return this.flushing;
    const operation = this.#flush(sender);
    this.flushing = operation;
    operation.then(
      (delivered) => {
        this.flushing = null;
        void this.#scheduleRetry(sender, delivered);
      },
      () => {
        this.flushing = null;
        void this.#scheduleRetry(sender, 0);
      }
    );
    return operation;
  }

  async #flush(sender) {
    await this.initialize();
    await this.#purgeExpired();
    const entries = (await readdir(this.directory, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
      .map((entry) => entry.name)
      .sort();
    let delivered = 0;
    for (const name of entries) {
      if (delivered >= FLUSH_BATCH_SIZE) break;
      const path = join(this.directory, name);
      try {
        const info = await lstat(path);
        if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_OUTBOX_EVENT_BYTES) continue;
        const event = JSON.parse(await readFile(path, "utf8"));
        await sender(event);
      } catch {
        // Keep failed events intact for the next startup or telemetry event.
        break;
      }
      await unlink(path).catch(() => {});
      delivered += 1;
    }
    if (delivered > 0 && (await readdir(this.directory)).some((name) => name.endsWith(".json"))) {
      setImmediate(() => { void this.flush(sender).catch(() => {}); });
    }
    return delivered;
  }

  async #purgeExpired() {
    const entries = await readdir(this.directory, { withFileTypes: true });
    const cutoff = Date.now() - MAX_OUTBOX_AGE_MS;
    const stagingCutoff = Date.now() - MAX_STAGING_AGE_MS;
    for (const entry of entries) {
      if (!entry.isFile()) continue;
      const path = join(this.directory, entry.name);
      try {
        const info = await lstat(path);
        if (entry.name.startsWith(".pending-") && entry.name.endsWith(".tmp") && info.isFile() && !info.isSymbolicLink() && info.mtimeMs < stagingCutoff) {
          await unlink(path);
          continue;
        }
        if (!entry.name.endsWith(".json")) continue;
        if (info.isFile() && !info.isSymbolicLink() && info.mtimeMs < cutoff) {
          await unlink(path);
          console.warn("Aurels telemetry event expired from the local outbox.");
        }
      } catch { /* A concurrent flush or filesystem failure must not affect enforcement. */ }
    }
  }

  async #scheduleRetry(sender, delivered) {
    let hasPendingEvents;
    try {
      hasPendingEvents = (await readdir(this.directory, { withFileTypes: true }))
        .some((entry) => entry.isFile() && entry.name.endsWith(".json"));
    } catch {
      hasPendingEvents = true;
    }
    if (!hasPendingEvents) {
      this.retryDelayMs = INITIAL_RETRY_DELAY_MS;
      return;
    }
    if (delivered >= FLUSH_BATCH_SIZE) {
      setImmediate(() => { void this.flush(sender).catch(() => {}); });
      return;
    }
    if (this.retryTimer) return;
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      void lstat(this.directory).then(
        () => this.flush(sender).catch(() => {}),
        (error) => { if (error.code !== "ENOENT") void this.flush(sender).catch(() => {}); }
      );
    }, this.retryDelayMs);
    this.retryTimer.unref?.();
    this.retryDelayMs = Math.min(this.retryDelayMs * 2, MAX_RETRY_DELAY_MS);
  }

  async #withQueueLock(operation) {
    const lockPath = join(this.directory, ".enqueue.lock");
    const deadline = Date.now() + 500;
    let handle;
    while (!handle) {
      try {
        handle = await open(lockPath, "wx", 0o600);
        await handle.writeFile(String(process.pid), "utf8");
        await handle.sync();
      } catch (error) {
        if (handle) {
          await handle.close().catch(() => {});
          handle = null;
          await unlink(lockPath).catch(() => {});
        }
        const contended = error.code === "EEXIST" || (process.platform === "win32" && ["EPERM", "EACCES"].includes(error.code));
        if (!contended) throw error;
        if (await this.#isStaleQueueLock(lockPath)) await unlink(lockPath).catch(() => {});
        if (Date.now() >= deadline) throw new Error("Telemetry queue is busy; event was not persisted");
        await new Promise((resolveDelay) => setTimeout(resolveDelay, 10 + Math.floor(Math.random() * 20)));
      }
    }
    try {
      return await operation();
    } finally {
      await handle.close();
      await unlink(lockPath).catch(() => {});
    }
  }

  async #isStaleQueueLock(lockPath) {
    try {
      const info = await lstat(lockPath);
      if (!info.isFile() || info.isSymbolicLink()) return false;
      const content = await readFile(lockPath, "utf8");
      const pid = Number(content);
      if (Number.isSafeInteger(pid) && pid > 0) {
        try { process.kill(pid, 0); return false; }
        catch (error) {
          if (error.code !== "ESRCH") return false;
          // A new contender may replace the stale path while the PID probe runs.
          // Only let the caller unlink the same file instance that was inspected.
          const current = await lstat(lockPath).catch(() => null);
          if (!current || current.dev !== info.dev || current.ino !== info.ino) return false;
          return (await readFile(lockPath, "utf8").catch(() => null)) === content;
        }
      }
      return Date.now() - info.mtimeMs > 30_000;
    } catch {
      // A missing lock may already have been replaced by another writer.
      return false;
    }
  }
}
