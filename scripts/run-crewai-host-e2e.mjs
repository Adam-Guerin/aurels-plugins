import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const result = spawnSync(process.env.CREWAI_PYTHON ?? "python", ["tests/e2e-crewai-host.py"], {
  cwd: resolve(import.meta.dirname, ".."), stdio: "inherit",
  env: { ...process.env, CREWAI_TELEMETRY_DISABLED: "true", OTEL_SDK_DISABLED: "true" },
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
