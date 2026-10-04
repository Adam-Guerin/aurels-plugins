import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { delimiter, join, resolve } from "node:path";

const repo = resolve(import.meta.dirname, "..");
const candidates = [
  process.env.HERMES_SOURCE_DIR,
  join(process.env.LOCALAPPDATA ?? "", "hermes", "hermes-agent"),
  join(process.env.HOME ?? "", ".hermes", "hermes-agent"),
  join(process.env.HOME ?? "", "hermes-agent"),
].filter(Boolean).map((candidate) => resolve(candidate));
const source = candidates.find((candidate) => existsSync(join(candidate, "hermes_cli", "plugins.py")));

if (!source) {
  console.error("Hermes host E2E needs a Hermes Agent source checkout. Set HERMES_SOURCE_DIR to its path.");
  process.exit(2);
}

const python = process.env.HERMES_PYTHON ?? "python";
const separator = process.env.PYTHONPATH ? delimiter : "";
const result = spawnSync(python, ["tests/e2e-hermes-host.py"], {
  cwd: repo,
  stdio: "inherit",
  env: {
    ...process.env,
    HERMES_SOURCE_DIR: source,
    PYTHONPATH: `${source}${separator}${process.env.PYTHONPATH ?? ""}`,
  },
});
if (result.error) throw result.error;
process.exit(result.status ?? 1);
