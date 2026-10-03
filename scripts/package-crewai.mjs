import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const output = resolve(root, "dist");
const source = resolve(root, "plugins/aurels-integrations/integrations/crewai");
await mkdir(output, { recursive: true });
const python = process.env.PYTHON ?? (process.platform === "win32" ? "python" : "python3");
execFileSync(python, ["-m", "pip", "wheel", "--no-deps", "--wheel-dir", output, source], { stdio: "inherit" });
