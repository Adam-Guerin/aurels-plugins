import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";

const root = resolve(import.meta.dirname, "..");
const output = resolve(root, "dist");
await mkdir(output, { recursive: true });
execFileSync("npm", ["pack", "--pack-destination", output], {
  cwd: resolve(root, "plugins/aurels-evaluator"), stdio: "inherit", shell: process.platform === "win32",
});
