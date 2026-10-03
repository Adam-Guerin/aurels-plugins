import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";

const integrations = new Set(["langgraph", "openai-agents", "mcp"]);
const name = process.argv[2];
if (!integrations.has(name)) throw new Error(`Unsupported npm integration: ${name ?? "(missing)"}`);

const root = resolve(import.meta.dirname, "..");
const packageDirectory = resolve(root, "plugins/aurels-integrations/integrations", name);
const output = resolve(root, "dist");
await mkdir(output, { recursive: true });
execFileSync("npm", ["pack", "--pack-destination", output], { cwd: packageDirectory, stdio: "inherit", shell: process.platform === "win32" });
