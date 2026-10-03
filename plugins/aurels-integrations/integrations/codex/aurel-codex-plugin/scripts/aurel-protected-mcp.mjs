#!/usr/bin/env node

import { spawn } from "node:child_process";
import process from "node:process";
import { fileURLToPath } from "node:url";

export function buildProxyLaunch(env = process.env) {
  const command = env.AUREL_UPSTREAM_MCP_COMMAND;
  if (!command) {
    throw new Error("AUREL_UPSTREAM_MCP_COMMAND is required for the Codex Aurel MCP guard.");
  }

  const proxyPath = env.AUREL_MCP_PROXY_PATH ?? "plugins/aurels-integrations/integrations/mcp/src/aurel-mcp-proxy.mjs";
  const args = parseArgs(env.AUREL_UPSTREAM_MCP_ARGS);
  return {
    proxyPath,
    command,
    args,
    argv: [proxyPath, "--", command, ...args],
  };
}

export function main(env = process.env) {
  let launch;
  try {
    launch = buildProxyLaunch(env);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(64);
  }

  const child = spawn(process.execPath, launch.argv, {
    stdio: "inherit",
    env: { ...env, AUREL_MCP_INTEGRATION: "codex" },
  });

  child.on("error", (error) => {
    console.error(`Failed to start Aurel MCP proxy: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(70);
  });
  child.on("exit", (code) => process.exit(code ?? 0));
}

export function parseArgs(value) {
  if (!value) return [];
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return value.split(" ").filter(Boolean);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main();
}
