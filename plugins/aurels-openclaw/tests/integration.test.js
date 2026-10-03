/**
 * Integration tests for OpenClaw plugin structure.
 * These tests validate plugin structure without requiring OpenClaw runtime.
 * Run with: node --test tests/integration.test.js
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

async function testPluginEntry() {
  try {
    const plugin = await import("../src/index.js");
    if (!plugin.default) {
      throw new Error("Plugin should have default export");
    }
    if (typeof plugin.default.register !== "function") {
      throw new Error("Plugin should have register function");
    }
    console.log("Plugin entry point validated");
    return true;
  } catch (error) {
    console.error("Failed to import plugin:", error);
    return false;
  }
}

async function testPluginManifest() {
  try {
    const manifestPath = join(process.cwd(), "openclaw.plugin.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    
    if (!manifest.id) {
      throw new Error("Manifest should have id");
    }
    if (!manifest.version) {
      throw new Error("Manifest should have version");
    }
    if (!manifest.configSchema) {
      throw new Error("Manifest should have configSchema");
    }
    
    console.log("Plugin manifest validated");
    return true;
  } catch (error) {
    console.error("Failed to validate manifest:", error);
    return false;
  }
}

async function testReadmeMatchesPackageAndLocalDecisionContract() {
  try {
    const packageJson = JSON.parse(readFileSync(join(process.cwd(), "package.json"), "utf8"));
    const readme = readFileSync(join(process.cwd(), "README.md"), "utf8");
    if (!readme.includes(`\`${packageJson.name}\``)) {
      throw new Error(`README package name does not match ${packageJson.name}`);
    }
    if (/Local deterministic `allow`/.test(readme) || !/Local ambiguous action/.test(readme)) {
      throw new Error("README must describe the offline policy as destructive block or ambiguous approval, never automatic allow");
    }
    console.log("Package identity and local decision documentation validated");
    return true;
  } catch (error) {
    console.error("Failed to validate README contract:", error);
    return false;
  }
}

async function runTests() {
  console.log("Running OpenClaw integration tests...");
  
  const entryOk = await testPluginEntry();
  if (!entryOk) {
    console.log("Plugin entry test failed");
    process.exit(1);
  }
  
  const manifestOk = await testPluginManifest();
  if (!manifestOk) {
    console.log("Plugin manifest test failed");
    process.exit(1);
  }

  const readmeOk = await testReadmeMatchesPackageAndLocalDecisionContract();
  if (!readmeOk) {
    console.log("README contract test failed");
    process.exit(1);
  }
  
  console.log("Integration tests passed");
}

runTests().catch(error => {
  console.error("Integration tests failed:", error);
  process.exit(1);
});
