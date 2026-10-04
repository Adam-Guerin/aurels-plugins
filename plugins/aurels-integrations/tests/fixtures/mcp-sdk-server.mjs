import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { appendFileSync } from "node:fs";

const server = new Server({ name: "aurels-dispatch-fixture", version: "1.0.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [{ name: "read_file", description: "Synthetic dispatch only", inputSchema: { type: "object" } }],
}));
server.setRequestHandler(CallToolRequestSchema, async ({ params }) => {
  if (process.env.AURELS_TEST_DISPATCH_LOG) appendFileSync(process.env.AURELS_TEST_DISPATCH_LOG, JSON.stringify(params.arguments) + "\n");
  if (params.arguments?.hostDelay) await new Promise((resolve) => setTimeout(resolve, params.arguments.hostDelay));
  return { isError: params.arguments?.hostFailure === true, content: [{ type: "text", text: JSON.stringify(params.arguments) }] };
});
await server.connect(new StdioServerTransport());
