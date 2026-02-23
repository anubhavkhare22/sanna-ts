#!/usr/bin/env node
/**
 * Minimal MCP server that reports its own environment variables.
 *
 * Used by downstream-env.test.ts to verify that the gateway's
 * environment allowlist is enforced when spawning child processes.
 *
 * Exposes one tool:
 *   - report_env: returns JSON.stringify(process.env)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "env-reporter", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "report_env",
      description: "Return the process environment as JSON",
      inputSchema: {
        type: "object" as const,
        properties: {},
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name } = request.params;

  if (name === "report_env") {
    return {
      content: [{ type: "text", text: JSON.stringify(process.env) }],
    };
  }

  return {
    content: [{ type: "text", text: `Unknown tool: ${name}` }],
    isError: true,
  };
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`Env reporter error: ${err}\n`);
  process.exit(1);
});
