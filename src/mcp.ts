#!/usr/bin/env node

import { isDirectExecution } from "./core/entrypoint.js";
import { main } from "./mcp/server.js";

export { main } from "./mcp/server.js";

if (isDirectExecution(import.meta.url)) {
  void main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`BrowseWeave MCP server failed to start: ${message}`);
    process.exitCode = 1;
  });
}
