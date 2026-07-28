import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.resolve(scriptDirectory, "..");
const serverPath = path.join(projectDirectory, "dist", "src", "mcp.js");

const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverPath],
  stderr: "pipe"
});
const client = new Client({ name: "browseweave-smoke-client", version: "0.1.0" });

try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  const names = new Set(tools.map((tool) => tool.name));
  const required = [
    "browser_status",
    "browser_list_tabs",
    "browser_snapshot",
    "browser_screenshot",
    "browser_click",
    "browser_type",
    "browser_fill_form",
    "browser_prepare_credential_handoff",
    "browser_fill_credentials",
    "browser_wait",
    "browser_hover",
    "browser_click_at",
    "browser_new_tab",
    "browser_cleanup_tabs"
  ];

  for (const name of required) {
    assert(names.has(name), `MCP tool is missing: ${name}`);
  }
  assert(!names.has("browser_confirm_action"), "Model-callable sensitive approval bypass must not exist");
  assert(!names.has("browser_confirm_pending"), "Model-callable pending-approval bypass must not exist");

  assert(tools.length >= 22, `Expected at least 22 BrowseWeave tools, received ${tools.length}`);
  const snapshot = tools.find((tool) => tool.name === "browser_snapshot");
  const click = tools.find((tool) => tool.name === "browser_click");
  const cleanup = tools.find((tool) => tool.name === "browser_cleanup_tabs");
  assert(snapshot?.inputSchema?.properties?.mode, "Snapshot context-filter mode is missing");
  assert(snapshot?.inputSchema?.properties?.query, "Snapshot query filter is missing");
  assert(snapshot?.inputSchema?.properties?.since_snapshot_id, "Snapshot delta input is missing");
  assert(click?.inputSchema?.properties?.frame_id, "Frame-aware element targeting is missing");
  assert(cleanup?.inputSchema?.properties?.tab_ids, "Managed-tab cleanup targeting is missing");
  console.error(`MCP smoke passed: ${tools.length} tools discovered`);
} finally {
  await client.close();
}
