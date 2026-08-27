import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { APP_VERSION } from "../src/core/version.js";

const cli = fileURLToPath(new URL("../dist/src/cli.js", import.meta.url));
const mcp = fileURLToPath(new URL("../dist/src/mcp.js", import.meta.url));

describe("public CLI surface", () => {
  it("starts the versioned MCP server through the npm-facing CLI subcommand", async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [cli, "mcp"],
      stderr: "pipe"
    });
    const client = new Client({ name: "browseweave-cli-test", version: "0.1.0" });
    try {
      await client.connect(transport);
      expect(client.getServerVersion()).toEqual({ name: "browseweave", version: APP_VERSION });
      expect((await client.listTools()).tools.length).toBeGreaterThanOrEqual(22);
    } finally {
      await client.close();
    }
  });

  it("keeps guided setup public without exposing a pairing-token command", () => {
    const result = spawnSync(process.execPath, [cli, "--help"], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`npx browseweave@${APP_VERSION} setup`);
    expect(result.stdout).toContain("--all-browsers");
    expect(result.stdout).toContain("Pairing credentials are never printed");
    expect(result.stdout).not.toContain("pairing-token");
  });

  it("prints a direct exact-runtime MCP entry without npm startup work", () => {
    const result = spawnSync(process.execPath, [cli, "mcp-config", "generic"], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status, result.stderr).toBe(0);
    const output = JSON.parse(result.stdout) as Record<string, any>;
    expect(output.config.mcpServers.browseweave).toEqual({
      command: process.execPath,
      args: [mcp],
      env: {}
    });
    expect(result.stdout).not.toMatch(/npm|npx|@latest/iu);
  });

  it("keeps all-browser setup mutually exclusive with a single browser target", () => {
    const result = spawnSync(process.execPath, [
      cli,
      "setup",
      "--all-browsers",
      "--browser",
      "chrome"
    ], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Choose either --all-browsers or one explicit --browser target");
  });

  it("accepts firefox as an explicit setup browser target", () => {
    const result = spawnSync(process.execPath, [cli, "setup", "--browser", "firefox"], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("visible interactive terminal");
    expect(result.stderr).not.toContain("--browser must be");
  });

  it("rejects an unknown setup browser target with the full accepted list", () => {
    const result = spawnSync(process.execPath, [cli, "setup", "--browser", "edge"], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("--browser must be chrome, zen, or firefox.");
  });

  it("resolves the packaged firefox extension directory on request", () => {
    const result = spawnSync(process.execPath, [cli, "extension-path", "firefox"], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout.trim()).toMatch(/firefox-mv2\/$/u);
  });

  it("refuses a duplicate all-browser selection before starting setup", () => {
    const result = spawnSync(process.execPath, [
      cli,
      "setup",
      "--all-browsers",
      "--all-browsers"
    ], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Choose --all-browsers only once");
  });

  it("accepts all-browser mode only from the required visible terminal", () => {
    const result = spawnSync(process.execPath, [cli, "setup", "--all-browsers"], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("visible interactive terminal");
  });

  it("rejects the removed legacy display command without printing data", () => {
    const result = spawnSync(process.execPath, [cli, "pairing-token", "--show", "--browser", "chrome"], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Unknown command: pairing-token");
  });
});
