import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  claudeRegistrationState,
  claudeProjectRegistrationState,
  clientSetup,
  codexRegistrationState,
  mergeCursorConfig,
  mergeOpenCodeConfig,
  parseStrictJson,
  selectOpenCodeVersion,
  serializeClientSetup,
  validateMcpLaunchSpec,
  type McpLaunchSpec
} from "../src/clients/client-config.js";

const spec: McpLaunchSpec = {
  command: "/opt/BrowseWeave Runtime/node",
  args: ['/opt/BrowseWeave App/mcp "global".js'],
  env: {}
};

const temporaryDirectories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "browseweave-client-config-"));
  temporaryDirectories.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("vendor-neutral MCP client setup", () => {
  it("builds argument arrays for Codex and Claude Code without shell quoting", () => {
    expect(clientSetup("codex", spec).command).toEqual([
      "codex", "mcp", "add", "browseweave", "--", spec.command, ...spec.args
    ]);
    expect(clientSetup("claude-code", spec).command).toEqual([
      "claude", "mcp", "add", "--transport", "stdio", "--scope", "user",
      "browseweave", "--", spec.command, ...spec.args
    ]);
  });

  it("produces Cursor, explicit OpenCode V1/V2, and generic stdio JSON", () => {
    expect(clientSetup("cursor", spec).config).toMatchObject({
      mcpServers: { browseweave: { command: spec.command, args: spec.args, env: {} } }
    });
    expect(clientSetup("opencode", spec, 1).config).toMatchObject({
      mcp: { browseweave: { type: "local", command: [spec.command, ...spec.args], enabled: true } }
    });
    expect(clientSetup("opencode", spec, 2).config).toMatchObject({
      mcp: { servers: { browseweave: { type: "local", command: [spec.command, ...spec.args], disabled: false } } }
    });
    expect(() => clientSetup("opencode", spec)).toThrow(/choose OpenCode schema/iu);
    expect(clientSetup("generic", spec).config).toMatchObject({ mcpServers: { browseweave: {} } });
  });

  it("never places credentials or environment values into generated configuration", () => {
    const output = serializeClientSetup(clientSetup("generic", spec));
    expect(output).not.toMatch(/token|secret|password|api[_-]?key/iu);
    expect(() => validateMcpLaunchSpec({
      ...spec,
      env: { BROWSER_MCP_BRIDGE_TOKEN: "must-not-be-written" }
    })).toThrow(/does not write environment variables/iu);
    expect(() => validateMcpLaunchSpec({ ...spec, command: "node" })).toThrow(/absolute path/iu);
  });

  it("rejects duplicate JSON keys including escaped aliases", () => {
    expect(() => parseStrictJson('{"mcpServers":{},"mcp\\u0053ervers":{}}')).toThrow(/duplicate object key/iu);
    expect(() => parseStrictJson('{"mcpServers":{/*comment*/}}')).toThrow(/safe strict JSON/iu);
  });

  it("verifies exact Codex and Claude registrations", () => {
    const codex = [{
      name: "browseweave",
      enabled: true,
      transport: { type: "stdio", command: spec.command, args: spec.args, env: null, env_vars: [] }
    }];
    expect(codexRegistrationState(codex, spec)).toBe("exact");
    expect(codexRegistrationState([], spec)).toBe("absent");
    expect(codexRegistrationState([{
      ...codex[0],
      transport: { ...codex[0]!.transport, command: "/foreign/node" }
    }], spec)).toBe("foreign");

    const claude = {
      mcpServers: {
        browseweave: { type: "stdio", command: spec.command, args: spec.args, env: {} }
      }
    };
    expect(claudeRegistrationState(claude, spec)).toBe("exact");
    expect(claudeRegistrationState({}, spec)).toBe("absent");
    expect(claudeRegistrationState({
      mcpServers: { browseweave: { ...claude.mcpServers.browseweave, cwd: "/foreign" } }
    }, spec)).toBe("foreign");
    expect(claudeRegistrationState({
      ...claude,
      projects: {
        "/work": { mcpServers: { browseweave: claude.mcpServers.browseweave } }
      }
    }, spec)).toBe("foreign");
    expect(claudeProjectRegistrationState(claude, spec)).toBe("exact");
  });
});

describe("safe direct MCP configuration merges", () => {
  it("atomically adds Cursor while preserving unrelated entries and is idempotent", async () => {
    const directory = await temporaryDirectory();
    const configPath = path.join(directory, ".cursor", "mcp.json");
    await mkdir(path.dirname(configPath), { recursive: true });
    await writeFile(configPath, JSON.stringify({
      editor: { theme: "dark" },
      mcpServers: { other: { command: "/opt/other", args: [] } }
    }), "utf8");

    expect(await mergeCursorConfig(configPath, spec)).toMatchObject({ status: "updated" });
    const merged = JSON.parse(await readFile(configPath, "utf8")) as Record<string, any>;
    expect(merged.editor).toEqual({ theme: "dark" });
    expect(merged.mcpServers.other).toEqual({ command: "/opt/other", args: [] });
    expect(merged.mcpServers.browseweave).toEqual({ command: spec.command, args: spec.args, env: {} });
    const afterFirstMerge = await readFile(configPath, "utf8");
    expect(await mergeCursorConfig(configPath, spec)).toMatchObject({ status: "unchanged" });
    expect(await readFile(configPath, "utf8")).toBe(afterFirstMerge);
    if (process.platform !== "win32") expect((await stat(configPath)).mode & 0o777).toBe(0o600);
  });

  it("creates a missing Cursor config but rejects foreign entries and symlinks", async () => {
    const directory = await temporaryDirectory();
    const createdPath = path.join(directory, "new", "mcp.json");
    expect(await mergeCursorConfig(createdPath, spec)).toMatchObject({ status: "created" });

    const foreignPath = path.join(directory, "foreign.json");
    await writeFile(foreignPath, JSON.stringify({
      mcpServers: { browseweave: { command: "/foreign/node", args: [] } }
    }));
    const before = await readFile(foreignPath, "utf8");
    await expect(mergeCursorConfig(foreignPath, spec)).rejects.toThrow(/foreign browseweave/iu);
    expect(await readFile(foreignPath, "utf8")).toBe(before);

    if (process.platform !== "win32") {
      const realPath = path.join(directory, "real.json");
      const linkPath = path.join(directory, "link.json");
      await writeFile(realPath, "{}\n");
      await symlink(realPath, linkPath);
      await expect(mergeCursorConfig(linkPath, spec)).rejects.toThrow(/non-regular/iu);
    }
  });

  it("merges the explicitly selected OpenCode schema without guessing from server names", async () => {
    const directory = await temporaryDirectory();
    const v1Path = path.join(directory, "v1.json");
    const literalServersEntry = { type: "local", command: ["/opt/servers"], enabled: true };
    await writeFile(v1Path, JSON.stringify({ mcp: { servers: literalServersEntry } }));
    expect(await mergeOpenCodeConfig(v1Path, spec, 1)).toMatchObject({ status: "updated", opencodeVersion: 1 });
    const v1 = JSON.parse(await readFile(v1Path, "utf8")) as Record<string, any>;
    expect(v1.mcp.servers).toEqual(literalServersEntry);
    expect(v1.mcp.browseweave).toEqual({
      type: "local", command: [spec.command, ...spec.args], enabled: true
    });

    const v2Path = path.join(directory, "v2.json");
    const timeout = { startup: 45_000, catalog: 30_000, execution: 600_000 };
    await writeFile(v2Path, JSON.stringify({
      mcp: { timeout, servers: { other: { type: "local", command: ["/opt/other"] } } }
    }));
    expect(await mergeOpenCodeConfig(v2Path, spec, 2)).toMatchObject({ status: "updated", opencodeVersion: 2 });
    const v2 = JSON.parse(await readFile(v2Path, "utf8")) as Record<string, any>;
    expect(v2.mcp.timeout).toEqual(timeout);
    expect(v2).toMatchObject({
      mcp: { servers: { browseweave: { disabled: false, command: [spec.command, ...spec.args] } } }
    });

    const jsoncPath = path.join(directory, "opencode.jsonc");
    const jsoncSource = '{\n  // Keep this user comment.\n  "mcp": {\n    "servers": {\n      "other": { "type": "local", "command": ["/opt/other"] },\n    },\n  },\n}\n';
    await writeFile(jsoncPath, jsoncSource);
    expect(await mergeOpenCodeConfig(jsoncPath, spec, 2)).toMatchObject({ status: "updated", opencodeVersion: 2 });
    const mergedJsonc = await readFile(jsoncPath, "utf8");
    expect(mergedJsonc).toContain("// Keep this user comment.");
    expect(mergedJsonc).toContain('"browseweave"');
    expect(await mergeOpenCodeConfig(jsoncPath, spec, 2)).toMatchObject({ status: "unchanged", opencodeVersion: 2 });
  });

  it("safely creates fresh OpenCode V1 and V2 configuration files", async () => {
    const directory = await temporaryDirectory();
    const v1Path = path.join(directory, "v1", "opencode.json");
    const v2Path = path.join(directory, "v2", "opencode.jsonc");
    expect(await mergeOpenCodeConfig(v1Path, spec, 1)).toMatchObject({ status: "created", opencodeVersion: 1 });
    expect(await mergeOpenCodeConfig(v2Path, spec, 2)).toMatchObject({ status: "created", opencodeVersion: 2 });
    expect(JSON.parse(await readFile(v1Path, "utf8"))).toEqual({
      mcp: { browseweave: { type: "local", command: [spec.command, ...spec.args], enabled: true } }
    });
    expect(JSON.parse(await readFile(v2Path, "utf8"))).toEqual({
      mcp: { servers: { browseweave: { type: "local", command: [spec.command, ...spec.args], disabled: false } } }
    });
  });

  it("selects OpenCode generation from executable names and requires a flag for conflicts or no binary", () => {
    expect(selectOpenCodeVersion({ v1: true, v2: false })).toBe(1);
    expect(selectOpenCodeVersion({ v1: false, v2: true })).toBe(2);
    expect(selectOpenCodeVersion({ v1: true, v2: true }, 1)).toBe(1);
    expect(selectOpenCodeVersion({ v1: true, v2: true }, 2)).toBe(2);
    expect(selectOpenCodeVersion({ v1: false, v2: false }, 2)).toBe(2);
    expect(() => selectOpenCodeVersion({ v1: true, v2: true })).toThrow(/both opencode/iu);
    expect(() => selectOpenCodeVersion({ v1: false, v2: false })).toThrow(/no opencode executable/iu);
    expect(() => selectOpenCodeVersion({ v1: true, v2: false }, 2)).toThrow(/opencode identifies OpenCode V1/iu);
    expect(() => selectOpenCodeVersion({ v1: false, v2: true }, 1)).toThrow(/opencode2 identifies OpenCode V2/iu);
  });

  it("leaves schema mismatches, duplicate keys, and foreign OpenCode entries untouched", async () => {
    const directory = await temporaryDirectory();
    const cases = [
      {
        name: "v2-as-v1.json",
        version: 1 as const,
        contents: JSON.stringify({ mcp: { timeout: { startup: 30_000 }, servers: { other: { type: "local", command: ["/opt/other"] } } } }),
        error: /does not match|not an OpenCode V1/iu
      },
      {
        name: "v1-as-v2.json",
        version: 2 as const,
        contents: JSON.stringify({ mcp: { other: { type: "local", command: ["/opt/other"], enabled: true } } }),
        error: /does not match V2/iu
      },
      {
        name: "duplicate.jsonc",
        version: 1 as const,
        contents: '{\n "mcp": {"other": {"type":"local","command":["/opt/other"]}},\n "m\\u0063p": {"other": {"type":"local","command":["/opt/other"]}}\n}',
        error: /duplicate object key/iu
      },
      {
        name: "foreign-v1.json",
        version: 1 as const,
        contents: JSON.stringify({ mcp: { browseweave: { type: "local", command: ["/foreign/node"], enabled: true } } }),
        error: /foreign browseweave/iu
      },
      {
        name: "foreign-v2.json",
        version: 2 as const,
        contents: JSON.stringify({ mcp: { servers: { browseweave: { type: "local", command: ["/foreign/node"], disabled: false } } } }),
        error: /foreign browseweave/iu
      }
    ];
    for (const testCase of cases) {
      const filePath = path.join(directory, testCase.name);
      await writeFile(filePath, testCase.contents);
      await expect(mergeOpenCodeConfig(filePath, spec, testCase.version)).rejects.toThrow(testCase.error);
      expect(await readFile(filePath, "utf8")).toBe(testCase.contents);
    }
  });
});
