import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertTrustedClientExecutableUnchanged,
  npmInvocationFromPinnedCli,
  resolveTrustedClientExecutable,
  safeClientPathEntries,
  trustedNpmCandidatePaths
} from "../src/clients/npm-invocation.js";

describe("trusted npm invocation", () => {
  it("derives npm from the active Node installation across supported platforms", () => {
    expect(trustedNpmCandidatePaths("/opt/node/bin/node", "linux")).toContain(
      "/opt/node/lib/node_modules/npm/bin/npm-cli.js"
    );
    expect(trustedNpmCandidatePaths("C:\\Node\\node.exe", "win32")).toContain(
      "C:\\Node\\node_modules\\npm\\bin\\npm-cli.js"
    );
  });

  it("never consults an inherited npm_execpath", () => {
    const previous = process.env.npm_execpath;
    process.env.npm_execpath = "/tmp/untrusted/npm-cli.js";
    try {
      expect(npmInvocationFromPinnedCli(
        "/opt/node/bin/node",
        "/opt/node/lib/node_modules/npm/bin/npm-cli.js",
        ["install", "browseweave@0.1.0"]
      )).toEqual({
        command: "/opt/node/bin/node",
        args: [
          "/opt/node/lib/node_modules/npm/bin/npm-cli.js",
          "install",
          "browseweave@0.1.0"
        ]
      });
    } finally {
      if (previous === undefined) delete process.env.npm_execpath;
      else process.env.npm_execpath = previous;
    }
  });

  it("removes package-local and npm/npx cache entries without removing normal user or system bins", () => {
    expect(safeClientPathEntries([
      "/work/app/node_modules/.bin",
      "/home/ada/.npm/_npx/123/node_modules/.bin",
      "/home/ada/.npm-global/bin",
      "/home/ada/.local/bin",
      "/usr/bin",
      "",
      "relative/bin"
    ].join(":"), { platform: "linux", home: "/home/ada" })).toEqual([
      "/home/ada/.npm-global/bin",
      "/home/ada/.local/bin",
      "/usr/bin"
    ]);

    expect(safeClientPathEntries([
      "C:\\work\\app\\node_modules\\.bin",
      "C:\\Users\\Ada\\AppData\\Local\\npm-cache\\_npx\\123",
      "C:\\Users\\Ada\\.local\\bin",
      "C:\\Windows\\System32"
    ].join(";"), {
      platform: "win32",
      home: "C:\\Users\\Ada",
      localAppData: "C:\\Users\\Ada\\AppData\\Local"
    })).toEqual([
      "C:\\Users\\Ada\\.local\\bin",
      "C:\\Windows\\System32"
    ]);
  });

  it("resolves a client once from the safe PATH instead of an earlier project or npx-cache binary", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-client-executable-"));
    const home = path.join(root, "home");
    const project = path.join(root, "project");
    const packageRoot = path.join(root, "browseweave-package");
    const projectBin = path.join(project, "node_modules", ".bin");
    const projectPlainBin = path.join(project, "bin");
    const packageBin = path.join(packageRoot, "bin");
    const npxBin = path.join(home, ".npm", "_npx", "123", "node_modules", ".bin");
    const safeBin = path.join(home, ".local", "bin");
    const executableName = process.platform === "win32" ? "codex.exe" : "codex";
    try {
      await Promise.all([
        mkdir(projectBin, { recursive: true }),
        mkdir(projectPlainBin, { recursive: true }),
        mkdir(npxBin, { recursive: true }),
        mkdir(safeBin, { recursive: true }),
        mkdir(packageBin, { recursive: true })
      ]);
      await Promise.all([
        writeFile(path.join(projectBin, executableName), "project payload", "utf8"),
        writeFile(path.join(projectPlainBin, executableName), "project payload outside node_modules", "utf8"),
        writeFile(path.join(packageBin, executableName), "package payload", "utf8"),
        writeFile(path.join(npxBin, executableName), "npx payload", "utf8"),
        writeFile(path.join(safeBin, executableName), "trusted client", "utf8")
      ]);
      if (process.platform !== "win32") {
        await Promise.all([
          chmod(path.join(projectBin, executableName), 0o755),
          chmod(path.join(projectPlainBin, executableName), 0o755),
          chmod(path.join(packageBin, executableName), 0o755),
          chmod(path.join(npxBin, executableName), 0o755),
          chmod(path.join(safeBin, executableName), 0o755)
        ]);
      }
      const pathValue = [projectBin, projectPlainBin, packageBin, npxBin, safeBin].join(path.delimiter);
      const env: NodeJS.ProcessEnv = process.platform === "win32"
        ? { Path: pathValue, INIT_CWD: project, LOCALAPPDATA: path.join(home, "AppData", "Local") }
        : { PATH: pathValue, INIT_CWD: project };
      const trusted = await resolveTrustedClientExecutable("codex", {
        env,
        cwd: project,
        home,
        packageRoot,
        temporaryDirectory: path.join(root, "blocked-temporary-root")
      });
      const expectedExecutable = await realpath(path.join(safeBin, executableName));
      expect(trusted?.executable).toBe(expectedExecutable);
      await expect(assertTrustedClientExecutableUnchanged(trusted!)).resolves.toBeUndefined();

      const fromHome = await resolveTrustedClientExecutable("codex", {
        env: process.platform === "win32"
          ? { Path: safeBin, INIT_CWD: home, LOCALAPPDATA: path.join(home, "AppData", "Local") }
          : { PATH: safeBin, INIT_CWD: home },
        cwd: home,
        home,
        packageRoot,
        temporaryDirectory: path.join(root, "blocked-temporary-root")
      });
      expect(fromHome?.executable).toBe(expectedExecutable);

      await writeFile(path.join(safeBin, executableName), "replacement client with a new identity", "utf8");
      await expect(assertTrustedClientExecutableUnchanged(trusted!)).rejects.toThrow(/changed after it was selected/iu);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects a world-writable client directory and continues to a safe user executable", async () => {
    if (process.platform === "win32") return;
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-client-owner-"));
    const home = path.join(root, "home");
    const project = path.join(root, "project");
    const unsafeBin = path.join(home, "unsafe-bin");
    const safeBin = path.join(home, ".local", "bin");
    try {
      await Promise.all([
        mkdir(project, { recursive: true }),
        mkdir(unsafeBin, { recursive: true }),
        mkdir(safeBin, { recursive: true })
      ]);
      await Promise.all([
        writeFile(path.join(unsafeBin, "codex"), "unsafe", "utf8"),
        writeFile(path.join(safeBin, "codex"), "safe", "utf8")
      ]);
      await Promise.all([
        chmod(unsafeBin, 0o777),
        chmod(path.join(unsafeBin, "codex"), 0o755),
        chmod(path.join(safeBin, "codex"), 0o755)
      ]);
      const trusted = await resolveTrustedClientExecutable("codex", {
        env: { PATH: [unsafeBin, safeBin].join(path.delimiter) },
        cwd: project,
        home,
        temporaryDirectory: path.join(root, "blocked-temporary-root")
      });
      expect(trusted?.executable).toBe(await realpath(path.join(safeBin, "codex")));
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("allows client-owned config writes below an executable ancestor without weakening directory trust", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-client-config-write-"));
    const home = path.join(root, "home");
    const clientHome = path.join(home, ".codex");
    const safeBin = path.join(clientHome, "bin");
    const executableName = process.platform === "win32" ? "codex.exe" : "codex";
    try {
      await mkdir(safeBin, { recursive: true });
      await writeFile(path.join(safeBin, executableName), "trusted client", "utf8");
      if (process.platform !== "win32") await chmod(path.join(safeBin, executableName), 0o755);

      const trusted = await resolveTrustedClientExecutable("codex", {
        env: process.platform === "win32"
          ? { Path: safeBin, LOCALAPPDATA: path.join(home, "AppData", "Local") }
          : { PATH: safeBin },
        cwd: home,
        home,
        temporaryDirectory: path.join(root, "blocked-temporary-root")
      });

      await writeFile(path.join(clientHome, "config.toml"), "[mcp_servers.browseweave]\n", "utf8");
      await expect(assertTrustedClientExecutableUnchanged(trusted!)).resolves.toBeUndefined();

      if (process.platform !== "win32") {
        await chmod(safeBin, 0o777);
        await expect(assertTrustedClientExecutableUnchanged(trusted!)).rejects.toThrow(/directory chain changed/iu);
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
