import { execFile } from "node:child_process";
import { access, chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { describe, expect, it, vi } from "vitest";
import {
  assertCanonicalRepositoryOrigin,
  assertPinnedCommandUnchanged,
  assertRequiredCiJobs,
  assertPinnedNpmUnchanged,
  canonicalRemoteTagArguments,
  canonicalRepositoryUrl,
  canonicalCiWorkflowRuns,
  hardenedGitArguments,
  nodeInvocationForTrustedRuntime,
  npmChildEnvironment,
  npmInvocationForTrustedCli,
  releaseCommandEnvironment,
  resolveTrustedCommand,
  resolveTrustedNpm,
  trustedCommandCandidatePaths,
  trustedNpmCandidatePaths,
  finalizeBootstrapCleanup
} from "../scripts/bootstrap-publish.mjs";

const runFile = promisify(execFile);

describe("bootstrap publish cleanup", () => {
  it("accepts only the canonical push workflow on the exact tagged commit", () => {
    const sha = "a".repeat(40);
    const canonical = {
      id: 123,
      head_sha: sha,
      path: ".github/workflows/ci.yml",
      event: "push",
      status: "completed",
      conclusion: "success",
      repository: { full_name: "xenitV1/browseweave" },
      head_repository: { full_name: "xenitV1/browseweave" }
    };
    expect(canonicalCiWorkflowRuns({ workflow_runs: [canonical] }, sha)).toEqual([canonical]);
    expect(canonicalCiWorkflowRuns({
      workflow_runs: [
        { ...canonical, path: ".github/workflows/lookalike.yml" },
        { ...canonical, id: 124, head_repository: { full_name: "attacker/fork" } },
        { ...canonical, id: 125, event: "pull_request" },
        { ...canonical, id: 126, head_sha: "b".repeat(40) }
      ]
    }, sha)).toEqual([]);
  });

  it("requires every cross-platform and release job in that workflow run", () => {
    const names = [
      "Node 24 / ubuntu-latest",
      "Node 24 / macos-latest",
      "Node 24 / windows-latest",
      "Minimum Node 22.14 / Ubuntu",
      "package-and-audit"
    ];
    const payload = {
      jobs: names.map((name) => ({ name, status: "completed", conclusion: "success" }))
    };
    expect(() => assertRequiredCiJobs(payload)).not.toThrow();
    payload.jobs[2] = { ...payload.jobs[2], conclusion: "failure" };
    expect(() => assertRequiredCiJobs(payload)).toThrow(/windows-latest/iu);
  });

  it("derives npm only from the Node installation and ignores npm_execpath", () => {
    expect(trustedNpmCandidatePaths("/opt/node/bin/node", "linux")).toContain(
      "/opt/node/lib/node_modules/npm/bin/npm-cli.js"
    );
    expect(trustedNpmCandidatePaths("C:\\Node\\node.exe", "win32")).toContain(
      "C:\\Node\\node_modules\\npm\\bin\\npm-cli.js"
    );
    const previous = process.env.npm_execpath;
    process.env.npm_execpath = "/tmp/untrusted/npm-cli.js";
    try {
      expect(npmInvocationForTrustedCli(
        "/opt/node/bin/node",
        "/opt/node/lib/node_modules/npm/bin/npm-cli.js",
        ["whoami"]
      )).toEqual({
        command: "/opt/node/bin/node",
        args: ["/opt/node/lib/node_modules/npm/bin/npm-cli.js", "whoami"]
      });
    } finally {
      if (previous === undefined) delete process.env.npm_execpath;
      else process.env.npm_execpath = previous;
    }
  });

  it("launches tagged Node scripts through the pinned runtime instead of process.execPath", () => {
    const pinnedNode = process.platform === "win32" ? "C:\\PinnedNode\\node.exe" : "/opt/pinned-node/bin/node";
    const script = process.platform === "win32" ? "C:\\Release\\check-npm-pack.mjs" : "/release/check-npm-pack.mjs";
    expect(pinnedNode).not.toBe(process.execPath);
    expect(nodeInvocationForTrustedRuntime({
      platform: process.platform,
      nodeExecutable: pinnedNode
    }, [script, "--publish", "--list"])).toEqual({
      command: pinnedNode,
      args: [script, "--publish", "--list"]
    });
    expect(() => nodeInvocationForTrustedRuntime({
      platform: process.platform,
      nodeExecutable: "relative-node"
    }, [script])).toThrow(/pinned Node\.js invocation is invalid/iu);
  });

  it("pins git to an absolute executable and ignores relative PATH entries", async () => {
    expect(trustedCommandCandidatePaths("git", {
      PATH: `relative${path.posix.delimiter}/usr/bin${path.posix.delimiter}/usr/bin`
    }, "linux")).toEqual(["/usr/bin/git"]);
    expect(trustedCommandCandidatePaths("gh", {
      Path: `relative${path.win32.delimiter}C:\\Tools${path.win32.delimiter}C:\\Tools`
    }, "win32")).toEqual(["C:\\Tools\\gh.exe"]);
    expect(() => trustedCommandCandidatePaths("node", { PATH: "/usr/bin" }, "linux")).toThrow(/only git and gh/iu);

    const trustedGit = await resolveTrustedCommand("git");
    expect(path.isAbsolute(trustedGit.executable)).toBe(true);
    await expect(assertPinnedCommandUnchanged(trustedGit)).resolves.toBeUndefined();
  }, 20_000);

  it("rejects fake project and npm-cache git/gh binaries before pinning a safe user tool", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-release-command-"));
    const home = path.join(root, "home");
    const project = path.join(root, "project");
    const projectBin = path.join(project, "node_modules", ".bin");
    const cacheBin = path.join(home, ".npm", "_npx", "123", "node_modules", ".bin");
    const unsafeBin = path.join(home, "unsafe-bin");
    const safeBin = path.join(home, "bin");
    const extension = process.platform === "win32" ? ".exe" : "";
    try {
      await Promise.all([
        mkdir(projectBin, { recursive: true }),
        mkdir(cacheBin, { recursive: true }),
        mkdir(unsafeBin, { recursive: true }),
        mkdir(safeBin, { recursive: true })
      ]);
      for (const command of ["git", "gh"] as const) {
        await Promise.all([
          writeFile(path.join(projectBin, `${command}${extension}`), "project payload", "utf8"),
          writeFile(path.join(cacheBin, `${command}${extension}`), "cache payload", "utf8"),
          writeFile(path.join(unsafeBin, `${command}${extension}`), "unsafe parent payload", "utf8"),
          writeFile(path.join(safeBin, `${command}${extension}`), "safe tool", "utf8")
        ]);
        if (process.platform !== "win32") {
          await Promise.all([
            chmod(path.join(projectBin, command), 0o755),
            chmod(path.join(cacheBin, command), 0o755),
            chmod(path.join(unsafeBin, command), 0o755),
            chmod(path.join(safeBin, command), 0o755)
          ]);
        }
      }
      if (process.platform !== "win32") await chmod(unsafeBin, 0o777);
      const pathValue = [projectBin, cacheBin, unsafeBin, safeBin].join(path.delimiter);
      const environment: NodeJS.ProcessEnv = process.platform === "win32"
        ? { Path: pathValue, USERPROFILE: home, LOCALAPPDATA: path.join(home, "AppData", "Local"), INIT_CWD: project }
        : { PATH: pathValue, HOME: home, INIT_CWD: project };
      for (const command of ["git", "gh"] as const) {
        const trusted = await resolveTrustedCommand(command, environment, process.platform, {
          home,
          cwd: project,
          packageRoot: project,
          temporaryDirectory: path.join(root, "blocked-temporary-root")
        });
        expect(trusted.executable).toBe(path.join(safeBin, `${command}${extension}`));
        await expect(assertPinnedCommandUnchanged(trusted)).resolves.toBeUndefined();
      }
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("gives Git and gh isolated allowlisted environments while preserving only gh authentication", () => {
    const controlRoot = path.join(tmpdir(), "browseweave-release-control");
    const gitHome = path.join(controlRoot, "git-home");
    const executable = process.platform === "win32" ? "C:\\Tools\\git.exe" : "/usr/bin/git";
    const source: NodeJS.ProcessEnv = {
      HOME: homedir(),
      USERPROFILE: homedir(),
      GH_TOKEN: "test-token-not-a-real-secret",
      GITHUB_TOKEN: "test-github-token-not-a-real-secret",
      GIT_SSH_COMMAND: "/tmp/payload",
      GIT_EXEC_PATH: "/tmp/fake-git-core",
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.fsmonitor",
      GIT_CONFIG_VALUE_0: "/tmp/payload",
      GIT_ASKPASS: "/tmp/payload",
      SSH_ASKPASS: "/tmp/payload",
      NODE_OPTIONS: "--import=/tmp/payload.mjs"
    };
    const git = releaseCommandEnvironment({ command: "git", executable, platform: process.platform }, source, {
      controlRoot,
      gitHome
    });
    expect(git).toMatchObject({
      HOME: gitHome,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_COUNT: "0",
      GIT_TERMINAL_PROMPT: "0",
      GIT_OPTIONAL_LOCKS: "0"
    });
    for (const unsafe of [
      "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
      "GIT_ASKPASS", "SSH_ASKPASS", "NODE_OPTIONS", "GH_TOKEN", "GITHUB_TOKEN"
    ]) expect(git).not.toHaveProperty(unsafe);
    if (process.platform === "win32") {
      expect(() => releaseCommandEnvironment({ command: "git", executable, platform: process.platform }, {
        ...source,
        SystemRoot: "relative-windows-root"
      }, { controlRoot, gitHome })).toThrow(/Windows system root is invalid/iu);
    }

    const ghExecutable = process.platform === "win32" ? "C:\\Tools\\gh.exe" : "/usr/bin/gh";
    const gh = releaseCommandEnvironment({ command: "gh", executable: ghExecutable, platform: process.platform }, source, {
      controlRoot
    });
    expect(gh).toMatchObject({
      GH_TOKEN: source.GH_TOKEN,
      GITHUB_TOKEN: source.GITHUB_TOKEN,
      GH_PROMPT_DISABLED: "1",
      GH_NO_UPDATE_NOTIFIER: "1"
    });
    for (const unsafe of [
      "GIT_SSH_COMMAND", "GIT_EXEC_PATH", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0",
      "GIT_CONFIG_VALUE_0", "GIT_ASKPASS", "SSH_ASKPASS", "NODE_OPTIONS"
    ]) expect(gh).not.toHaveProperty(unsafe);
  });

  it("forces no hooks, fsmonitor, pager, prompt, SSH protocol, or attacker-selected remote", () => {
    const hooks = process.platform === "win32"
      ? "C:\\Temp\\browseweave-empty-hooks"
      : "/tmp/browseweave-empty-hooks";
    const args = hardenedGitArguments(["status", "--porcelain=v1"], hooks, process.platform);
    expect(args).toContain("--no-pager");
    expect(args).toContain(`core.hooksPath=${hooks}`);
    expect(args).toContain("core.fsmonitor=false");
    expect(args).toContain("core.attributesFile=" + (process.platform === "win32" ? "NUL" : "/dev/null"));
    expect(args).toContain("credential.helper=");
    expect(args).toContain("protocol.allow=never");
    expect(args).toContain("protocol.https.allow=always");

    expect(() => assertCanonicalRepositoryOrigin(canonicalRepositoryUrl)).not.toThrow();
    for (const origin of [
      "git@github.com:xenitV1/browseweave.git",
      "ssh://git@github.com/xenitV1/browseweave.git",
      "https://github.com/attacker/browseweave.git"
    ]) expect(() => assertCanonicalRepositoryOrigin(origin)).toThrow(/origin must be exactly/iu);
    expect(canonicalRemoteTagArguments("0.1.0-beta.1")).toEqual([
      "ls-remote", "--tags", canonicalRepositoryUrl,
      "refs/tags/v0.1.0-beta.1", "refs/tags/v0.1.0-beta.1^{}"
    ]);
  });

  it("does not execute repository post-checkout or fsmonitor programs during hardened Git operations", async () => {
    if (process.platform === "win32") return;
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-git-hooks-"));
    const repository = path.join(root, "repository");
    const worktree = path.join(root, "worktree");
    const controlRoot = path.join(root, "control");
    const gitHome = path.join(controlRoot, "git-home");
    const emptyHooks = path.join(controlRoot, "empty-hooks");
    const hookMarker = path.join(root, "hook-ran");
    const fsmonitorMarker = path.join(root, "fsmonitor-ran");
    try {
      await mkdir(controlRoot);
      await Promise.all([
        mkdir(repository),
        mkdir(gitHome),
        mkdir(emptyHooks)
      ]);
      const trustedGit = await resolveTrustedCommand("git");
      const cleanEnvironment = releaseCommandEnvironment(trustedGit, {
        HOME: homedir(),
        GIT_SSH_COMMAND: path.join(root, "attacker-ssh")
      }, { controlRoot, gitHome });
      const runGit = async (args: string[], cwd = repository) => await runFile(
        trustedGit.executable,
        hardenedGitArguments(args, emptyHooks),
        { cwd, env: cleanEnvironment }
      );
      await runGit(["init"], repository);
      await writeFile(path.join(repository, "README.md"), "release fixture\n", "utf8");
      await runGit(["add", "README.md"]);
      await runGit(["-c", "user.name=BrowseWeave Test", "-c", "user.email=test@example.invalid", "commit", "-m", "fixture"]);

      const defaultHooks = path.join(repository, ".git", "hooks");
      const postCheckout = path.join(defaultHooks, "post-checkout");
      const fsmonitor = path.join(root, "fsmonitor.sh");
      await Promise.all([
        writeFile(postCheckout, `#!/bin/sh\nprintf ran > ${JSON.stringify(hookMarker)}\n`, "utf8"),
        writeFile(fsmonitor, `#!/bin/sh\nprintf ran > ${JSON.stringify(fsmonitorMarker)}\nexit 1\n`, "utf8")
      ]);
      await Promise.all([chmod(postCheckout, 0o755), chmod(fsmonitor, 0o755)]);
      await runFile(trustedGit.executable, ["-C", repository, "config", "core.fsmonitor", fsmonitor], {
        cwd: repository,
        env: cleanEnvironment
      });

      await runGit(["status", "--porcelain=v1"]);
      await runGit(["worktree", "add", "--detach", worktree, "HEAD"]);
      await expect(access(hookMarker)).rejects.toMatchObject({ code: "ENOENT" });
      await expect(access(fsmonitorMarker)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 20_000);

  it("pins the live Node and npm content tree and gives npm a code-injection-free environment", async () => {
    const trusted = await resolveTrustedNpm();
    await expect(assertPinnedNpmUnchanged(trusted)).resolves.toBeUndefined();
    const clean = npmChildEnvironment(trusted, {
      HOME: "/home/ada",
      NODE_OPTIONS: "--import=/tmp/untrusted.mjs",
      NODE_PATH: "/tmp/untrusted-modules",
      npm_execpath: "/tmp/untrusted/npm-cli.js",
      NPM_CONFIG_USERCONFIG: "/tmp/isolated-userconfig",
      BROWSEWEAVE_RELEASE: "bootstrap-local"
    });
    expect(clean).toMatchObject({
      HOME: "/home/ada",
      NPM_CONFIG_USERCONFIG: "/tmp/isolated-userconfig",
      BROWSEWEAVE_RELEASE: "bootstrap-local"
    });
    expect(clean).not.toHaveProperty("NODE_OPTIONS");
    expect(clean).not.toHaveProperty("NODE_PATH");
    expect(clean).not.toHaveProperty("npm_execpath");
    expect(clean.PATH ?? clean.Path).toContain(path.dirname(trusted.nodeExecutable));
  }, 20_000);

  it("runs every cleanup, preserves the publish error, and warns after an authenticated cleanup failure", async () => {
    const warning = vi.fn();
    const secondCleanup = vi.fn(async () => undefined);
    const operationError = new Error("publish failed");
    const cleanupError = new Error("temporary root removal failed");

    const outcome = finalizeBootstrapCleanup({
      operationError,
      npmAuthenticationAttempted: true,
      cleanupTasks: [async () => { throw cleanupError; }, secondCleanup],
      warn: warning
    });

    await expect(outcome).rejects.toMatchObject({
      name: "AggregateError",
      errors: [operationError, cleanupError]
    });
    expect(secondCleanup).toHaveBeenCalledOnce();
    expect(warning).toHaveBeenCalledOnce();
  });

  it("does not emit an authentication warning before login was attempted", async () => {
    const warning = vi.fn();
    const cleanupError = new Error("cleanup failed");
    await expect(finalizeBootstrapCleanup({
      operationError: undefined,
      npmAuthenticationAttempted: false,
      cleanupTasks: [async () => { throw cleanupError; }],
      warn: warning
    })).rejects.toBe(cleanupError);
    expect(warning).not.toHaveBeenCalled();
  });

  it("does not warn about a credential after cleanup proved it inactive", async () => {
    const warning = vi.fn();
    const operationError = new Error("publish failed");
    await expect(finalizeBootstrapCleanup({
      operationError,
      npmAuthenticationAttempted: true,
      cleanupTasks: [async () => undefined],
      credentialIsInactive: () => true,
      warn: warning
    })).rejects.toBe(operationError);
    expect(warning).not.toHaveBeenCalled();
  });
});
