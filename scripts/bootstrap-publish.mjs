import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants, createReadStream } from "node:fs";
import { access, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { releaseDistTag } from "./version-helpers.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.resolve(scriptDirectory, "..");
const registry = "https://registry.npmjs.org/";
const expectedNpmUser = "xenitv0";
const maximumCapturedBytes = 2 * 1024 * 1024;
const maximumPinnedNpmFiles = 5_000;
const maximumPinnedNpmBytes = 100 * 1024 * 1024;
const requiredCiChecks = [
  "Node 24 / ubuntu-latest",
  "Node 24 / macos-latest",
  "Node 24 / windows-latest",
  "Minimum Node 22.14 / Ubuntu",
  "package-and-audit"
];
const canonicalCiWorkflowPath = ".github/workflows/ci.yml";
export const canonicalRepositoryUrl = "https://github.com/xenitV1/browseweave.git";

function fail(message) {
  throw new Error(`Bootstrap publish refused: ${message}`);
}

export function trustedNpmCandidatePaths(nodeExecutable, platform = process.platform) {
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  if (!pathApi.isAbsolute(nodeExecutable) || /[\0\r\n]/u.test(nodeExecutable)) return [];
  const binDirectory = pathApi.dirname(nodeExecutable);
  const installationRoot = pathApi.dirname(binDirectory);
  const candidates = platform === "win32"
    ? [
        pathApi.join(binDirectory, "node_modules", "npm", "bin", "npm-cli.js"),
        pathApi.join(installationRoot, "node_modules", "npm", "bin", "npm-cli.js")
      ]
    : [
        pathApi.join(installationRoot, "lib", "node_modules", "npm", "bin", "npm-cli.js"),
        pathApi.join(installationRoot, "libexec", "lib", "node_modules", "npm", "bin", "npm-cli.js")
      ];
  if (platform !== "win32" && installationRoot === "/usr") {
    candidates.push("/usr/share/nodejs/npm/bin/npm-cli.js");
  }
  return [...new Set(candidates)];
}

export function npmInvocationForTrustedCli(nodeExecutable, npmCliPath, args) {
  if (!path.isAbsolute(nodeExecutable) || !path.isAbsolute(npmCliPath)
    || /[\0\r\n]/u.test(nodeExecutable) || /[\0\r\n]/u.test(npmCliPath)
    || !Array.isArray(args) || args.some((argument) => typeof argument !== "string")) {
    fail("the pinned npm invocation is invalid");
  }
  return { command: nodeExecutable, args: [npmCliPath, ...args] };
}

export function nodeInvocationForTrustedRuntime(trustedNpm, args) {
  const pathApi = pathApiFor(trustedNpm?.platform);
  if (trustedNpm?.platform !== process.platform
    || typeof trustedNpm?.nodeExecutable !== "string" || !pathApi.isAbsolute(trustedNpm.nodeExecutable)
    || /[\0\r\n]/u.test(trustedNpm.nodeExecutable)
    || !Array.isArray(args) || args.some((argument) => typeof argument !== "string")) {
    fail("the pinned Node.js invocation is invalid");
  }
  return { command: trustedNpm.nodeExecutable, args: [...args] };
}

function pathApiFor(platform) {
  return platform === "win32" ? path.win32 : path.posix;
}

function pathIsInsideForPlatform(root, target, platform) {
  const pathApi = pathApiFor(platform);
  const relative = pathApi.relative(pathApi.resolve(root), pathApi.resolve(target));
  if (relative === "") return true;
  const comparable = platform === "win32" ? relative.toLowerCase() : relative;
  return comparable !== ".." && !comparable.startsWith(`..${pathApi.sep}`) && !pathApi.isAbsolute(relative);
}

function safeAbsoluteReleasePath(value, platform) {
  const pathApi = pathApiFor(platform);
  if (typeof value !== "string" || value === "" || /[\0\r\n]/u.test(value) || !pathApi.isAbsolute(value)) {
    return undefined;
  }
  if (platform === "win32" && value.startsWith("\\\\")) return undefined;
  return pathApi.normalize(value);
}

function releasePathHasUnsafeComponent(value) {
  const segments = value.split(/[\\/]+/u).filter(Boolean).map((segment) => segment.toLowerCase());
  if (segments.some((segment) => segment === ".npm" || segment === "_npx"
    || segment === "_cacache" || segment === "npm-cache")) return true;
  return segments.some((segment, index) => segment === "node_modules" && segments[index + 1] === ".bin");
}

function releasePathTrustRoots(environment, platform, options) {
  const pathApi = pathApiFor(platform);
  const currentPlatform = platform === process.platform;
  const home = safeAbsoluteReleasePath(
    options.home ?? (currentPlatform ? homedir() : environment.USERPROFILE),
    platform
  );
  const roots = [
    options.cwd ?? (currentPlatform ? process.cwd() : undefined),
    options.packageRoot ?? (currentPlatform ? projectDirectory : undefined),
    options.temporaryDirectory ?? (currentPlatform ? tmpdir() : environment.TEMP),
    environment.INIT_CWD,
    environment.npm_config_cache,
    environment.NPM_CONFIG_CACHE,
    ...(options.cacheDirectories ?? [])
  ];
  if (home) {
    roots.push(platform === "win32"
      ? pathApi.join(options.localAppData ?? environment.LOCALAPPDATA ?? home, "npm-cache")
      : pathApi.join(home, ".npm"));
  }
  return roots
    .map((entry) => safeAbsoluteReleasePath(entry, platform))
    .filter((entry) => entry !== undefined);
}

export function trustedCommandCandidatePaths(
  command,
  environment = process.env,
  platform = process.platform,
  options = {}
) {
  if (command !== "git" && command !== "gh") fail("only git and gh may be resolved as release commands");
  const pathApi = pathApiFor(platform);
  const pathValue = platform === "win32"
    ? environment.Path ?? environment.PATH
    : environment.PATH;
  if (typeof pathValue !== "string" || pathValue === "") return [];
  const forbiddenRoots = releasePathTrustRoots(environment, platform, options);
  const executableName = platform === "win32" ? `${command}.exe` : command;
  const candidates = [];
  for (const rawDirectory of pathValue.split(pathApi.delimiter)) {
    const directory = safeAbsoluteReleasePath(rawDirectory, platform);
    if (!directory || releasePathHasUnsafeComponent(directory)) continue;
    const candidate = pathApi.join(directory, executableName);
    if (forbiddenRoots.some((root) => pathIsInsideForPlatform(root, candidate, platform))) continue;
    if (!candidates.includes(candidate)) candidates.push(candidate);
  }
  return candidates;
}

function commandMetadataIsTrusted(info, platform) {
  if (!info.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > 256 * 1024 * 1024) return false;
  if (platform === "win32") return true;
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  return (uid === undefined || info.uid === 0 || info.uid === uid) && (info.mode & 0o022) === 0;
}

function fileSystemIdentity(info) {
  return Object.freeze({
    dev: info.dev,
    ino: info.ino,
    mode: info.mode,
    size: info.size,
    mtimeMs: info.mtimeMs,
    uid: info.uid,
    gid: info.gid
  });
}

function fileSystemIdentitiesMatch(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.size === right.size && left.mtimeMs === right.mtimeMs
    && left.uid === right.uid && left.gid === right.gid;
}

function directoryPathsFromAnchor(anchor, target, pathApi) {
  const relative = pathApi.relative(anchor, target);
  if (relative === "") return [anchor];
  const directories = [anchor];
  let current = anchor;
  for (const segment of relative.split(pathApi.sep).filter(Boolean)) {
    current = pathApi.join(current, segment);
    directories.push(current);
  }
  return directories;
}

async function trustedCommandDirectoryChain(directory, home, platform) {
  const pathApi = pathApiFor(platform);
  const canonicalDirectory = await realpath(directory);
  const canonicalHome = await realpath(home);
  const anchor = pathIsInsideForPlatform(canonicalHome, canonicalDirectory, platform)
    ? canonicalHome
    : pathApi.parse(canonicalDirectory).root;
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  const gid = typeof process.getgid === "function" ? process.getgid() : undefined;
  const directories = [];
  for (const current of directoryPathsFromAnchor(anchor, canonicalDirectory, pathApi)) {
    if (await realpath(current) !== current) fail("a release executable directory is not canonical");
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) fail("a release executable path component is unsafe");
    if (platform !== "win32") {
      if (uid === undefined || (info.uid !== uid && info.uid !== 0)) fail("a release executable directory has an unsafe owner");
      if ((info.mode & 0o002) !== 0) fail("a release executable directory is writable by other users");
      if ((info.mode & 0o020) !== 0 && !(info.uid === uid && gid !== undefined && info.gid === gid)) {
        fail("a release executable directory is writable by an untrusted group");
      }
    }
    directories.push(Object.freeze({ path: current, identity: fileSystemIdentity(info) }));
  }
  return directories;
}

export async function resolveTrustedCommand(
  command,
  environment = process.env,
  platform = process.platform,
  options = {}
) {
  const home = safeAbsoluteReleasePath(
    options.home ?? (platform === process.platform ? homedir() : environment.USERPROFILE),
    platform
  );
  if (!home) fail("the release executable home trust root is invalid");
  const forbiddenRoots = releasePathTrustRoots(environment, platform, options);
  const canonicalForbiddenRoots = await Promise.all(forbiddenRoots.map(async (root) => await realpath(root).catch(() => root)));
  for (const candidate of trustedCommandCandidatePaths(command, environment, platform, options)) {
    try {
      const executable = await realpath(candidate);
      const pathApi = pathApiFor(platform);
      if (!pathApi.isAbsolute(executable) || /[\0\r\n]/u.test(executable)) continue;
      if (canonicalForbiddenRoots.some((root) => pathIsInsideForPlatform(root, executable, platform))) continue;
      const info = await lstat(executable);
      if (!commandMetadataIsTrusted(info, platform)) continue;
      await access(executable, platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
      const identity = await sha256RegularFile(executable, 256 * 1024 * 1024);
      const directoryChains = await Promise.all([
        trustedCommandDirectoryChain(pathApi.dirname(candidate), home, platform),
        trustedCommandDirectoryChain(pathApi.dirname(executable), home, platform)
      ]);
      const directories = new Map();
      for (const directory of directoryChains.flat()) directories.set(directory.path, directory);
      return Object.freeze({
        command,
        executable,
        identity,
        metadata: fileSystemIdentity(info),
        directories: Object.freeze([...directories.values()]),
        platform
      });
    } catch {
      // Try only the next absolute candidate from the original PATH snapshot.
    }
  }
  fail(`${command} could not be resolved to a safe absolute release executable`);
}

export async function assertPinnedCommandUnchanged(trustedCommand) {
  const pathApi = trustedCommand?.platform === "win32" ? path.win32 : path.posix;
  if ((trustedCommand?.command !== "git" && trustedCommand?.command !== "gh")
    || typeof trustedCommand?.executable !== "string" || !pathApi.isAbsolute(trustedCommand.executable)) {
    fail("the pinned release command identity is invalid");
  }
  const canonical = await realpath(trustedCommand.executable).catch(() => "");
  if (canonical !== trustedCommand.executable) fail(`the pinned ${trustedCommand.command} executable changed`);
  const info = await lstat(trustedCommand.executable);
  if (!commandMetadataIsTrusted(info, trustedCommand.platform)) {
    fail(`the pinned ${trustedCommand.command} executable became unsafe`);
  }
  if (!fileSystemIdentitiesMatch(trustedCommand.metadata, fileSystemIdentity(info))) {
    fail(`the pinned ${trustedCommand.command} executable metadata changed`);
  }
  for (const directory of trustedCommand.directories ?? []) {
    const canonicalDirectory = await realpath(directory.path).catch(() => "");
    const directoryInfo = await lstat(directory.path).catch(() => undefined);
    if (canonicalDirectory !== directory.path || !directoryInfo
      || !directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()
      || !fileSystemIdentitiesMatch(directory.identity, fileSystemIdentity(directoryInfo))) {
      fail(`the pinned ${trustedCommand.command} executable directory changed`);
    }
  }
  await access(
    trustedCommand.executable,
    trustedCommand.platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK
  );
  const identity = await sha256RegularFile(trustedCommand.executable, 256 * 1024 * 1024);
  if (JSON.stringify(identity) !== JSON.stringify(trustedCommand.identity)) {
    fail(`the pinned ${trustedCommand.command} executable changed during the release process`);
  }
}

function pathIsInside(root, target) {
  const relative = path.relative(root, target);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

async function sha256RegularFile(file, maximumBytes) {
  const before = await lstat(file);
  if (!before.isFile() || before.isSymbolicLink() || before.size < 0 || before.size > maximumBytes) {
    fail(`unsafe pinned tool file: ${file}`);
  }
  const hash = createHash("sha256");
  let bytes = 0;
  await new Promise((resolve, reject) => {
    const stream = createReadStream(file);
    stream.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > maximumBytes) {
        stream.destroy(new Error("Pinned tool file exceeds its size budget."));
        return;
      }
      hash.update(chunk);
    });
    stream.once("error", reject);
    stream.once("end", resolve);
  });
  const after = await lstat(file);
  if (!after.isFile() || after.isSymbolicLink() || bytes !== before.size
    || after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
    || after.mtimeMs !== before.mtimeMs) {
    fail(`pinned tool file changed while it was measured: ${file}`);
  }
  return Object.freeze({
    sha256: hash.digest("hex"),
    dev: after.dev,
    ino: after.ino,
    size: after.size,
    mtimeMs: after.mtimeMs
  });
}

async function snapshotPinnedNpmTree(packageRoot) {
  const rootInfo = await lstat(packageRoot);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) fail("the pinned npm package root is unsafe");
  const paths = [];
  const visit = async (directory, relativeDirectory) => {
    const names = (await readdir(directory)).sort((left, right) => left.localeCompare(right, "en"));
    for (const name of names) {
      const absolute = path.join(directory, name);
      const relative = relativeDirectory ? `${relativeDirectory}/${name}` : name;
      const info = await lstat(absolute);
      if (info.isSymbolicLink()) fail(`the pinned npm tree contains a symbolic link: ${relative}`);
      if (info.isDirectory()) {
        paths.push({ absolute, relative, type: "directory", info });
        await visit(absolute, relative);
      } else if (info.isFile()) {
        paths.push({ absolute, relative, type: "file", info });
      } else {
        fail(`the pinned npm tree contains an unsupported entry: ${relative}`);
      }
      if (paths.length > maximumPinnedNpmFiles) fail("the pinned npm tree exceeds its file-count budget");
    }
  };
  await visit(packageRoot, "");

  let totalBytes = 0;
  let fileCount = 0;
  const treeHash = createHash("sha256");
  for (const entry of paths) {
    if (entry.type === "directory") {
      treeHash.update(`directory\0${entry.relative}\0${entry.info.mode}\n`, "utf8");
      continue;
    }
    totalBytes += entry.info.size;
    fileCount += 1;
    if (totalBytes > maximumPinnedNpmBytes) fail("the pinned npm tree exceeds its byte budget");
    const contents = await readFile(entry.absolute);
    const after = await lstat(entry.absolute);
    if (!after.isFile() || after.isSymbolicLink() || contents.length !== entry.info.size
      || after.dev !== entry.info.dev || after.ino !== entry.info.ino
      || after.size !== entry.info.size || after.mtimeMs !== entry.info.mtimeMs) {
      fail(`the pinned npm tree changed while it was measured: ${entry.relative}`);
    }
    treeHash.update(
      `file\0${entry.relative}\0${after.mode}\0${after.size}\0${createHash("sha256").update(contents).digest("hex")}\n`,
      "utf8"
    );
  }
  return Object.freeze({ sha256: treeHash.digest("hex"), fileCount, totalBytes, entryCount: paths.length });
}

export async function resolveTrustedNpm() {
  const nodeExecutable = await realpath(process.execPath);
  const nodeInfo = await lstat(nodeExecutable);
  if (!nodeInfo.isFile() || nodeInfo.isSymbolicLink()) fail("the current Node.js executable is unsafe");
  const installationRoot = path.resolve(path.dirname(nodeExecutable), "..");

  for (const candidate of trustedNpmCandidatePaths(nodeExecutable)) {
    try {
      const npmCliPath = await realpath(candidate);
      const cliInfo = await lstat(npmCliPath);
      if (!cliInfo.isFile() || cliInfo.isSymbolicLink()) continue;
      if (process.platform !== "win32" && cliInfo.uid !== nodeInfo.uid) continue;
      const packageRoot = path.resolve(path.dirname(npmCliPath), "..");
      if (!pathIsInside(installationRoot, packageRoot)) continue;
      const canonicalPackageCli = await realpath(path.join(packageRoot, "bin", "npm-cli.js"));
      if (canonicalPackageCli !== npmCliPath) continue;
      const metadataPath = path.join(packageRoot, "package.json");
      const metadataInfo = await lstat(metadataPath);
      if (!metadataInfo.isFile() || metadataInfo.isSymbolicLink()) continue;
      const metadata = JSON.parse(await readFile(metadataPath, "utf8"));
      if (metadata.name !== "npm" || typeof metadata.version !== "string"
        || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(metadata.version)) continue;
      const nodeIdentity = await sha256RegularFile(nodeExecutable, 256 * 1024 * 1024);
      const npmTreeIdentity = await snapshotPinnedNpmTree(packageRoot);
      return Object.freeze({
        platform: process.platform,
        nodeExecutable,
        npmCliPath,
        packageRoot,
        nodeIdentity,
        npmTreeIdentity
      });
    } catch {
      // Try only the next location derived from the current Node installation.
    }
  }
  fail("npm could not be pinned to the installation that supplied the current Node.js executable");
}

export async function assertPinnedNpmUnchanged(trustedNpm) {
  const [nodeCanonical, npmCanonical] = await Promise.all([
    realpath(trustedNpm.nodeExecutable).catch(() => ""),
    realpath(trustedNpm.npmCliPath).catch(() => "")
  ]);
  if (nodeCanonical !== trustedNpm.nodeExecutable || npmCanonical !== trustedNpm.npmCliPath
    || !pathIsInside(path.resolve(path.dirname(trustedNpm.nodeExecutable), ".."), trustedNpm.packageRoot)) {
    fail("the pinned npm installation changed during the release process");
  }
  const [nodeIdentity, npmTreeIdentity] = await Promise.all([
    sha256RegularFile(trustedNpm.nodeExecutable, 256 * 1024 * 1024),
    snapshotPinnedNpmTree(trustedNpm.packageRoot)
  ]);
  if (JSON.stringify(nodeIdentity) !== JSON.stringify(trustedNpm.nodeIdentity)
    || JSON.stringify(npmTreeIdentity) !== JSON.stringify(trustedNpm.npmTreeIdentity)) {
    fail("the pinned Node.js or npm installation changed during the release process");
  }
}

const COMMON_RELEASE_COMMAND_ENVIRONMENT_KEYS = new Set([
  "LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM", "NO_COLOR", "FORCE_COLOR", "TZ"
]);

function fixedReleasePath(trustedCommand, systemRoot) {
  const pathApi = pathApiFor(trustedCommand.platform);
  const executableDirectory = pathApi.dirname(trustedCommand.executable);
  if (trustedCommand.platform === "win32") {
    const safeSystemRoot = safeAbsoluteReleasePath(systemRoot, trustedCommand.platform);
    if (!safeSystemRoot) fail("the Windows system root is invalid");
    return [...new Set([
      executableDirectory,
      pathApi.join(safeSystemRoot, "System32"),
      safeSystemRoot
    ])].join(pathApi.delimiter);
  }
  return [...new Set([
    executableDirectory,
    "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"
  ])].join(pathApi.delimiter);
}

function safeGhConfigurationPath(value, home, trustedCommand) {
  const candidate = safeAbsoluteReleasePath(value, trustedCommand.platform);
  if (!candidate || !pathIsInsideForPlatform(home, candidate, trustedCommand.platform)) return undefined;
  if (releasePathHasUnsafeComponent(candidate)) return undefined;
  return candidate;
}

export function releaseCommandEnvironment(trustedCommand, source, options) {
  if ((trustedCommand?.command !== "git" && trustedCommand?.command !== "gh")
    || trustedCommand.platform !== process.platform) {
    fail("the release command environment target is invalid");
  }
  const controlRoot = safeAbsoluteReleasePath(options?.controlRoot, trustedCommand.platform);
  if (!controlRoot) fail("the release command control root is invalid");
  const clean = {};
  for (const [name, value] of Object.entries(source ?? {})) {
    if (COMMON_RELEASE_COMMAND_ENVIRONMENT_KEYS.has(name) && typeof value === "string") clean[name] = value;
  }
  if (trustedCommand.platform === "win32") {
    const systemRoot = safeAbsoluteReleasePath(
      source?.SystemRoot || source?.SYSTEMROOT || source?.WINDIR || "C:\\Windows",
      trustedCommand.platform
    );
    if (!systemRoot) fail("the Windows system root is invalid");
    clean.SystemRoot = systemRoot;
    clean.Path = fixedReleasePath(trustedCommand, systemRoot);
    clean.ComSpec = path.win32.join(systemRoot, "System32", "cmd.exe");
    clean.PATHEXT = ".COM;.EXE;.BAT;.CMD";
    clean.TEMP = controlRoot;
    clean.TMP = controlRoot;
  } else {
    clean.PATH = fixedReleasePath(trustedCommand, undefined);
    clean.TMPDIR = controlRoot;
  }

  if (trustedCommand.command === "git") {
    const gitHome = safeAbsoluteReleasePath(options?.gitHome, trustedCommand.platform);
    if (!gitHome || !pathIsInsideForPlatform(controlRoot, gitHome, trustedCommand.platform)) {
      fail("the isolated Git home is invalid");
    }
    clean.HOME = gitHome;
    if (trustedCommand.platform === "win32") clean.USERPROFILE = gitHome;
    clean.XDG_CONFIG_HOME = gitHome;
    clean.GIT_CONFIG_NOSYSTEM = "1";
    clean.GIT_CONFIG_SYSTEM = trustedCommand.platform === "win32" ? "NUL" : "/dev/null";
    clean.GIT_CONFIG_GLOBAL = trustedCommand.platform === "win32" ? "NUL" : "/dev/null";
    clean.GIT_CONFIG_COUNT = "0";
    clean.GIT_ATTR_NOSYSTEM = "1";
    clean.GIT_TERMINAL_PROMPT = "0";
    clean.GCM_INTERACTIVE = "Never";
    clean.GIT_OPTIONAL_LOCKS = "0";
    clean.GIT_PAGER = "cat";
    clean.PAGER = "cat";
    return clean;
  }

  for (const name of ["GH_TOKEN", "GITHUB_TOKEN"]) {
    if (typeof source?.[name] === "string" && source[name] !== "") clean[name] = source[name];
  }
  const sourceHome = safeAbsoluteReleasePath(
    trustedCommand.platform === "win32" ? source?.USERPROFILE : source?.HOME,
    trustedCommand.platform
  ) ?? homedir();
  if (trustedCommand.platform === "win32") {
    clean.USERPROFILE = sourceHome;
    const appData = safeGhConfigurationPath(source?.APPDATA, sourceHome, trustedCommand);
    const localAppData = safeGhConfigurationPath(source?.LOCALAPPDATA, sourceHome, trustedCommand);
    if (appData) clean.APPDATA = appData;
    if (localAppData) clean.LOCALAPPDATA = localAppData;
  } else {
    clean.HOME = sourceHome;
    const xdgConfigHome = safeGhConfigurationPath(source?.XDG_CONFIG_HOME, sourceHome, trustedCommand);
    if (xdgConfigHome) clean.XDG_CONFIG_HOME = xdgConfigHome;
  }
  const ghConfigDirectory = safeGhConfigurationPath(source?.GH_CONFIG_DIR, sourceHome, trustedCommand);
  if (ghConfigDirectory) clean.GH_CONFIG_DIR = ghConfigDirectory;
  clean.GH_PAGER = "cat";
  clean.GH_PROMPT_DISABLED = "1";
  clean.GH_NO_UPDATE_NOTIFIER = "1";
  return clean;
}

export function hardenedGitArguments(args, hooksPath, platform = process.platform) {
  if (!Array.isArray(args) || args.some((argument) => typeof argument !== "string")) {
    fail("the Git argument list is invalid");
  }
  const safeHooksPath = safeAbsoluteReleasePath(hooksPath, platform);
  if (!safeHooksPath) fail("the isolated Git hooks path is invalid");
  const nullDevice = platform === "win32" ? "NUL" : "/dev/null";
  return [
    "--no-pager",
    "-c", `core.hooksPath=${safeHooksPath}`,
    "-c", "core.fsmonitor=false",
    "-c", "core.untrackedCache=false",
    "-c", `core.attributesFile=${nullDevice}`,
    "-c", "credential.helper=",
    "-c", "core.askPass=",
    "-c", "maintenance.auto=false",
    "-c", "gc.auto=0",
    "-c", "protocol.allow=never",
    "-c", "protocol.https.allow=always",
    ...args
  ];
}

async function prepareTrustedReleaseCommand(trustedCommand, source, controlRoot) {
  const controlInfo = await lstat(controlRoot);
  if (!controlInfo.isDirectory() || controlInfo.isSymbolicLink()
    || (process.platform !== "win32" && ((controlInfo.mode & 0o077) !== 0
      || (typeof process.getuid === "function" && controlInfo.uid !== process.getuid())))) {
    fail("the release command control directory is unsafe");
  }
  const gitHome = path.join(controlRoot, "git-home");
  const hooksPath = path.join(controlRoot, "empty-git-hooks");
  if (trustedCommand.command === "git") {
    await Promise.all([
      mkdir(gitHome, { mode: 0o700 }),
      mkdir(hooksPath, { mode: 0o700 })
    ]);
  }
  return Object.freeze({
    ...trustedCommand,
    controlRoot,
    ...(trustedCommand.command === "git" ? { gitHome, hooksPath } : {}),
    childEnvironment: Object.freeze(releaseCommandEnvironment(trustedCommand, source, {
      controlRoot,
      ...(trustedCommand.command === "git" ? { gitHome } : {})
    }))
  });
}

async function runCaptured(command, args, cwd, env = process.env, options = {}) {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      shell: false,
      windowsHide: true,
      detached: options.shieldSignals === true,
      stdio: ["ignore", "pipe", "pipe"]
    });
    const stdout = [];
    const stderr = [];
    let capturedBytes = 0;
    let settled = false;
    const capture = (destination) => (chunk) => {
      capturedBytes += chunk.length;
      if (capturedBytes > maximumCapturedBytes) {
        child.kill();
        if (!settled) {
          settled = true;
          reject(new Error(`${command} produced more output than the bootstrap verifier permits.`));
        }
        return;
      }
      destination.push(chunk);
    };
    child.stdout.on("data", capture(stdout));
    child.stderr.on("data", capture(stderr));
    child.once("error", (error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    });
    child.once("exit", (code) => {
      if (settled) return;
      settled = true;
      resolve({
        code: code ?? 1,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8")
      });
    });
  });
}

async function runTrustedCommandCaptured(trustedCommand, args, cwd, options = {}) {
  await assertPinnedCommandUnchanged(trustedCommand);
  if (!trustedCommand.childEnvironment || !trustedCommand.controlRoot) {
    fail("the release command was not prepared with an isolated environment");
  }
  const invocationArgs = trustedCommand.command === "git"
    ? hardenedGitArguments(args, trustedCommand.hooksPath, trustedCommand.platform)
    : args;
  return await runCaptured(trustedCommand.executable, invocationArgs, cwd, trustedCommand.childEnvironment, options);
}

async function runInherited(command, args, cwd, env = process.env) {
  const code = await new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd, env, shell: false, windowsHide: true, stdio: "inherit" });
    child.once("error", reject);
    child.once("exit", (exitCode) => resolve(exitCode ?? 1));
  });
  if (code !== 0) throw new Error(`${command} failed with exit code ${code}.`);
}

const SAFE_NPM_ENVIRONMENT_KEYS = new Set([
  "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM", "NO_COLOR", "FORCE_COLOR", "TZ",
  "TMPDIR", "TMP", "TEMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "SystemRoot", "WINDIR",
  "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
  "NPM_CONFIG_USERCONFIG",
  "BROWSEWEAVE_RELEASE", "BROWSEWEAVE_RELEASE_CONFIRMATION", "BROWSEWEAVE_BOOTSTRAP_ORCHESTRATED",
  "BROWSEWEAVE_BOOTSTRAP_NPM_USER", "BROWSEWEAVE_BOOTSTRAP_PACKAGE_STATE"
]);

export function npmChildEnvironment(trustedNpm, source) {
  const clean = {};
  for (const [name, value] of Object.entries(source)) {
    if (SAFE_NPM_ENVIRONMENT_KEYS.has(name) && typeof value === "string") clean[name] = value;
  }
  const nodeDirectory = path.dirname(trustedNpm.nodeExecutable);
  if (trustedNpm.platform === "win32") {
    const systemRoot = clean.SystemRoot || clean.SYSTEMROOT || clean.WINDIR || "C:\\Windows";
    clean.Path = [nodeDirectory, path.win32.join(systemRoot, "System32"), systemRoot].join(path.win32.delimiter);
    clean.ComSpec = path.win32.join(systemRoot, "System32", "cmd.exe");
    clean.PATHEXT = ".COM;.EXE;.BAT;.CMD";
  } else {
    clean.PATH = [nodeDirectory, "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"].join(path.posix.delimiter);
  }
  return clean;
}

async function runNpmCaptured(trustedNpm, args, cwd, env = process.env, shieldSignals = false) {
  await assertPinnedNpmUnchanged(trustedNpm);
  const invocation = npmInvocationForTrustedCli(trustedNpm.nodeExecutable, trustedNpm.npmCliPath, args);
  const cleanEnvironment = npmChildEnvironment(trustedNpm, env);
  return await runCaptured(invocation.command, invocation.args, cwd, cleanEnvironment, { shieldSignals });
}

async function runNpmInherited(trustedNpm, args, cwd, env = process.env) {
  await assertPinnedNpmUnchanged(trustedNpm);
  const invocation = npmInvocationForTrustedCli(trustedNpm.nodeExecutable, trustedNpm.npmCliPath, args);
  const cleanEnvironment = npmChildEnvironment(trustedNpm, env);
  await runInherited(invocation.command, invocation.args, cwd, cleanEnvironment);
}

async function requireSuccessful(result, label) {
  if (result.code !== 0) fail(`${label} failed`);
  return result.stdout.trim();
}

export function assertCanonicalRepositoryOrigin(origin) {
  if (origin !== canonicalRepositoryUrl) {
    fail(`origin must be exactly ${canonicalRepositoryUrl}`);
  }
}

export function canonicalRemoteTagArguments(version) {
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(version)) {
    fail("the remote tag version is invalid");
  }
  return [
    "ls-remote",
    "--tags",
    canonicalRepositoryUrl,
    `refs/tags/v${version}`,
    `refs/tags/v${version}^{}`
  ];
}

async function assertCleanTaggedRepository(version, trustedGit) {
  const topLevel = await requireSuccessful(
    await runTrustedCommandCaptured(trustedGit, ["rev-parse", "--show-toplevel"], projectDirectory),
    "Git repository lookup"
  );
  if (await realpath(topLevel) !== await realpath(projectDirectory)) {
    fail("run this only from the BrowseWeave repository root");
  }

  const status = await requireSuccessful(
    await runTrustedCommandCaptured(
      trustedGit,
      ["status", "--porcelain=v1", "--untracked-files=all"],
      projectDirectory
    ),
    "Git cleanliness check"
  );
  if (status !== "") fail("the main worktree must be completely clean before bootstrap publishing");

  const origin = await requireSuccessful(
    await runTrustedCommandCaptured(
      trustedGit,
      ["config", "--local", "--get-all", "remote.origin.url"],
      projectDirectory
    ),
    "Git origin lookup"
  );
  assertCanonicalRepositoryOrigin(origin);

  const head = await requireSuccessful(
    await runTrustedCommandCaptured(trustedGit, ["rev-parse", "HEAD"], projectDirectory),
    "HEAD lookup"
  );
  const tagRef = `refs/tags/v${version}^{commit}`;
  const tagCommit = await requireSuccessful(
    await runTrustedCommandCaptured(trustedGit, ["rev-parse", "--verify", tagRef], projectDirectory),
    `tag v${version} lookup`
  );
  if (head !== tagCommit) fail(`HEAD must be exactly tag v${version}`);
  const remoteTagOutput = await requireSuccessful(
    await runTrustedCommandCaptured(
      trustedGit,
      canonicalRemoteTagArguments(version),
      trustedGit.controlRoot
    ),
    `remote tag v${version} lookup`
  );
  const remoteTagCommits = remoteTagOutput
    .split(/\r?\n/u)
    .map((line) => line.trim().split(/\s+/u)[0])
    .filter(Boolean);
  if (!remoteTagCommits.includes(tagCommit)) {
    fail(`tag v${version} must already be pushed to the canonical origin at the exact release commit`);
  }
  return tagCommit;
}

export function canonicalCiWorkflowRuns(payload, tagCommit) {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.workflow_runs)
    || !/^[a-f0-9]{40}$/u.test(tagCommit)) {
    fail("GitHub returned an invalid workflow-run response");
  }
  return payload.workflow_runs.filter((run) => run && typeof run === "object"
    && Number.isSafeInteger(run.id) && run.id > 0
    && run.head_sha === tagCommit
    && run.path === canonicalCiWorkflowPath
    && run.event === "push"
    && run.status === "completed"
    && run.conclusion === "success"
    && run.repository?.full_name === "xenitV1/browseweave"
    && run.head_repository?.full_name === "xenitV1/browseweave");
}

export function assertRequiredCiJobs(payload) {
  if (!payload || typeof payload !== "object" || !Array.isArray(payload.jobs)) {
    fail("GitHub returned an invalid workflow-job response");
  }
  const missing = requiredCiChecks.filter((name) => !payload.jobs.some((job) =>
    job && typeof job === "object" && job.name === name
      && job.status === "completed" && job.conclusion === "success"
  ));
  if (missing.length > 0) fail(`the canonical CI workflow has no successful job for: ${missing.join(", ")}`);
}

async function assertHostedCiSuccess(tagCommit, trustedGh) {
  const response = await runTrustedCommandCaptured(
    trustedGh,
    [
      "api",
      "--hostname",
      "github.com",
      `repos/xenitV1/browseweave/actions/workflows/ci.yml/runs?head_sha=${tagCommit}&event=push&status=success&per_page=100`,
      "-H",
      "Accept: application/vnd.github+json"
    ],
    trustedGh.controlRoot
  );
  if (response.code !== 0) fail("the exact tagged commit's hosted CI results could not be verified");
  let payload;
  try {
    payload = JSON.parse(response.stdout);
  } catch {
    fail("GitHub returned invalid hosted CI data");
  }
  const workflowRuns = canonicalCiWorkflowRuns(payload, tagCommit);
  if (workflowRuns.length === 0) {
    fail("the exact tagged commit has no successful canonical .github/workflows/ci.yml push run");
  }
  const failures = [];
  for (const workflowRun of workflowRuns) {
    const jobsResponse = await runTrustedCommandCaptured(
      trustedGh,
      [
        "api",
        "--hostname",
        "github.com",
        `repos/xenitV1/browseweave/actions/runs/${workflowRun.id}/jobs?per_page=100`,
        "-H",
        "Accept: application/vnd.github+json"
      ],
      trustedGh.controlRoot
    );
    if (jobsResponse.code !== 0) {
      failures.push(new Error(`workflow run ${workflowRun.id} jobs could not be verified`));
      continue;
    }
    try {
      assertRequiredCiJobs(JSON.parse(jobsResponse.stdout));
      return;
    } catch (error) {
      failures.push(error);
    }
  }
  throw new AggregateError(failures, "Bootstrap publish refused: no canonical CI workflow run passed every required job.");
}

async function assertNoNpmPublishAuthentication(trustedNpm) {
  const codeInjectionEnvironmentNames = [
    "NODE_OPTIONS",
    "NODE_PATH",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH"
  ];
  const unsafeEnvironment = codeInjectionEnvironmentNames.filter((name) => (process.env[name] ?? "").trim() !== "");
  if (unsafeEnvironment.length > 0) {
    fail(`start the bootstrap from a clean terminal without ${unsafeEnvironment.join(", ")}`);
  }
  const tokenEnvironmentNames = [
    "NODE_AUTH_TOKEN",
    "NPM_TOKEN",
    "NPM_AUTH_TOKEN",
    "NPM_CONFIG__AUTH",
    "NPM_CONFIG__AUTHTOKEN",
    "npm_config__auth",
    "npm_config__authtoken"
  ];
  if (tokenEnvironmentNames.some((name) => typeof process.env[name] === "string" && process.env[name] !== "")) {
    fail("remove npm authentication from the environment before dependency installation, build, test, or tagged package scripts run");
  }

  const whoami = await runNpmCaptured(trustedNpm, ["whoami", `--registry=${registry}`], projectDirectory);
  if (whoami.code === 0) {
    fail(`npm is already authenticated. Run 'npm logout --registry=${registry}', then restart this reviewed bootstrap orchestrator; authentication is requested only after dependency installation, build, tests, packing, and git verification finish`);
  }
  if (!npmResponseProvesUnauthenticated(whoami)) {
    fail("npm did not prove an unauthenticated starting state; check registry connectivity without adding a token");
  }
}

function npmResponseProvesUnauthenticated(result) {
  return result && typeof result === "object" && result.code !== 0
    && /\bENEEDAUTH\b|\bE401\b|\b401\b|not logged in|not authorized/iu.test(`${result.stdout}\n${result.stderr}`);
}

async function assertPackageIsUnpublished(trustedNpm, cwd, env = process.env) {
  const lookup = await runNpmCaptured(
    trustedNpm,
    ["view", "browseweave", "name", "--json", `--registry=${registry}`],
    cwd,
    env
  );
  if (lookup.code === 0) fail("browseweave already exists on npm; use the trusted publisher workflow instead");
  if (!/\bE404\b|\b404\b/u.test(`${lookup.stdout}\n${lookup.stderr}`)) {
    fail("npm package availability check did not return E404");
  }
}

async function assertNpmBootstrapIdentity(trustedNpm, cwd, env) {
  const whoami = await requireSuccessful(
    await runNpmCaptured(trustedNpm, ["whoami", `--registry=${registry}`], cwd, env),
    "npm identity check"
  );
  if (whoami !== expectedNpmUser) fail(`npm identity must be exactly ${expectedNpmUser}`);
  await assertPackageIsUnpublished(trustedNpm, cwd, env);
}

export function isExactPrivateRemovalStatus(stdout) {
  return stdout === " M package.json\n" || stdout === " M package.json\r\n";
}

async function assertOnlyPrivateRemoval(worktreeDirectory, originalPackageJson, trustedGit) {
  const status = await runTrustedCommandCaptured(
    trustedGit,
    ["status", "--porcelain=v1", "--untracked-files=all"],
    worktreeDirectory
  );
  if (status.code !== 0) fail("detached worktree diff check failed");
  if (!isExactPrivateRemovalStatus(status.stdout)) {
    fail("the detached worktree may differ from its tag only by package.json private removal");
  }

  const changedPackageJson = JSON.parse(await readFile(path.join(worktreeDirectory, "package.json"), "utf8"));
  const expectedPackageJson = structuredClone(originalPackageJson);
  delete expectedPackageJson.private;
  if (JSON.stringify(changedPackageJson) !== JSON.stringify(expectedPackageJson)) {
    fail("package.json changed by more than removal of private:true");
  }
}

export async function finalizeBootstrapCleanup({
  operationError,
  npmAuthenticationAttempted,
  cleanupTasks,
  credentialIsInactive = () => false,
  warn
}) {
  const cleanupErrors = [];
  for (const cleanupTask of cleanupTasks) {
    try {
      await cleanupTask();
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  const errors = [
    ...(operationError === undefined ? [] : [operationError]),
    ...cleanupErrors
  ];
  if (npmAuthenticationAttempted && errors.length > 0 && !credentialIsInactive()) warn();
  if (errors.length > 1) throw new AggregateError(errors, "Bootstrap publish and cleanup failed.");
  if (errors.length === 1) throw errors[0];
}

function createReleaseSignalGuard() {
  let receivedSignal;
  const record = (signal) => {
    if (receivedSignal !== undefined) return;
    receivedSignal = signal;
    process.stderr.write(`${signal} received. BrowseWeave will stop after protected npm credential cleanup.\n`);
  };
  const onSigint = () => record("SIGINT");
  const onSigterm = () => record("SIGTERM");
  process.on("SIGINT", onSigint);
  process.on("SIGTERM", onSigterm);
  return {
    throwIfInterrupted() {
      if (receivedSignal === undefined) return;
      const error = new Error(`Bootstrap publish interrupted by ${receivedSignal}.`);
      error.code = "BROWSEWEAVE_RELEASE_INTERRUPTED";
      throw error;
    },
    remove() {
      process.removeListener("SIGINT", onSigint);
      process.removeListener("SIGTERM", onSigterm);
    }
  };
}

async function bootstrapPublishOperation(signalGuard) {
  if (process.env.GITHUB_ACTIONS === "true" || process.env.CI === "true") {
    fail("bootstrap publishing is local-only and cannot run in CI");
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    fail("run bootstrap publishing yourself in an interactive local terminal");
  }
  signalGuard.throwIfInterrupted();

  const temporaryRoot = await mkdtemp(path.join(tmpdir(), "browseweave-bootstrap-"));
  try {
    const gitControlRoot = path.join(temporaryRoot, "trusted-git");
    const ghControlRoot = path.join(temporaryRoot, "trusted-gh");
    await Promise.all([
      mkdir(gitControlRoot, { mode: 0o700 }),
      mkdir(ghControlRoot, { mode: 0o700 })
    ]);

  // This file is the reviewed bootstrap orchestrator. Its auth check happens
  // before dependency installation, builds, tests, or any other tagged package
  // script. Those broader code surfaces never execute with publish authority.
  // Resolve npm only from the current Node.js installation and keep that exact
  // file identity pinned across the later authentication boundary.
  const trustedNpm = await resolveTrustedNpm();
  const [resolvedGit, resolvedGh] = await Promise.all([
    resolveTrustedCommand("git"),
    resolveTrustedCommand("gh")
  ]);
  const [trustedGit, trustedGh] = await Promise.all([
    prepareTrustedReleaseCommand(resolvedGit, process.env, gitControlRoot),
    prepareTrustedReleaseCommand(resolvedGh, process.env, ghControlRoot)
  ]);
  await assertNoNpmPublishAuthentication(trustedNpm);
  await assertPackageIsUnpublished(trustedNpm, projectDirectory);
  signalGuard.throwIfInterrupted();

  const packageJson = JSON.parse(await readFile(path.join(projectDirectory, "package.json"), "utf8"));
  if (packageJson.name !== "browseweave" || packageJson.private !== true) {
    fail("the tagged source package must be browseweave with private:true");
  }
  let distTag;
  try {
    distTag = releaseDistTag(packageJson.version);
  } catch {
    fail("package.json version is invalid");
  }

  const expectedConfirmation = `bootstrap browseweave@${packageJson.version}`;
  if (process.argv.slice(2).join(" ") !== expectedConfirmation) {
    fail(`confirmation must be exactly: ${expectedConfirmation}`);
  }

  const tagCommit = await assertCleanTaggedRepository(packageJson.version, trustedGit);
  await assertHostedCiSuccess(tagCommit, trustedGh);
  signalGuard.throwIfInterrupted();
  const {
    assertArchiveUnchanged,
    inspectReleaseArchive,
    snapshotReleaseInputs
  } = await import("./verify-release-archive.mjs");

  const worktreeDirectory = path.join(temporaryRoot, "worktree");
  const npmAuthenticationConfig = path.join(temporaryRoot, "npm-auth-config");
  let worktreeAdded = false;
  let operationError;
  let npmAuthenticationAttempted = false;
  let npmAuthenticationEnvironment;
  let npmCredentialProvenInactive = false;

  try {
    signalGuard.throwIfInterrupted();
    const addResult = await runTrustedCommandCaptured(
      trustedGit,
      ["worktree", "add", "--detach", worktreeDirectory, tagCommit],
      projectDirectory
    );
    if (addResult.code !== 0) fail("temporary detached worktree creation failed");
    worktreeAdded = true;

    await runNpmInherited(trustedNpm, ["ci", "--ignore-scripts"], worktreeDirectory);
    await runNpmInherited(trustedNpm, ["run", "verify:release"], worktreeDirectory);
    signalGuard.throwIfInterrupted();

    const cleanStatus = await requireSuccessful(
      await runTrustedCommandCaptured(
        trustedGit,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        worktreeDirectory
      ),
      "verified worktree cleanliness check"
    );
    if (cleanStatus !== "") fail("verification changed tracked or unignored files in the detached worktree");

    await requireSuccessful(
      await runNpmCaptured(trustedNpm, ["pkg", "delete", "private"], worktreeDirectory),
      "temporary package unlock"
    );
    await assertOnlyPrivateRemoval(worktreeDirectory, packageJson, trustedGit);

    const releaseEnvironment = {
      ...npmChildEnvironment(trustedNpm, process.env),
      npm_execpath: trustedNpm.npmCliPath,
      BROWSEWEAVE_RELEASE: "bootstrap-local",
      BROWSEWEAVE_RELEASE_CONFIRMATION: expectedConfirmation,
      BROWSEWEAVE_BOOTSTRAP_ORCHESTRATED: "1",
      BROWSEWEAVE_BOOTSTRAP_NPM_USER: expectedNpmUser,
      BROWSEWEAVE_BOOTSTRAP_PACKAGE_STATE: "E404"
    };
    await assertPinnedNpmUnchanged(trustedNpm);
    const checkNpmPackInvocation = nodeInvocationForTrustedRuntime(trustedNpm, [
      path.join(worktreeDirectory, "scripts", "check-npm-pack.mjs"), "--publish", "--list"
    ]);
    await runInherited(
      checkNpmPackInvocation.command,
      checkNpmPackInvocation.args,
      worktreeDirectory,
      releaseEnvironment
    );
    await assertOnlyPrivateRemoval(worktreeDirectory, packageJson, trustedGit);

    const dryRun = await runNpmCaptured(
      trustedNpm,
      ["pack", "--dry-run", "--ignore-scripts", "--json"],
      worktreeDirectory,
      releaseEnvironment
    );
    if (dryRun.code !== 0) fail("release input snapshot listing failed");
    let dryRunManifest;
    try {
      dryRunManifest = JSON.parse(dryRun.stdout);
    } catch {
      fail("npm returned invalid JSON for the release input snapshot");
    }
    if (!Array.isArray(dryRunManifest) || dryRunManifest.length !== 1
      || !Array.isArray(dryRunManifest[0]?.files)) {
      fail("npm returned an unexpected release input snapshot");
    }
    const releaseInputPaths = dryRunManifest[0].files.map((entry) => entry?.path);
    if (releaseInputPaths.some((file) => typeof file !== "string")) fail("npm returned an invalid release input path");
    const releaseInputSnapshot = await snapshotReleaseInputs(worktreeDirectory, releaseInputPaths);

    const releaseDirectory = path.join(temporaryRoot, "release");
    await mkdir(releaseDirectory, { mode: 0o700 });
    const packed = await runNpmCaptured(
      trustedNpm,
      ["pack", "--ignore-scripts", "--json", "--pack-destination", releaseDirectory],
      worktreeDirectory,
      releaseEnvironment
    );
    if (packed.code !== 0) fail("creation of the fixed release tarball failed");
    let packedManifest;
    try {
      packedManifest = JSON.parse(packed.stdout);
    } catch {
      fail("npm returned invalid JSON while creating the release tarball");
    }
    const expectedArchiveName = `browseweave-${packageJson.version}.tgz`;
    const releaseFiles = await readdir(releaseDirectory);
    if (!Array.isArray(packedManifest) || packedManifest.length !== 1
      || packedManifest[0]?.filename !== expectedArchiveName
      || releaseFiles.length !== 1 || releaseFiles[0] !== expectedArchiveName) {
      fail("npm did not create exactly the expected release tarball");
    }
    const archivePath = path.join(releaseDirectory, expectedArchiveName);
    const archiveInfo = await lstat(archivePath);
    if (!archiveInfo.isFile() || archiveInfo.isSymbolicLink() || archiveInfo.size > 5 * 1024 * 1024) {
      fail("the fixed release tarball is not a safe regular file");
    }
    await assertOnlyPrivateRemoval(worktreeDirectory, packageJson, trustedGit);
    const verifiedArchive = await inspectReleaseArchive({
      archivePath,
      version: packageJson.version,
      snapshot: releaseInputSnapshot
    });

    const removeVerifiedWorktree = await runTrustedCommandCaptured(
      trustedGit,
      ["worktree", "remove", "--force", worktreeDirectory],
      projectDirectory
    );
    if (removeVerifiedWorktree.code !== 0) {
      fail("the verified worktree could not be removed before npm authentication");
    }
    worktreeAdded = false;
    signalGuard.throwIfInterrupted();

    process.stderr.write(
      `The fixed browseweave@${packageJson.version} tarball is verified. npm authentication starts now; `
      + "complete the human login prompt. No dependency, build, test, tagged package, or git command will run afterward.\n"
    );
    await writeFile(npmAuthenticationConfig, "", { encoding: "utf8", mode: 0o600, flag: "wx" });
    npmAuthenticationEnvironment = {
      ...releaseEnvironment,
      NPM_CONFIG_USERCONFIG: npmAuthenticationConfig
    };
    npmAuthenticationAttempted = true;
    await runNpmInherited(
      trustedNpm,
      ["login", `--registry=${registry}`, `--userconfig=${npmAuthenticationConfig}`],
      temporaryRoot,
      npmAuthenticationEnvironment
    );
    signalGuard.throwIfInterrupted();
    await assertNpmBootstrapIdentity(trustedNpm, temporaryRoot, npmAuthenticationEnvironment);
    await assertArchiveUnchanged(archivePath, verifiedArchive.sha256);
    signalGuard.throwIfInterrupted();

    // Only npm identity/E404/exact-tarball publication and this orchestrator's
    // in-memory cleanup remain once publish authority exists.
    // Local machines cannot generate npm provenance; later releases use trusted OIDC.
    await runNpmInherited(
      trustedNpm,
      [
        "publish", archivePath, "--access", "public", "--ignore-scripts", "--provenance=false",
        "--tag", distTag
      ],
      temporaryRoot,
      npmAuthenticationEnvironment
    );
    signalGuard.throwIfInterrupted();
  } catch (error) {
    operationError = error;
  }

  const cleanupTasks = [];
  if (worktreeAdded) {
    cleanupTasks.push(async () => {
      const cleanup = await runTrustedCommandCaptured(
        trustedGit,
        ["worktree", "remove", "--force", worktreeDirectory],
        projectDirectory
      );
      if (cleanup.code !== 0) throw new Error("Temporary git worktree cleanup failed.");
    });
  }
  if (npmAuthenticationAttempted && npmAuthenticationEnvironment) {
    cleanupTasks.push(async () => {
      const logout = await runNpmCaptured(
        trustedNpm,
        ["logout", `--registry=${registry}`, `--userconfig=${npmAuthenticationConfig}`],
        temporaryRoot,
        npmAuthenticationEnvironment,
        true
      );
      if (logout.code !== 0) {
        throw new Error("npm did not confirm temporary credential logout.");
      }
      const afterLogout = await runNpmCaptured(
        trustedNpm,
        ["whoami", `--registry=${registry}`, `--userconfig=${npmAuthenticationConfig}`],
        temporaryRoot,
        npmAuthenticationEnvironment,
        true
      );
      if (afterLogout.code === 0 || !npmResponseProvesUnauthenticated(afterLogout)) {
        throw new Error("The temporary npm publication credential was not proven revoked.");
      }
      npmCredentialProvenInactive = true;
    });
  }
  cleanupTasks.push(async () => rm(temporaryRoot, { recursive: true, force: true }));
  await finalizeBootstrapCleanup({
    operationError,
    npmAuthenticationAttempted,
    cleanupTasks,
    credentialIsInactive: () => npmCredentialProvenInactive,
    warn: () => process.stderr.write(
      "The temporary npm credential was not proven inactive. Open npmjs.com, go to Access Tokens, "
      + "and revoke the newest token before running any repository command.\n"
    )
  });
  signalGuard.throwIfInterrupted();

  process.stderr.write(
    `Published browseweave@${packageJson.version} on the npm ${distTag} tag. Configure npm trusted publishing for `
    + "xenitV1/browseweave, publish.yml, environment npm. The temporary bootstrap credential was revoked; "
    + "use the manual GitHub workflow for every later release.\n"
  );
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

async function bootstrapPublish() {
  const signalGuard = createReleaseSignalGuard();
  try {
    await bootstrapPublishOperation(signalGuard);
  } finally {
    signalGuard.remove();
  }
}

const invokedAsScript = process.argv[1]
  ? pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url
  : false;
if (invokedAsScript) {
  try {
    await bootstrapPublish();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = error?.code === "BROWSEWEAVE_RELEASE_INTERRUPTED" ? 130 : 1;
  }
}
