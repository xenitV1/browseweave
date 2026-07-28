import { constants as fsConstants, type Stats } from "node:fs";
import { access, lstat, readFile, realpath } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import path from "node:path";

export interface CommandInvocation {
  command: string;
  args: string[];
}

export type ClientExecutableName = "codex" | "claude" | "cursor-agent" | "opencode" | "opencode2";

interface TrustedFileSystemIdentity {
  readonly dev: number;
  readonly ino: number;
  readonly mode: number;
  readonly size: number;
  readonly mtimeMs: number;
  readonly uid: number;
  readonly gid: number;
}

export interface TrustedClientExecutable {
  readonly name: ClientExecutableName;
  readonly executable: string;
  readonly identity: TrustedFileSystemIdentity;
  readonly directories: ReadonlyArray<{
    readonly path: string;
    readonly identity: TrustedFileSystemIdentity;
  }>;
}

export interface ClientPathFilterOptions {
  platform?: NodeJS.Platform;
  home?: string;
  localAppData?: string;
  cacheDirectories?: string[];
}

export interface TrustedClientResolutionOptions extends ClientPathFilterOptions {
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  packageRoot?: string;
  temporaryDirectory?: string;
  projectDirectories?: string[];
  uid?: number;
}

type PathApi = typeof path.posix;

function pathApiFor(platform: NodeJS.Platform): PathApi {
  return platform === "win32" ? path.win32 : path.posix;
}

function pathIsInside(root: string, target: string, pathApi: PathApi, platform: NodeJS.Platform): boolean {
  const normalizedRoot = pathApi.resolve(root);
  const normalizedTarget = pathApi.resolve(target);
  const relative = pathApi.relative(normalizedRoot, normalizedTarget);
  if (relative === "") return true;
  const comparable = platform === "win32" ? relative.toLowerCase() : relative;
  return comparable !== ".."
    && !comparable.startsWith(`..${pathApi.sep}`)
    && !pathApi.isAbsolute(relative);
}

function safeAbsolutePath(value: string | undefined, pathApi: PathApi, platform: NodeJS.Platform): string | undefined {
  if (!value || /[\0\r\n]/u.test(value) || !pathApi.isAbsolute(value)) return undefined;
  if (platform === "win32" && value.startsWith("\\\\")) return undefined;
  return pathApi.normalize(value);
}

function pathSegments(value: string): string[] {
  return value.split(/[\\/]+/u).filter(Boolean).map((segment) => segment.toLowerCase());
}

function containsUnsafeClientPathComponent(value: string): boolean {
  const segments = pathSegments(value);
  if (segments.some((segment) => segment === "_npx" || segment === "_cacache" || segment === "npm-cache" || segment === ".npm")) {
    return true;
  }
  return segments.some((segment, index) => segment === "node_modules" && segments[index + 1] === ".bin");
}

function defaultClientCacheDirectories(options: ClientPathFilterOptions, pathApi: PathApi): string[] {
  const directories = [...(options.cacheDirectories ?? [])];
  if (options.platform === "win32") {
    if (options.localAppData) directories.push(pathApi.join(options.localAppData, "npm-cache"));
  } else if (options.home) {
    directories.push(pathApi.join(options.home, ".npm"));
  }
  return directories;
}

/**
 * Remove package-local and npm/npx cache search paths before looking up an MCP client.
 * Relative and empty PATH components are rejected because they resolve through the caller's cwd.
 */
export function safeClientPathEntries(pathValue: string, options: ClientPathFilterOptions = {}): string[] {
  const platform = options.platform ?? process.platform;
  const pathApi = pathApiFor(platform);
  const home = options.home ?? homedir();
  const cacheDirectories = defaultClientCacheDirectories({ ...options, platform, home }, pathApi)
    .map((entry) => safeAbsolutePath(entry, pathApi, platform))
    .filter((entry): entry is string => entry !== undefined);
  const seen = new Set<string>();
  const safe: string[] = [];
  for (const rawEntry of pathValue.split(pathApi.delimiter)) {
    const entry = safeAbsolutePath(rawEntry, pathApi, platform);
    if (!entry || containsUnsafeClientPathComponent(entry)) continue;
    if (cacheDirectories.some((cache) => pathIsInside(cache, entry, pathApi, platform))) continue;
    const key = platform === "win32" ? entry.toLowerCase() : entry;
    if (seen.has(key)) continue;
    seen.add(key);
    safe.push(entry);
  }
  return safe;
}

function executableCandidateNames(name: ClientExecutableName, platform: NodeJS.Platform): string[] {
  if (platform !== "win32") return [name];
  return [".com", ".exe", ".bat", ".cmd", ""]
    .map((extension) => `${name}${extension}`);
}

async function canonicalOrAbsolute(value: string, pathApi: PathApi): Promise<string> {
  return await realpath(value).catch(() => pathApi.resolve(value));
}

function trustedFileSystemIdentity(info: Stats): TrustedFileSystemIdentity {
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

function identitiesMatch(
  left: TrustedFileSystemIdentity,
  right: TrustedFileSystemIdentity
): boolean {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.uid === right.uid
    && left.gid === right.gid;
}

function pathsFromAnchor(anchor: string, target: string, pathApi: PathApi): string[] {
  const relative = pathApi.relative(anchor, target);
  if (relative === "") return [anchor];
  const paths = [anchor];
  let current = anchor;
  for (const segment of relative.split(pathApi.sep).filter(Boolean)) {
    current = pathApi.join(current, segment);
    paths.push(current);
  }
  return paths;
}

async function trustedDirectoryChain(
  directory: string,
  canonicalHome: string,
  platform: NodeJS.Platform,
  expectedUid: number | undefined,
  expectedGid: number | undefined,
  pathApi: PathApi
): Promise<Array<{ path: string; identity: TrustedFileSystemIdentity }>> {
  const canonicalDirectory = await realpath(directory);
  const anchor = pathIsInside(canonicalHome, canonicalDirectory, pathApi, platform)
    ? canonicalHome
    : pathApi.parse(canonicalDirectory).root;
  const trusted: Array<{ path: string; identity: TrustedFileSystemIdentity }> = [];
  for (const current of pathsFromAnchor(anchor, canonicalDirectory, pathApi)) {
    if (await realpath(current) !== current) throw new Error("A client executable directory is not canonical.");
    const info = await lstat(current);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error("A client executable path component is not a canonical directory.");
    }
    if (platform !== "win32") {
      if (expectedUid === undefined || (info.uid !== expectedUid && info.uid !== 0)) {
        throw new Error("A client executable directory has an unsafe owner.");
      }
      if ((info.mode & 0o002) !== 0) {
        throw new Error("A client executable directory is writable by other users.");
      }
      if ((info.mode & 0o020) !== 0
        && !(info.uid === expectedUid && expectedGid !== undefined && info.gid === expectedGid)) {
        throw new Error("A client executable directory is writable by an untrusted group.");
      }
    }
    trusted.push(Object.freeze({ path: current, identity: trustedFileSystemIdentity(info) }));
  }
  return trusted;
}

/** Resolve a client only from a sanitized PATH and pin its canonical owner-safe file identity. */
export async function resolveTrustedClientExecutable(
  name: ClientExecutableName,
  options: TrustedClientResolutionOptions = {}
): Promise<TrustedClientExecutable | undefined> {
  const platform = options.platform ?? process.platform;
  if (platform !== process.platform) {
    throw new Error("Client executable resolution must use the current operating system.");
  }
  const pathApi = pathApiFor(platform);
  const env = options.env ?? process.env;
  const home = safeAbsolutePath(options.home ?? homedir(), pathApi, platform);
  const cwd = safeAbsolutePath(options.cwd ?? process.cwd(), pathApi, platform);
  const temporaryDirectory = safeAbsolutePath(options.temporaryDirectory ?? tmpdir(), pathApi, platform);
  if (!home || !cwd || !temporaryDirectory) {
    throw new Error("The client executable trust roots are invalid.");
  }
  const explicitCache = env.npm_config_cache ?? env.NPM_CONFIG_CACHE;
  const localAppData = options.localAppData ?? env.LOCALAPPDATA;
  const cacheDirectories = [
    ...(options.cacheDirectories ?? []),
    ...(explicitCache ? [explicitCache] : [])
  ];
  const pathValue = platform === "win32" ? (env.Path ?? env.PATH ?? "") : (env.PATH ?? "");
  const entries = safeClientPathEntries(pathValue, {
    platform,
    home,
    ...(localAppData ? { localAppData } : {}),
    cacheDirectories
  });

  const lexicalForbiddenRoots = [
    temporaryDirectory,
    ...defaultClientCacheDirectories({
      platform,
      home,
      ...(localAppData ? { localAppData } : {}),
      cacheDirectories
    }, pathApi)
  ];
  if (options.packageRoot) lexicalForbiddenRoots.push(options.packageRoot);
  for (const directory of options.projectDirectories ?? []) lexicalForbiddenRoots.push(directory);
  const initCwd = safeAbsolutePath(env.INIT_CWD, pathApi, platform);
  if (initCwd && !pathIsInside(initCwd, home, pathApi, platform)) lexicalForbiddenRoots.push(initCwd);
  // Running npx from the home directory must not disable legitimate ~/.local/bin tools.
  // A narrower cwd remains an untrusted project root and is excluded.
  if (!pathIsInside(cwd, home, pathApi, platform)) lexicalForbiddenRoots.push(cwd);

  const safeLexicalRoots = lexicalForbiddenRoots
    .map((entry) => safeAbsolutePath(entry, pathApi, platform))
    .filter((entry): entry is string => entry !== undefined);
  const canonicalForbiddenRoots = await Promise.all(
    safeLexicalRoots.map((entry) => canonicalOrAbsolute(entry, pathApi))
  );
  const expectedUid = options.uid ?? (typeof process.getuid === "function" ? process.getuid() : undefined);
  const expectedGid = typeof process.getgid === "function" ? process.getgid() : undefined;
  const canonicalHome = await realpath(home);

  for (const directory of entries) {
    for (const candidateName of executableCandidateNames(name, platform)) {
      const candidate = pathApi.join(directory, candidateName);
      if (safeLexicalRoots.some((root) => pathIsInside(root, candidate, pathApi, platform))) continue;
      try {
        const executable = await realpath(candidate);
        if (!pathApi.isAbsolute(executable) || /[\0\r\n]/u.test(executable)) continue;
        if (canonicalForbiddenRoots.some((root) => pathIsInside(root, executable, pathApi, platform))) continue;
        const info = await lstat(executable);
        if (!info.isFile() || info.isSymbolicLink()) continue;
        if (platform !== "win32") {
          if (expectedUid === undefined || (info.uid !== expectedUid && info.uid !== 0)) continue;
          if ((info.mode & 0o022) !== 0) continue;
          await access(executable, fsConstants.X_OK);
        }
        const directoryChains = await Promise.all([
          trustedDirectoryChain(directory, canonicalHome, platform, expectedUid, expectedGid, pathApi),
          trustedDirectoryChain(pathApi.dirname(executable), canonicalHome, platform, expectedUid, expectedGid, pathApi)
        ]);
        const directories = new Map<string, { path: string; identity: TrustedFileSystemIdentity }>();
        for (const item of directoryChains.flat()) directories.set(item.path, item);
        return Object.freeze({
          name,
          executable,
          identity: trustedFileSystemIdentity(info),
          directories: Object.freeze([...directories.values()])
        });
      } catch {
        // Continue only to another candidate from the already-sanitized PATH.
      }
    }
  }
  return undefined;
}

/** Fail if the canonical client selected earlier was replaced before a later probe or mutation. */
export async function assertTrustedClientExecutableUnchanged(trusted: TrustedClientExecutable): Promise<void> {
  const canonical = await realpath(trusted.executable).catch(() => "");
  if (canonical !== trusted.executable) throw new Error(`${trusted.name} changed after it was selected.`);
  const info = await lstat(trusted.executable).catch(() => undefined);
  if (!info || !info.isFile() || info.isSymbolicLink()
    || !identitiesMatch(trusted.identity, trustedFileSystemIdentity(info))) {
    throw new Error(`${trusted.name} changed after it was selected.`);
  }
  for (const directory of trusted.directories) {
    const directoryCanonical = await realpath(directory.path).catch(() => "");
    const directoryInfo = await lstat(directory.path).catch(() => undefined);
    if (directoryCanonical !== directory.path || !directoryInfo
      || !directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()
      || !identitiesMatch(directory.identity, trustedFileSystemIdentity(directoryInfo))) {
      throw new Error(`${trusted.name} directory chain changed after it was selected.`);
    }
  }
  if (process.platform !== "win32") await access(trusted.executable, fsConstants.X_OK);
}

export function trustedNpmCandidatePaths(
  nodeExecutable: string,
  platform: NodeJS.Platform = process.platform
): string[] {
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

export function npmInvocationFromPinnedCli(
  nodeExecutable: string,
  npmCliPath: string,
  args: string[]
): CommandInvocation {
  if (!path.isAbsolute(nodeExecutable) || !path.isAbsolute(npmCliPath)
    || /[\0\r\n]/u.test(nodeExecutable) || /[\0\r\n]/u.test(npmCliPath)
    || args.some((argument) => typeof argument !== "string")) {
    throw new Error("The pinned npm invocation is invalid.");
  }
  return { command: nodeExecutable, args: [npmCliPath, ...args] };
}

/** Resolve npm only beside the Node.js installation running BrowseWeave. */
export async function trustedNpmInvocation(args: string[]): Promise<CommandInvocation> {
  const nodeExecutable = await realpath(process.execPath);
  const nodeInfo = await lstat(nodeExecutable);
  if (!nodeInfo.isFile() || nodeInfo.isSymbolicLink()) {
    throw new Error("The current Node.js executable is unsafe.");
  }

  for (const candidate of trustedNpmCandidatePaths(nodeExecutable)) {
    try {
      const npmCliPath = await realpath(candidate);
      const cliInfo = await lstat(npmCliPath);
      if (!cliInfo.isFile() || cliInfo.isSymbolicLink()) continue;
      if (process.platform !== "win32" && cliInfo.uid !== nodeInfo.uid) continue;
      const packageRoot = path.resolve(path.dirname(npmCliPath), "..");
      if (await realpath(path.join(packageRoot, "bin", "npm-cli.js")) !== npmCliPath) continue;
      const metadataPath = path.join(packageRoot, "package.json");
      const metadataInfo = await lstat(metadataPath);
      if (!metadataInfo.isFile() || metadataInfo.isSymbolicLink()) continue;
      const metadata = JSON.parse(await readFile(metadataPath, "utf8")) as Record<string, unknown>;
      if (metadata.name !== "npm" || typeof metadata.version !== "string"
        || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(metadata.version)) continue;
      return npmInvocationFromPinnedCli(nodeExecutable, npmCliPath, args);
    } catch {
      // Try only the next location derived from this Node.js installation.
    }
  }
  throw new Error("npm was not found in the trusted installation that supplied Node.js.");
}
