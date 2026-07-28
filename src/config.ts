import {
  constants as fsConstants,
  type FileHandle,
  chmod,
  lstat,
  mkdir,
  open,
  readFile
} from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import path from "node:path";

export const APP_ID = "browseweave" as const;
export const LEGACY_APP_ID = "zen-codex-bridge" as const;
export const DEFAULT_WS_HOST = "127.0.0.1" as const;
export const DEFAULT_WS_PORT = 32_110;
export const DEFAULT_IPC_HOST = "127.0.0.1" as const;
export const DEFAULT_IPC_PORT = 32_111;
export const HELLO_TIMEOUT_MS = 10_000;
export const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;
export const MAX_COMMAND_TIMEOUT_MS = 60_000;
export const APPROVAL_TTL_MS = 5 * 60_000;
export const MAX_COMMAND_PAYLOAD_BYTES = 512 * 1024;
export const MAX_WS_PAYLOAD_BYTES = 16 * 1024 * 1024;
export const MAX_IPC_MESSAGE_BYTES = 24 * 1024 * 1024;
export const MAX_PENDING_COMMANDS = 128;
export const MAX_PENDING_APPROVALS = 128;

export interface RuntimePaths {
  runtimeDir: string;
  configDir: string;
  stateDir: string;
  /** Extension pairing secret retained under the original public CLI path name. */
  tokenPath: string;
  ipcTokenPath: string;
  extensionKeyPath: string;
  auditLogPath: string;
  legacyTokenPath?: string;
}

export interface DaemonConfig extends RuntimePaths {
  wsHost: typeof DEFAULT_WS_HOST;
  wsPort: number;
  ipcHost: typeof DEFAULT_IPC_HOST;
  ipcPort: number;
  pairingToken: string;
  ipcToken: string;
  allowedOrigins: readonly string[];
  helloTimeoutMs: number;
  commandTimeoutMs: number;
  approvalTtlMs: number;
  maxCommandPayloadBytes: number;
  maxWsPayloadBytes: number;
  maxIpcMessageBytes: number;
  maxPendingCommands: number;
  maxPendingApprovals: number;
}

type Environment = Readonly<Record<string, string | undefined>>;

function platformPath(platform: NodeJS.Platform): typeof path.posix | typeof path.win32 {
  return platform === "win32" ? path.win32 : path.posix;
}

function absoluteDirectory(
  value: string | undefined,
  label: string,
  platform: NodeJS.Platform,
  fallback: string
): string {
  if (value === undefined || value.length === 0) return fallback;
  if (!platformPath(platform).isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path.`);
  }
  return value;
}

function userHome(env: Environment, platform: NodeJS.Platform): string {
  const candidate = platform === "win32" ? env.USERPROFILE : env.HOME;
  if (candidate && platformPath(platform).isAbsolute(candidate)) return candidate;
  return homedir();
}

/** Resolve per-user paths without assuming Linux/XDG on macOS or Windows. */
export function getRuntimePaths(
  env: Environment = process.env,
  platform: NodeJS.Platform = process.platform
): RuntimePaths {
  const pathApi = platformPath(platform);
  const home = userHome(env, platform);

  if (platform === "win32") {
    const localAppData = absoluteDirectory(
      env.LOCALAPPDATA,
      "LOCALAPPDATA",
      platform,
      pathApi.join(home, "AppData", "Local")
    );
    const root = pathApi.join(localAppData, "BrowseWeave");
    return {
      runtimeDir: pathApi.join(root, "Cache"),
      configDir: pathApi.join(root, "Config"),
      stateDir: pathApi.join(root, "State"),
      tokenPath: pathApi.join(root, "Config", "pairing-token"),
      ipcTokenPath: pathApi.join(root, "Config", "ipc-token"),
      extensionKeyPath: pathApi.join(root, "Config", "extension-public-key.json"),
      auditLogPath: pathApi.join(root, "State", "audit.jsonl")
    };
  }

  if (platform === "darwin") {
    const appSupport = pathApi.join(home, "Library", "Application Support", "BrowseWeave");
    const stateDir = pathApi.join(home, "Library", "Logs", "BrowseWeave");
    return {
      runtimeDir: pathApi.join(home, "Library", "Caches", "BrowseWeave"),
      configDir: appSupport,
      stateDir,
      tokenPath: pathApi.join(appSupport, "pairing-token"),
      ipcTokenPath: pathApi.join(appSupport, "ipc-token"),
      extensionKeyPath: pathApi.join(appSupport, "extension-public-key.json"),
      auditLogPath: pathApi.join(stateDir, "audit.jsonl")
    };
  }

  const configHome = absoluteDirectory(
    env.XDG_CONFIG_HOME,
    "XDG_CONFIG_HOME",
    platform,
    pathApi.join(home, ".config")
  );
  const stateHome = absoluteDirectory(
    env.XDG_STATE_HOME,
    "XDG_STATE_HOME",
    platform,
    pathApi.join(home, ".local", "state")
  );
  let runtimeHome: string;
  if (env.XDG_RUNTIME_DIR) {
    runtimeHome = absoluteDirectory(env.XDG_RUNTIME_DIR, "XDG_RUNTIME_DIR", platform, "");
  } else if (platform === "linux" && typeof process.getuid === "function") {
    runtimeHome = `/run/user/${process.getuid()}`;
  } else {
    runtimeHome = pathApi.join(stateHome, APP_ID, "runtime");
  }
  const configDir = pathApi.join(configHome, APP_ID);
  const stateDir = pathApi.join(stateHome, APP_ID);
  return {
    runtimeDir: pathApi.join(runtimeHome, APP_ID),
    configDir,
    stateDir,
    tokenPath: pathApi.join(configDir, "pairing-token"),
    ipcTokenPath: pathApi.join(configDir, "ipc-token"),
    extensionKeyPath: pathApi.join(configDir, "extension-public-key.json"),
    auditLogPath: pathApi.join(stateDir, "audit.jsonl"),
    legacyTokenPath: pathApi.join(configHome, LEGACY_APP_ID, "pairing-token")
  };
}

export async function ensurePrivateDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`A safe application directory could not be created: ${directory}`);
  }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error(`The application directory is not owned by the current user: ${directory}`);
  }
  if (process.platform !== "win32") await chmod(directory, 0o700);
}

/** Backwards-compatible name retained for older imports. */
export const ensureRuntimeDirectory = ensurePrivateDirectory;

export function validatePairingToken(token: string): string {
  if (token.length < 32 || token.length > 256 || /[\r\n\0]/u.test(token)) {
    throw new Error("The pairing token must contain 32-256 characters and no line breaks.");
  }
  return token;
}

async function securelyCreateFile(filePath: string, contents: string): Promise<boolean> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      filePath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
      0o600
    );
    await handle.writeFile(contents, { encoding: "utf8" });
    await handle.sync();
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw error;
  } finally {
    await handle?.close();
  }
}

async function readSecureToken(tokenPath: string, label = "local authentication secret"): Promise<string> {
  const info = await lstat(tokenPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`The ${label} is not a safe regular file: ${tokenPath}`);
  }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error(`The ${label} is not owned by the current user: ${tokenPath}`);
  }
  if (process.platform !== "win32" && (info.mode & 0o077) !== 0) {
    throw new Error(`The ${label} permissions are unsafe. Restrict the file to its owner: ${tokenPath}`);
  }
  return validatePairingToken((await readFile(tokenPath, "utf8")).trim());
}

export async function getPairingToken(
  paths: RuntimePaths = getRuntimePaths(),
  env: Environment = process.env
): Promise<string> {
  const configured = env.BROWSER_MCP_BRIDGE_TOKEN || env.ZEN_CODEX_BRIDGE_TOKEN;
  if (configured) return validatePairingToken(configured);

  await ensurePrivateDirectory(paths.configDir);
  try {
    return await readSecureToken(paths.tokenPath, "extension pairing secret");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  if (paths.legacyTokenPath && paths.legacyTokenPath !== paths.tokenPath) {
    try {
      const legacyToken = await readSecureToken(paths.legacyTokenPath, "legacy extension pairing secret");
      if (await securelyCreateFile(paths.tokenPath, `${legacyToken}\n`)) return legacyToken;
      return await readSecureToken(paths.tokenPath, "extension pairing secret");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }

  const generated = randomBytes(32).toString("hex");
  if (await securelyCreateFile(paths.tokenPath, `${generated}\n`)) return generated;
  return await readSecureToken(paths.tokenPath, "extension pairing secret");
}

export async function getIpcToken(
  paths: RuntimePaths = getRuntimePaths(),
  env: Environment = process.env
): Promise<string> {
  const configured = env.BROWSER_MCP_BRIDGE_IPC_TOKEN;
  if (configured) return validatePairingToken(configured);

  await ensurePrivateDirectory(paths.configDir);
  try {
    return await readSecureToken(paths.ipcTokenPath, "IPC authentication secret");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  const generated = randomBytes(32).toString("hex");
  if (await securelyCreateFile(paths.ipcTokenPath, `${generated}\n`)) return generated;
  return await readSecureToken(paths.ipcTokenPath, "IPC authentication secret");
}

function parseAllowedOrigins(value: string | undefined): readonly string[] {
  if (value === undefined || value.trim() === "") return [];
  return value.split(",").map((origin) => origin.trim()).filter(Boolean);
}

function parsePort(value: string | undefined, fallback: number, label: string): number {
  if (value === undefined || value.trim() === "") return fallback;
  if (!/^\d{1,5}$/u.test(value)) throw new Error(`${label} must be an integer port.`);
  const port = Number(value);
  if (port < 1 || port > 65_535) throw new Error(`${label} must be between 1 and 65535.`);
  return port;
}

export async function loadDaemonConfig(env: Environment = process.env): Promise<DaemonConfig> {
  const paths = getRuntimePaths(env);
  await ensurePrivateDirectory(paths.runtimeDir);
  await ensurePrivateDirectory(paths.configDir);
  await ensurePrivateDirectory(paths.stateDir);
  const [pairingToken, ipcToken] = await Promise.all([
    getPairingToken(paths, env),
    getIpcToken(paths, env)
  ]);
  return {
    ...paths,
    wsHost: DEFAULT_WS_HOST,
    wsPort: parsePort(env.BROWSER_MCP_BRIDGE_WS_PORT, DEFAULT_WS_PORT, "BROWSER_MCP_BRIDGE_WS_PORT"),
    ipcHost: DEFAULT_IPC_HOST,
    ipcPort: parsePort(env.BROWSER_MCP_BRIDGE_IPC_PORT, DEFAULT_IPC_PORT, "BROWSER_MCP_BRIDGE_IPC_PORT"),
    pairingToken,
    ipcToken,
    allowedOrigins: parseAllowedOrigins(
      env.BROWSER_MCP_BRIDGE_ALLOWED_ORIGINS || env.ZEN_CODEX_BRIDGE_ALLOWED_ORIGINS
    ),
    helloTimeoutMs: HELLO_TIMEOUT_MS,
    commandTimeoutMs: DEFAULT_COMMAND_TIMEOUT_MS,
    approvalTtlMs: APPROVAL_TTL_MS,
    maxCommandPayloadBytes: MAX_COMMAND_PAYLOAD_BYTES,
    maxWsPayloadBytes: MAX_WS_PAYLOAD_BYTES,
    maxIpcMessageBytes: MAX_IPC_MESSAGE_BYTES,
    maxPendingCommands: MAX_PENDING_COMMANDS,
    maxPendingApprovals: MAX_PENDING_APPROVALS
  };
}
