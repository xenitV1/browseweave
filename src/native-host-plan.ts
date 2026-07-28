import { createHash } from "node:crypto";
import path from "node:path";
import { NATIVE_SETUP_HOST_NAME } from "./native-setup-protocol.js";

export const NATIVE_HOST_DESCRIPTION = "BrowseWeave secure local setup bridge" as const;
export const NATIVE_HOST_LAUNCHER_MARKER =
  "Managed by BrowseWeave. Do not edit while managed." as const;

const NATIVE_HOST_LAUNCHER_HASH_LABEL = "BrowseWeave-Launcher-SHA256: " as const;
const NATIVE_HOST_LAUNCHER_NAME = "browseweave-native-host" as const;
const NATIVE_HOST_SCRIPT_NAME = "native-host.js" as const;
const POSIX_SINGLE_QUOTE_ESCAPE = "'\"'\"'" as const;
const MAX_MANAGED_LAUNCHER_BYTES = 32 * 1024;

export type NativeHostPlanPlatform = "linux" | "darwin" | "win32";
export type NativeHostBrowser = "firefox" | "chrome";
export type NativeHostArtifactState = "absent" | "exact" | "owned" | "foreign";

export interface FirefoxNativeHostManifest {
  readonly name: typeof NATIVE_SETUP_HOST_NAME;
  readonly description: typeof NATIVE_HOST_DESCRIPTION;
  readonly path: string;
  readonly type: "stdio";
  readonly allowed_extensions: readonly string[];
}

export interface ChromeNativeHostManifest {
  readonly name: typeof NATIVE_SETUP_HOST_NAME;
  readonly description: typeof NATIVE_HOST_DESCRIPTION;
  readonly path: string;
  readonly type: "stdio";
  readonly allowed_origins: readonly string[];
}

export type NativeHostManifest = FirefoxNativeHostManifest | ChromeNativeHostManifest;

export interface NativeHostManifestPlan {
  readonly browser: NativeHostBrowser;
  readonly path: string;
  readonly content: string;
  /** POSIX installers should create manifests as owner-readable files. */
  readonly mode?: 0o600;
  readonly manifest: NativeHostManifest;
}

export interface NativeHostLauncherPlan {
  readonly path: string;
  readonly content: string;
  readonly mode: 0o700;
  readonly nodePath: string;
  readonly nativeHostScriptPath: string;
}

/** A per-user default-value registration. No machine-wide registry write is planned. */
export interface WindowsNativeHostRegistrySpec {
  readonly hive: "HKEY_CURRENT_USER";
  readonly keyPath: string;
  readonly valueName: "";
  readonly valueType: "REG_SZ";
  readonly valueData: string;
}

export interface NativeHostRegistrationPlan {
  readonly platform: NativeHostPlanPlatform;
  readonly hostName: typeof NATIVE_SETUP_HOST_NAME;
  /** POSIX launcher path or the supplied fixed Windows executable path. */
  readonly hostExecutablePath: string;
  readonly launcher?: NativeHostLauncherPlan;
  readonly manifests: readonly NativeHostManifestPlan[];
  readonly windowsRegistry: readonly WindowsNativeHostRegistrySpec[];
}

export interface NativeHostRegistrationPlanInput {
  readonly platform: NodeJS.Platform;
  readonly home: string;
  /** Required on Linux/macOS. It is embedded as a safely quoted absolute path. */
  readonly nodePath?: string;
  /** Required on Linux/macOS and must name the built native-host.js entrypoint. */
  readonly nativeHostScriptPath?: string;
  /** Required on Windows. Script and command-wrapper hosts are deliberately rejected. */
  readonly windowsHostExecutablePath?: string;
  /** Defaults to <home>\AppData\Local on Windows. */
  readonly localAppData?: string;
  readonly firefoxExtensionIds: readonly string[];
  /** Omit to leave Google Chrome unregistered. An empty array is invalid. */
  readonly chromiumExtensionOrigins?: readonly string[];
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hasControlCharacter(value: string): boolean {
  return /[\0-\x1f\x7f]/u.test(value);
}

function assertCanonicalPosixPath(value: unknown, label: string, allowRoot = false): asserts value is string {
  if (
    typeof value !== "string" ||
    !path.posix.isAbsolute(value) ||
    hasControlCharacter(value) ||
    path.posix.normalize(value) !== value ||
    (!allowRoot && value === "/")
  ) {
    throw new Error(`${label} must be a canonical absolute POSIX path without control characters.`);
  }
}

function assertCanonicalWindowsPath(value: unknown, label: string): asserts value is string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z]:\\/u.test(value) ||
    !path.win32.isAbsolute(value) ||
    hasControlCharacter(value) ||
    path.win32.normalize(value) !== value ||
    /^(?:\\\\[.?]\\|\\\\)/u.test(value) ||
    /^[A-Za-z]:\\$/u.test(value)
  ) {
    throw new Error(
      `${label} must be a canonical absolute local-drive Windows path without control characters.`
    );
  }
}

function validFirefoxExtensionId(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 128 || hasControlCharacter(value)) return false;
  return /^(?:\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}|[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9.-]*)$/u.test(value);
}

function validChromiumExtensionOrigin(value: unknown): value is string {
  return typeof value === "string" && /^chrome-extension:\/\/[a-p]{32}\/$/u.test(value);
}

function exactSortedAllowlist(
  values: readonly string[],
  label: string,
  validator: (value: unknown) => value is string
): readonly string[] {
  if (!Array.isArray(values) || values.length < 1 || values.length > 8) {
    throw new Error(`${label} must contain between 1 and 8 exact entries.`);
  }
  const unique = new Set<string>();
  for (const value of values) {
    if (!validator(value) || value.includes("*")) {
      throw new Error(`${label} contains an invalid or wildcard entry.`);
    }
    if (unique.has(value)) throw new Error(`${label} contains a duplicate entry.`);
    unique.add(value);
  }
  return Object.freeze([...unique].sort((left, right) => left < right ? -1 : left > right ? 1 : 0));
}

/** Quote one pathname as a single POSIX shell word without permitting expansion. */
export function quotePosixNativeHostPath(value: string): string {
  assertCanonicalPosixPath(value, "Native host path");
  return `'${value.replaceAll("'", POSIX_SINGLE_QUOTE_ESCAPE)}'`;
}

function launcherBody(nodePath: string, nativeHostScriptPath: string): string {
  return `exec ${quotePosixNativeHostPath(nodePath)} ${quotePosixNativeHostPath(nativeHostScriptPath)} "$@"\n`;
}

function managedLauncherContent(nodePath: string, nativeHostScriptPath: string): string {
  const body = launcherBody(nodePath, nativeHostScriptPath);
  return `#!/bin/sh\n# ${NATIVE_HOST_LAUNCHER_MARKER}\n# ${NATIVE_HOST_LAUNCHER_HASH_LABEL}${sha256(body)}\n${body}`;
}

interface ParsedShellWord {
  readonly value: string;
  readonly next: number;
}

/** Decode only the single-quote form emitted by quotePosixNativeHostPath. */
function parseManagedShellWord(line: string, start: number): ParsedShellWord | undefined {
  if (line[start] !== "'") return undefined;
  let cursor = start + 1;
  let value = "";
  while (cursor < line.length) {
    if (line.startsWith(POSIX_SINGLE_QUOTE_ESCAPE, cursor)) {
      value += "'";
      cursor += POSIX_SINGLE_QUOTE_ESCAPE.length;
      continue;
    }
    const character = line[cursor];
    if (character === "'") return { value, next: cursor + 1 };
    if (character === undefined) return undefined;
    value += character;
    cursor += 1;
  }
  return undefined;
}

function hasCanonicalLauncherBody(body: string): boolean {
  if (!body.startsWith("exec ") || !body.endsWith("\n") || body.slice(0, -1).includes("\n")) return false;
  const line = body.slice(0, -1);
  const node = parseManagedShellWord(line, "exec ".length);
  if (!node || line[node.next] !== " ") return false;
  const script = parseManagedShellWord(line, node.next + 1);
  if (!script || line.slice(script.next) !== ' "$@"') return false;
  try {
    assertCanonicalPosixPath(node.value, "Managed Node executable");
    assertCanonicalPosixPath(script.value, "Managed native host script");
  } catch {
    return false;
  }
  return path.posix.basename(script.value) === NATIVE_HOST_SCRIPT_NAME;
}

/**
 * Recognize an intact launcher from this generator. The SHA-256 marker is an
 * integrity/upgrade guard, not a substitute for filesystem ownership checks.
 */
export function isManagedNativeHostLauncher(content: string): boolean {
  if (typeof content !== "string" || Buffer.byteLength(content, "utf8") > MAX_MANAGED_LAUNCHER_BYTES) {
    return false;
  }
  const prefix = `#!/bin/sh\n# ${NATIVE_HOST_LAUNCHER_MARKER}\n# ${NATIVE_HOST_LAUNCHER_HASH_LABEL}`;
  if (!content.startsWith(prefix)) return false;
  const digestEnd = content.indexOf("\n", prefix.length);
  if (digestEnd < 0) return false;
  const digest = content.slice(prefix.length, digestEnd);
  const body = content.slice(digestEnd + 1);
  return /^[a-f0-9]{64}$/u.test(digest) && sha256(body) === digest && hasCanonicalLauncherBody(body);
}

function serializeManifest(manifest: NativeHostManifest): string {
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

function createManifestPlan(
  browser: NativeHostBrowser,
  manifestPath: string,
  executablePath: string,
  allowlist: readonly string[],
  platform: NativeHostPlanPlatform
): NativeHostManifestPlan {
  const manifest: NativeHostManifest = browser === "firefox"
    ? Object.freeze({
        name: NATIVE_SETUP_HOST_NAME,
        description: NATIVE_HOST_DESCRIPTION,
        path: executablePath,
        type: "stdio" as const,
        allowed_extensions: allowlist
      })
    : Object.freeze({
        name: NATIVE_SETUP_HOST_NAME,
        description: NATIVE_HOST_DESCRIPTION,
        path: executablePath,
        type: "stdio" as const,
        allowed_origins: allowlist
      });
  return Object.freeze({
    browser,
    path: manifestPath,
    content: serializeManifest(manifest),
    ...(platform === "win32" ? {} : { mode: 0o600 as const }),
    manifest
  });
}

function windowsRegistrySpec(
  browser: NativeHostBrowser,
  manifestPath: string
): WindowsNativeHostRegistrySpec {
  const vendor = browser === "firefox" ? "Mozilla" : "Google\\Chrome";
  return Object.freeze({
    hive: "HKEY_CURRENT_USER" as const,
    keyPath: `Software\\${vendor}\\NativeMessagingHosts\\${NATIVE_SETUP_HOST_NAME}`,
    valueName: "" as const,
    valueType: "REG_SZ" as const,
    valueData: manifestPath
  });
}

function posixPlan(
  input: NativeHostRegistrationPlanInput,
  platform: "linux" | "darwin",
  firefoxIds: readonly string[],
  chromeOrigins: readonly string[] | undefined
): NativeHostRegistrationPlan {
  assertCanonicalPosixPath(input.home, "User home", true);
  assertCanonicalPosixPath(input.nodePath, "Node executable");
  assertCanonicalPosixPath(input.nativeHostScriptPath, "Native host script");
  if (path.posix.basename(input.nativeHostScriptPath) !== NATIVE_HOST_SCRIPT_NAME) {
    throw new Error(`Native host script must be the built ${NATIVE_HOST_SCRIPT_NAME} entrypoint.`);
  }
  if (input.windowsHostExecutablePath !== undefined || input.localAppData !== undefined) {
    throw new Error("Windows-only native host paths cannot be used on a POSIX plan.");
  }

  const launcherPath = platform === "linux"
    ? path.posix.join(input.home, ".local", "share", "browseweave", "native-host", NATIVE_HOST_LAUNCHER_NAME)
    : path.posix.join(
        input.home,
        "Library",
        "Application Support",
        "BrowseWeave",
        "NativeMessaging",
        NATIVE_HOST_LAUNCHER_NAME
      );
  const launcher: NativeHostLauncherPlan = Object.freeze({
    path: launcherPath,
    content: managedLauncherContent(input.nodePath, input.nativeHostScriptPath),
    mode: 0o700 as const,
    nodePath: input.nodePath,
    nativeHostScriptPath: input.nativeHostScriptPath
  });
  const firefoxManifestPath = platform === "linux"
    ? path.posix.join(input.home, ".mozilla", "native-messaging-hosts", `${NATIVE_SETUP_HOST_NAME}.json`)
    : path.posix.join(
        input.home,
        "Library",
        "Application Support",
        "Mozilla",
        "NativeMessagingHosts",
        `${NATIVE_SETUP_HOST_NAME}.json`
      );
  const manifests: NativeHostManifestPlan[] = [
    createManifestPlan("firefox", firefoxManifestPath, launcherPath, firefoxIds, platform)
  ];
  if (chromeOrigins) {
    const chromeManifestPath = platform === "linux"
      ? path.posix.join(
          input.home,
          ".config",
          "google-chrome",
          "NativeMessagingHosts",
          `${NATIVE_SETUP_HOST_NAME}.json`
        )
      : path.posix.join(
          input.home,
          "Library",
          "Application Support",
          "Google",
          "Chrome",
          "NativeMessagingHosts",
          `${NATIVE_SETUP_HOST_NAME}.json`
        );
    manifests.push(createManifestPlan("chrome", chromeManifestPath, launcherPath, chromeOrigins, platform));
  }
  return Object.freeze({
    platform,
    hostName: NATIVE_SETUP_HOST_NAME,
    hostExecutablePath: launcherPath,
    launcher,
    manifests: Object.freeze(manifests),
    windowsRegistry: Object.freeze([])
  });
}

function windowsPlan(
  input: NativeHostRegistrationPlanInput,
  firefoxIds: readonly string[],
  chromeOrigins: readonly string[] | undefined
): NativeHostRegistrationPlan {
  assertCanonicalWindowsPath(input.home, "User home");
  if (input.nodePath !== undefined || input.nativeHostScriptPath !== undefined) {
    throw new Error("Windows native messaging requires the fixed executable host, not Node or a script wrapper.");
  }
  assertCanonicalWindowsPath(input.windowsHostExecutablePath, "Windows native host executable");
  if (!/\.exe$/iu.test(input.windowsHostExecutablePath)) {
    throw new Error("Windows native host must be supplied as a fixed absolute .exe executable.");
  }
  const localAppData = input.localAppData ?? path.win32.join(input.home, "AppData", "Local");
  assertCanonicalWindowsPath(localAppData, "Local application data directory");

  const base = path.win32.join(localAppData, "BrowseWeave", "NativeMessagingHosts");
  const firefoxManifestPath = path.win32.join(
    base,
    "Firefox",
    `${NATIVE_SETUP_HOST_NAME}.json`
  );
  const manifests: NativeHostManifestPlan[] = [
    createManifestPlan(
      "firefox",
      firefoxManifestPath,
      input.windowsHostExecutablePath,
      firefoxIds,
      "win32"
    )
  ];
  const registry: WindowsNativeHostRegistrySpec[] = [
    windowsRegistrySpec("firefox", firefoxManifestPath)
  ];
  if (chromeOrigins) {
    const chromeManifestPath = path.win32.join(
      base,
      "Chrome",
      `${NATIVE_SETUP_HOST_NAME}.json`
    );
    manifests.push(createManifestPlan(
      "chrome",
      chromeManifestPath,
      input.windowsHostExecutablePath,
      chromeOrigins,
      "win32"
    ));
    registry.push(windowsRegistrySpec("chrome", chromeManifestPath));
  }
  return Object.freeze({
    platform: "win32" as const,
    hostName: NATIVE_SETUP_HOST_NAME,
    hostExecutablePath: input.windowsHostExecutablePath,
    manifests: Object.freeze(manifests),
    windowsRegistry: Object.freeze(registry)
  });
}

/** Build a deterministic, per-user native-messaging registration plan. */
export function createNativeHostRegistrationPlan(
  input: NativeHostRegistrationPlanInput
): NativeHostRegistrationPlan {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Native host registration input must be an object.");
  }
  const firefoxIds = exactSortedAllowlist(
    input.firefoxExtensionIds,
    "Firefox extension IDs",
    validFirefoxExtensionId
  );
  const chromeOrigins = input.chromiumExtensionOrigins === undefined
    ? undefined
    : exactSortedAllowlist(
        input.chromiumExtensionOrigins,
        "Chrome extension origins",
        validChromiumExtensionOrigin
      );

  if (input.platform === "linux" || input.platform === "darwin") {
    return posixPlan(input, input.platform, firefoxIds, chromeOrigins);
  }
  if (input.platform === "win32") return windowsPlan(input, firefoxIds, chromeOrigins);
  throw new Error(`Native messaging registration is not supported on platform ${input.platform}.`);
}

export function nativeHostLauncherState(
  expected: NativeHostLauncherPlan,
  content: string | undefined
): NativeHostArtifactState {
  if (content === undefined) return "absent";
  if (content === expected.content) return "exact";
  return isManagedNativeHostLauncher(content) ? "owned" : "foreign";
}

/** Native manifests have no ownership marker: only byte-exact expected content is trusted. */
export function nativeHostManifestState(
  expected: NativeHostManifestPlan,
  content: string | undefined
): Exclude<NativeHostArtifactState, "owned"> {
  if (content === undefined) return "absent";
  return content === expected.content ? "exact" : "foreign";
}

/** Windows registration is trusted only when every default-value field matches exactly. */
export function windowsNativeHostRegistryState(
  expected: WindowsNativeHostRegistrySpec,
  observed: WindowsNativeHostRegistrySpec | undefined
): Exclude<NativeHostArtifactState, "owned"> {
  if (observed === undefined) return "absent";
  return observed.hive === expected.hive &&
    observed.keyPath === expected.keyPath &&
    observed.valueName === expected.valueName &&
    observed.valueType === expected.valueType &&
    observed.valueData === expected.valueData
    ? "exact"
    : "foreign";
}
