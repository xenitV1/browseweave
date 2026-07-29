import { constants as fsConstants } from "node:fs";
import { lstat, open, readdir, readFile } from "node:fs/promises";
import { userInfo } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extensionTreeDigest, managedExtensionParentPath } from "./flow.js";
import { APP_VERSION, BROWSER_EXTENSION_VERSION } from "../core/version.js";

const CHROMIUM_EXTENSION_ID_PATTERN = /^[a-p]{32}$/u;
const MAX_PREFERENCES_BYTES = 32 * 1024 * 1024;

export interface ChromiumExtensionDiscoveryInput {
  readonly platform?: NodeJS.Platform;
  readonly home?: string;
  readonly chromeUserData?: string;
  readonly expectedExtensionPath?: string;
}

function chromeUserDataPath(platform: NodeJS.Platform, home: string): string {
  if (platform === "linux") return path.posix.join(home, ".config", "google-chrome");
  if (platform === "darwin") {
    return path.posix.join(home, "Library", "Application Support", "Google", "Chrome");
  }
  if (platform === "win32") {
    return path.win32.join(home, "AppData", "Local", "Google", "Chrome", "User Data");
  }
  throw new Error(`Unsupported operating system: ${platform}`);
}

function managedChromiumExtensionPath(platform: NodeJS.Platform, home: string): string {
  const pathApi = pathApiFor(platform);
  return pathApi.join(managedExtensionParentPath(home, platform), "chromium-mv3");
}

function pathApiFor(platform: NodeJS.Platform): typeof path.posix | typeof path.win32 {
  return platform === "win32" ? path.win32 : path.posix;
}

function isInside(root: string, candidate: string, pathApi: typeof path.posix | typeof path.win32): boolean {
  const relative = pathApi.relative(root, candidate);
  return relative !== "" && !relative.startsWith("..") && !pathApi.isAbsolute(relative);
}

async function readOwnerSafeJson(filePath: string, platform: NodeJS.Platform): Promise<unknown> {
  const info = await lstat(filePath);
  if (!info.isFile() || info.isSymbolicLink() || info.size < 2 || info.size > MAX_PREFERENCES_BYTES) {
    throw new Error("A Chrome profile Preferences file is unsafe.");
  }
  if (platform !== "win32" && typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error("A Chrome profile Preferences file has the wrong owner.");
  }
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino || opened.size !== info.size
    ) throw new Error("A Chrome profile Preferences file changed while it was inspected.");
    return JSON.parse(await handle.readFile("utf8")) as unknown;
  } finally {
    await handle.close();
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function extensionSettings(value: unknown): Record<string, unknown> {
  if (!isRecord(value) || !isRecord(value.extensions) || !isRecord(value.extensions.settings)) return {};
  return value.extensions.settings;
}

async function verifiedUnpackedCandidate(input: {
  readonly id: string;
  readonly value: unknown;
  readonly chromeUserData: string;
  readonly managedExtensionPath: string;
  readonly expectedDigest: string;
  readonly platform: NodeJS.Platform;
}): Promise<string | undefined> {
  if (!CHROMIUM_EXTENSION_ID_PATTERN.test(input.id) || !isRecord(input.value)) return undefined;
  const value = input.value;
  if (
    value.location !== 4 || value.from_webstore !== false ||
    !Array.isArray(value.disable_reasons) || value.disable_reasons.length !== 0 ||
    typeof value.path !== "string" || /[\0\r\n]/u.test(value.path)
  ) return undefined;

  const pathApi = pathApiFor(input.platform);
  const normalizedCandidate = pathApi.normalize(value.path);
  if (
    !pathApi.isAbsolute(value.path) || normalizedCandidate !== value.path ||
    (
      !isInside(input.chromeUserData, normalizedCandidate, pathApi) &&
      normalizedCandidate !== input.managedExtensionPath
    )
  ) return undefined;
  const directoryInfo = await lstat(value.path);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) return undefined;
  if (
    input.platform !== "win32" && typeof process.getuid === "function" &&
    directoryInfo.uid !== process.getuid()
  ) return undefined;

  const manifestValue = JSON.parse(await readFile(pathApi.join(value.path, "manifest.json"), "utf8")) as unknown;
  if (
    !isRecord(manifestValue) || manifestValue.name !== "BrowseWeave" ||
    manifestValue.version !== BROWSER_EXTENSION_VERSION || manifestValue.version_name !== APP_VERSION ||
    manifestValue.manifest_version !== 3 ||
    !Array.isArray(manifestValue.permissions) || !manifestValue.permissions.includes("nativeMessaging")
  ) return undefined;
  if (await extensionTreeDigest(value.path) !== input.expectedDigest) return undefined;
  return `chrome-extension://${input.id}/`;
}

/**
 * Discover only an enabled unpacked Chrome copy that is byte-for-byte equal to
 * the packaged BrowseWeave build. Store releases use their compiled permanent
 * origin instead and never depend on profile inspection.
 */
export async function discoverLocalChromiumExtensionOrigins(
  input: ChromiumExtensionDiscoveryInput = {}
): Promise<readonly string[]> {
  const platform = input.platform ?? process.platform;
  const pathApi = pathApiFor(platform);
  const home = pathApi.normalize(input.home ?? userInfo().homedir);
  if (!pathApi.isAbsolute(home) || /[\0\r\n]/u.test(home)) {
    throw new Error("The operating system did not provide a safe user home directory.");
  }
  const chromeUserData = pathApi.normalize(input.chromeUserData ?? chromeUserDataPath(platform, home));
  const expectedExtensionPath = pathApi.normalize(
    input.expectedExtensionPath ?? fileURLToPath(new URL("../../../extension/dist/chromium-mv3/", import.meta.url))
  );
  const managedExtensionPath = pathApi.normalize(managedChromiumExtensionPath(platform, home));
  if (
    !pathApi.isAbsolute(chromeUserData) || !isInside(home, chromeUserData, pathApi) ||
    !pathApi.isAbsolute(expectedExtensionPath) || !pathApi.isAbsolute(managedExtensionPath) ||
    !isInside(home, managedExtensionPath, pathApi)
  ) throw new Error("Chrome extension discovery received an unsafe path.");

  let profiles;
  try {
    profiles = await readdir(chromeUserData, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const expectedDigest = await extensionTreeDigest(expectedExtensionPath);
  const origins = new Set<string>();
  for (const profile of profiles) {
    if (!profile.isDirectory() || (profile.name !== "Default" && !/^Profile \d+$/u.test(profile.name))) continue;
    let preferences: unknown;
    try {
      preferences = await readOwnerSafeJson(pathApi.join(chromeUserData, profile.name, "Preferences"), platform);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    for (const [id, value] of Object.entries(extensionSettings(preferences))) {
      const origin = await verifiedUnpackedCandidate({
        id,
        value,
        chromeUserData,
        managedExtensionPath,
        expectedDigest,
        platform
      });
      if (origin) origins.add(origin);
    }
  }
  if (origins.size > 1) {
    throw new Error("More than one verified local BrowseWeave Chrome identity was found. Remove old copies, then run Repair again.");
  }
  return Object.freeze([...origins]);
}
