import { constants as fsConstants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { userInfo } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  createNativeHostRegistrationPlan,
  type NativeHostRegistrationPlan
} from "./native-host-plan.js";
import type { NativeCallerPolicy } from "./native-setup-protocol.js";

/** Must match browser_specific_settings.gecko.id in every Firefox/Zen build. */
export const FIREFOX_EXTENSION_ID = "browseweave@local.invalid" as const;

/**
 * Filled only after the Chrome Web Store allocates BrowseWeave's permanent ID.
 * Native Chrome registration stays disabled until then because wildcards are forbidden.
 */
export const CHROMIUM_EXTENSION_ORIGIN: string | undefined = undefined;

function safeAccountHome(platform: NodeJS.Platform): string {
  const accountHome = userInfo().homedir;
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  if (!pathApi.isAbsolute(accountHome) || /[\0\r\n]/u.test(accountHome)) {
    throw new Error("The operating system did not provide a safe user home directory.");
  }
  return pathApi.normalize(accountHome);
}

export function currentNativeHostRegistrationPlan(
  platform: NodeJS.Platform = process.platform,
  chromiumExtensionOrigins: readonly string[] | undefined = CHROMIUM_EXTENSION_ORIGIN
    ? [CHROMIUM_EXTENSION_ORIGIN]
    : undefined
): NativeHostRegistrationPlan {
  const accountHome = safeAccountHome(platform);
  const common = {
    platform,
    home: accountHome,
    firefoxExtensionIds: [FIREFOX_EXTENSION_ID],
    ...(chromiumExtensionOrigins && chromiumExtensionOrigins.length > 0
      ? { chromiumExtensionOrigins }
      : {})
  };
  if (platform === "win32") {
    const executable = process.execPath;
    if (path.win32.basename(executable).toLowerCase() !== "browseweave-native-host.exe") {
      throw new Error("The Windows BrowseWeave native host executable is not installed.");
    }
    return createNativeHostRegistrationPlan({
      ...common,
      windowsHostExecutablePath: executable,
      localAppData: path.win32.join(accountHome, "AppData", "Local")
    });
  }
  return createNativeHostRegistrationPlan({
    ...common,
    nodePath: process.execPath,
    nativeHostScriptPath: fileURLToPath(new URL("./native-host.js", import.meta.url))
  });
}

async function assertExactOwnedManifest(input: {
  path: string;
  content: string;
}): Promise<void> {
  const info = await lstat(input.path);
  if (!info.isFile() || info.isSymbolicLink() || info.size < 2 || info.size > 64 * 1024) {
    throw new Error("The installed native host manifest is unsafe.");
  }
  if (process.platform !== "win32" && typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error("The installed native host manifest has the wrong owner.");
  }
  if (process.platform !== "win32" && (info.mode & 0o077) !== 0) {
    throw new Error("The installed native host manifest permissions are too broad.");
  }
  const handle = await open(input.path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino || opened.size !== info.size ||
      await handle.readFile("utf8") !== input.content
    ) throw new Error("The installed native host manifest does not match this BrowseWeave runtime.");
  } finally {
    await handle.close();
  }
}

export function nativeCallerPolicy(
  argv: readonly string[],
  plan: NativeHostRegistrationPlan = currentNativeHostRegistrationPlan()
): NativeCallerPolicy {
  const first = argv[0] ?? "";
  if (first.startsWith("chrome-extension://")) {
    const chrome = plan.manifests.find((manifest) => manifest.browser === "chrome");
    if (!chrome || !("allowed_origins" in chrome.manifest)) {
      throw new Error("This BrowseWeave build has no authorized Chrome extension identity.");
    }
    return {
      browser_family: "chromium",
      allowed_origins: chrome.manifest.allowed_origins
    };
  }
  const firefox = plan.manifests.find((manifest) => manifest.browser === "firefox" && manifest.path === first);
  if (!firefox || !("allowed_extensions" in firefox.manifest)) {
    throw new Error("The Firefox native host manifest path is not authorized.");
  }
  return {
    browser_family: "firefox",
    manifest_path: firefox.path,
    allowed_extension_ids: firefox.manifest.allowed_extensions
  };
}

/**
 * Chrome development identities are authorized only when the per-user
 * installer created the byte-exact manifest for that exact caller origin.
 * Production builds use the same path with the permanent Web Store origin.
 */
export async function nativeCallerPolicyFromInstalledRegistration(
  argv: readonly string[]
): Promise<NativeCallerPolicy> {
  const first = argv[0] ?? "";
  if (!first.startsWith("chrome-extension://")) return nativeCallerPolicy(argv);
  if (!/^chrome-extension:\/\/[a-p]{32}\/$/u.test(first)) {
    throw new Error("The Chrome extension origin is invalid.");
  }
  const plan = currentNativeHostRegistrationPlan(process.platform, [first]);
  const chrome = plan.manifests.find((manifest) => manifest.browser === "chrome");
  if (!chrome) throw new Error("The Chrome native host registration is unavailable.");
  await assertExactOwnedManifest(chrome);
  return nativeCallerPolicy(argv, plan);
}
