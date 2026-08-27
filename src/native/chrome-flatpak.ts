import { createHash } from "node:crypto";
import path from "node:path";
import { NATIVE_SETUP_HOST_NAME } from "./setup-protocol.js";

/** The Flatpak application ID of Google Chrome. */
export const CHROME_FLATPAK_APP_ID = "com.google.Chrome" as const;

/**
 * Chrome's Flatpak sandbox remaps its own XDG directories under ~/.var/app,
 * and the app permissions do not include the user home. Every artifact the
 * sandboxed browser must read therefore lives under this application root.
 */
export function chromeFlatpakAppRoot(home: string): string {
  return path.posix.join(home, ".var", "app", CHROME_FLATPAK_APP_ID);
}

/** The sandbox-visible Chrome user-data directory that holds every profile. */
export function chromeFlatpakUserDataPath(home: string): string {
  return path.posix.join(chromeFlatpakAppRoot(home), "config", "google-chrome");
}

/** The sandbox-visible parent of the managed BrowseWeave extension copy. */
export function chromeFlatpakExtensionParentPath(home: string): string {
  return path.posix.join(chromeFlatpakAppRoot(home), "browseweave");
}

/** The per-user native-messaging manifest location Chrome reads inside its sandbox. */
export function chromeFlatpakManifestPath(home: string): string {
  return path.posix.join(
    chromeFlatpakUserDataPath(home),
    "NativeMessagingHosts",
    `${NATIVE_SETUP_HOST_NAME}.json`
  );
}

/** The sandbox-side wrapper that forwards the native host to the host side. */
export function chromeFlatpakWrapperPath(home: string): string {
  return path.posix.join(
    chromeFlatpakExtensionParentPath(home),
    "browseweave-native-host-chrome-flatpak"
  );
}

const CHROME_FLATPAK_SPAWN_HASH_LABEL = "BrowseWeave-Flatpak-Spawn-SHA256: " as const;
const MAX_MANAGED_WRAPPER_BYTES = 32 * 1024;

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function flatpakSpawnWrapperBody(hostLauncherPath: string): string {
  return `exec flatpak-spawn --host '${hostLauncherPath.replaceAll("'", "'\"'\"'")}' "$@"\n`;
}

/**
 * The wrapper executes the real per-user launcher on the host through
 * flatpak-spawn, so the sandbox never needs a copy of Node or the bridge.
 */
export function managedChromeFlatpakWrapperContent(hostLauncherPath: string): string {
  const body = flatpakSpawnWrapperBody(hostLauncherPath);
  return `#!/bin/sh\n# Managed by BrowseWeave. Do not edit while managed.\n# ${CHROME_FLATPAK_SPAWN_HASH_LABEL}${sha256(body)}\n${body}`;
}

function hasCanonicalFlatpakSpawnBody(body: string, hostLauncherPath: string): boolean {
  if (!body.startsWith("exec flatpak-spawn --host '") || !body.endsWith(`' "$@"\n`)) return false;
  const quoted = body.slice("exec flatpak-spawn --host '".length, -`' "$@"\n`.length);
  const decoded = quoted.replaceAll("'\"'\"'", "'");
  return decoded === hostLauncherPath && !decoded.includes("\n");
}

/**
 * Recognize an intact sandbox wrapper from this generator. The SHA-256 marker
 * is an integrity guard, matching the host-side managed launcher discipline.
 */
export function isManagedChromeFlatpakWrapper(content: string, hostLauncherPath: string): boolean {
  if (typeof content !== "string" || Buffer.byteLength(content, "utf8") > MAX_MANAGED_WRAPPER_BYTES) {
    return false;
  }
  const prefix = `#!/bin/sh\n# Managed by BrowseWeave. Do not edit while managed.\n# ${CHROME_FLATPAK_SPAWN_HASH_LABEL}`;
  if (!content.startsWith(prefix)) return false;
  const digestEnd = content.indexOf("\n", prefix.length);
  if (digestEnd < 0) return false;
  const digest = content.slice(prefix.length, digestEnd);
  const body = content.slice(digestEnd + 1);
  return /^[a-f0-9]{64}$/u.test(digest) &&
    sha256(body) === digest &&
    hasCanonicalFlatpakSpawnBody(body, hostLauncherPath);
}

export interface ChromeFlatpakSessionBusPolicy {
  /** True when the sandbox may talk to the host Flatpak session bus name. */
  readonly spawnHostGranted: boolean;
}

/**
 * Parse the `[Session Bus Policy]` section printed by `flatpak override --show`
 * or `flatpak info --show-metadata`. Both use the same `name=talk` line format.
 */
export function chromeFlatpakSessionBusPolicy(text: string): ChromeFlatpakSessionBusPolicy {
  let inSessionBusPolicy = false;
  let spawnHostGranted = false;
  for (const rawLine of text.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.startsWith("[") && line.endsWith("]")) {
      inSessionBusPolicy = line === "[Session Bus Policy]";
      continue;
    }
    if (!inSessionBusPolicy || spawnHostGranted) continue;
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    const name = line.slice(0, separator).trim();
    const access = line.slice(separator + 1).trim();
    if (name === "org.freedesktop.Flatpak" && (access === "talk" || access === "own")) {
      spawnHostGranted = true;
    }
  }
  return { spawnHostGranted };
}

/** The one-time command the owner must run to grant the sandbox spawn access. */
export const CHROME_FLATPAK_SPAWN_GRANT_COMMAND =
  `flatpak override --user --talk-name=org.freedesktop.Flatpak ${CHROME_FLATPAK_APP_ID}` as const;
