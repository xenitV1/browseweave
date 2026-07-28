import { cp, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { discoverLocalChromiumExtensionOrigins } from "../src/chromium-extension-discovery.js";
import { APP_VERSION, BROWSER_EXTENSION_VERSION } from "../src/version.js";

const roots: string[] = [];
const FIRST_ID = "abcdefghijklmnopabcdefghijklmnop";
const SECOND_ID = "ponmlkjihgfedcbaponmlkjihgfedcba";

function managedExtensionPath(home: string): string {
  if (process.platform === "linux") {
    return path.join(home, ".local", "share", "browseweave", "extension", "chromium-mv3");
  }
  if (process.platform === "darwin") {
    return path.join(
      home,
      "Library",
      "Application Support",
      "BrowseWeave",
      "extension",
      "chromium-mv3"
    );
  }
  if (process.platform === "win32") {
    return path.join(home, "AppData", "Local", "BrowseWeave", "extension", "chromium-mv3");
  }
  throw new Error(`Unsupported test operating system: ${process.platform}`);
}

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(roots.splice(0).map(async (root) => await rm(root, { recursive: true, force: true })));
});

async function fixture(): Promise<{
  root: string;
  home: string;
  chrome: string;
  expected: string;
}> {
  const root = await mkdtemp(path.join(tmpdir(), "browseweave-chrome-discovery-"));
  roots.push(root);
  const home = path.join(root, "home");
  const chrome = path.join(home, ".config", "google-chrome");
  const expected = path.join(root, "expected");
  await mkdir(expected, { recursive: true, mode: 0o700 });
  await writeFile(path.join(expected, "manifest.json"), JSON.stringify({
    manifest_version: 3,
    name: "BrowseWeave",
    version: BROWSER_EXTENSION_VERSION,
    version_name: APP_VERSION,
    permissions: ["nativeMessaging"]
  }), { mode: 0o600 });
  await writeFile(path.join(expected, "background.js"), "export {};\n", { mode: 0o600 });
  return { root, home, chrome, expected };
}

async function addProfile(input: {
  chrome: string;
  expected: string;
  profile: string;
  id: string;
  disabled?: boolean;
  mutate?: boolean;
  unpackedPath?: string;
}): Promise<void> {
  const unpacked = input.unpackedPath ?? path.join(input.chrome, input.profile, "UnpackedExtensions", input.id);
  await mkdir(path.dirname(unpacked), { recursive: true, mode: 0o700 });
  await cp(input.expected, unpacked, { recursive: true });
  if (input.mutate) await writeFile(path.join(unpacked, "background.js"), "modified\n", { mode: 0o600 });
  await mkdir(path.join(input.chrome, input.profile), { recursive: true, mode: 0o700 });
  await writeFile(path.join(input.chrome, input.profile, "Preferences"), JSON.stringify({
    extensions: {
      settings: {
        [input.id]: {
          location: 4,
          from_webstore: false,
          disable_reasons: input.disabled ? [1] : [],
          path: unpacked
        }
      }
    }
  }), { mode: 0o600 });
}

describe("local Chrome extension discovery", () => {
  it("accepts one enabled byte-exact unpacked BrowseWeave copy", async () => {
    const value = await fixture();
    await addProfile({ ...value, profile: "Default", id: FIRST_ID });
    await expect(discoverLocalChromiumExtensionOrigins({
      platform: process.platform,
      home: value.home,
      chromeUserData: value.chrome,
      expectedExtensionPath: value.expected
    })).resolves.toEqual([`chrome-extension://${FIRST_ID}/`]);
  });

  it("accepts the exact managed per-user extension path used by first-time setup", async () => {
    const value = await fixture();
    const managed = managedExtensionPath(value.home);
    await addProfile({
      ...value,
      profile: "Default",
      id: FIRST_ID,
      unpackedPath: managed
    });
    await expect(discoverLocalChromiumExtensionOrigins({
      platform: process.platform,
      home: value.home,
      chromeUserData: value.chrome,
      expectedExtensionPath: value.expected
    })).resolves.toEqual([`chrome-extension://${FIRST_ID}/`]);
  });

  it("ignores an exact copy loaded from an unrelated directory", async () => {
    const value = await fixture();
    await addProfile({
      ...value,
      profile: "Default",
      id: FIRST_ID,
      unpackedPath: path.join(value.home, "Downloads", "BrowseWeave")
    });
    await expect(discoverLocalChromiumExtensionOrigins({
      platform: process.platform,
      home: value.home,
      chromeUserData: value.chrome,
      expectedExtensionPath: value.expected
    })).resolves.toEqual([]);
  });

  it("ignores disabled or modified unpacked copies", async () => {
    const disabled = await fixture();
    await addProfile({ ...disabled, profile: "Default", id: FIRST_ID, disabled: true });
    await expect(discoverLocalChromiumExtensionOrigins({
      platform: process.platform,
      home: disabled.home,
      chromeUserData: disabled.chrome,
      expectedExtensionPath: disabled.expected
    })).resolves.toEqual([]);

    const modified = await fixture();
    await addProfile({ ...modified, profile: "Default", id: FIRST_ID, mutate: true });
    await expect(discoverLocalChromiumExtensionOrigins({
      platform: process.platform,
      home: modified.home,
      chromeUserData: modified.chrome,
      expectedExtensionPath: modified.expected
    })).resolves.toEqual([]);
  });

  it("fails closed when two verified local identities exist", async () => {
    const value = await fixture();
    await addProfile({ ...value, profile: "Default", id: FIRST_ID });
    await addProfile({ ...value, profile: "Profile 1", id: SECOND_ID });
    await expect(discoverLocalChromiumExtensionOrigins({
      platform: process.platform,
      home: value.home,
      chromeUserData: value.chrome,
      expectedExtensionPath: value.expected
    })).rejects.toThrow("More than one verified local BrowseWeave Chrome identity");
  });
});
