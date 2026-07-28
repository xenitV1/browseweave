import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  assertArchiveMatchesSnapshot,
  assertNativeMessagingExtensionManifest,
  assertReleasePackageManifest,
  parseNpmTarball
} from "../scripts/verify-release-archive.mjs";

const projectDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function writeTarField(header: Buffer, offset: number, length: number, value: string): void {
  header.write(value, offset, Math.min(length, Buffer.byteLength(value)), "utf8");
}

function tarFile(name: string, contents: Buffer): Buffer {
  const header = Buffer.alloc(512);
  writeTarField(header, 0, 100, name);
  writeTarField(header, 100, 8, "0000644\0");
  writeTarField(header, 108, 8, "0000000\0");
  writeTarField(header, 116, 8, "0000000\0");
  writeTarField(header, 124, 12, `${contents.length.toString(8).padStart(11, "0")}\0`);
  writeTarField(header, 136, 12, "00000000000\0");
  header.fill(0x20, 148, 156);
  header[156] = "0".charCodeAt(0);
  writeTarField(header, 257, 6, "ustar\0");
  writeTarField(header, 263, 2, "00");
  let checksum = 0;
  for (const byte of header) checksum += byte;
  writeTarField(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
  const padding = Buffer.alloc((512 - (contents.length % 512)) % 512);
  return Buffer.concat([header, contents, padding]);
}

function archive(name: string, text: string): Buffer {
  return gzipSync(Buffer.concat([
    tarFile(name, Buffer.from(text, "utf8")),
    Buffer.alloc(1024)
  ]));
}

describe("fixed npm release archive verification", () => {
  it("keeps every release gate aligned on critical runtime and extension files", async () => {
    const gateFiles = [
      "scripts/check-npm-pack.mjs",
      "scripts/verify-release-archive.mjs",
      ".github/workflows/publish.yml"
    ];
    const requiredPaths = [
      "README.md",
      "LICENSE",
      "CHANGELOG.md",
      "SUPPORT.md",
      "CODE_OF_CONDUCT.md",
      "CONTRIBUTING.md",
      "dist/src/setup/chromium-extension-discovery.js",
      "dist/src/cli/application.js",
      "dist/src/core/entrypoint.js",
      "dist/src/daemon/runtime.js",
      "dist/src/setup/zen-flatpak.js",
      "dist/src/mcp.d.ts",
      "dist/src/mcp/server.js",
      "dist/src/native/host.js",
      "dist/src/native/purge-data.js",
      "dist/src/native/purge-data.d.ts"
    ];
    const extensionSuffixes = [
      "manifest.json",
      "background.js",
      "content.js",
      "options.html",
      "options.js",
      "popup.html",
      "popup.js",
      "icons/icon-16.png",
      "icons/icon-32.png",
      "icons/icon-48.png",
      "icons/icon-96.png",
      "icons/icon-128.png",
      "styles/ui.css",
      "PRIVACY.md",
      "THIRD_PARTY_NOTICES.md",
      "LICENSE"
    ];
    for (const target of ["firefox-mv2", "chromium-mv3"]) {
      for (const suffix of extensionSuffixes) requiredPaths.push(`extension/dist/${target}/${suffix}`);
    }

    for (const gateFile of gateFiles) {
      const contents = await readFile(path.join(projectDirectory, gateFile), "utf8");
      for (const requiredPath of requiredPaths) {
        expect(contents, `${gateFile} must require ${requiredPath}`).toContain(JSON.stringify(requiredPath));
      }
    }
    const [bootstrap, workflow] = await Promise.all([
      readFile(path.join(projectDirectory, "scripts/bootstrap-publish.mjs"), "utf8"),
      readFile(path.join(projectDirectory, ".github/workflows/publish.yml"), "utf8")
    ]);
    expect(bootstrap).toContain('"--tag", distTag');
    expect(workflow).toContain('dist_tag=${distTag}');
    expect(workflow).toContain('--tag "${{ steps.verify.outputs.dist_tag }}"');
  });

  it("parses a regular package tar entry and binds it to the verified input hash", () => {
    const compressed = archive("package/README.md", "verified\n");
    const files = parseNpmTarball(compressed);
    expect(files.get("README.md")?.toString("utf8")).toBe("verified\n");
    const contents = Buffer.from("verified\n");
    const snapshot = new Map([["README.md", {
      size: contents.length,
      sha256: createHash("sha256").update(contents).digest("hex")
    }]]);
    expect(() => assertArchiveMatchesSnapshot(files, snapshot)).not.toThrow();
    files.set("README.md", Buffer.from("changed\n"));
    expect(() => assertArchiveMatchesSnapshot(files, snapshot)).toThrow(/differs from the verified input/iu);
  });

  it("rejects traversal paths before exposing archive contents", () => {
    expect(() => parseNpmTarball(archive("package/../outside", "bad"))).toThrow(/unsafe tar path component/iu);
  });

  it("requires the native host executable mapping in release metadata", () => {
    const manifest = {
      name: "browseweave",
      version: "0.1.0",
      license: "MIT",
      repository: { url: "git+https://github.com/xenitV1/browseweave.git" },
      homepage: "https://github.com/xenitV1/browseweave#readme",
      bin: {
        browseweave: "dist/src/cli.js",
        "browseweave-mcp": "dist/src/mcp.js",
        "browseweave-daemon": "dist/src/daemon.js",
        "browseweave-native-host": "dist/src/native-host.js"
      }
    };
    expect(() => assertReleasePackageManifest(manifest, "0.1.0")).not.toThrow();
    delete (manifest.bin as Record<string, string>)["browseweave-native-host"];
    expect(() => assertReleasePackageManifest(manifest, "0.1.0")).toThrow(/executable metadata/iu);
  });

  it("requires nativeMessaging and the mapped package version in both browser manifests", () => {
    const releaseVersion = "0.1.0-beta.1";
    const firefox = {
      version: "0.1.0.10002",
      version_name: releaseVersion,
      permissions: ["<all_urls>", "tabs", "webNavigation", "storage", "nativeMessaging"]
    };
    const chromium = {
      version: "0.1.0.10002",
      version_name: releaseVersion,
      permissions: ["tabs", "webNavigation", "storage", "scripting", "nativeMessaging"]
    };
    expect(() => assertNativeMessagingExtensionManifest(firefox, "firefox-mv2", releaseVersion)).not.toThrow();
    expect(() => assertNativeMessagingExtensionManifest(chromium, "chromium-mv3", releaseVersion)).not.toThrow();
    const wrongVersion = { ...firefox, version: "0.1.0.10003" };
    expect(() => assertNativeMessagingExtensionManifest(wrongVersion, "firefox-mv2", releaseVersion))
      .toThrow(/extension version/iu);
    chromium.permissions.pop();
    expect(() => assertNativeMessagingExtensionManifest(chromium, "chromium-mv3", releaseVersion))
      .toThrow(/native messaging/iu);
  });
});
