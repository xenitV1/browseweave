import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { gunzipSync } from "node:zlib";
import { browserExtensionVersion } from "./version-helpers.mjs";

const MAX_ARCHIVE_BYTES = 5 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 5 * 1024 * 1024;
const MAX_FILES = 200;

const requiredFiles = new Set([
  "LICENSE",
  "README.md",
  "CHANGELOG.md",
  "SUPPORT.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "SKILL.md",
  "PRIVACY.md",
  "SECURITY.md",
  "THIRD_PARTY_NOTICES.md",
  "package.json",
  "assets/brand/browseweave-logo.png",
  "assets/brand/browseweave-mark.png",
  "extension/PRIVACY.md",
  "dist/src/browser-environment.js",
  "dist/src/chromium-extension-discovery.js",
  "dist/src/cli.js",
  "dist/src/client-config.js",
  "dist/src/config.js",
  "dist/src/daemon.js",
  "dist/src/ipc-client.js",
  "dist/src/mcp.js",
  "dist/src/mcp.d.ts",
  "dist/src/native-bootstrap.js",
  "dist/src/native-host-config.js",
  "dist/src/native-host-install.js",
  "dist/src/native-host-plan.js",
  "dist/src/native-host.js",
  "dist/src/native-service.js",
  "dist/src/native-setup-protocol.js",
  "dist/src/npm-invocation.js",
  "dist/src/protocol.js",
  "dist/src/purge-data.js",
  "dist/src/purge-data.d.ts",
  "dist/src/service-install-guard.js",
  "dist/src/service-plan.js",
  "dist/src/setup-flow.js",
  "dist/src/setup-status.js",
  "dist/src/version.js",
  "dist/src/zen-flatpak.js",
  "extension/dist/firefox-mv2/manifest.json",
  "extension/dist/firefox-mv2/background.js",
  "extension/dist/firefox-mv2/content.js",
  "extension/dist/firefox-mv2/options.html",
  "extension/dist/firefox-mv2/options.js",
  "extension/dist/firefox-mv2/popup.html",
  "extension/dist/firefox-mv2/popup.js",
  "extension/dist/firefox-mv2/icons/icon-16.png",
  "extension/dist/firefox-mv2/icons/icon-32.png",
  "extension/dist/firefox-mv2/icons/icon-48.png",
  "extension/dist/firefox-mv2/icons/icon-96.png",
  "extension/dist/firefox-mv2/icons/icon-128.png",
  "extension/dist/firefox-mv2/styles/ui.css",
  "extension/dist/firefox-mv2/PRIVACY.md",
  "extension/dist/firefox-mv2/THIRD_PARTY_NOTICES.md",
  "extension/dist/firefox-mv2/LICENSE",
  "extension/dist/chromium-mv3/manifest.json",
  "extension/dist/chromium-mv3/background.js",
  "extension/dist/chromium-mv3/content.js",
  "extension/dist/chromium-mv3/options.html",
  "extension/dist/chromium-mv3/options.js",
  "extension/dist/chromium-mv3/popup.html",
  "extension/dist/chromium-mv3/popup.js",
  "extension/dist/chromium-mv3/icons/icon-16.png",
  "extension/dist/chromium-mv3/icons/icon-32.png",
  "extension/dist/chromium-mv3/icons/icon-48.png",
  "extension/dist/chromium-mv3/icons/icon-96.png",
  "extension/dist/chromium-mv3/icons/icon-128.png",
  "extension/dist/chromium-mv3/styles/ui.css",
  "extension/dist/chromium-mv3/PRIVACY.md",
  "extension/dist/chromium-mv3/THIRD_PARTY_NOTICES.md",
  "extension/dist/chromium-mv3/LICENSE"
]);

const contentRules = [
  ["npm authentication setting", /\/\/(?:registry\.)?npmjs\.org\/:_authToken\s*=/iu],
  ["npm access token", /\bnpm_[a-z0-9]{20,}\b/iu],
  ["GitHub access token", /\b(?:ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,})\b/iu],
  ["OpenAI-style secret key", /\bsk-[a-z0-9_-]{20,}\b/iu],
  ["private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u],
  ["dangling source map directive", /[#@]\s*sourceMappingURL=/u],
  ["personal home path", /(?:\/home\/[a-z0-9._-]+\/|\/Users\/[a-z0-9._ -]+\/|[a-z]:\\Users\\[^\\\r\n]+\\)/iu],
  ["legacy product path", /(?:Projeler\/zen-codex-bridge|zen-codex-bridge\.service|web-ext-artifacts\/zen-codex-bridge)/iu]
];

function fail(message) {
  throw new Error(`Release archive refused: ${message}`);
}

const expectedBins = {
  browseweave: "dist/src/cli.js",
  "browseweave-mcp": "dist/src/mcp.js",
  "browseweave-daemon": "dist/src/daemon.js",
  "browseweave-native-host": "dist/src/native-host.js"
};

const expectedExtensionPermissions = {
  "firefox-mv2": ["<all_urls>", "tabs", "webNavigation", "storage", "nativeMessaging"],
  "chromium-mv3": ["tabs", "webNavigation", "storage", "scripting", "nativeMessaging"]
};

export function assertReleasePackageManifest(manifest, version) {
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)
    || manifest.name !== "browseweave" || manifest.version !== version || Object.hasOwn(manifest, "private")) {
    fail("package identity is invalid");
  }
  if (manifest.license !== "MIT"
    || manifest.repository?.url !== "git+https://github.com/xenitV1/browseweave.git"
    || manifest.homepage !== "https://github.com/xenitV1/browseweave#readme") {
    fail("package provenance metadata is invalid");
  }
  if (JSON.stringify(manifest.bin) !== JSON.stringify(expectedBins)) {
    fail("package executable metadata is invalid");
  }
}

export function assertNativeMessagingExtensionManifest(manifest, target, releaseVersion) {
  const expected = expectedExtensionPermissions[target];
  if (!expected || !manifest || typeof manifest !== "object" || Array.isArray(manifest)
    || !Array.isArray(manifest.permissions)
    || new Set(manifest.permissions).size !== manifest.permissions.length
    || manifest.permissions.length !== expected.length
    || !expected.every((permission) => manifest.permissions.includes(permission))) {
    fail(`${target} native messaging permission set is incomplete or unexpected`);
  }
  if (manifest.version !== browserExtensionVersion(releaseVersion) || manifest.version_name !== releaseVersion) {
    fail(`${target} extension version does not match browseweave@${releaseVersion}`);
  }
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function allowedPath(file) {
  if ([
    "LICENSE", "README.md", "CHANGELOG.md", "SUPPORT.md", "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md", "PRIVACY.md", "SECURITY.md", "SKILL.md", "THIRD_PARTY_NOTICES.md",
    "package.json"
  ].includes(file)) return true;
  if (file === "extension/PRIVACY.md") return true;
  if (/^extension\/dist\/(?:firefox-mv2|chromium-mv3)\/LICENSE$/u.test(file)) return true;
  if (/^assets\/brand\/browseweave-(?:logo|mark)\.png$/u.test(file)) return true;
  if (/^dist\/src\/[a-z0-9-]+\.(?:js|d\.ts)$/u.test(file)) return true;
  return /^extension\/dist\/(?:firefox-mv2|chromium-mv3)\/(?:[a-z0-9_-]+\/)*[a-z0-9_.-]+\.(?:js|json|html|css|png|md)$/iu.test(file);
}

function readString(header, start, length) {
  const field = header.subarray(start, start + length);
  const nul = field.indexOf(0);
  return field.subarray(0, nul < 0 ? field.length : nul).toString("utf8");
}

function readOctal(header, start, length, label) {
  const value = readString(header, start, length).trim();
  if (!/^[0-7]+$/u.test(value)) fail(`invalid tar ${label}`);
  return Number.parseInt(value, 8);
}

export function parseNpmTarball(compressed) {
  if (!Buffer.isBuffer(compressed) || compressed.length === 0 || compressed.length > MAX_ARCHIVE_BYTES) {
    fail("compressed size is invalid");
  }
  let tar;
  try {
    tar = gunzipSync(compressed, { maxOutputLength: MAX_UNPACKED_BYTES + 1024 });
  } catch {
    fail("gzip stream is invalid or exceeds the unpacked budget");
  }
  if (tar.length > MAX_UNPACKED_BYTES || tar.length % 512 !== 0) fail("tar stream size is invalid");

  const files = new Map();
  let totalSize = 0;
  let offset = 0;
  let foundEnd = false;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (!tar.subarray(offset).every((byte) => byte === 0)) fail("non-zero data follows the tar terminator");
      foundEnd = true;
      break;
    }
    const expectedChecksum = readOctal(header, 148, 8, "checksum");
    let actualChecksum = 0;
    for (let index = 0; index < 512; index += 1) {
      actualChecksum += index >= 148 && index < 156 ? 32 : header[index];
    }
    if (actualChecksum !== expectedChecksum) fail("tar header checksum mismatch");
    const prefix = readString(header, 345, 155);
    const shortName = readString(header, 0, 100);
    const entryName = prefix ? `${prefix}/${shortName}` : shortName;
    const type = header[156];
    if (type !== 0 && type !== 48) fail(`non-regular tar entry: ${entryName}`);
    if (readString(header, 157, 100) !== "") fail(`tar link target is forbidden: ${entryName}`);
    if (!entryName.startsWith("package/") || entryName.includes("\\") || entryName.includes("//")) {
      fail("unsafe tar path");
    }
    const relative = entryName.slice("package/".length);
    const parts = relative.split("/");
    if (!relative || parts.some((part) => part === "" || part === "." || part === "..")) {
      fail("unsafe tar path component");
    }
    if (files.has(relative)) fail(`duplicate tar path: ${relative}`);
    const size = readOctal(header, 124, 12, "size");
    if (!Number.isSafeInteger(size) || size < 0 || size > MAX_UNPACKED_BYTES) fail(`invalid tar size: ${relative}`);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    if (dataEnd > tar.length) fail(`truncated tar entry: ${relative}`);
    files.set(relative, Buffer.from(tar.subarray(dataStart, dataEnd)));
    totalSize += size;
    if (totalSize > MAX_UNPACKED_BYTES || files.size > MAX_FILES) fail("unpacked package budget exceeded");
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  if (!foundEnd || files.size === 0) fail("tar terminator or files are missing");
  return files;
}

export async function snapshotReleaseInputs(projectDirectory, filePaths) {
  if (!Array.isArray(filePaths) || filePaths.length === 0 || new Set(filePaths).size !== filePaths.length) {
    fail("release input list is empty or contains duplicates");
  }
  const snapshot = new Map();
  for (const file of filePaths) {
    if (typeof file !== "string" || !allowedPath(file) || path.isAbsolute(file)) fail(`unsafe snapshot path: ${file}`);
    const absolute = path.resolve(projectDirectory, file);
    if (!absolute.startsWith(`${path.resolve(projectDirectory)}${path.sep}`)) fail(`unsafe snapshot path: ${file}`);
    const info = await lstat(absolute);
    if (!info.isFile() || info.isSymbolicLink()) fail(`snapshot input is not a regular file: ${file}`);
    const contents = await readFile(absolute);
    snapshot.set(file, { size: contents.length, sha256: sha256(contents) });
  }
  return snapshot;
}

export function assertArchiveMatchesSnapshot(files, snapshot) {
  if (!(files instanceof Map) || !(snapshot instanceof Map) || files.size !== snapshot.size) {
    fail("archive and verified input file counts differ");
  }
  for (const [file, expected] of snapshot) {
    const contents = files.get(file);
    if (!Buffer.isBuffer(contents)) fail(`verified input is missing from archive: ${file}`);
    if (contents.length !== expected.size || sha256(contents) !== expected.sha256) {
      fail(`archive content differs from the verified input: ${file}`);
    }
  }
}

export async function inspectReleaseArchive({ archivePath, version, snapshot }) {
  const info = await lstat(archivePath);
  if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_ARCHIVE_BYTES) fail("tarball is not a safe regular file");
  const compressed = await readFile(archivePath);
  const files = parseNpmTarball(compressed);

  for (const file of files.keys()) {
    if (!allowedPath(file)) fail(`unexpected package path: ${file}`);
    if (/(?:^|\/)(?:\.npmrc|\.env(?:\.|$)|package-lock\.json$)/u.test(file)) fail(`forbidden package path: ${file}`);
    if (/(?:^|\/)setup-ticket\.json$/u.test(file)) fail(`short-lived setup ticket entered package: ${file}`);
    if (/(?:\.map|\.ts|\.tsx)$/u.test(file) && !file.endsWith(".d.ts")) fail(`source file entered package: ${file}`);
  }
  for (const file of requiredFiles) if (!files.has(file)) fail(`required package file is missing: ${file}`);

  for (const [file, contents] of files) {
    if (file.endsWith(".png")) continue;
    const text = contents.toString("utf8");
    for (const [label, pattern] of contentRules) if (pattern.test(text)) fail(`${label} detected in ${file}`);
  }

  const manifest = JSON.parse(files.get("package.json").toString("utf8"));
  assertReleasePackageManifest(manifest, version);
  const nativeHost = files.get("dist/src/native-host.js").toString("utf8");
  if (!nativeHost.startsWith("#!/usr/bin/env node\n")) fail("native host executable is missing its Node.js launcher line");
  for (const target of ["firefox-mv2", "chromium-mv3"]) {
    const extensionManifest = JSON.parse(files.get(`extension/dist/${target}/manifest.json`).toString("utf8"));
    assertNativeMessagingExtensionManifest(extensionManifest, target, version);
    const notice = files.get(`extension/dist/${target}/THIRD_PARTY_NOTICES.md`).toString("utf8");
    const background = files.get(`extension/dist/${target}/background.js`).toString("utf8");
    if (!notice.includes("webextension-polyfill") || !notice.includes("0.12.0")
      || !notice.includes("https://github.com/mozilla/webextension-polyfill/tree/0.12.0")) {
      fail(`${target} MPL corresponding-source notice is invalid`);
    }
    if (!background.startsWith("/*! BrowseWeave third-party notices: THIRD_PARTY_NOTICES.md.")) {
      fail(`${target} bundle notice banner is missing`);
    }
    if (!files.get(`extension/dist/${target}/LICENSE`).equals(files.get("LICENSE"))) {
      fail(`${target} bundled MIT license differs from the package license`);
    }
  }
  if (snapshot) assertArchiveMatchesSnapshot(files, snapshot);
  return { sha256: sha256(compressed), files: files.size, size: compressed.length };
}

export async function assertArchiveUnchanged(archivePath, expectedSha256) {
  const info = await lstat(archivePath);
  if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_ARCHIVE_BYTES) fail("verified tarball was replaced");
  const actual = sha256(await readFile(archivePath));
  if (actual !== expectedSha256) fail("verified tarball changed after verification");
}
