import { createWriteStream } from "node:fs";
import { access, lstat, mkdir, readFile, readdir, rename, rm } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";
import yazl from "yazl";
import { parseReleaseVersion } from "./version-helpers.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const scriptDirectory = path.dirname(scriptPath);
export const projectDirectory = path.resolve(scriptDirectory, "..");
const reproducibleTimestamp = new Date(1980, 0, 1, 0, 0, 0, 0);
const expectedArchiveFiles = new Set([
  "LICENSE",
  "PRIVACY.md",
  "THIRD_PARTY_NOTICES.md",
  "background.js",
  "content.js",
  "icons/icon-16.png",
  "icons/icon-32.png",
  "icons/icon-48.png",
  "icons/icon-96.png",
  "icons/icon-128.png",
  "manifest.json",
  "options.html",
  "options.js",
  "popup.html",
  "popup.js",
  "styles/ui.css"
]);
const contentRules = [
  { label: "npm authentication setting", pattern: /\/\/(?:registry\.)?npmjs\.org\/:_authToken\s*=/iu },
  { label: "npm access token", pattern: /\bnpm_[a-z0-9]{20,}\b/iu },
  { label: "GitHub personal access token", pattern: /\b(?:ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,})\b/iu },
  { label: "OpenAI-style secret key", pattern: /\bsk-[a-z0-9_-]{20,}\b/iu },
  { label: "private key material", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u },
  { label: "personal Linux home path", pattern: /\/home\/[a-z0-9._-]+\//iu },
  { label: "personal macOS home path", pattern: /\/Users\/[a-z0-9._ -]+\//iu },
  { label: "personal Windows home path", pattern: /[a-z]:\\Users\\[^\\\r\n]+\\/iu },
  { label: "legacy BrowseWeave product name", pattern: /(?:\bzen[\s_-]+codex(?:[\s_-]+bridge)?\b|\bzen-browser-mcp\b|zen-codex-bridge\.service)/iu }
];

async function archiveFiles(directory, relativeDirectory = "") {
  const entries = await readdir(path.join(directory, relativeDirectory), { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`Refusing to package symbolic link: ${relativePath}`);
    }
    if (entry.isDirectory()) {
      files.push(...await archiveFiles(directory, relativePath));
    } else if (entry.isFile()) {
      files.push(relativePath);
    } else {
      throw new Error(`Refusing to package unsupported filesystem entry: ${relativePath}`);
    }
  }
  return files;
}

async function inspectArchiveInputs(sourceDirectory) {
  const files = await archiveFiles(sourceDirectory);
  const normalizedFiles = files.map((relativePath) => relativePath.split(path.sep).join("/"));
  const fileSet = new Set(normalizedFiles);

  if (files.length !== fileSet.size) throw new Error("Extension archive contains duplicate paths.");
  for (const expected of expectedArchiveFiles) {
    if (!fileSet.has(expected)) throw new Error(`Extension archive input is missing: ${expected}`);
  }
  for (const relativePath of normalizedFiles) {
    if (!expectedArchiveFiles.has(relativePath)) {
      throw new Error(`Unexpected extension archive input: ${relativePath}`);
    }
    if (/(?:^|\/)(?:src|manifests|notes?)(?:\/|$)|(?:\.map|\.ts|\.tsx)$|(?:^|\/)tsconfig(?:\.[^/]*)?\.json$/iu.test(relativePath)) {
      throw new Error(`Source, build metadata, or notes entered the extension archive: ${relativePath}`);
    }
    if (relativePath.endsWith(".png")) continue;
    const contents = await readFile(path.join(sourceDirectory, ...relativePath.split("/")), "utf8");
    for (const rule of contentRules) {
      if (rule.pattern.test(contents)) {
        throw new Error(`${rule.label} detected in extension archive input: ${relativePath}`);
      }
    }
  }

  return files;
}

export async function packageVersion() {
  const packageJson = JSON.parse(await readFile(path.join(projectDirectory, "package.json"), "utf8"));
  parseReleaseVersion(packageJson.version);
  return packageJson.version;
}

export async function createExtensionArchive(sourceDirectory, target) {
  await access(path.join(sourceDirectory, "manifest.json"));
  await mkdir(path.dirname(target), { recursive: true });
  const temporaryTarget = `${target}.${process.pid}.tmp`;
  await rm(temporaryTarget, { force: true });

  const zipFile = new yazl.ZipFile();
  for (const relativePath of await inspectArchiveInputs(sourceDirectory)) {
    const absolutePath = path.join(sourceDirectory, relativePath);
    const metadata = await lstat(absolutePath);
    if (!metadata.isFile()) throw new Error(`Refusing to package non-file entry: ${relativePath}`);
    zipFile.addFile(absolutePath, relativePath.split(path.sep).join("/"), {
      mtime: reproducibleTimestamp,
      mode: 0o100644,
      compress: true,
      forceDosTimestamp: true
    });
  }

  const writing = pipeline(zipFile.outputStream, createWriteStream(temporaryTarget, { mode: 0o600 }));
  zipFile.end();
  try {
    await writing;
    await rm(target, { force: true });
    await rename(temporaryTarget, target);
  } catch (error) {
    await rm(temporaryTarget, { force: true });
    throw error;
  }
}

async function main() {
  const version = await packageVersion();
  const sourceDirectory = path.join(projectDirectory, "extension", "dist", "firefox-mv2");
  const target = path.join(projectDirectory, "web-ext-artifacts", `browseweave-${version}-firefox-mv2.xpi`);
  await createExtensionArchive(sourceDirectory, target);
  console.error(`BrowseWeave Firefox XPI ready: ${target}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === scriptPath) await main();
