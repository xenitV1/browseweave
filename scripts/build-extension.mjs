import { copyFile, lstat, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { browserExtensionVersion, parseReleaseVersion } from "./version-helpers.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.resolve(scriptDirectory, "..");
const extensionDirectory = path.join(projectDirectory, "extension");
const sourceDirectory = path.join(extensionDirectory, "src");
const manifestsDirectory = path.join(extensionDirectory, "manifests");
const outputRoot = path.join(extensionDirectory, "dist");
const thirdPartyNoticeName = "THIRD_PARTY_NOTICES.md";
const thirdPartyNoticeSource = path.join(projectDirectory, thirdPartyNoticeName);
const projectLicenseName = "LICENSE";
const projectLicenseSource = path.join(projectDirectory, projectLicenseName);
const thirdPartyBanner = [
  "/*! BrowseWeave third-party notices: THIRD_PARTY_NOTICES.md.",
  " * Bundles webextension-polyfill 0.12.0 under MPL-2.0.",
  " * Source: https://github.com/mozilla/webextension-polyfill/tree/0.12.0",
  " */"
].join("\n");

const allowedRootEntries = new Map([
  ["PRIVACY.md", "file"],
  ["dist", "directory"],
  ["icons", "directory"],
  ["manifests", "directory"],
  ["options.html", "file"],
  ["popup.html", "file"],
  ["src", "directory"],
  ["styles", "directory"],
  ["tsconfig.json", "file"]
]);
const requiredRootEntries = new Set([...allowedRootEntries.keys()].filter((name) => name !== "dist"));
const staticFiles = [
  "PRIVACY.md",
  "options.html",
  "popup.html",
  "styles/ui.css",
  "icons/icon-16.png",
  "icons/icon-32.png",
  "icons/icon-48.png",
  "icons/icon-96.png",
  "icons/icon-128.png"
];

const packageJson = JSON.parse(await readFile(path.join(projectDirectory, "package.json"), "utf8"));
parseReleaseVersion(packageJson.version);
const manifestVersion = browserExtensionVersion(packageJson.version);

const targetDefinitions = [
  {
    name: "firefox-mv2",
    esbuildTarget: ["firefox142"],
    manifest: path.join(manifestsDirectory, "firefox-mv2.json")
  },
  {
    name: "chromium-mv3",
    esbuildTarget: ["chrome116"],
    manifest: path.join(manifestsDirectory, "chromium-mv3.json")
  }
];

const entryNames = ["background", "content", "popup", "options"];

function polyfillEntryPlugin() {
  return {
    name: "browseweave-webextension-polyfill",
    setup(context) {
      context.onResolve({ filter: /^browseweave-entry:/ }, (args) => ({
        path: args.path.slice("browseweave-entry:".length),
        namespace: "browseweave-entry"
      }));
      context.onLoad({ filter: /.*/, namespace: "browseweave-entry" }, (args) => ({
        contents: [
          'import "webextension-polyfill";',
          `import ${JSON.stringify(path.join(sourceDirectory, `${args.path}.ts`))};`
        ].join("\n"),
        loader: "js",
        resolveDir: projectDirectory
      }));
    }
  };
}

async function validateExtensionRoot() {
  const entries = await readdir(extensionDirectory, { withFileTypes: true });
  const names = new Set(entries.map((entry) => entry.name));
  for (const entry of entries) {
    const expectedType = allowedRootEntries.get(entry.name);
    if (!expectedType) {
      throw new Error(`Unexpected extension root entry: ${entry.name}`);
    }
    if ((expectedType === "file" && !entry.isFile())
      || (expectedType === "directory" && !entry.isDirectory())
      || entry.isSymbolicLink()) {
      throw new Error(`Extension root entry has an unexpected type: ${entry.name}`);
    }
  }
  for (const required of requiredRootEntries) {
    if (!names.has(required)) throw new Error(`Required extension root entry is missing: ${required}`);
  }
}

async function copyStaticFiles(destination) {
  for (const relativePath of staticFiles) {
    const source = path.join(extensionDirectory, relativePath);
    const metadata = await lstat(source);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`Extension static input must be a regular file: ${relativePath}`);
    }
    const target = path.join(destination, relativePath);
    await mkdir(path.dirname(target), { recursive: true });
    await copyFile(source, target);
  }
  const noticeMetadata = await lstat(thirdPartyNoticeSource);
  if (!noticeMetadata.isFile() || noticeMetadata.isSymbolicLink()) {
    throw new Error(`${thirdPartyNoticeName} must be a regular project file.`);
  }
  await copyFile(thirdPartyNoticeSource, path.join(destination, thirdPartyNoticeName));
  const licenseMetadata = await lstat(projectLicenseSource);
  if (!licenseMetadata.isFile() || licenseMetadata.isSymbolicLink()) {
    throw new Error(`${projectLicenseName} must be a regular project file.`);
  }
  await copyFile(projectLicenseSource, path.join(destination, projectLicenseName));
}

await validateExtensionRoot();
await rm(outputRoot, { recursive: true, force: true });
await mkdir(outputRoot, { recursive: true });

for (const target of targetDefinitions) {
  const outputDirectory = path.join(outputRoot, target.name);
  await mkdir(outputDirectory, { recursive: true });

  await build({
    entryPoints: Object.fromEntries(entryNames.map((name) => [name, `browseweave-entry:${name}`])),
    outdir: outputDirectory,
    bundle: true,
    platform: "browser",
    format: "iife",
    target: target.esbuildTarget,
    sourcemap: false,
    minify: false,
    banner: { js: thirdPartyBanner },
    logLevel: "info",
    plugins: [polyfillEntryPlugin()]
  });

  await copyStaticFiles(outputDirectory);
  const manifest = JSON.parse(await readFile(target.manifest, "utf8"));
  manifest.version = manifestVersion;
  manifest.version_name = packageJson.version;
  await writeFile(
    path.join(outputDirectory, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    { encoding: "utf8", mode: 0o644 }
  );
}

console.error(`BrowseWeave extension builds ready: ${targetDefinitions.map(({ name }) => name).join(", ")}`);
