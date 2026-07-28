import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { browserExtensionVersion, parseReleaseVersion } from "./version-helpers.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const defaultProjectDirectory = path.resolve(path.dirname(scriptPath), "..");

export async function assertAppVersion(projectDirectory = defaultProjectDirectory) {
  const packageJson = JSON.parse(await readFile(path.join(projectDirectory, "package.json"), "utf8"));
  parseReleaseVersion(packageJson.version);

  const compiledVersionPath = path.join(projectDirectory, "dist", "src", "version.js");
  const compiledVersion = await import(pathToFileURL(compiledVersionPath).href);
  if (compiledVersion.APP_VERSION !== packageJson.version) {
    throw new Error(
      `Version mismatch: src/version.ts exports ${JSON.stringify(compiledVersion.APP_VERSION)}, `
      + `but package.json declares ${JSON.stringify(packageJson.version)}.`
    );
  }
  const expectedBrowserVersion = browserExtensionVersion(packageJson.version);
  if (compiledVersion.BROWSER_EXTENSION_VERSION !== expectedBrowserVersion) {
    throw new Error(
      `Browser version mismatch: src/version.ts exports ${JSON.stringify(compiledVersion.BROWSER_EXTENSION_VERSION)}, `
      + `but ${JSON.stringify(packageJson.version)} maps to ${JSON.stringify(expectedBrowserVersion)}.`
    );
  }
  return packageJson.version;
}

if (process.argv[1] && path.resolve(process.argv[1]) === scriptPath) {
  const version = await assertAppVersion();
  process.stderr.write(`BrowseWeave version check passed: ${version}.\n`);
}
