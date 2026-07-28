import { execFile } from "node:child_process";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { assertAppVersion } from "./check-version.mjs";
import { browserExtensionVersion } from "./version-helpers.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.resolve(scriptDirectory, "..");
const packageJsonPath = path.join(projectDirectory, "package.json");
const packageJson = JSON.parse(await readFile(packageJsonPath, "utf8"));
const expectedBrowserExtensionVersion = browserExtensionVersion(packageJson.version);
const run = promisify(execFile);

const expectedRepository = "git+https://github.com/xenitV1/browseweave.git";
const releaseFlag = process.env.BROWSEWEAVE_RELEASE ?? "";
const trustedReleaseMode = releaseFlag === "1";
const bootstrapReleaseMode = releaseFlag === "bootstrap-local";
const releaseMode = trustedReleaseMode || bootstrapReleaseMode;
const publishIntent = process.argv.includes("--publish");
const expectedBins = {
  browseweave: "dist/src/cli.js",
  "browseweave-mcp": "dist/src/mcp.js",
  "browseweave-daemon": "dist/src/daemon.js",
  "browseweave-native-host": "dist/src/native-host.js"
};
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
  "dist/src/setup/browser-environment.js",
  "dist/src/setup/chromium-extension-discovery.js",
  "dist/src/cli.js",
  "dist/src/cli/application.js",
  "dist/src/clients/client-config.js",
  "dist/src/core/config.js",
  "dist/src/core/entrypoint.js",
  "dist/src/daemon.js",
  "dist/src/daemon/runtime.js",
  "dist/src/bridge/ipc-client.js",
  "dist/src/mcp.js",
  "dist/src/mcp.d.ts",
  "dist/src/mcp/server.js",
  "dist/src/native/bootstrap.js",
  "dist/src/native/host-config.js",
  "dist/src/native/host-install.js",
  "dist/src/native/host-plan.js",
  "dist/src/native-host.js",
  "dist/src/native/host.js",
  "dist/src/native/service.js",
  "dist/src/native/setup-protocol.js",
  "dist/src/clients/npm-invocation.js",
  "dist/src/core/protocol.js",
  "dist/src/native/purge-data.js",
  "dist/src/native/purge-data.d.ts",
  "dist/src/native/service-install-guard.js",
  "dist/src/native/service-plan.js",
  "dist/src/setup/flow.js",
  "dist/src/bridge/setup-status.js",
  "dist/src/core/version.js",
  "dist/src/setup/zen-flatpak.js",
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

function fail(message) {
  throw new Error(`npm pack safety check failed: ${message}`);
}

function assertMetadata() {
  if (packageJson.name !== "browseweave") fail("package name must be browseweave");
  if (publishIntent && !releaseMode) {
    fail("publishing is blocked outside the explicitly gated release workflow");
  }
  if (releaseFlag !== "" && !releaseMode) {
    fail("BROWSEWEAVE_RELEASE must be unset, 1, or bootstrap-local");
  }
  if (releaseMode) {
    const expectedTag = `refs/tags/v${packageJson.version}`;
    if (packageJson.private === true) fail("release mode requires the workflow's temporary private-field removal");
    if (trustedReleaseMode) {
      const expectedConfirmation = `publish browseweave@${packageJson.version}`;
      if (process.env.GITHUB_ACTIONS !== "true"
        || process.env.GITHUB_EVENT_NAME !== "workflow_dispatch"
        || process.env.GITHUB_REPOSITORY !== "xenitV1/browseweave"
        || process.env.GITHUB_REF !== expectedTag
        || process.env.BROWSEWEAVE_RELEASE_CONFIRMATION !== expectedConfirmation) {
        fail(`trusted release mode requires the manual workflow, ${expectedTag}, and confirmation: ${expectedConfirmation}`);
      }
    } else {
      const expectedConfirmation = `bootstrap browseweave@${packageJson.version}`;
      if (process.env.GITHUB_ACTIONS === "true"
        || process.env.BROWSEWEAVE_RELEASE_CONFIRMATION !== expectedConfirmation
        || process.env.BROWSEWEAVE_BOOTSTRAP_ORCHESTRATED !== "1"
        || process.env.BROWSEWEAVE_BOOTSTRAP_NPM_USER !== "xenitv0"
        || process.env.BROWSEWEAVE_BOOTSTRAP_PACKAGE_STATE !== "E404") {
        fail(`bootstrap release mode requires the local orchestrator and confirmation: ${expectedConfirmation}`);
      }
    }
  } else if (packageJson.private !== true) {
    fail("private must remain true outside the explicitly gated release workflow");
  }
  if (packageJson.license !== "MIT") fail("MIT license metadata is missing");
  if (packageJson.repository?.url !== expectedRepository) fail("repository URL is missing or unexpected");
  if (packageJson.homepage !== "https://github.com/xenitV1/browseweave#readme") fail("homepage is missing or unexpected");
  const expectedPublishConfig = {
    access: "public",
    provenance: true,
    registry: "https://registry.npmjs.org/"
  };
  if (JSON.stringify(packageJson.publishConfig) !== JSON.stringify(expectedPublishConfig)) {
    fail("public registry/provenance publishConfig is incomplete");
  }
  if (!Array.isArray(packageJson.files) || packageJson.files.length === 0) fail("an explicit files allowlist is required");
  if (JSON.stringify(packageJson.bin) !== JSON.stringify(expectedBins)) fail("public executable mapping is unexpected");
  if (packageJson.main !== "dist/src/mcp.js" || packageJson.types !== "dist/src/mcp.d.ts" || packageJson.type !== "module") {
    fail("public module metadata is unexpected");
  }
  const expectedDependencies = {
    "@modelcontextprotocol/sdk": "1.30.0",
    "jsonc-parser": "3.3.1",
    ws: "8.21.1",
    zod: "3.25.76"
  };
  if (JSON.stringify(packageJson.dependencies) !== JSON.stringify(expectedDependencies)) {
    fail("runtime dependency metadata is unexpected");
  }
  const unexpectedDependencyFields = [
    "optionalDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "bundledDependencies",
    "bundleDependencies"
  ];
  for (const dependencyField of unexpectedDependencyFields) {
    if (Object.hasOwn(packageJson, dependencyField)) fail(`unexpected dependency metadata: ${dependencyField}`);
  }
  for (const lifecycleHook of ["preinstall", "install", "postinstall", "prepare"]) {
    if (Object.hasOwn(packageJson.scripts ?? {}, lifecycleHook)) {
      fail(`install lifecycle hook is forbidden: ${lifecycleHook}`);
    }
  }
}

function allowedPackPath(filePath) {
  if ([
    "LICENSE", "README.md", "CHANGELOG.md", "SUPPORT.md", "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md", "SKILL.md", "PRIVACY.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md",
    "package.json"
  ].includes(filePath)) return true;
  if (filePath === "extension/PRIVACY.md") return true;
  if (/^extension\/dist\/(?:firefox-mv2|chromium-mv3)\/LICENSE$/u.test(filePath)) return true;
  if (/^assets\/brand\/browseweave-(?:logo|mark)\.png$/u.test(filePath)) return true;
  if (/^dist\/src\/(?:[a-z0-9-]+\/)*[a-z0-9-]+\.(?:js|d\.ts)$/u.test(filePath)) return true;
  return /^extension\/dist\/(?:firefox-mv2|chromium-mv3)\/(?:[a-z0-9_-]+\/)*[a-z0-9_.-]+\.(?:js|json|html|css|png|md)$/iu.test(filePath);
}

const contentRules = [
  { label: "npm authentication setting", pattern: /\/\/(?:registry\.)?npmjs\.org\/:_authToken\s*=/iu },
  { label: "npm access token", pattern: /\bnpm_[a-z0-9]{20,}\b/iu },
  { label: "GitHub personal access token", pattern: /\b(?:ghp_[a-z0-9]{20,}|github_pat_[a-z0-9_]{20,})\b/iu },
  { label: "OpenAI-style secret key", pattern: /\bsk-[a-z0-9_-]{20,}\b/iu },
  { label: "private key material", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u },
  { label: "dangling source map directive", pattern: /[#@]\s*sourceMappingURL=/u },
  { label: "personal Linux home path", pattern: /\/home\/[a-z0-9._-]+\//iu },
  { label: "personal macOS home path", pattern: /\/Users\/[a-z0-9._ -]+\//iu },
  { label: "personal Windows home path", pattern: /[a-z]:\\Users\\[^\\\r\n]+\\/iu },
  { label: "legacy source-repository path", pattern: /(?:Projeler\/zen-codex-bridge|zen-codex-bridge\.service|web-ext-artifacts\/zen-codex-bridge)/iu }
];

async function npmPackList() {
  const npmArguments = ["pack", "--dry-run", "--json", "--ignore-scripts"];
  let result;
  if (process.env.npm_execpath && path.isAbsolute(process.env.npm_execpath)) {
    result = await run(process.execPath, [process.env.npm_execpath, ...npmArguments], {
      cwd: projectDirectory,
      maxBuffer: 16 * 1024 * 1024
    });
  } else {
    result = await run(process.platform === "win32" ? "npm.cmd" : "npm", npmArguments, {
      cwd: projectDirectory,
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true
    });
  }
  const parsed = JSON.parse(result.stdout);
  if (!Array.isArray(parsed) || parsed.length !== 1 || !Array.isArray(parsed[0]?.files)) {
    fail("npm returned an unexpected dry-run manifest");
  }
  return parsed[0];
}

async function inspectPack() {
  await assertAppVersion(projectDirectory);
  assertMetadata();
  const pack = await npmPackList();
  const paths = pack.files.map((entry) => entry.path);
  const pathSet = new Set(paths);

  if (paths.length !== pathSet.size) fail("duplicate archive paths were reported");
  for (const required of requiredFiles) {
    if (!pathSet.has(required)) fail(`required runtime file is missing: ${required}`);
  }
  if (paths.some((filePath) => !allowedPackPath(filePath))) {
    fail(`unexpected archive path: ${paths.find((filePath) => !allowedPackPath(filePath))}`);
  }
  if (paths.some((filePath) => /(?:^|\/)(?:\.npmrc|\.env(?:\.|$)|package-lock\.json$)/u.test(filePath))) {
    fail("a local configuration or lock file entered the archive");
  }
  if (paths.some((filePath) => /(?:^|\/)setup-ticket\.json$/u.test(filePath))) {
    fail("a short-lived browser setup ticket entered the archive");
  }
  if (paths.some((filePath) => /(?:\.map|\.ts|\.tsx)$/u.test(filePath) && !filePath.endsWith(".d.ts"))) {
    fail("source code or source maps entered the archive");
  }
  if (paths.some((filePath) => /(?:zen-codex|zen-browser)/iu.test(filePath))) {
    fail("a legacy product name entered an archive path");
  }

  for (const filePath of paths) {
    const absolutePath = path.resolve(projectDirectory, filePath);
    if (!absolutePath.startsWith(`${projectDirectory}${path.sep}`)) fail(`unsafe archive path: ${filePath}`);
    const info = await lstat(absolutePath);
    if (!info.isFile() || info.isSymbolicLink()) fail(`archive input is not a regular file: ${filePath}`);
    if (/\.(?:png)$/u.test(filePath)) continue;
    const contents = await readFile(absolutePath, "utf8");
    for (const rule of contentRules) {
      if (rule.pattern.test(contents)) fail(`${rule.label} detected in ${filePath}`);
    }
  }

  for (const executablePath of Object.values(expectedBins)) {
    const executable = await readFile(path.join(projectDirectory, executablePath), "utf8");
    if (!executable.startsWith("#!/usr/bin/env node\n")) {
      fail(`public executable is missing its Node.js launcher line: ${executablePath}`);
    }
  }

  const extensionPermissions = new Map([
    ["firefox-mv2", ["<all_urls>", "tabs", "webNavigation", "storage", "nativeMessaging"]],
    ["chromium-mv3", ["tabs", "webNavigation", "storage", "scripting", "nativeMessaging"]]
  ]);
  for (const [target, expectedPermissions] of extensionPermissions) {
    const manifestPath = path.join(projectDirectory, "extension", "dist", target, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (manifest.version !== expectedBrowserExtensionVersion || manifest.version_name !== packageJson.version) {
      fail(`${target} extension version does not match browseweave@${packageJson.version}`);
    }
    if (!Array.isArray(manifest.permissions)
      || new Set(manifest.permissions).size !== manifest.permissions.length
      || manifest.permissions.length !== expectedPermissions.length
      || !expectedPermissions.every((permission) => manifest.permissions.includes(permission))) {
      fail(`${target} native messaging permission set is incomplete or unexpected`);
    }
  }

  if (pack.unpackedSize > 5 * 1024 * 1024) fail("unpacked archive exceeds the 5 MiB release budget");
  if (process.argv.includes("--list")) {
    for (const filePath of [...paths].sort()) process.stdout.write(`${filePath}\n`);
  }
  process.stderr.write(`npm pack safety check passed: ${paths.length} files, ${pack.unpackedSize} unpacked bytes.\n`);
}

await inspectPack();
