#!/usr/bin/env node

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants as fsConstants, type FileHandle, access, chmod, link, lstat, mkdir, mkdtemp, open, readFile, realpath, rename, rm } from "node:fs/promises";
import { homedir, userInfo } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { callBridge } from "../bridge/ipc-client.js";
import {
  authorizeServiceMutation,
  isProvenStoppedSystemdService,
  runManagedServiceInstallOperation,
  waitForExactBridgeHealth
} from "../native/service-install-guard.js";
import {
  claudeRegistrationState,
  claudeProjectRegistrationState,
  clientSetup,
  codexRegistrationState,
  defaultMcpLaunchSpec,
  mergeCursorConfig,
  mergeOpenCodeConfig,
  parseStrictJson,
  readStrictJsonConfig,
  selectOpenCodeVersion,
  serializeClientSetup,
  type McpLaunchSpec,
  type RegistrationState,
  type SupportedMcpClient
} from "../clients/client-config.js";
import { ensurePrivateDirectory, getIpcToken, getPairingToken, getRuntimePaths } from "../core/config.js";
import {
  assertManagedServiceEnvironment,
  createServicePlan,
  matchesWindowsTask,
  matchesWindowsTaskDefinition,
  serviceInstallCommands,
  serviceDefinitionState,
  type ServiceCommand,
  type ServicePlan
} from "../native/service-plan.js";
import {
  createSetupTicket,
  prepareManagedExtension,
  startSetupPageServer,
  type SetupPageServer,
  type SetupTicket,
  type SetupBrowserTarget
} from "../setup/flow.js";
import {
  parseSetupDaemonStatus,
  parseSetupPairingReceipt,
  receiptMatchesConnectedBrowser,
  type SetupBrowserStatus
} from "../bridge/setup-status.js";
import { APP_VERSION } from "../core/version.js";
import {
  assertTrustedClientExecutableUnchanged,
  resolveTrustedClientExecutable,
  trustedNpmInvocation,
  type ClientExecutableName,
  type TrustedClientExecutable
} from "../clients/npm-invocation.js";
import {
  CHROMIUM_EXTENSION_ORIGIN,
  currentNativeHostRegistrationPlan
} from "../native/host-config.js";
import { installNativeHostRegistration, uninstallNativeHostRegistration } from "../native/host-install.js";
import { discoverLocalChromiumExtensionOrigins } from "../setup/chromium-extension-discovery.js";
import { configureZenFlatpakNativeMessaging } from "../setup/zen-flatpak.js";
import { purgeOwnedApplicationDirectories } from "../native/purge-data.js";
import { browserLaunchEnvironment } from "../setup/browser-environment.js";

const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;
const CLIENTS = new Set<SupportedMcpClient>(["codex", "claude-code", "cursor", "opencode", "generic"]);
const PACKAGE_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const CURRENT_CLI_PATH = fileURLToPath(new URL("../cli.js", import.meta.url));
const resolvedClientExecutables = new Map<ClientExecutableName, Promise<TrustedClientExecutable | undefined>>();
const availableClientExecutables = new Map<ClientExecutableName, Promise<TrustedClientExecutable | undefined>>();

interface CapturedCommand {
  code: number;
  stdout: string;
  stderr: string;
}

type DefinitionState =
  | { status: "missing" }
  | { status: "exact" | "owned" | "foreign"; contents: string };

function usage(): string {
  return `BrowseWeave ${APP_VERSION}

Usage:
  npx browseweave@${APP_VERSION} setup [--browser chrome|zen] [--browser-path <absolute-path>] [--new-profile] [--client <name>] [--opencode-v1|--opencode-v2]
  npx browseweave@${APP_VERSION} doctor
  npx browseweave@${APP_VERSION} service-install
  npx browseweave@${APP_VERSION} service-uninstall
  npx browseweave@${APP_VERSION} native-host-install
  npx browseweave@${APP_VERSION} native-host-uninstall
  npx browseweave@${APP_VERSION} local-install
  npx browseweave@${APP_VERSION} local-uninstall [--purge-data]
  npx browseweave@${APP_VERSION} mcp-config <codex|claude-code|cursor|generic>
  npx browseweave@${APP_VERSION} mcp-config opencode <--opencode-v1|--opencode-v2>
  npx browseweave@${APP_VERSION} mcp-add <codex|claude-code|cursor>
  npx browseweave@${APP_VERSION} mcp-add opencode [--opencode-v1|--opencode-v2]
  npx browseweave@${APP_VERSION} extension-path <chrome|chromium|zen|firefox>
  npx browseweave@${APP_VERSION} --version

Security:
  MCP client configuration never contains the browser pairing credential.
  Pairing credentials are never printed. Use guided setup or local-install repair.
`;
}

async function resolveExtensionPath(browserTarget: string | undefined): Promise<string> {
  const target = browserTarget === "chrome" || browserTarget === "chromium"
    ? "chromium-mv3"
    : browserTarget === "zen" || browserTarget === "firefox"
      ? "firefox-mv2"
      : undefined;
  if (!target) throw new Error("Choose one of: chrome, chromium, zen, firefox.");
  const directory = fileURLToPath(new URL(`../../../extension/dist/${target}/`, import.meta.url));
  const directoryInfo = await lstat(directory);
  if (!directoryInfo.isDirectory()) throw new Error(`The packaged ${target} extension directory is missing.`);
  const manifestPath = path.join(directory, "manifest.json");
  const manifestInfo = await lstat(manifestPath);
  if (!manifestInfo.isFile()) throw new Error(`The packaged ${target} extension manifest is missing.`);
  return directory;
}

async function printExtensionPath(browserTarget: string | undefined): Promise<void> {
  process.stdout.write(`${await resolveExtensionPath(browserTarget)}\n`);
}

function parseClient(value: string | undefined): SupportedMcpClient {
  if (!value || !CLIENTS.has(value as SupportedMcpClient)) {
    throw new Error("Choose one of: codex, claude-code, cursor, opencode, generic.");
  }
  return value as SupportedMcpClient;
}

function decodeCommandOutput(buffer: Buffer): string {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
    return buffer.subarray(2).toString("utf16le");
  }
  return buffer.toString("utf8");
}

async function runCaptured(command: string, args: string[]): Promise<CapturedCommand> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let capturedBytes = 0;
    let settled = false;
    const timeout = globalThis.setTimeout(() => {
      child.kill();
      if (!settled) {
        settled = true;
        reject(new Error(`${command} did not finish within 10 seconds.`));
      }
    }, 10_000);

    const rejectOnce = (error: Error): void => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timeout);
      child.kill();
      reject(error);
    };

    const capture = (destination: Buffer[]) => (chunk: Buffer) => {
      capturedBytes += chunk.length;
      if (capturedBytes > MAX_CAPTURE_BYTES) {
        rejectOnce(new Error(`${command} produced more output than BrowseWeave can safely verify.`));
        return;
      }
      destination.push(chunk);
    };
    child.stdout.on("data", capture(stdout));
    child.stderr.on("data", capture(stderr));
    child.once("error", rejectOnce);
    child.once("exit", (code) => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timeout);
      resolve({
        code: code ?? 1,
        stdout: decodeCommandOutput(Buffer.concat(stdout)),
        stderr: decodeCommandOutput(Buffer.concat(stderr))
      });
    });
  });
}

async function runCommand(command: string, args: string[]): Promise<number> {
  return await new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: "inherit", shell: false, windowsHide: true });
    child.once("error", reject);
    child.once("exit", (code) => resolve(code ?? 1));
  });
}

function resolvedClientExecutable(name: ClientExecutableName): Promise<TrustedClientExecutable | undefined> {
  const existing = resolvedClientExecutables.get(name);
  if (existing) return existing;
  const resolution = resolveTrustedClientExecutable(name, { packageRoot: PACKAGE_ROOT });
  resolvedClientExecutables.set(name, resolution);
  return resolution;
}

async function runTrustedClientCaptured(
  trusted: TrustedClientExecutable,
  args: string[]
): Promise<CapturedCommand> {
  await assertTrustedClientExecutableUnchanged(trusted);
  return await runCaptured(trusted.executable, args);
}

async function runTrustedClientCommand(trusted: TrustedClientExecutable, args: string[]): Promise<number> {
  await assertTrustedClientExecutableUnchanged(trusted);
  return await runCommand(trusted.executable, args);
}

function availableClientExecutable(name: ClientExecutableName): Promise<TrustedClientExecutable | undefined> {
  const existing = availableClientExecutables.get(name);
  if (existing) return existing;
  const availability = (async () => {
    const trusted = await resolvedClientExecutable(name);
    if (!trusted) return undefined;
    try {
      return (await runTrustedClientCaptured(trusted, ["--version"])).code === 0 ? trusted : undefined;
    } catch {
      return undefined;
    }
  })();
  availableClientExecutables.set(name, availability);
  return availability;
}

async function clientExecutableAvailable(name: ClientExecutableName): Promise<boolean> {
  return await availableClientExecutable(name) !== undefined;
}

function fixedManagedSystemExecutable(command: string): string {
  if (process.platform === "linux" && command === "systemctl") return "/usr/bin/systemctl";
  if (process.platform === "darwin" && command === "launchctl") return "/bin/launchctl";
  if (process.platform === "win32" && (command === "schtasks.exe" || command === "whoami.exe")) {
    const systemRoot = process.env.SystemRoot || process.env.WINDIR || "C:\\Windows";
    if (!path.win32.isAbsolute(systemRoot) || /[\0\r\n]/u.test(systemRoot)) {
      throw new Error("The Windows system directory is invalid.");
    }
    return path.win32.join(path.win32.normalize(systemRoot), "System32", command);
  }
  throw new Error(`BrowseWeave refused an unexpected managed-system command: ${command}`);
}

interface SetupOptions {
  browser?: SetupBrowserTarget;
  browserPath?: string;
  newProfile: boolean;
  clients: Array<Exclude<SupportedMcpClient, "generic">>;
  opencodeVersion?: 1 | 2;
  fromSource: boolean;
}

interface BrowserLauncher {
  target: SetupBrowserTarget;
  label: string;
  command: string;
  prefixArgs: string[];
  zenFlatpak?: boolean;
}

const SETUP_CLIENTS = new Set<Exclude<SupportedMcpClient, "generic">>([
  "codex",
  "claude-code",
  "cursor",
  "opencode"
]);

function parseSetupOptions(args: string[]): SetupOptions {
  let browserTarget: SetupBrowserTarget | undefined;
  let browserPath: string | undefined;
  let browserSeen = false;
  let fromSource = false;
  let newProfile = false;
  let opencodeVersion: 1 | 2 | undefined;
  const clients: Array<Exclude<SupportedMcpClient, "generic">> = [];
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--browser") {
      if (browserSeen) throw new Error("Choose --browser only once.");
      const value = args[index + 1];
      if (value !== "chrome" && value !== "zen") throw new Error("--browser must be chrome or zen.");
      browserTarget = value;
      browserSeen = true;
      index += 1;
      continue;
    }
    if (argument === "--browser-path") {
      if (browserPath !== undefined) throw new Error("Choose --browser-path only once.");
      const value = args[index + 1];
      if (!value || !path.isAbsolute(value) || /[\0\r\n]/u.test(value)) {
        throw new Error("--browser-path must be a safe absolute executable path.");
      }
      browserPath = value;
      index += 1;
      continue;
    }
    if (argument === "--client") {
      const value = args[index + 1] as Exclude<SupportedMcpClient, "generic"> | undefined;
      if (!value || !SETUP_CLIENTS.has(value)) {
        throw new Error("--client must be codex, claude-code, cursor, or opencode.");
      }
      if (!clients.includes(value)) clients.push(value);
      index += 1;
      continue;
    }
    if (argument === "--from-source") {
      fromSource = true;
      continue;
    }
    if (argument === "--new-profile") {
      if (newProfile) throw new Error("Choose --new-profile only once.");
      newProfile = true;
      continue;
    }
    if (argument === "--opencode-v1" || argument === "--opencode-v2") {
      const selected = argument === "--opencode-v1" ? 1 : 2;
      if (opencodeVersion !== undefined) {
        throw new Error("Choose at most one of --opencode-v1 or --opencode-v2.");
      }
      opencodeVersion = selected;
      continue;
    }
    throw new Error(`Unexpected setup option: ${argument}`);
  }
  if (browserPath !== undefined && browserTarget === undefined) {
    throw new Error("Use --browser chrome or --browser zen together with --browser-path.");
  }
  if (opencodeVersion !== undefined && clients.length > 0 && !clients.includes("opencode")) {
    throw new Error("Use an OpenCode version flag only with --client opencode, or let setup auto-detect clients.");
  }
  return {
    ...(browserTarget ? { browser: browserTarget } : {}),
    ...(browserPath ? { browserPath } : {}),
    clients,
    ...(opencodeVersion ? { opencodeVersion } : {}),
    fromSource,
    newProfile
  };
}

function nativeAccountHome(): string {
  const home = userInfo().homedir;
  const pathApi = process.platform === "win32" ? path.win32 : path.posix;
  if (!pathApi.isAbsolute(home) || /[\0\r\n]/u.test(home)) {
    throw new Error("The operating system did not provide a safe absolute user home directory.");
  }
  return pathApi.normalize(home);
}

function assertManagedSetupEnvironment(): string {
  const home = nativeAccountHome();
  assertManagedServiceEnvironment({
    platform: process.platform,
    home,
    ...(typeof process.getuid === "function" ? { uid: process.getuid() } : {}),
    env: process.env
  });
  return home;
}

function persistentRuntimeRoot(): string {
  const accountHome = assertManagedSetupEnvironment();
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.win32.join(accountHome, "AppData", "Local");
    if (!path.isAbsolute(localAppData) || /[\0\r\n]/u.test(localAppData)) {
      throw new Error("LOCALAPPDATA is not a safe absolute directory.");
    }
    return path.join(localAppData, "BrowseWeave", "Runtime");
  }
  if (process.platform === "darwin") {
    return path.join(accountHome, "Library", "Application Support", "BrowseWeave", "Runtime");
  }
  const dataHome = process.env.XDG_DATA_HOME || path.join(accountHome, ".local", "share");
  if (!path.isAbsolute(dataHome) || /[\0\r\n]/u.test(dataHome)) {
    throw new Error("XDG_DATA_HOME is not a safe absolute directory.");
  }
  return path.join(dataHome, "browseweave", "runtime");
}

async function exactRuntimeCliPath(versionDirectory: string): Promise<string> {
  const packageDirectory = path.join(versionDirectory, "node_modules", "browseweave");
  const packageJsonPath = path.join(packageDirectory, "package.json");
  const packageJsonInfo = await lstat(packageJsonPath);
  if (!packageJsonInfo.isFile() || packageJsonInfo.isSymbolicLink()) {
    throw new Error("The persistent BrowseWeave package metadata is unsafe.");
  }
  const metadata = JSON.parse(await readFile(packageJsonPath, "utf8")) as Record<string, unknown>;
  if (metadata.name !== "browseweave" || metadata.version !== APP_VERSION) {
    throw new Error(`The persistent BrowseWeave package is not the required browseweave@${APP_VERSION}.`);
  }
  const cliPath = path.join(packageDirectory, "dist", "src", "cli.js");
  const cliInfo = await lstat(cliPath);
  if (!cliInfo.isFile() || cliInfo.isSymbolicLink()) throw new Error("The persistent BrowseWeave CLI is unsafe.");
  return cliPath;
}

async function installPersistentRuntime(): Promise<string> {
  const runtimeRoot = persistentRuntimeRoot();
  await ensurePrivateDirectory(runtimeRoot);
  const versionDirectory = path.join(runtimeRoot, APP_VERSION);
  try {
    return await exactRuntimeCliPath(versionDirectory);
  } catch (error) {
    try {
      await lstat(versionDirectory);
      throw error;
    } catch (presenceError) {
      if ((presenceError as NodeJS.ErrnoException).code !== "ENOENT") throw presenceError;
    }
  }

  const temporaryDirectory = await mkdtemp(path.join(runtimeRoot, `.install-${APP_VERSION}-`));
  try {
    process.stdout.write(`Installing the private browseweave@${APP_VERSION} runtime for this user…\n`);
    const install = await trustedNpmInvocation([
      "install",
      "--prefix",
      temporaryDirectory,
      "--no-save",
      "--package-lock=false",
      "--ignore-scripts",
      "--omit=dev",
      `browseweave@${APP_VERSION}`,
      "--registry=https://registry.npmjs.org/"
    ]);
    const installCode = await runCommand(install.command, install.args);
    if (installCode !== 0) {
      throw new Error("The private per-user npm installation failed; no administrator access is required or recommended.");
    }
    await exactRuntimeCliPath(temporaryDirectory);
    try {
      await rename(temporaryDirectory, versionDirectory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      await exactRuntimeCliPath(versionDirectory);
    }
    return await exactRuntimeCliPath(versionDirectory);
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
}

async function handOffSetupToPersistentInstall(setupArgs: string[]): Promise<boolean> {
  const versionDirectory = path.join(persistentRuntimeRoot(), APP_VERSION);
  try {
    const installedCli = await exactRuntimeCliPath(versionDirectory);
    if (await realpath(installedCli) === await realpath(CURRENT_CLI_PATH)) return false;
  } catch {
    // Install the exact public version below into private per-user app data.
  }
  const installedCli = await installPersistentRuntime();
  const exitCode = await runCommand(process.execPath, [installedCli, "setup", ...setupArgs]);
  if (exitCode !== 0) throw new Error(`The persistent BrowseWeave setup exited with code ${exitCode}.`);
  return true;
}

async function handOffCommandToPersistentInstall(args: readonly string[]): Promise<boolean> {
  const packageJsonPath = fileURLToPath(new URL("../../../package.json", import.meta.url));
  const packageJsonInfo = await lstat(packageJsonPath);
  if (!packageJsonInfo.isFile() || packageJsonInfo.isSymbolicLink()) {
    throw new Error("The BrowseWeave package metadata is unsafe.");
  }
  const metadata = JSON.parse(await readFile(packageJsonPath, "utf8")) as Record<string, unknown>;
  if (metadata.name !== "browseweave" || metadata.version !== APP_VERSION) {
    throw new Error("The BrowseWeave package identity is invalid.");
  }
  // A source checkout deliberately keeps private:true and must execute the code
  // being developed. A public npx invocation delegates maintenance commands to
  // the exact persistent runtime installed by setup, avoiding an ephemeral cache path.
  if (metadata.private === true) return false;

  const versionDirectory = path.join(persistentRuntimeRoot(), APP_VERSION);
  let installedCli: string;
  try {
    installedCli = await exactRuntimeCliPath(versionDirectory);
  } catch {
    return false;
  }
  if (await realpath(installedCli) === await realpath(CURRENT_CLI_PATH)) return false;
  const exitCode = await runCommand(process.execPath, [installedCli, ...args]);
  if (exitCode !== 0) process.exitCode = exitCode;
  return true;
}

async function assertPrivateSourceSetup(): Promise<void> {
  const packageJsonPath = fileURLToPath(new URL("../../../package.json", import.meta.url));
  const info = await lstat(packageJsonPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error("Source setup requires a safe private BrowseWeave checkout.");
  }
  const metadata = JSON.parse(await readFile(packageJsonPath, "utf8")) as Record<string, unknown>;
  if (metadata.name !== "browseweave" || metadata.version !== APP_VERSION || metadata.private !== true) {
    throw new Error("--from-source is restricted to the private development checkout and is unavailable in the public npm package.");
  }
}

async function accessibleFile(candidate: string): Promise<boolean> {
  try {
    await access(candidate, process.platform === "win32" ? fsConstants.F_OK : fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function detectBrowserLauncher(
  requested?: SetupBrowserTarget,
  customExecutable?: string
): Promise<BrowserLauncher> {
  if (customExecutable !== undefined) {
    if (!requested) throw new Error("A custom browser path requires an explicit chrome or zen target.");
    const resolved = await realpath(customExecutable).catch(() => undefined);
    if (!resolved || /[\0\r\n]/u.test(resolved)) throw new Error("The custom browser executable could not be resolved safely.");
    const info = await lstat(resolved);
    if (!info.isFile() || !(await accessibleFile(resolved))) {
      throw new Error("The custom browser path is not an executable regular file.");
    }
    return {
      target: requested,
      label: requested === "chrome" ? "Google Chrome" : "Zen Browser",
      command: resolved,
      prefixArgs: []
    };
  }
  const candidates: BrowserLauncher[] = [];
  if (process.platform === "linux") {
    for (const executable of [
      "/usr/bin/google-chrome-stable",
      "/usr/bin/google-chrome",
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser"
    ]) {
      if (await accessibleFile(executable)) {
        candidates.push({ target: "chrome", label: "Google Chrome", command: executable, prefixArgs: [] });
        break;
      }
    }
    let installedFlatpak: string | undefined;
    for (const candidate of ["/usr/bin/flatpak", "/usr/local/bin/flatpak"]) {
      if (await accessibleFile(candidate)) {
        installedFlatpak = candidate;
        break;
      }
    }
    const flatpakZen = installedFlatpak
      ? await runCaptured(installedFlatpak, ["info", "app.zen_browser.zen"]).catch(() => undefined)
      : undefined;
    if (installedFlatpak && flatpakZen?.code === 0) {
      candidates.push({
        target: "zen",
        label: "Zen Browser",
        command: installedFlatpak,
        prefixArgs: ["run", "app.zen_browser.zen"],
        zenFlatpak: true
      });
    }
  } else if (process.platform === "darwin") {
    const chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    const zenCandidates = [
      "/Applications/Zen.app/Contents/MacOS/zen",
      "/Applications/Zen Browser.app/Contents/MacOS/zen"
    ];
    if (await accessibleFile(chrome)) {
      candidates.push({ target: "chrome", label: "Google Chrome", command: chrome, prefixArgs: [] });
    }
    for (const zen of zenCandidates) {
      if (await accessibleFile(zen)) {
        candidates.push({ target: "zen", label: "Zen Browser", command: zen, prefixArgs: [] });
        break;
      }
    }
  } else if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(homedir(), "AppData", "Local");
    const programFiles = process.env.PROGRAMFILES || "C:\\Program Files";
    const programFilesX86 = process.env["PROGRAMFILES(X86)"] || "C:\\Program Files (x86)";
    const chromeCandidates = [
      path.join(programFiles, "Google", "Chrome", "Application", "chrome.exe"),
      path.join(programFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
      path.join(localAppData, "Google", "Chrome", "Application", "chrome.exe")
    ];
    const zenCandidates = [
      path.join(localAppData, "Programs", "Zen Browser", "zen.exe"),
      path.join(programFiles, "Zen Browser", "zen.exe")
    ];
    for (const chrome of chromeCandidates) {
      if (await accessibleFile(chrome)) {
        candidates.push({ target: "chrome", label: "Google Chrome", command: chrome, prefixArgs: [] });
        break;
      }
    }
    for (const zen of zenCandidates) {
      if (await accessibleFile(zen)) {
        candidates.push({ target: "zen", label: "Zen Browser", command: zen, prefixArgs: [] });
        break;
      }
    }
  }

  const selected = requested
    ? candidates.find((candidate) => candidate.target === requested)
    : candidates.find((candidate) => candidate.target === "chrome") ?? candidates[0];
  if (!selected) {
    throw new Error(requested
      ? `${requested === "chrome" ? "Google Chrome" : "Zen Browser"} was not found in a supported installation location.`
      : "Google Chrome or Zen Browser was not found in a supported installation location.");
  }
  return selected;
}

async function launchDetached(command: string, args: string[]): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: path.dirname(command),
      detached: true,
      env: browserLaunchEnvironment(),
      stdio: "ignore",
      shell: false,
      windowsHide: true
    });
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

async function openSetupBrowser(launcher: BrowserLauncher, setupUrl: string): Promise<void> {
  const managementUrl = launcher.target === "chrome"
    ? "chrome://extensions/"
    : "about:debugging#/runtime/this-firefox";
  await launchDetached(launcher.command, [...launcher.prefixArgs, managementUrl]);
  await new Promise((resolve) => globalThis.setTimeout(resolve, 750));
  await launchDetached(launcher.command, [...launcher.prefixArgs, setupUrl]);
}

function setupPathPickerHint(): string {
  if (process.platform === "darwin") return "In the file picker, press Cmd+Shift+G and paste the path.";
  if (process.platform === "win32") return "Paste the path into the file picker's address bar.";
  return "In the file picker, press Ctrl+L and paste the path.";
}

function setupLoadInstruction(launcher: BrowserLauncher, extensionPath: string, setupUrl: string): string {
  const selection = launcher.target === "chrome"
    ? `In chrome://extensions, enable Developer mode, choose Load unpacked, and select: ${extensionPath}`
    : `In about:debugging#/runtime/this-firefox, choose Load Temporary Add-on and select: ${path.join(extensionPath, "manifest.json")}`;
  return [
    "Browser approval is required. If BrowseWeave could not open the pages automatically:",
    selection,
    setupPathPickerHint(),
    `Then open this private local setup page: ${setupUrl}`
  ].join("\n");
}

async function runServiceCommands(commands: ServiceCommand[]): Promise<void> {
  for (const item of commands) {
    const exitCode = await runCommand(fixedManagedSystemExecutable(item.command), item.args);
    if (exitCode !== 0 && item.allowFailure !== true) {
      throw new Error(`${item.command} failed with exit code ${exitCode}.`);
    }
  }
}

async function runServiceCleanupCommands(commands: ServiceCommand[]): Promise<unknown[]> {
  const errors: unknown[] = [];
  for (const item of commands) {
    try {
      const exitCode = await runCommand(fixedManagedSystemExecutable(item.command), item.args);
      if (exitCode !== 0 && item.allowFailure !== true) {
        errors.push(new Error(`${item.command} cleanup failed with exit code ${exitCode}.`));
      }
    } catch (error) {
      errors.push(error);
    }
  }
  return errors;
}

async function currentWindowsSid(): Promise<string> {
  const result = await runCaptured(fixedManagedSystemExecutable("whoami.exe"), ["/user", "/fo", "csv", "/nh"]);
  const sid = result.stdout.match(/S-\d-\d+(?:-\d+)+/u)?.[0];
  if (result.code !== 0 || !sid) throw new Error("The current Windows user SID could not be verified.");
  return sid;
}

async function currentServicePlan(): Promise<ServicePlan> {
  if (process.platform !== "win32" && typeof process.getuid === "function" && process.getuid() === 0) {
    throw new Error("Do not install BrowseWeave as root. Run it from your normal user account.");
  }
  const accountHome = assertManagedSetupEnvironment();
  const daemonPath = fileURLToPath(new URL("../daemon.js", import.meta.url));
  const input = {
    platform: process.platform,
    home: accountHome,
    nodePath: process.execPath,
    daemonPath,
    ...(process.env.XDG_CONFIG_HOME ? { configHome: process.env.XDG_CONFIG_HOME } : {}),
    ...(process.env.LOCALAPPDATA ? { localAppData: process.env.LOCALAPPDATA } : {}),
    ...(typeof process.getuid === "function" ? { uid: process.getuid() } : {}),
    ...(process.platform === "win32" ? { userId: await currentWindowsSid() } : {})
  };
  return createServicePlan(input);
}

async function inspectDefinition(plan: ServicePlan): Promise<DefinitionState> {
  if (!plan.definitionPath || plan.definitionContent === undefined) return { status: "missing" };
  try {
    const info = await lstat(plan.definitionPath);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error(`Refusing a non-regular service definition: ${plan.definitionPath}`);
    }
    if (process.platform !== "win32" && typeof process.getuid === "function" && info.uid !== process.getuid()) {
      throw new Error(`Service definition is not owned by the current user: ${plan.definitionPath}`);
    }
    const contents = await readFile(plan.definitionPath, "utf8");
    return { status: serviceDefinitionState(plan, contents), contents };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { status: "missing" };
    throw error;
  }
}

async function writeManagedDefinition(plan: ServicePlan, state: DefinitionState): Promise<"created" | "updated" | "unchanged"> {
  if (!plan.definitionPath || plan.definitionContent === undefined) return "unchanged";
  if (state.status === "foreign") {
    throw new Error(`A service definition not owned by BrowseWeave already exists: ${plan.definitionPath}`);
  }
  if (state.status === "exact") return "unchanged";

  const directory = path.dirname(plan.definitionPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const directoryInfo = await lstat(directory);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw new Error(`Refusing an unsafe service definition directory: ${directory}`);
  }
  if (process.platform !== "win32" && typeof process.getuid === "function" && directoryInfo.uid !== process.getuid()) {
    throw new Error(`Service definition directory is not owned by the current user: ${directory}`);
  }

  if (state.status === "owned") {
    const current = await readFile(plan.definitionPath, "utf8");
    if (current !== state.contents) {
      throw new Error(`Service definition changed while BrowseWeave was preparing the update: ${plan.definitionPath}`);
    }
  }

  const temporaryPath = path.join(
    directory,
    `.${path.basename(plan.definitionPath)}.${process.pid}-${randomBytes(8).toString("hex")}.tmp`
  );
  let handle: FileHandle | undefined;
  try {
    handle = await open(temporaryPath, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
    await handle.writeFile(plan.definitionContent, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    if (state.status === "missing") {
      await link(temporaryPath, plan.definitionPath);
      await rm(temporaryPath);
    } else {
      await rename(temporaryPath, plan.definitionPath);
    }
    if (process.platform !== "win32") await chmod(plan.definitionPath, 0o600);
  } catch (error) {
    await handle?.close();
    await rm(temporaryPath, { force: true });
    throw error;
  }
  return state.status === "missing" ? "created" : "updated";
}

async function inspectWindowsTask(
  plan: ServicePlan,
  definitionState: DefinitionState
): Promise<"missing" | "exact" | "owned" | "foreign"> {
  if (!plan.inspectionCommand || !plan.windowsTask) return "missing";
  const result = await runCaptured(
    fixedManagedSystemExecutable(plan.inspectionCommand.command),
    plan.inspectionCommand.args
  );
  if (result.code !== 0) return "missing";
  if (matchesWindowsTask(plan, result.stdout)) return "exact";
  if (definitionState.status === "owned" && matchesWindowsTaskDefinition(definitionState.contents, result.stdout)) {
    return "owned";
  }
  return "foreign";
}

async function verifyNewNonWindowsServiceStopped(plan: ServicePlan): Promise<void> {
  if (plan.platform === "linux") {
    const result = await runCaptured(
      fixedManagedSystemExecutable("systemctl"),
      ["--user", "is-active", plan.identifier]
    );
    const state = result.stdout.trim();
    if (!isProvenStoppedSystemdService(result.code, state)) {
      throw new Error(
        `The newly-created service could not be proven stopped (${state || result.stderr.trim() || "unknown state"}).`
      );
    }
    return;
  }
  if (plan.platform === "darwin") {
    if (typeof process.getuid !== "function" || !Number.isInteger(process.getuid())) {
      throw new Error("The newly-created LaunchAgent could not be checked without the current user ID.");
    }
    const result = await runCaptured(
      fixedManagedSystemExecutable("launchctl"),
      ["print", `gui/${process.getuid()}/${plan.identifier}`]
    );
    if (result.code === 0) {
      throw new Error(`The newly-created LaunchAgent is still registered: ${plan.identifier}`);
    }
  }
}

async function cleanupFailedNewServiceInstall(input: {
  plan: ServicePlan;
  definitionWasMissing: boolean;
  windowsTaskWasMissing: boolean;
}): Promise<unknown[]> {
  const errors: unknown[] = [];
  let definitionState: DefinitionState | undefined;
  try {
    definitionState = await inspectDefinition(input.plan);
  } catch (error) {
    errors.push(error);
  }

  if (input.plan.platform === "win32" && input.windowsTaskWasMissing) {
    try {
      const taskState = await inspectWindowsTask(input.plan, definitionState ?? { status: "missing" });
      if (taskState === "exact") {
        errors.push(...await runServiceCleanupCommands(input.plan.uninstallCommands));
        const afterCleanup = await inspectWindowsTask(input.plan, definitionState ?? { status: "missing" });
        if (afterCleanup !== "missing") {
          throw new Error(`The newly-created Windows task was not proven deleted: ${input.plan.identifier}`);
        }
      } else if (taskState !== "missing") {
        throw new Error(`The newly-created Windows task changed identity and was not removed: ${input.plan.identifier}`);
      }
    } catch (error) {
      errors.push(error);
    }
  } else if (input.plan.platform !== "win32" && input.definitionWasMissing) {
    try {
      if (definitionState?.status === "exact") {
        errors.push(...await runServiceCleanupCommands(input.plan.uninstallCommands));
        await verifyNewNonWindowsServiceStopped(input.plan);
      } else if (definitionState !== undefined && definitionState.status !== "missing") {
        throw new Error(
          `The newly-created service definition changed identity, so BrowseWeave did not stop it: ` +
          `${input.plan.definitionPath ?? input.plan.identifier}`
        );
      }
    } catch (error) {
      errors.push(error);
    }
  }

  let definitionRemoved = false;
  if (input.definitionWasMissing) {
    try {
      const current = await inspectDefinition(input.plan);
      if (current.status === "exact") {
        await removeOwnedDefinition(input.plan, current);
        definitionRemoved = true;
      } else if (current.status !== "missing") {
        throw new Error(
          `The newly-created service definition changed identity and was not removed: ` +
          `${input.plan.definitionPath ?? input.plan.identifier}`
        );
      }
    } catch (error) {
      errors.push(error);
    }
  }

  if (definitionRemoved && input.plan.postUninstallCommands) {
    errors.push(...await runServiceCleanupCommands(input.plan.postUninstallCommands));
  }
  return errors;
}

async function installService(): Promise<void> {
  const plan = await currentServicePlan();
  const runtimePaths = getRuntimePaths();
  await Promise.all([
    getPairingToken(runtimePaths),
    getIpcToken(runtimePaths)
  ]);
  const definitionState = await inspectDefinition(plan);
  if (definitionState.status === "foreign") {
    throw new Error(`A foreign or modified service definition was not overwritten: ${plan.definitionPath ?? plan.identifier}`);
  }

  let windowsTaskState: "missing" | "exact" | "owned" | "foreign" = "missing";
  if (plan.platform === "win32") {
    windowsTaskState = await inspectWindowsTask(plan, definitionState);
    if (windowsTaskState === "foreign") {
      throw new Error(`A Windows task not owned by BrowseWeave already exists: ${plan.identifier}`);
    }
  }

  // callBridge never sends the IPC secret until the endpoint proves it first.
  // If authentication fails, the guard performs connect-only probes and blocks
  // all definition/task mutations when either default port is occupied.
  await authorizeServiceMutation({
    authenticateStatus: async () => await callBridge("status", {}, 2_000)
  });

  await runManagedServiceInstallOperation({
    installAndStart: async () => {
      if (plan.platform === "win32") {
        if (windowsTaskState === "owned") {
          if (!plan.replacePreparationCommands) throw new Error("The owned Windows task cannot be upgraded safely.");
          // Keep the old managed definition intact until the old task is gone. If
          // writing or creating the replacement then fails, a retry sees a missing
          // task plus an owned definition and can complete the install safely.
          await runServiceCommands(plan.replacePreparationCommands);
          await writeManagedDefinition(plan, definitionState);
          await runServiceCommands(plan.installCommands);
        } else {
          await writeManagedDefinition(plan, definitionState);
          await runServiceCommands(windowsTaskState === "exact" ? plan.refreshCommands ?? [] : plan.installCommands);
        }
      } else {
        const definitionExisted = definitionState.status !== "missing";
        await writeManagedDefinition(plan, definitionState);
        const commands = serviceInstallCommands(plan, definitionExisted);
        await runServiceCommands(commands);
      }
    },
    verifyHealth: async () => {
      await waitForExactBridgeHealth({
        status: async () => await callBridge("status", {}, 1_500)
      });
    },
    cleanupNewResources: async () => await cleanupFailedNewServiceInstall({
      plan,
      definitionWasMissing: definitionState.status === "missing",
      windowsTaskWasMissing: plan.platform === "win32" && windowsTaskState === "missing"
    })
  });
  process.stdout.write(`BrowseWeave daemon service installed: ${plan.identifier}\n`);
}

async function nativeHostAccountHome(): Promise<string> {
  if (process.platform !== "win32" && typeof process.getuid === "function" && process.getuid() === 0) {
    throw new Error("Do not install BrowseWeave as root. Run it from your normal user account.");
  }
  return nativeAccountHome();
}

async function installNativeHost(requiredBrowser?: SetupBrowserTarget): Promise<void> {
  const home = await nativeHostAccountHome();
  let localChromeOrigins: readonly string[] | undefined;
  if (!CHROMIUM_EXTENSION_ORIGIN) {
    const deadline = Date.now() + (requiredBrowser === "chrome" ? 10_000 : 0);
    do {
      localChromeOrigins = await discoverLocalChromiumExtensionOrigins();
      if (localChromeOrigins.length > 0 || requiredBrowser !== "chrome" || Date.now() >= deadline) break;
      await new Promise((resolve) => globalThis.setTimeout(resolve, 250));
    } while (true);
    if (requiredBrowser === "chrome" && localChromeOrigins.length === 0) {
      throw new Error(
        "Google Chrome connected, but its exact unpacked extension identity was not saved yet. " +
        "Keep Chrome open and run setup again; BrowseWeave will not use a wildcard native-host permission."
      );
    }
  }
  const plan = currentNativeHostRegistrationPlan(process.platform, localChromeOrigins);
  await installNativeHostRegistration(plan, home);
  process.stdout.write(`BrowseWeave native setup helper installed for ${plan.manifests.map(({ browser }) => browser).join(", ")}.\n`);
}

async function uninstallNativeHost(): Promise<void> {
  const home = await nativeHostAccountHome();
  const localChromeOrigins = CHROMIUM_EXTENSION_ORIGIN
    ? undefined
    : await discoverLocalChromiumExtensionOrigins();
  const plan = currentNativeHostRegistrationPlan(process.platform, localChromeOrigins);
  await uninstallNativeHostRegistration(plan, home);
  process.stdout.write("BrowseWeave native setup helper removed. Browser pairing data was preserved.\n");
}

async function localInstall(): Promise<void> {
  await installService();
  await installNativeHost();
}

async function localUninstall(purgeData = false): Promise<void> {
  await uninstallNativeHost();
  await uninstallService();
  if (!purgeData) return;
  const runtimePaths = getRuntimePaths();
  const targets = [
    runtimePaths.configDir,
    runtimePaths.stateDir,
    runtimePaths.runtimeDir,
    path.dirname(persistentRuntimeRoot()),
    ...(runtimePaths.legacyTokenPath ? [path.dirname(runtimePaths.legacyTokenPath)] : [])
  ];
  const removed = await purgeOwnedApplicationDirectories(targets);
  process.stdout.write(
    `BrowseWeave local data purged from ${removed.length} application ${removed.length === 1 ? "directory" : "directories"}. ` +
    "Remove the browser extension separately to clear its browser-owned storage.\n"
  );
}

async function removeOwnedDefinition(plan: ServicePlan, expected: DefinitionState): Promise<void> {
  if (!plan.definitionPath || expected.status === "missing") return;
  if (expected.status === "foreign") {
    throw new Error(`Service definition was modified and was not removed: ${plan.definitionPath}`);
  }
  const current = await readFile(plan.definitionPath, "utf8");
  if (current !== expected.contents || serviceDefinitionState(plan, current) === "foreign") {
    throw new Error(`Service definition changed during uninstall and was not removed: ${plan.definitionPath}`);
  }
  await rm(plan.definitionPath);
}

async function uninstallService(): Promise<void> {
  const plan = await currentServicePlan();
  const definitionState = await inspectDefinition(plan);
  if (definitionState.status === "foreign") {
    throw new Error(`A foreign or modified service definition was not removed: ${plan.definitionPath ?? plan.identifier}`);
  }

  if (plan.platform === "win32") {
    const taskState = await inspectWindowsTask(plan, definitionState);
    if (taskState === "foreign") {
      throw new Error(`A Windows task not owned by BrowseWeave was not removed: ${plan.identifier}`);
    }
    if (taskState === "exact" || taskState === "owned") await runServiceCommands(plan.uninstallCommands);
  } else if (definitionState.status !== "missing") {
    await runServiceCommands(plan.uninstallCommands);
  }

  await removeOwnedDefinition(plan, definitionState);
  if (definitionState.status !== "missing" && plan.postUninstallCommands) {
    await runServiceCommands(plan.postUninstallCommands);
  }
  process.stdout.write(`BrowseWeave daemon service removed: ${plan.identifier}. User data was preserved.\n`);
}

async function doctor(): Promise<void> {
  const paths = getRuntimePaths();
  const checks: Array<Record<string, unknown>> = [];
  try {
    await access(paths.tokenPath);
    checks.push({ check: "pairing_token", ok: true });
  } catch {
    checks.push({ check: "pairing_token", ok: false });
  }
  try {
    await access(paths.ipcTokenPath);
    checks.push({ check: "ipc_authentication", ok: true });
  } catch {
    checks.push({ check: "ipc_authentication", ok: false });
  }
  try {
    const status = await callBridge("status", {}, 5_000);
    checks.push({ check: "daemon", ok: true, status });
  } catch (error) {
    checks.push({ check: "daemon", ok: false, error: error instanceof Error ? error.message : String(error) });
  }
  const clientCommands: ClientExecutableName[] = ["codex", "claude", "cursor-agent", "opencode", "opencode2"];
  for (const command of clientCommands) {
    checks.push({ check: `client:${command}`, ok: await clientExecutableAvailable(command) });
  }
  process.stdout.write(`${JSON.stringify({ product: "BrowseWeave", version: APP_VERSION, checks }, null, 2)}\n`);
  if (checks.some((check) => check.check === "daemon" && check.ok === false)) process.exitCode = 1;
}

async function codexState(spec: McpLaunchSpec, executable: TrustedClientExecutable): Promise<RegistrationState> {
  const result = await runTrustedClientCaptured(executable, ["mcp", "list", "--json"]);
  if (result.code !== 0) throw new Error("Codex MCP configuration could not be verified.");
  return codexRegistrationState(parseStrictJson(result.stdout, "Codex MCP list"), spec);
}

function claudeConfigPath(): string {
  if (process.env.CLAUDE_CONFIG_DIR) {
    throw new Error("Automatic Claude Code setup is disabled when CLAUDE_CONFIG_DIR is set because the user-scope file cannot be located safely.");
  }
  return path.join(homedir(), ".claude.json");
}

async function claudeState(spec: McpLaunchSpec, allowMissing: boolean): Promise<RegistrationState> {
  const configPath = claudeConfigPath();
  let state: RegistrationState;
  try {
    state = claudeRegistrationState(await readStrictJsonConfig(configPath), spec);
  } catch (error) {
    if (allowMissing && (error as NodeJS.ErrnoException).code === "ENOENT") state = "absent";
    else throw error;
  }
  const projectPath = path.join(process.cwd(), ".mcp.json");
  try {
    if (claudeProjectRegistrationState(await readStrictJsonConfig(projectPath), spec) !== "absent") return "foreign";
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return state;
}

async function addCliManagedClient(client: "codex" | "claude-code", spec: McpLaunchSpec): Promise<"added" | "unchanged"> {
  const command: ClientExecutableName = client === "codex" ? "codex" : "claude";
  const executable = await availableClientExecutable(command);
  if (!executable) {
    throw new Error(`${command} is not installed or no trusted executable was found on the safe user PATH.`);
  }
  const before = client === "codex" ? await codexState(spec, executable) : await claudeState(spec, true);
  if (before === "foreign") {
    throw new Error(`${client} already contains a foreign browseweave MCP entry; it was not changed.`);
  }
  if (before === "exact") return "unchanged";

  const setup = clientSetup(client, spec);
  if (!setup.command) throw new Error("No safe MCP setup command is available.");
  const [setupCommand, ...args] = setup.command;
  if (setupCommand !== command) throw new Error("The MCP client setup command did not match the selected executable.");
  const exitCode = await runTrustedClientCommand(executable, args);
  if (exitCode !== 0) throw new Error(`${client} MCP registration failed with exit code ${exitCode}.`);
  const after = client === "codex" ? await codexState(spec, executable) : await claudeState(spec, false);
  if (after !== "exact") {
    throw new Error(`${client} reported success but its BrowseWeave MCP registration did not match the expected executable and arguments.`);
  }
  return "added";
}

function cursorConfigPath(): string {
  return path.join(homedir(), ".cursor", "mcp.json");
}

async function openCodeConfigPath(): Promise<string> {
  if (process.env.OPENCODE_CONFIG) {
    if (!path.isAbsolute(process.env.OPENCODE_CONFIG)) throw new Error("OPENCODE_CONFIG must be an absolute file path.");
    return process.env.OPENCODE_CONFIG;
  }
  const configHome = process.env.XDG_CONFIG_HOME || path.join(homedir(), ".config");
  if (!path.isAbsolute(configHome)) throw new Error("XDG_CONFIG_HOME must be absolute.");
  const candidates = [
    path.join(configHome, "opencode", "opencode.json"),
    path.join(configHome, "opencode", "opencode.jsonc")
  ];
  const existing: string[] = [];
  for (const candidate of candidates) {
    try {
      const info = await lstat(candidate);
      if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Unsafe OpenCode configuration file: ${candidate}`);
      existing.push(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  if (existing.length > 1) {
    throw new Error("Both OpenCode JSON and JSONC configuration files exist; refusing an ambiguous automatic update.");
  }
  return existing[0] ?? candidates[0]!;
}

async function resolveInstalledOpenCodeVersion(requestedVersion?: 1 | 2): Promise<1 | 2> {
  const [v1, v2] = await Promise.all([
    clientExecutableAvailable("opencode"),
    clientExecutableAvailable("opencode2")
  ]);
  return selectOpenCodeVersion({ v1, v2 }, requestedVersion);
}

async function addMcpClient(client: SupportedMcpClient, requestedOpenCodeVersion?: 1 | 2): Promise<void> {
  const spec = defaultMcpLaunchSpec();
  if (client === "generic") {
    throw new Error("Generic clients cannot be edited safely without their exact schema. Use 'browseweave mcp-config generic', review the output, and adapt its command/args entry to the client's official MCP format.");
  }
  if (client === "codex" || client === "claude-code") {
    const status = await addCliManagedClient(client, spec);
    process.stdout.write(`BrowseWeave MCP registration for ${client}: ${status}. Start a new client session, then call browser_status.\n`);
    return;
  }
  if (client === "cursor") {
    const result = await mergeCursorConfig(cursorConfigPath(), spec);
    process.stdout.write(`BrowseWeave Cursor MCP configuration: ${result.status} (${result.path}).\n`);
    return;
  }
  const version = await resolveInstalledOpenCodeVersion(requestedOpenCodeVersion);
  const result = await mergeOpenCodeConfig(await openCodeConfigPath(), spec, version);
  process.stdout.write(`BrowseWeave OpenCode V${result.opencodeVersion} MCP configuration: ${result.status} (${result.path}).\n`);
}

async function daemonBrowsersWithRetry(timeoutMs = 10_000): Promise<SetupBrowserStatus[]> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      return parseSetupDaemonStatus(await callBridge("status", {}, 2_000));
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => globalThis.setTimeout(resolve, 250));
    }
  }
  throw lastError instanceof Error ? lastError : new Error("The BrowseWeave service did not become ready.");
}

async function directoryExists(directory: string): Promise<boolean> {
  try {
    const info = await lstat(directory);
    return info.isDirectory() && !info.isSymbolicLink();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function detectedSetupClients(options: SetupOptions): Promise<SetupOptions["clients"]> {
  const requested = options.clients;
  if (requested.length > 0) return requested;
  const detected: SetupOptions["clients"] = [];
  if (await clientExecutableAvailable("codex")) detected.push("codex");
  if (await clientExecutableAvailable("claude")) detected.push("claude-code");
  if (await clientExecutableAvailable("cursor-agent") || await directoryExists(path.join(homedir(), ".cursor"))) {
    detected.push("cursor");
  }
  if (options.opencodeVersion !== undefined
    || await clientExecutableAvailable("opencode")
    || await clientExecutableAvailable("opencode2")) detected.push("opencode");
  return detected;
}

async function configureSetupClients(
  clients: SetupOptions["clients"],
  requestedOpenCodeVersion?: 1 | 2
): Promise<void> {
  if (clients.length === 0) {
    process.stdout.write(
      "No supported MCP client was detected. Install one, then run 'browseweave mcp-add <client>'.\n"
    );
    return;
  }
  const failures: string[] = [];
  for (const client of clients) {
    try {
      await addMcpClient(client, client === "opencode" ? requestedOpenCodeVersion : undefined);
    } catch (error) {
      const message = error instanceof Error ? error.message : "configuration failed";
      failures.push(`${client}: ${message.replace(/[\r\n]+/gu, " ").slice(0, 300)}`);
    }
  }
  if (failures.length > 0) {
    throw new Error(`Browser setup succeeded, but these MCP registrations need attention: ${failures.join("; ")}`);
  }
}

async function waitForSetupBrowser(input: {
  setupId: string;
  family: SetupBrowserStatus["browser_family"];
  forbiddenBrowserIds: ReadonlySet<string>;
  expiresAt: string;
  interrupted: () => boolean;
}): Promise<SetupBrowserStatus> {
  const deadline = Date.parse(input.expiresAt);
  while (Date.now() < deadline) {
    if (input.interrupted()) throw new Error("BrowseWeave setup was cancelled; no pairing key was exposed.");
    let receiptValue: unknown;
    try {
      receiptValue = await callBridge("setup_pairing_status", { setup_id: input.setupId }, 2_000);
    } catch {
      await new Promise((resolve) => globalThis.setTimeout(resolve, 400));
      continue;
    }
    const receipt = parseSetupPairingReceipt({
      value: receiptValue,
      setupId: input.setupId,
      expiresAt: input.expiresAt,
      browserFamily: input.family
    });
    if (receipt.setup_pairing_status === "not_found") {
      throw new Error("The one-click setup session no longer exists. Run setup again.");
    }
    if ((receipt.setup_pairing_status === "pending" || receipt.setup_pairing_status === "completed")
      && receipt.extension_version !== APP_VERSION) {
      throw new Error(
        `The running extension is ${receipt.extension_version}, but setup requires ${APP_VERSION}. ` +
        "Reload the BrowseWeave extension from the printed folder and run setup again."
      );
    }
    if ((receipt.setup_pairing_status === "pending" || receipt.setup_pairing_status === "completed")
      && input.forbiddenBrowserIds.has(receipt.browser_id)) {
      throw new Error(
        "The already-connected browser profile answered the new-profile request. " +
        "Open the intended new profile, load BrowseWeave there, and run setup --new-profile again."
      );
    }
    if (receipt.setup_pairing_status === "completed") {
      try {
        const connected = parseSetupDaemonStatus(await callBridge("status", {}, 2_000))
          .find((browser) => receiptMatchesConnectedBrowser(receipt, browser));
        if (connected) return connected;
      } catch {
        // A just-restarted service gets another bounded status attempt.
      }
    }
    await new Promise((resolve) => globalThis.setTimeout(resolve, 400));
  }
  throw new Error("The one-click browser connection expired. Run the setup command again; no secret was retained in the setup page.");
}

async function runSetup(options: SetupOptions, originalArgs: string[]): Promise<void> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("Run setup yourself in a visible interactive terminal so browser consent cannot be hidden.");
  }
  assertManagedSetupEnvironment();
  if (options.fromSource) await assertPrivateSourceSetup();
  if (!options.fromSource && await handOffSetupToPersistentInstall(originalArgs)) return;

  const setupClients = await detectedSetupClients(options);
  const setupOpenCodeVersion = setupClients.includes("opencode")
    ? await resolveInstalledOpenCodeVersion(options.opencodeVersion)
    : undefined;

  const launcher = await detectBrowserLauncher(options.browser, options.browserPath);
  const packagedExtensionPath = await resolveExtensionPath(launcher.target);
  const extensionPath = await prepareManagedExtension({
    sourcePath: packagedExtensionPath,
    stableParent: path.join(path.dirname(persistentRuntimeRoot()), "extension"),
    target: launcher.target === "chrome" ? "chromium-mv3" : "firefox-mv2",
    version: APP_VERSION
  });
  const requestedFamily = launcher.target === "chrome" ? "chromium" : "firefox";
  process.stdout.write(`BrowseWeave setup selected ${launcher.label}.\n`);
  await installService();
  const baseline = await daemonBrowsersWithRetry();
  const alreadyConnected = options.newProfile
    ? undefined
    : baseline.find((browser) =>
      browser.browser_family === requestedFamily && browser.extension_version === APP_VERSION
    );
  let selectedBrowser: SetupBrowserStatus | undefined = alreadyConnected;
  if (alreadyConnected) {
    process.stdout.write(`${launcher.label} is already connected (${alreadyConnected.browser_id}).\n`);
  } else {
    let page: SetupPageServer | undefined;
    let ticket: SetupTicket | undefined;
    let pairingBeginAttempted = false;
    let interrupted = false;
    let operationFailed = false;
    let operationError: unknown;
    const cleanupErrors: unknown[] = [];
    const onSignal = () => { interrupted = true; };
    process.once("SIGINT", onSignal);
    process.once("SIGTERM", onSignal);
    try {
      page = await startSetupPageServer({ browser: launcher.target, extensionPath });
      ticket = await createSetupTicket({
        extensionPath,
        setupId: page.setupId,
        setupSecret: page.setupSecret,
        expiresAt: page.expiresAt
      });
      pairingBeginAttempted = true;
      const begin = await callBridge("setup_pairing_begin", {
        setup_id: page.setupId,
        setup_secret: page.setupSecret,
        expires_at: page.expiresAt,
        browser_family: requestedFamily
      }, 5_000);
      if (
        !begin || typeof begin !== "object" || Array.isArray(begin) ||
        Object.keys(begin).sort().join(",") !== "browser_family,expires_at,setup_id,setup_pairing_ready" ||
        (begin as Record<string, unknown>).setup_pairing_ready !== true ||
        (begin as Record<string, unknown>).setup_id !== page.setupId ||
        (begin as Record<string, unknown>).expires_at !== page.expiresAt ||
        (begin as Record<string, unknown>).browser_family !== requestedFamily
      ) throw new Error("The daemon did not accept the exact one-click setup session.");
      if (interrupted) throw new Error("BrowseWeave setup was cancelled; no pairing key was exposed.");
      process.stdout.write(`${setupLoadInstruction(launcher, extensionPath, page.url)}\n`);
      try {
        await openSetupBrowser(launcher, page.url);
      } catch (error) {
        const message = error instanceof Error ? error.message.replace(/[\r\n]+/gu, " ").slice(0, 300) : "browser launch failed";
        process.stderr.write(
          `BrowseWeave could not open the browser pages automatically (${message}). ` +
          "The setup session remains active; follow the printed steps before it expires.\n"
        );
      }
      process.stdout.write(
        `A private setup page and ${launcher.label}'s extension screen are open. ` +
        "Load BrowseWeave, return to the setup page, and choose 'Connect this browser'. No key needs to be copied.\n"
      );
      const connected = await waitForSetupBrowser({
        setupId: page.setupId,
        family: requestedFamily,
        forbiddenBrowserIds: options.newProfile
          ? new Set(baseline.map((browser) => browser.browser_id))
          : new Set<string>(),
        expiresAt: page.expiresAt,
        interrupted: () => interrupted
      });
      selectedBrowser = connected;
      process.stdout.write(`${launcher.label} connected securely (${connected.browser_id}).\n`);
    } catch (error) {
      operationFailed = true;
      operationError = error;
    } finally {
      process.removeListener("SIGINT", onSignal);
      process.removeListener("SIGTERM", onSignal);
      if (pairingBeginAttempted && page) {
        try {
          const cancelled = await callBridge("setup_pairing_cancel", { setup_id: page.setupId }, 3_000);
          if (
            !cancelled || typeof cancelled !== "object" || Array.isArray(cancelled) ||
            Object.keys(cancelled).sort().join(",") !== "setup_id,setup_pairing_cancelled" ||
            (cancelled as Record<string, unknown>).setup_pairing_cancelled !== true ||
            (cancelled as Record<string, unknown>).setup_id !== page.setupId
          ) throw new Error("The daemon did not confirm setup-session cancellation.");
        } catch (error) {
          cleanupErrors.push(error);
        }
      }
      try {
        await ticket?.remove();
      } catch (error) {
        cleanupErrors.push(error);
      }
      try {
        await page?.close();
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (operationFailed) {
      if (cleanupErrors.length > 0) {
        throw new AggregateError(
          [operationError, ...cleanupErrors],
          "Browser setup failed and one or more short-lived resources also failed to clean up."
        );
      }
      throw operationError;
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(cleanupErrors, "Browser setup completed, but short-lived setup resources did not clean up safely.");
    }
  }

  // Initial enrollment uses the private local setup page. Register the native
  // reconnect helper only after the browser has saved the exact extension
  // identity, so a fresh unpacked Chrome installation never needs a wildcard.
  await installNativeHost(launcher.target);
  if (launcher.zenFlatpak) {
    const portal = await configureZenFlatpakNativeMessaging({ home: nativeAccountHome() });
    if (portal.status === "configured") {
      process.stdout.write(
        "Zen Flatpak native reconnect was enabled. Fully restart Zen once before using the Settings reconnect button.\n"
      );
    } else if (portal.status === "unavailable") {
      process.stderr.write(
        "BrowseWeave could not locate Zen's active Flatpak profile. Initial pairing succeeded, but the Settings reconnect helper may require Repair after Zen creates a profile.\n"
      );
    }
  }
  await configureSetupClients(setupClients, setupOpenCodeVersion);
  const connected = await daemonBrowsersWithRetry(5_000);
  if (!selectedBrowser || !connected.some((browser) =>
    browser.browser_id === selectedBrowser.browser_id
    && browser.browser_family === selectedBrowser.browser_family
    && browser.browser_name === selectedBrowser.browser_name
    && browser.browser_version === selectedBrowser.browser_version
    && browser.extension_version === APP_VERSION
  )) {
    throw new Error(`${launcher.label} did not remain connected after setup.`);
  }
  process.stdout.write(
    "BrowseWeave setup is complete. Start a new AI-client session and call browser_status.\n"
  );
}

function openCodeVersionFlag(rest: string[], required: boolean): 1 | 2 | undefined {
  const unexpected = rest.find((argument) => argument !== "--opencode-v1" && argument !== "--opencode-v2");
  if (unexpected) throw new Error(`Unexpected option: ${unexpected}`);
  const v1Count = rest.filter((argument) => argument === "--opencode-v1").length;
  const v2Count = rest.filter((argument) => argument === "--opencode-v2").length;
  if (v1Count > 1 || v2Count > 1 || (v1Count > 0 && v2Count > 0)) {
    throw new Error("Choose at most one of --opencode-v1 or --opencode-v2.");
  }
  if (v1Count === 0 && v2Count === 0) {
    if (required) throw new Error("Choose exactly one of --opencode-v1 or --opencode-v2.");
    return undefined;
  }
  return v2Count === 1 ? 2 : 1;
}

export async function main(): Promise<void> {
  const commandArgs = process.argv.slice(2);
  const [command, arg, ...rest] = commandArgs;
  if (!command || command === "help" || command === "--help" || command === "-h") {
    process.stdout.write(usage());
    return;
  }
  if (command === "--version" || command === "-v") {
    process.stdout.write(`${APP_VERSION}\n`);
    return;
  }
  if (command !== "setup" && await handOffCommandToPersistentInstall(commandArgs)) return;
  if (command === "doctor") {
    await doctor();
    return;
  }
  if (command === "setup") {
    const setupArgs = [arg, ...rest].filter((value): value is string => value !== undefined);
    await runSetup(parseSetupOptions(setupArgs), setupArgs);
    return;
  }
  if (command === "service-install") {
    await installService();
    return;
  }
  if (command === "service-uninstall") {
    await uninstallService();
    return;
  }
  if (command === "native-host-install") {
    await installNativeHost();
    return;
  }
  if (command === "native-host-uninstall") {
    await uninstallNativeHost();
    return;
  }
  if (command === "local-install") {
    await localInstall();
    return;
  }
  if (command === "local-uninstall") {
    const options = [arg, ...rest].filter((value): value is string => value !== undefined);
    if (options.length > 1 || (options.length === 1 && options[0] !== "--purge-data")) {
      throw new Error("local-uninstall accepts only the optional --purge-data flag.");
    }
    await localUninstall(options[0] === "--purge-data");
    return;
  }
  if (command === "mcp-config") {
    const client = parseClient(arg);
    const version = client === "opencode" ? openCodeVersionFlag(rest, true) : undefined;
    if (client !== "opencode" && rest.length > 0) throw new Error(`Unexpected option: ${rest[0]}`);
    process.stdout.write(serializeClientSetup(clientSetup(client, undefined, version)));
    return;
  }
  if (command === "mcp-add") {
    const client = parseClient(arg);
    const version = client === "opencode" ? openCodeVersionFlag(rest, false) : undefined;
    if (client !== "opencode" && rest.length > 0) throw new Error(`Unexpected option: ${rest[0]}`);
    await addMcpClient(client, version);
    return;
  }
  if (command === "extension-path") {
    if (rest.length > 0) throw new Error(`Unexpected option: ${rest[0]}`);
    await printExtensionPath(arg);
    return;
  }
  throw new Error(`Unknown command: ${command}\n\n${usage()}`);
}
