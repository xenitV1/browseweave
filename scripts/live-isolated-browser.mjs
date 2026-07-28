#!/usr/bin/env node

import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { execFile, spawn, spawnSync } from "node:child_process";
import { access, chmod, cp, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import net from "node:net";
import { WebSocket } from "ws";

const execFileAsync = promisify(execFile);
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDirectory, "..");
const fixturePath = path.join(projectRoot, "tests", "fixtures", "live-isolated-qa.html");
const DEFAULT_FIXTURE_PORT = 41_732;
const OLD_SERVICE = "zen-codex-bridge.service";
const NEW_SERVICE = "browseweave-daemon.service";
const WEB_EXT_VERSION = "10.5.0";
const ZEN_FLATPAK_APP_ID = "app.zen_browser.zen";
const DEFAULT_WS_LITERAL = "ws://127.0.0.1:32110";
const DEFAULT_DISPLAY_LITERAL = "127.0.0.1:32110";
const FIREFOX_OPTIONS_AUTO_OPEN_LITERAL = "if (token.length < 16) void extensionBrowser.runtime.openOptionsPage();";
const FIREFOX_OPTIONS_QA_LITERAL = "if (false && token.length < 16) void extensionBrowser.runtime.openOptionsPage();";
const GUIDED_SETUP_TIMEOUT_MS = 5 * 60_000;
const AUTOMATED_QA_TIMEOUT_MS = 2 * 60_000;
const TEMPORARY_BRIDGE_ENVIRONMENT_KEYS = [
  "XDG_CONFIG_HOME",
  "XDG_STATE_HOME",
  "XDG_RUNTIME_DIR",
  "TMPDIR",
  "BROWSER_MCP_BRIDGE_WS_PORT",
  "BROWSER_MCP_BRIDGE_IPC_PORT"
];
const PARALLEL_PATCH_EXPECTATIONS = new Map([
  ["PRIVACY.md", { ws: 1, display: 0 }],
  ["background.js", { ws: 1, display: 1 }],
  ["manifest.json", { ws: 1, display: 0 }],
  ["options.html", { ws: 1, display: 0 }],
  ["popup.html", { ws: 0, display: 1 }]
]);

function fail(message) {
  throw new Error(message);
}

function parseArguments(argv) {
  let browser = "chrome";
  let fixturePort = DEFAULT_FIXTURE_PORT;
  let fixturePortExplicit = false;
  let mode = "preflight";
  let explicitMode = false;
  const chooseMode = (nextMode) => {
    if (explicitMode && mode !== nextMode) fail("Choose exactly one of --preflight, --run, --parallel, or --parallel-self-test.");
    mode = nextMode;
    explicitMode = true;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--run") {
      chooseMode("run");
      continue;
    }
    if (argument === "--preflight") {
      chooseMode("preflight");
      continue;
    }
    if (argument === "--parallel") {
      chooseMode("parallel");
      continue;
    }
    if (argument === "--parallel-self-test") {
      chooseMode("parallel-self-test");
      continue;
    }
    if (argument === "--browser") {
      browser = argv[index + 1];
      index += 1;
      continue;
    }
    if (argument === "--fixture-port") {
      fixturePort = Number(argv[index + 1]);
      fixturePortExplicit = true;
      index += 1;
      continue;
    }
    if (argument === "--help" || argument === "-h") {
      process.stdout.write(
        "Usage: node scripts/live-isolated-browser.mjs [--preflight|--run|--parallel|--parallel-self-test] --browser chrome|zen [--fixture-port 41732]\n\n" +
        "Preflight is the default. --run is the post-cutover default-port check. --parallel proves protocol v3 on dynamic loopback ports while the legacy service stays active; --fixture-port is only an explicit override. --parallel-self-test proves temporary daemon/auth/guided-setup/patch/cleanup without opening a browser.\n"
      );
      process.exit(0);
    }
    fail(`Unknown option: ${argument}`);
  }
  if (browser !== "chrome" && browser !== "zen") fail("--browser must be chrome or zen.");
  if (!Number.isSafeInteger(fixturePort) || fixturePort < 1_024 || fixturePort > 65_535) {
    fail("--fixture-port must be an integer between 1024 and 65535.");
  }
  return { browser, fixturePort, fixturePortExplicit, mode };
}

function executableAvailable(command, args = ["--version"]) {
  return spawnSync(command, args, { stdio: "ignore" }).status === 0;
}

function serviceActive(service) {
  return spawnSync("systemctl", ["--user", "is-active", "--quiet", service], { stdio: "ignore" }).status === 0;
}

function parsedFlatpakApplications(output) {
  if (typeof output !== "string") fail("The Flatpak process list was not text.");
  const applications = [];
  for (const line of output.split(/\r?\n/gu)) {
    if (!line.trim()) continue;
    const fields = line.split("\t");
    if (
      fields.length !== 3 || !/^[A-Za-z0-9._-]+$/u.test(fields[0] || "") ||
      !/^\d+$/u.test(fields[1] || "") || !/^(?:\d+|[-?])$/u.test(fields[2] || "")
    ) fail("The Flatpak process list had an unexpected shape, so disposable Zen QA was refused.");
    applications.push(fields[0]);
  }
  return applications;
}

function flatpakApplicationListed(output, applicationId) {
  return parsedFlatpakApplications(output).includes(applicationId);
}

function zenApplicationRunning(run = spawnSync) {
  const flatpak = run("flatpak", ["ps", "--columns=application,pid,child-pid"], {
    encoding: "utf8",
    timeout: 5_000,
    maxBuffer: 256 * 1024
  });
  if (flatpak.error || flatpak.status !== 0) {
    fail("BrowseWeave could not verify whether Zen is already running, so disposable Zen QA was refused.");
  }
  const exactProcess = run("pgrep", ["-x", "zen"], {
    encoding: "utf8",
    timeout: 5_000,
    maxBuffer: 64 * 1024
  });
  if (exactProcess.error || (exactProcess.status !== 0 && exactProcess.status !== 1)) {
    fail("BrowseWeave could not safely check for an existing Zen process.");
  }
  return flatpakApplicationListed(flatpak.stdout, ZEN_FLATPAK_APP_ID) || exactProcess.status === 0;
}

async function portListening(port) {
  return await new Promise((resolve) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(500, () => finish(false));
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

async function extensionBuild(browserName) {
  const { APP_VERSION, BROWSER_EXTENSION_VERSION } = await import("../dist/src/version.js");
  const directory = path.join(
    projectRoot,
    "extension",
    "dist",
    browserName === "chrome" ? "chromium-mv3" : "firefox-mv2"
  );
  const manifestPath = path.join(directory, "manifest.json");
  let manifest;
  try {
    manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  } catch {
    fail(`Build the extension before live QA; manifest is missing or invalid: ${manifestPath}`);
  }
  const expectedManifestVersion = browserName === "chrome" ? 3 : 2;
  if (
    manifest.manifest_version !== expectedManifestVersion || manifest.name !== "BrowseWeave" ||
    manifest.version !== BROWSER_EXTENSION_VERSION || manifest.version_name !== APP_VERSION
  ) {
    fail(`The ${browserName} live-QA extension build is not the expected BrowseWeave manifest.`);
  }
  for (const relativePath of [
    "background.js",
    "content.js",
    "options.html",
    "options.js",
    "popup.html",
    "popup.js",
    "styles/ui.css",
    "icons/icon-16.png",
    "icons/icon-32.png",
    "icons/icon-48.png",
    "icons/icon-96.png",
    "icons/icon-128.png"
  ]) {
    try {
      await readFile(path.join(directory, relativePath));
    } catch {
      fail(`The extension build is incomplete; missing ${relativePath}. Run npm run build first.`);
    }
  }
  return directory;
}

function countLiteral(source, literal) {
  let count = 0;
  let offset = 0;
  while (true) {
    const index = source.indexOf(literal, offset);
    if (index < 0) return count;
    count += 1;
    offset = index + literal.length;
  }
}

async function extensionFiles(directory) {
  const files = [];
  const visit = async (current, prefix = "") => {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(current, entry.name);
      if (entry.isSymbolicLink()) fail(`The extension build contains an unsupported symbolic link: ${relative}`);
      if (entry.isDirectory()) await visit(absolute, relative);
      else if (entry.isFile()) files.push({ absolute, relative });
      else fail(`The extension build contains an unsupported filesystem entry: ${relative}`);
    }
  };
  await visit(directory);
  return files.sort((left, right) => left.relative.localeCompare(right.relative, "en"));
}

async function validateDefaultPortPatchSurface(directory) {
  const files = await extensionFiles(directory);
  const found = new Set();
  let totalWs = 0;
  let totalDisplay = 0;
  for (const file of files) {
    const contents = await readFile(file.absolute);
    const source = contents.toString("utf8");
    const expected = PARALLEL_PATCH_EXPECTATIONS.get(file.relative);
    const wsCount = countLiteral(source, DEFAULT_WS_LITERAL);
    const withoutWs = source.split(DEFAULT_WS_LITERAL).join("");
    const displayCount = countLiteral(withoutWs, DEFAULT_DISPLAY_LITERAL);
    const portCount = countLiteral(source, "32110");
    if (portCount > 0 && expected === undefined) {
      fail(`Refusing to patch an unexpected 32110 occurrence in ${file.relative}.`);
    }
    if (expected !== undefined) {
      found.add(file.relative);
      if (wsCount !== expected.ws || displayCount !== expected.display || portCount !== expected.ws + expected.display) {
        fail(
          `Refusing to patch ${file.relative}: expected ${expected.ws} WebSocket and ${expected.display} display literals, found ${wsCount} and ${displayCount}.`
        );
      }
      totalWs += wsCount;
      totalDisplay += displayCount;
    }
  }
  for (const expectedPath of PARALLEL_PATCH_EXPECTATIONS.keys()) {
    if (!found.has(expectedPath)) fail(`Refusing to patch an incomplete extension build; missing ${expectedPath}.`);
  }
  if (totalWs !== 4 || totalDisplay !== 2) {
    fail(`Refusing to patch an unexpected extension surface (${totalWs} WebSocket, ${totalDisplay} display literals).`);
  }
}

async function makeParallelExtensionCopy(sourceDirectory, destinationDirectory, webSocketPort) {
  if (!Number.isSafeInteger(webSocketPort) || webSocketPort < 1_024 || webSocketPort > 65_535 || webSocketPort === 32_110) {
    fail("The temporary WebSocket port is invalid.");
  }
  await validateDefaultPortPatchSurface(sourceDirectory);
  await cp(sourceDirectory, destinationDirectory, { recursive: true, errorOnExist: true, force: false });
  const manifest = JSON.parse(await readFile(path.join(destinationDirectory, "manifest.json"), "utf8"));
  if (manifest.manifest_version === 2) {
    const backgroundPath = path.join(destinationDirectory, "background.js");
    const background = await readFile(backgroundPath, "utf8");
    if (
      countLiteral(background, FIREFOX_OPTIONS_AUTO_OPEN_LITERAL) !== 1 ||
      background.includes(FIREFOX_OPTIONS_QA_LITERAL)
    ) fail("The temporary Zen QA copy has an unexpected install-time Settings hook.");
    const focused = background.replace(FIREFOX_OPTIONS_AUTO_OPEN_LITERAL, FIREFOX_OPTIONS_QA_LITERAL);
    if (
      focused.includes(FIREFOX_OPTIONS_AUTO_OPEN_LITERAL) ||
      countLiteral(focused, FIREFOX_OPTIONS_QA_LITERAL) !== 1
    ) fail("The temporary Zen QA copy could not keep the trusted setup tab visible.");
    await writeFile(backgroundPath, focused, "utf8");
  } else if (manifest.manifest_version !== 3) {
    fail("The temporary extension copy has an unsupported manifest version.");
  }
  const replacementWs = `ws://127.0.0.1:${webSocketPort}`;
  const replacementDisplay = `127.0.0.1:${webSocketPort}`;
  for (const [relative, expected] of PARALLEL_PATCH_EXPECTATIONS) {
    const filePath = path.join(destinationDirectory, relative);
    const source = await readFile(filePath, "utf8");
    const replacedWs = source.split(DEFAULT_WS_LITERAL).join(replacementWs);
    const patched = replacedWs.split(DEFAULT_DISPLAY_LITERAL).join(replacementDisplay);
    await writeFile(filePath, patched, "utf8");
    const wsCount = countLiteral(patched, replacementWs);
    const withoutWs = patched.split(replacementWs).join("");
    const displayCount = countLiteral(withoutWs, replacementDisplay);
    if (
      wsCount !== expected.ws || displayCount !== expected.display ||
      patched.includes(DEFAULT_WS_LITERAL) || patched.includes(DEFAULT_DISPLAY_LITERAL)
    ) {
      fail(`The temporary extension port patch failed integrity checks for ${relative}.`);
    }
  }
  for (const file of await extensionFiles(destinationDirectory)) {
    if ((await readFile(file.absolute)).includes(Buffer.from("32110", "utf8"))) {
      fail(`The temporary extension still contains the default port in ${file.relative}.`);
    }
  }
  return destinationDirectory;
}

async function reserveFreeLoopbackPort(excluded) {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const server = net.createServer();
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (address && typeof address === "object" && !excluded.has(address.port) && address.port >= 1_024) {
      excluded.add(address.port);
      return { server, port: address.port };
    }
    await closeNetServer(server);
  }
  fail("Could not reserve a safe dynamic loopback port.");
}

async function closeNetServer(server) {
  if (!server) return;
  await new Promise((resolve) => server.close(() => resolve()));
}

async function waitForChromeDevToolsEndpoint(port, browser) {
  const deadline = Date.now() + 15_000;
  let launchError;
  let lastError = "endpoint not ready";
  const onLaunchError = (error) => {
    launchError = error;
  };
  browser.once("error", onLaunchError);
  try {
    while (Date.now() < deadline) {
      if (launchError) {
        fail(`Google Chrome could not start: ${launchError instanceof Error ? launchError.message : String(launchError)}`);
      }
      if (childExited(browser)) {
        fail(`Google Chrome exited before its local DevTools endpoint became ready (${browser.signalCode || browser.exitCode}).`);
      }
      try {
        const response = await fetch(`http://127.0.0.1:${port}/json/version`, {
          cache: "no-store",
          signal: AbortSignal.timeout(750)
        });
        if (!response.ok) {
          lastError = `HTTP ${response.status}`;
        } else {
          const version = await response.json();
          const endpoint = new URL(version.webSocketDebuggerUrl);
          if (
            endpoint.protocol !== "ws:" ||
            (endpoint.hostname !== "127.0.0.1" && endpoint.hostname !== "localhost") ||
            Number(endpoint.port) !== port
          ) {
            fail("Google Chrome returned a non-local or unexpected DevTools endpoint.");
          }
          return endpoint.toString();
        }
      } catch (error) {
        lastError = error instanceof Error ? error.message.replace(/[\r\n]+/gu, " ").slice(0, 160) : "request failed";
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  } finally {
    browser.removeListener("error", onLaunchError);
  }
  fail(`Google Chrome's local DevTools endpoint did not become ready (${lastError}).`);
}

async function sendChromeDevToolsCommand(endpoint, method, parameters) {
  return await new Promise((resolve, reject) => {
    const socket = new WebSocket(endpoint, { perMessageDeflate: false });
    let settled = false;
    const timer = setTimeout(() => finish(new Error(`Chrome DevTools command ${method} timed out.`)), 8_000);
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.removeAllListeners();
      socket.on("error", () => undefined);
      if (socket.readyState === WebSocket.OPEN) socket.close();
      else if (socket.readyState !== WebSocket.CLOSED) socket.terminate();
      if (error) reject(error);
      else resolve(value);
    };
    socket.once("open", () => {
      socket.send(JSON.stringify({ id: 1, method, params: parameters }), (error) => {
        if (error) finish(error);
      });
    });
    socket.on("message", (data, isBinary) => {
      if (isBinary) {
        finish(new Error("Chrome DevTools returned an unexpected binary response."));
        return;
      }
      let message;
      try {
        message = JSON.parse(data.toString("utf8"));
      } catch {
        finish(new Error("Chrome DevTools returned invalid JSON."));
        return;
      }
      if (message.id !== 1) return;
      if (message.error) {
        const detail = typeof message.error.message === "string" ? message.error.message : "command rejected";
        finish(new Error(`Chrome DevTools rejected ${method}: ${detail}`));
        return;
      }
      finish(undefined, message.result);
    });
    socket.once("error", (error) => finish(error));
    socket.once("close", () => finish(new Error(`Chrome DevTools disconnected before ${method} completed.`)));
  });
}

async function loadTemporaryChromeExtension(debugPort, browser, extensionDirectory) {
  if (!path.isAbsolute(extensionDirectory)) fail("The temporary Chrome extension path must be absolute.");
  const endpoint = await waitForChromeDevToolsEndpoint(debugPort, browser);
  const result = await sendChromeDevToolsCommand(endpoint, "Extensions.loadUnpacked", { path: extensionDirectory });
  if (!result || typeof result.id !== "string" || !/^[a-p]{32}$/u.test(result.id)) {
    fail("Chrome DevTools did not confirm the temporary unpacked extension ID.");
  }
  return endpoint;
}

async function activateChromeSetupPage(endpoint, setupUrl, browser) {
  const parsedEndpoint = new URL(endpoint);
  const deadline = Date.now() + 10_000;
  let lastError = "setup target not ready";
  while (Date.now() < deadline) {
    if (childExited(browser)) {
      fail(`Google Chrome exited before its local setup page could be activated (${browser.signalCode || browser.exitCode}).`);
    }
    try {
      const response = await fetch(`http://127.0.0.1:${parsedEndpoint.port}/json/list`, {
        cache: "no-store",
        signal: AbortSignal.timeout(750)
      });
      if (!response.ok) {
        lastError = `HTTP ${response.status}`;
      } else {
        const targets = await response.json();
        if (!Array.isArray(targets) || targets.length > 100) fail("Chrome DevTools returned an invalid target list.");
        const matches = targets.filter((target) =>
          target && typeof target === "object" && target.type === "page" && target.url === setupUrl
        );
        if (matches.length > 1) fail("Chrome opened duplicate local setup pages.");
        const targetId = matches[0]?.id;
        if (typeof targetId === "string" && /^[A-Fa-f0-9]{32}$/u.test(targetId)) {
          await sendChromeDevToolsCommand(endpoint, "Target.activateTarget", { targetId });
          return;
        }
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message.replace(/[\r\n]+/gu, " ").slice(0, 160) : "request failed";
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  fail(`Chrome did not expose the exact local setup page to DevTools (${lastError}).`);
}

async function waitForZenTemporaryAddon(browserRunner) {
  const streams = [browserRunner.stdout, browserRunner.stderr].filter(Boolean);
  if (streams.length !== 2) fail("The Zen browser runner did not expose both output streams.");
  await new Promise((resolve, reject) => {
    let settled = false;
    let observed = "";
    const timer = setTimeout(() => finish(new Error("web-ext did not confirm the temporary Zen add-on within 60 seconds.")), 60_000);
    const onData = (chunk) => {
      observed = `${observed}${chunk.toString("utf8")}`.slice(-8_000);
      if (observed.includes("as a temporary add-on")) finish();
    };
    const onError = (error) => finish(error);
    const onExit = (code, signal) => finish(new Error(
      `The Zen browser runner exited before confirming the temporary add-on (${signal || code}).`
    ));
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const stream of streams) stream.removeListener("data", onData);
      browserRunner.removeListener("error", onError);
      browserRunner.removeListener("exit", onExit);
      if (error) reject(error);
      else resolve();
    };
    for (const stream of streams) stream.on("data", onData);
    browserRunner.once("error", onError);
    browserRunner.once("exit", onExit);
  });
}

function safeChromeDiagnostic(output) {
  return output
    .replace(/DevTools listening on ws:\/\/\S+/gu, "DevTools listening on [masked local endpoint]")
    .replace(/[\r\n]+/gu, " ")
    .trim()
    .slice(0, 1_000);
}

const SAFE_GUI_ENVIRONMENT_KEYS = new Set([
  "PATH",
  "HOME",
  "USER",
  "LOGNAME",
  "SHELL",
  "LANG",
  "DISPLAY",
  "WAYLAND_DISPLAY",
  "XAUTHORITY",
  "DBUS_SESSION_BUS_ADDRESS",
  "XDG_SESSION_TYPE",
  "XDG_CURRENT_DESKTOP",
  "XDG_SESSION_DESKTOP",
  "XDG_DATA_HOME",
  "XDG_DATA_DIRS",
  "DESKTOP_SESSION",
  "GDK_BACKEND",
  "QT_QPA_PLATFORM",
  "OZONE_PLATFORM",
  "OZONE_PLATFORM_HINT",
  "MOZ_ENABLE_WAYLAND",
  "PULSE_SERVER",
  "PIPEWIRE_REMOTE",
  "FONTCONFIG_PATH",
  "FONTCONFIG_FILE",
  "GTK_THEME",
  "TZ"
]);

function minimalGuiEnvironment() {
  const environment = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    if (SAFE_GUI_ENVIRONMENT_KEYS.has(key) || /^LC_[A-Z_]+$/u.test(key)) environment[key] = value;
  }
  return environment;
}

function sanitizedTemporaryEnvironment(paths, webSocketPort, ipcPort) {
  return {
    ...minimalGuiEnvironment(),
    XDG_CONFIG_HOME: paths.config,
    XDG_STATE_HOME: paths.state,
    XDG_RUNTIME_DIR: paths.runtime,
    TMPDIR: paths.tmp,
    NPM_CONFIG_USERCONFIG: paths.npmrc,
    NPM_CONFIG_CACHE: paths.npmCache,
    BROWSER_MCP_BRIDGE_WS_PORT: String(webSocketPort),
    BROWSER_MCP_BRIDGE_IPC_PORT: String(ipcPort),
    NO_UPDATE_NOTIFIER: "1"
  };
}

function temporaryRuntimePaths(temporaryRoot) {
  return {
    config: path.join(temporaryRoot, "xdg-config"),
    state: path.join(temporaryRoot, "xdg-state"),
    runtime: path.join(temporaryRoot, "xdg-runtime"),
    tmp: path.join(temporaryRoot, "tmp"),
    npmCache: path.join(temporaryRoot, "npm-cache"),
    npmrc: path.join(temporaryRoot, "npmrc")
  };
}

async function initializeTemporaryRuntimePaths(paths) {
  await Promise.all(Object.values(paths).filter((value) => value !== paths.npmrc).map((directory) => (
    mkdir(directory, { recursive: true, mode: 0o700 })
  )));
  await writeFile(paths.npmrc, "registry=https://registry.npmjs.org/\n", { encoding: "utf8", mode: 0o600, flag: "wx" });
}

async function verifiedNewDaemon() {
  try {
    const { callBridge } = await import("../dist/src/ipc-client.js");
    const status = await callBridge("status", {}, 5_000);
    if (
      !status || typeof status !== "object" || Array.isArray(status) ||
      status.service !== "browseweave" || status.protocol_version !== 3 || status.websocket_listening !== true
    ) {
      fail("The service on the default ports is not the expected BrowseWeave protocol-v3 daemon.");
    }
    return status;
  } catch (error) {
    fail(error instanceof Error
      ? `The new BrowseWeave daemon could not be authenticated: ${error.message}`
      : "The new BrowseWeave daemon could not be authenticated.");
  }
}

async function authenticateTemporaryDaemon(environment, daemon, output) {
  const probe = [
    "import { callBridge } from './dist/src/ipc-client.js';",
    "const status = await callBridge('status', {}, 2000);",
    "if (status?.service !== 'browseweave' || status?.protocol_version !== 3 || status?.websocket_listening !== true) process.exit(2);",
    "process.stdout.write('browseweave:3:ready');"
  ].join("\n");
  const deadline = Date.now() + 8_000;
  let lastError = "";
  while (Date.now() < deadline) {
    if (childExited(daemon)) {
      fail(`The temporary BrowseWeave daemon exited before authentication.${output() ? ` ${output()}` : ""}`);
    }
    try {
      const result = await execFileAsync(process.execPath, ["--input-type=module", "--eval", probe], {
        cwd: projectRoot,
        env: environment,
        timeout: 3_000,
        maxBuffer: 32 * 1024
      });
      if (result.stdout === "browseweave:3:ready") return;
      lastError = "unexpected authenticated status";
    } catch (error) {
      lastError = error instanceof Error ? error.message.replace(/[\r\n]+/gu, " ").slice(0, 240) : "probe failed";
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  fail(`The temporary protocol-v3 daemon could not authenticate over its alternate IPC port (${lastError}).`);
}

async function callTemporaryBridge(context, method, params = {}, timeoutMs = 5_000) {
  const previous = TEMPORARY_BRIDGE_ENVIRONMENT_KEYS.map((key) => ({
    key,
    present: Object.hasOwn(process.env, key),
    value: process.env[key]
  }));
  try {
    for (const key of TEMPORARY_BRIDGE_ENVIRONMENT_KEYS) {
      const value = context.environment[key];
      if (typeof value !== "string" || value.length === 0) {
        fail(`The temporary bridge environment is missing ${key}.`);
      }
      process.env[key] = value;
    }
    const { callBridge } = await import("../dist/src/ipc-client.js");
    return await callBridge(method, params, timeoutMs);
  } finally {
    for (const item of previous) {
      if (item.present && item.value !== undefined) process.env[item.key] = item.value;
      else delete process.env[item.key];
    }
  }
}

function exactObjectKeys(value, expected) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");
}

function assertSetupPairingBegin(value, expected) {
  if (
    !exactObjectKeys(value, [
      "setup_pairing_ready",
      "setup_id",
      "expires_at",
      "browser_family"
    ]) ||
    value.setup_pairing_ready !== true || value.setup_id !== expected.setupId ||
    value.expires_at !== expected.expiresAt || value.browser_family !== expected.browserFamily
  ) {
    fail("The temporary daemon did not accept the exact guided setup session.");
  }
}

async function waitForGuidedSetup(context, input) {
  const [{ APP_VERSION }, setupStatus] = await Promise.all([
    import("../dist/src/version.js"),
    import("../dist/src/setup-status.js")
  ]);
  const deadline = Math.min(Date.parse(input.expiresAt), Date.now() + GUIDED_SETUP_TIMEOUT_MS);
  let lastBridgeError = "";
  while (Date.now() < deadline) {
    if (input.interrupted()) fail("The disposable guided setup was interrupted.");
    if (childExited(input.browserRunner)) {
      fail(`The disposable browser exited during guided setup (${input.browserRunner.signalCode || input.browserRunner.exitCode}).`);
    }
    let receiptValue;
    try {
      receiptValue = await callTemporaryBridge(
        context,
        "setup_pairing_status",
        { setup_id: input.setupId },
        2_000
      );
      lastBridgeError = "";
    } catch (error) {
      lastBridgeError = error instanceof Error
        ? error.message.replace(/[\r\n]+/gu, " ").slice(0, 200)
        : "authenticated status call failed";
      await new Promise((resolve) => setTimeout(resolve, 300));
      continue;
    }
    const receipt = setupStatus.parseSetupPairingReceipt({
      value: receiptValue,
      setupId: input.setupId,
      expiresAt: input.expiresAt,
      browserFamily: input.browserFamily
    });
    if (receipt.setup_pairing_status === "not_found") {
      fail("The temporary guided setup session disappeared before completion.");
    }
    if (
      (receipt.setup_pairing_status === "pending" || receipt.setup_pairing_status === "completed") &&
      receipt.extension_version !== APP_VERSION
    ) {
      fail(`The loaded extension is ${receipt.extension_version}; live QA requires ${APP_VERSION}.`);
    }
    if (receipt.setup_pairing_status === "completed") {
      const browsers = setupStatus.parseSetupDaemonStatus(
        await callTemporaryBridge(context, "status", {}, 2_000)
      );
      const connected = browsers.find((browser) => setupStatus.receiptMatchesConnectedBrowser(receipt, browser));
      if (connected) return connected;
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  fail(
    "The trusted Connect this browser confirmation did not complete before the five-minute setup window expired." +
    (lastBridgeError ? ` Last authenticated status error: ${lastBridgeError}` : "")
  );
}

async function runGuidedSetup(context, input) {
  const { createSetupTicket, startSetupPageServer } = await import("../dist/src/setup-flow.js");
  const browserFamily = input.browser === "chrome" ? "chromium" : "firefox";
  let page;
  let ticket;
  let pairingStarted = false;
  let operationError;
  let connected;
  const cleanupErrors = [];
  try {
    page = await startSetupPageServer({
      browser: input.browser,
      extensionPath: context.extensionDirectory,
      ttlMs: GUIDED_SETUP_TIMEOUT_MS
    });
    ticket = await createSetupTicket({
      extensionPath: context.extensionDirectory,
      setupId: page.setupId,
      setupSecret: page.setupSecret,
      expiresAt: page.expiresAt
    });
    const begin = await callTemporaryBridge(context, "setup_pairing_begin", {
      setup_id: page.setupId,
      setup_secret: page.setupSecret,
      expires_at: page.expiresAt,
      browser_family: browserFamily
    });
    assertSetupPairingBegin(begin, {
      setupId: page.setupId,
      expiresAt: page.expiresAt,
      browserFamily
    });
    pairingStarted = true;
    await input.activateSetupPage(page.url);
    process.stdout.write(
      "\nBrowseWeave is ready in the disposable browser. Choose 'Connect this browser' once.\n" +
      "The extension was already loaded before its short-lived local ticket was created; no key is displayed or copied.\n\n"
    );
    connected = await waitForGuidedSetup(context, {
      setupId: page.setupId,
      expiresAt: page.expiresAt,
      browserFamily,
      browserRunner: input.browserRunner,
      interrupted: input.interrupted
    });
  } catch (error) {
    operationError = error;
  } finally {
    if (pairingStarted && page) {
      try {
        const cancelled = await callTemporaryBridge(
          context,
          "setup_pairing_cancel",
          { setup_id: page.setupId },
          3_000
        );
        if (
          !exactObjectKeys(cancelled, ["setup_pairing_cancelled", "setup_id"]) ||
          cancelled.setup_pairing_cancelled !== true || cancelled.setup_id !== page.setupId
        ) fail("The temporary daemon did not confirm guided setup cleanup.");
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
  if (operationError) {
    if (cleanupErrors.length > 0) {
      throw new AggregateError([operationError, ...cleanupErrors], "Guided setup and cleanup both failed.");
    }
    throw operationError;
  }
  if (cleanupErrors.length > 0) {
    throw new AggregateError(cleanupErrors, "Guided setup succeeded, but its short-lived resources were not fully removed.");
  }
  if (!connected) fail("The guided setup completed without an exact browser identity.");
  return connected;
}

async function validateTemporarySecretFiles(paths) {
  for (const filename of ["pairing-token", "ipc-token"]) {
    const filePath = path.join(paths.config, "browseweave", filename);
    const info = await lstat(filePath);
    if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0) {
      fail(`The temporary ${filename} was not created as an owner-only regular file.`);
    }
  }
}

async function waitForClosedPorts(ports) {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const states = await Promise.all(ports.map((port) => portListening(port)));
    if (states.every((listening) => !listening)) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  fail(`A temporary BrowseWeave port remained open after cleanup: ${ports.join(", ")}`);
}

async function waitForProcessExit(child, timeoutMs) {
  if (!child || childExited(child)) return;
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, timeoutMs))
  ]);
}

async function stopProcessGroup(child) {
  if (!child || childExited(child)) return;
  terminateProcessGroup(child);
  await waitForProcessExit(child, 3_000);
  if (!childExited(child) && child.pid) {
    try {
      if (detachedProcessGroupOwned(child.pid)) process.kill(-child.pid, "SIGKILL");
      else child.kill("SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
    await waitForProcessExit(child, 2_000);
  }
  if (!childExited(child)) fail("A temporary process could not be stopped safely.");
}

async function withParallelRuntime(state, operation, additionalExcludedPorts = []) {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), "browseweave-live-qa-"));
  const paths = temporaryRuntimePaths(temporaryRoot);
  let webSocketReservation;
  let ipcReservation;
  let daemon;
  let webSocketPort;
  let ipcPort;
  let operationResult;
  let operationError;
  let daemonOutput = "";
  const appendDaemonOutput = (chunk) => {
    if (daemonOutput.length >= 4_000) return;
    daemonOutput += chunk.toString("utf8").replace(/[\r\n]+/gu, " ").slice(0, 4_000 - daemonOutput.length);
  };
  try {
    await initializeTemporaryRuntimePaths(paths);
    const excluded = new Set([32_110, 32_111, DEFAULT_FIXTURE_PORT, ...additionalExcludedPorts]);
    webSocketReservation = await reserveFreeLoopbackPort(excluded);
    ipcReservation = await reserveFreeLoopbackPort(excluded);
    webSocketPort = webSocketReservation.port;
    ipcPort = ipcReservation.port;
    const extensionDirectory = await makeParallelExtensionCopy(
      state.extensionDirectory,
      path.join(temporaryRoot, "extension"),
      webSocketPort
    );
    const environment = sanitizedTemporaryEnvironment(paths, webSocketPort, ipcPort);
    await Promise.all([closeNetServer(webSocketReservation.server), closeNetServer(ipcReservation.server)]);
    webSocketReservation = undefined;
    ipcReservation = undefined;
    daemon = spawn(process.execPath, [path.join(projectRoot, "dist", "src", "daemon.js")], {
      cwd: projectRoot,
      detached: true,
      env: environment,
      stdio: ["ignore", "pipe", "pipe"]
    });
    daemon.stdout?.on("data", appendDaemonOutput);
    daemon.stderr?.on("data", appendDaemonOutput);
    await authenticateTemporaryDaemon(environment, daemon, () => daemonOutput.trim());
    await validateTemporarySecretFiles(paths);
    operationResult = await operation({
      temporaryRoot,
      paths,
      environment,
      extensionDirectory,
      webSocketPort,
      ipcPort
    });
  } catch (error) {
    operationError = error;
  } finally {
    let cleanupError;
    try {
      await closeNetServer(webSocketReservation?.server).catch(() => undefined);
      await closeNetServer(ipcReservation?.server).catch(() => undefined);
      await stopProcessGroup(daemon);
      if (webSocketPort !== undefined && ipcPort !== undefined) {
        await waitForClosedPorts([webSocketPort, ipcPort]);
      }
      await removeTemporaryRoot(temporaryRoot);
      try {
        await access(temporaryRoot);
        fail("The temporary parallel-QA root still exists after cleanup.");
      } catch (error) {
        if (error instanceof Error && "code" in error && error.code !== "ENOENT") throw error;
      }
    } catch (error) {
      cleanupError = error;
    }
    if (cleanupError && !operationError) operationError = cleanupError;
  }
  if (operationError) throw operationError;
  return operationResult;
}

async function preflight(options) {
  if (process.platform !== "linux") fail("This live-isolation launcher is intentionally Linux-only.");
  if (!process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) {
    fail("No graphical desktop display is available for a visible browser QA run.");
  }
  if (!executableAvailable("openssl", ["version"])) fail("OpenSSL is required to create an ephemeral localhost certificate.");
  if (!executableAvailable("npx")) fail("npx is required to run the exact isolated web-ext browser launcher.");

  if (options.browser === "chrome") {
    if (!executableAvailable("/usr/bin/google-chrome-stable")) {
      fail("Google Chrome Stable was not found at /usr/bin/google-chrome-stable.");
    }
    if ((options.mode === "parallel" || options.mode === "parallel-self-test") && !process.env.DISPLAY) {
      fail("Parallel Chrome QA needs an X11/XWayland DISPLAY so the browser can keep a fully temporary XDG runtime.");
    }
  } else if (!executableAvailable("flatpak", ["info", ZEN_FLATPAK_APP_ID])) {
    fail(`The Zen Flatpak app ${ZEN_FLATPAK_APP_ID} is not installed for this user.`);
  }

  const zenAlreadyRunning = options.browser === "zen" ? zenApplicationRunning() : false;
  if (zenAlreadyRunning && (options.mode === "run" || options.mode === "parallel")) {
    fail(
      "Zen is already open. Disposable Zen QA was refused because stopping the Flatpak test sandbox can also close an existing Zen session. " +
      "Save your work, close Zen yourself, and retry only when no Zen window is running."
    );
  }

  const extensionDirectory = await extensionBuild(options.browser);
  const oldActive = serviceActive(OLD_SERVICE);
  const newActive = serviceActive(NEW_SERVICE);
  const [webSocketListening, ipcListening] = await Promise.all([
    portListening(32_110),
    portListening(32_111)
  ]);
  process.stdout.write(
    `${options.browser === "chrome" ? "Chrome Stable" : "Zen"} isolated-live-QA preflight\n` +
    `  Extension build: ${extensionDirectory}\n` +
    `  Legacy service active: ${oldActive ? "yes" : "no"}\n` +
    `  BrowseWeave service active: ${newActive ? "yes" : "no"}\n` +
    (options.browser === "zen" ? `  Existing Zen session: ${zenAlreadyRunning ? "yes" : "no"}\n` : "") +
    `  Default WebSocket port 32110: ${webSocketListening ? "listening" : "closed"}\n` +
    `  Default IPC port 32111: ${ipcListening ? "listening" : "closed"}\n`
  );
  return { extensionDirectory, oldActive, newActive, webSocketListening, ipcListening, zenAlreadyRunning };
}

async function generateCertificate(directory) {
  const keyPath = path.join(directory, "localhost-key.pem");
  const certificatePath = path.join(directory, "localhost-cert.pem");
  await execFileAsync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
    "-keyout", keyPath,
    "-out", certificatePath,
    "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-addext", "keyUsage=digitalSignature,keyEncipherment",
    "-addext", "extendedKeyUsage=serverAuth"
  ], { maxBuffer: 1024 * 1024 });
  await chmod(keyPath, 0o600);
  const [key, certificate] = await Promise.all([
    readFile(keyPath),
    readFile(certificatePath)
  ]);
  const publicKey = new X509Certificate(certificate).publicKey.export({ type: "spki", format: "der" });
  const spkiSha256 = createHash("sha256").update(publicKey).digest("base64");
  return { key, certificate, spkiSha256 };
}

async function listen(server, port) {
  await new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once("error", onError);
    server.listen(port, "127.0.0.1", () => {
      server.off("error", onError);
      resolve();
    });
  });
}

async function closeServer(server) {
  await new Promise((resolve) => server.close(() => resolve()));
}

function safeTemporaryRoot(directory) {
  const expectedPrefix = path.join(tmpdir(), "browseweave-live-qa-");
  return path.isAbsolute(directory) && directory.startsWith(expectedPrefix) && directory.length > expectedPrefix.length;
}

async function removeTemporaryRoot(directory) {
  if (!safeTemporaryRoot(directory)) fail("Refusing to remove an unexpected live-QA directory.");
  await rm(directory, { recursive: true, force: true });
}

function childExited(child) {
  return Boolean(child) && (child.exitCode !== null || child.signalCode !== null);
}

function terminateProcessGroup(child) {
  if (!child || childExited(child) || !child.pid) return;
  try {
    if (detachedProcessGroupOwned(child.pid)) process.kill(-child.pid, "SIGTERM");
    else child.kill("SIGTERM");
  } catch {
    try {
      child.kill("SIGTERM");
    } catch {
      // The browser runner already exited.
    }
  }
}

function detachedProcessGroupOwned(pid, run = spawnSync) {
  if (!Number.isSafeInteger(pid) || pid <= 1) return false;
  const result = run("ps", ["-o", "pgid=", "-p", String(pid)], {
    encoding: "utf8",
    timeout: 2_000,
    maxBuffer: 16 * 1024
  });
  if (result.error || result.status !== 0) return false;
  const processGroupId = Number(String(result.stdout).trim());
  return Number.isSafeInteger(processGroupId) && processGroupId === pid;
}

async function waitForSetupLanding(input) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (input.interrupted()) fail("The disposable browser launch was interrupted.");
    if (childExited(input.browserRunner)) {
      fail(`The disposable browser exited before opening its local setup landing page (${input.browserRunner.signalCode || input.browserRunner.exitCode}).`);
    }
    if (input.observed()) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  fail("The disposable browser did not open its local setup landing page.");
}

async function runAutomatedBridgeQa(context, input) {
  const runner = spawn(process.execPath, [
    path.join(projectRoot, "scripts", "live-isolated-bridge-qa.mjs"),
    "--fixture-url",
    input.fixtureUrl,
    "--browser-id",
    input.browserId,
    "--skip-credential",
    "--allow-http-loopback-fixture",
    "--recover-missing-marker"
  ], {
    cwd: projectRoot,
    detached: true,
    stdio: "inherit",
    env: context.environment
  });
  input.runnerStarted(runner);
  let timeoutHandle;
  const outcome = await Promise.race([
    new Promise((resolve) => {
      runner.once("error", (error) => resolve({ kind: "error", error }));
      runner.once("exit", (code, signal) => resolve({ kind: "exit", code, signal }));
    }),
    new Promise((resolve) => {
      timeoutHandle = setTimeout(() => resolve({ kind: "timeout" }), AUTOMATED_QA_TIMEOUT_MS);
    })
  ]);
  clearTimeout(timeoutHandle);
  if (outcome.kind === "timeout") {
    await stopProcessGroup(runner);
    fail("The automatic disposable-browser QA exceeded its two-minute limit.");
  }
  if (outcome.kind === "error") throw outcome.error;
  if (input.interrupted()) {
    await stopProcessGroup(runner);
    fail("The automatic disposable-browser QA was interrupted.");
  }
  if (outcome.code !== 0) {
    fail(`The automatic disposable-browser QA failed (${outcome.signal || outcome.code}).`);
  }
}

async function runBrowser(options, state) {
  void options;
  void state;
  fail(
    "The old default-port --run path was retired because it required printing a pairing credential. " +
    "Use --parallel for the isolated guided one-click setup path."
  );
  if (state.oldActive) {
    fail(
      "The legacy zen-codex-bridge.service is still active. This launcher will not interrupt it or reuse its port. Complete the controlled cutover first."
    );
  }
  if (!state.webSocketListening || !state.ipcListening) {
    fail("The authenticated BrowseWeave daemon must be listening on both default ports before live QA.");
  }
  await verifiedNewDaemon();

  const temporaryRoot = await mkdtemp(path.join(tmpdir(), "browseweave-live-qa-"));
  const temporaryPaths = temporaryRuntimePaths(temporaryRoot);
  const runId = randomBytes(12).toString("hex");
  let server;
  let child;
  let interrupted = false;
  try {
    await initializeTemporaryRuntimePaths(temporaryPaths);
    const environment = sanitizedTemporaryEnvironment(temporaryPaths, 32_110, 32_111);
    const fixture = await readFile(fixturePath);
    const certificate = await generateCertificate(temporaryRoot);
    server = createHttpsServer({ key: certificate.key, cert: certificate.certificate }, (request, response) => {
      const url = new URL(request.url || "/", "https://localhost");
      if (url.pathname === "/health") {
        response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
        response.end("ok");
        return;
      }
      if (url.pathname !== "/live-isolated-qa.html") {
        response.writeHead(404, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
        response.end("Not found");
        return;
      }
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff"
      });
      response.end(fixture);
    });
    await listen(server, options.fixturePort);

    const fixtureUrl = `https://localhost:${options.fixturePort}/live-isolated-qa.html?qa_run=${runId}`;
    const artifactsDirectory = path.join(temporaryRoot, "web-ext-artifacts");
    const webExtArguments = [
      "--yes",
      `web-ext@${WEB_EXT_VERSION}`,
      "run",
      "--no-config-discovery",
      "--no-reload",
      "--no-input",
      `--source-dir=${state.extensionDirectory}`,
      `--artifacts-dir=${artifactsDirectory}`,
      `--start-url=${fixtureUrl}`
    ];
    if (options.browser === "chrome") {
      webExtArguments.push(
        "--target=chromium",
        "--chromium-binary=/usr/bin/google-chrome-stable",
        "--args=--no-first-run",
        "--args=--no-default-browser-check",
        "--args=--disable-sync",
        // Keep the browser's automation signal truthful. web-ext otherwise
        // disables it by default, which is outside BrowseWeave's policy.
        "--args=--enable-blink-features=AutomationControlled",
        `--args=--ignore-certificate-errors-spki-list=${certificate.spkiSha256}`
      );
    } else {
      webExtArguments.push(
        "--target=firefox-desktop",
        "--firefox=flatpak:app.zen_browser.zen"
      );
    }

    process.stdout.write(
      "\nA disposable browser profile is about to open. The normal browser profile is not used.\n" +
      `Fixture URL: ${fixtureUrl}\n\n` +
      "This retired default-port path cannot enroll a disposable extension. Use --parallel so the private guided setup page keeps the credential hidden.\n" +
      (options.browser === "zen"
        ? "If Zen shows a localhost certificate warning, accept it only for the disposable profile.\n"
        : "") +
      "\nKeep the fixture tab open. In a second terminal, run:\n" +
      `  node scripts/live-isolated-bridge-qa.mjs --fixture-url '${fixtureUrl}'\n\n` +
      "Close the disposable browser when QA finishes; its profile and certificate will then be deleted.\n\n"
    );

    child = spawn("npx", webExtArguments, {
      cwd: projectRoot,
      detached: true,
      stdio: "inherit",
      env: environment
    });
    for (const signal of ["SIGINT", "SIGTERM"]) {
      process.once(signal, () => {
        interrupted = true;
        terminateProcessGroup(child);
      });
    }
    const outcome = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code, signal) => resolve({ code, signal }));
    });
    if (!interrupted && outcome.code !== 0) {
      fail(`The isolated browser runner exited unsuccessfully (${outcome.signal || outcome.code}).`);
    }
    if (interrupted) process.exitCode = 130;
  } finally {
    terminateProcessGroup(child);
    if (server) await closeServer(server).catch(() => undefined);
    await removeTemporaryRoot(temporaryRoot);
    process.stdout.write("Disposable browser profile, local certificate, and live-QA artifacts removed.\n");
  }
}

async function runParallelBrowser(options, state) {
  await withParallelRuntime(state, async (context) => {
    const runId = randomBytes(12).toString("hex");
    const fixture = await readFile(fixturePath);
    let fixturePort = options.fixturePortExplicit ? options.fixturePort : 0;
    const setupLandingPath = `/guided-setup/${runId}`;
    let setupRedirectUrl = "";
    let setupLandingObserved = false;
    const server = createHttpServer((request, response) => {
      const url = new URL(request.url || "/", `http://127.0.0.1:${fixturePort}`);
      if (url.pathname === "/health") {
        response.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
        response.end("ok");
        return;
      }
      if (request.method === "GET" && url.pathname === setupLandingPath && !url.search && !url.hash) {
        setupLandingObserved = true;
        if (setupRedirectUrl) {
          response.writeHead(302, {
            location: setupRedirectUrl,
            "cache-control": "no-store",
            "referrer-policy": "no-referrer",
            "x-content-type-options": "nosniff"
          });
          response.end();
          return;
        }
        response.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store, no-cache, must-revalidate",
          refresh: "1",
          "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
          "referrer-policy": "no-referrer",
          "x-content-type-options": "nosniff"
        });
        response.end(
          "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">" +
          "<title>Preparing BrowseWeave</title><style>body{font:18px system-ui;margin:10vh auto;max-width:42rem;padding:1rem;color:#132238}</style>" +
          "<h1>Preparing BrowseWeave</h1><p>The disposable extension is loading. This page will continue automatically.</p></html>"
        );
        return;
      }
      if (request.method !== "GET" || url.pathname !== "/live-isolated-qa.html") {
        response.writeHead(404, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
        response.end("Not found");
        return;
      }
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; form-action 'self'",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff"
      });
      response.end(fixture);
    });
    let browserRunner;
    let qaRunner;
    let debugReservation;
    let debugPort;
    let chromeDevToolsEndpoint;
    let interrupted = false;
    let chromeOutput = "";
    const signalHandlers = new Map();
    const appendChromeOutput = (chunk) => {
      if (chromeOutput.length >= 4_000) return;
      chromeOutput += chunk.toString("utf8").slice(0, 4_000 - chromeOutput.length);
    };
    try {
      await listen(server, fixturePort);
      if (fixturePort === 0) {
        const address = server.address();
        if (!address || typeof address === "string" || address.address !== "127.0.0.1" || address.port < 1_024) {
          fail("The disposable fixture did not receive a safe dynamic loopback port.");
        }
        fixturePort = address.port;
      }
      const fixtureUrl = `http://127.0.0.1:${fixturePort}/live-isolated-qa.html?qa_run=${runId}`;
      const setupLandingUrl = `http://127.0.0.1:${fixturePort}${setupLandingPath}`;
      const browserProfile = path.join(context.temporaryRoot, "browser-profile");
      await mkdir(browserProfile, { mode: 0o700 });
      if (options.browser === "chrome") {
        const excluded = new Set([
          32_110,
          32_111,
          fixturePort,
          context.webSocketPort,
          context.ipcPort
        ]);
        debugReservation = await reserveFreeLoopbackPort(excluded);
        debugPort = debugReservation.port;
        await closeNetServer(debugReservation.server);
        debugReservation = undefined;
        browserRunner = spawn("/usr/bin/google-chrome-stable", [
          `--user-data-dir=${browserProfile}`,
          "--no-first-run",
          "--no-default-browser-check",
          "--disable-sync",
          "--password-store=basic",
          "--ozone-platform=x11",
          "--enable-automation",
          "--remote-debugging-address=127.0.0.1",
          `--remote-debugging-port=${debugPort}`,
          "--enable-unsafe-extension-debugging",
          "--enable-blink-features=AutomationControlled",
          fixtureUrl,
          setupLandingUrl
        ], {
          cwd: projectRoot,
          detached: true,
          stdio: ["ignore", "pipe", "pipe"],
          env: context.environment
        });
        browserRunner.stdout?.on("data", appendChromeOutput);
        browserRunner.stderr?.on("data", appendChromeOutput);
      } else {
        const webExtArguments = [
          "--yes",
          `web-ext@${WEB_EXT_VERSION}`,
          "run",
          "--no-config-discovery",
          "--no-reload",
          "--no-input",
          `--source-dir=${context.extensionDirectory}`,
          `--artifacts-dir=${path.join(context.temporaryRoot, "web-ext-artifacts")}`,
          `--start-url=${setupLandingUrl}`,
          `--start-url=${fixtureUrl}`,
          "--profile-create-if-missing",
          "--keep-profile-changes",
          "--target=firefox-desktop",
          "--firefox=flatpak:app.zen_browser.zen",
          `--firefox-profile=${browserProfile}`
        ];
        browserRunner = spawn("npx", webExtArguments, {
          cwd: projectRoot,
          detached: true,
          stdio: ["ignore", "pipe", "pipe"],
          env: context.environment
        });
        browserRunner.stdout?.pipe(process.stdout, { end: false });
        browserRunner.stderr?.pipe(process.stderr, { end: false });
      }

      for (const signal of ["SIGINT", "SIGTERM"]) {
        const handler = () => {
          interrupted = true;
          terminateProcessGroup(browserRunner);
          terminateProcessGroup(qaRunner);
        };
        signalHandlers.set(signal, handler);
        process.once(signal, handler);
      }
      if (options.browser === "chrome") {
        try {
          chromeDevToolsEndpoint = await loadTemporaryChromeExtension(
            debugPort,
            browserRunner,
            context.extensionDirectory
          );
        } catch (error) {
          if (interrupted) {
            process.exitCode = 130;
            return;
          }
          const diagnostic = safeChromeDiagnostic(chromeOutput);
          const message = error instanceof Error ? error.message : String(error);
          fail(`${message}${diagnostic ? ` Chrome said: ${diagnostic}` : ""}`);
        }
      } else {
        try {
          await waitForZenTemporaryAddon(browserRunner);
        } catch (error) {
          if (interrupted) {
            process.exitCode = 130;
            return;
          }
          throw error;
        }
      }

      await waitForSetupLanding({
        browserRunner,
        interrupted: () => interrupted,
        observed: () => setupLandingObserved
      });
      const connected = await runGuidedSetup(context, {
        browser: options.browser,
        browserRunner,
        interrupted: () => interrupted,
        async activateSetupPage(value) {
          const parsed = new URL(value);
          if (
            parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1" || !parsed.port ||
            parsed.username || parsed.password || parsed.search || parsed.hash ||
            !/^\/setup\/[a-f0-9]{24}$/u.test(parsed.pathname)
          ) fail("The generated local setup page URL was not the exact secretless loopback form.");
          setupRedirectUrl = parsed.toString();
          if (options.browser === "chrome") {
            if (!chromeDevToolsEndpoint) fail("Chrome DevTools was not ready to activate the local setup page.");
            await activateChromeSetupPage(chromeDevToolsEndpoint, setupRedirectUrl, browserRunner);
          }
        }
      });
      process.stdout.write(
        "\nGuided one-click setup completed with an exact browser receipt.\n" +
        (options.browser === "chrome" ? "  Chrome MV3 load was confirmed by DevTools before ticket creation.\n" : "") +
        (options.browser === "zen"
          ? "  Zen MV2 load was confirmed by web-ext before ticket creation; only its disposable install-time Settings auto-open was suppressed so consent stayed visible.\n"
          : "") +
        `  Connected browser: ${connected.browser_id} (${connected.browser_name} ${connected.browser_version})\n` +
        `  Extension version: ${connected.extension_version}\n` +
        `  Alternate WebSocket port: ${context.webSocketPort}\n` +
        `  Alternate IPC port: ${context.ipcPort}\n` +
        "  Default ports and both user services were left unchanged.\n" +
        `  Disposable fixture: ${fixtureUrl}\n` +
        "Running isolated bridge checks automatically; credential handoff is skipped so no second human action is requested.\n\n"
      );
      await runAutomatedBridgeQa(context, {
        fixtureUrl,
        browserId: connected.browser_id,
        interrupted: () => interrupted,
        runnerStarted(runner) {
          qaRunner = runner;
        }
      });
      process.stdout.write("Automatic disposable-browser QA passed; closing the browser and cleaning the isolated runtime.\n");
    } catch (error) {
      if (interrupted) {
        process.exitCode = 130;
        return;
      }
      throw error;
    } finally {
      for (const [signal, handler] of signalHandlers) process.removeListener(signal, handler);
      let cleanupError;
      for (const cleanup of [
        () => closeNetServer(debugReservation?.server),
        () => stopProcessGroup(qaRunner),
        () => stopProcessGroup(browserRunner),
        () => debugPort === undefined ? Promise.resolve() : waitForClosedPorts([debugPort]),
        () => closeServer(server)
      ]) {
        try {
          await cleanup();
        } catch (error) {
          cleanupError ||= error;
        }
      }
      if (cleanupError) throw cleanupError;
    }
  }, options.fixturePortExplicit ? [options.fixturePort] : []);
  process.stdout.write("Parallel protocol-v3 daemon and every disposable QA artifact were removed.\n");
}

async function verifyGuidedSetupControlPlane(context, browser) {
  const [{ createSetupTicket, startSetupPageServer }, { parseSetupPairingReceipt }] = await Promise.all([
    import("../dist/src/setup-flow.js"),
    import("../dist/src/setup-status.js")
  ]);
  const browserFamily = browser === "chrome" ? "chromium" : "firefox";
  let page;
  let ticket;
  let pairingStarted = false;
  try {
    page = await startSetupPageServer({
      browser,
      extensionPath: context.extensionDirectory,
      ttlMs: 30_000
    });
    ticket = await createSetupTicket({
      extensionPath: context.extensionDirectory,
      setupId: page.setupId,
      setupSecret: page.setupSecret,
      expiresAt: page.expiresAt
    });
    const begin = await callTemporaryBridge(context, "setup_pairing_begin", {
      setup_id: page.setupId,
      setup_secret: page.setupSecret,
      expires_at: page.expiresAt,
      browser_family: browserFamily
    });
    assertSetupPairingBegin(begin, {
      setupId: page.setupId,
      expiresAt: page.expiresAt,
      browserFamily
    });
    pairingStarted = true;
    const status = parseSetupPairingReceipt({
      value: await callTemporaryBridge(context, "setup_pairing_status", { setup_id: page.setupId }),
      setupId: page.setupId,
      expiresAt: page.expiresAt,
      browserFamily
    });
    if (status.setup_pairing_status !== "waiting") {
      fail("The guided setup control-plane self-test did not remain in its exact waiting state.");
    }
  } finally {
    if (pairingStarted && page) {
      const cancelled = await callTemporaryBridge(
        context,
        "setup_pairing_cancel",
        { setup_id: page.setupId },
        3_000
      );
      if (
        !exactObjectKeys(cancelled, ["setup_pairing_cancelled", "setup_id"]) ||
        cancelled.setup_pairing_cancelled !== true || cancelled.setup_id !== page.setupId
      ) fail("The guided setup control-plane self-test did not cancel exactly.");
    }
    await ticket?.remove();
    await page?.close();
  }
  try {
    await lstat(path.join(context.extensionDirectory, "setup-ticket.json"));
    fail("The guided setup control-plane self-test left a ticket in the extension copy.");
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
  }
}

async function runParallelSelfTest(state, browser) {
  if (
    !flatpakApplicationListed(`${ZEN_FLATPAK_APP_ID}\t123\t456\ncom.example.Other\t789\t790\n`, ZEN_FLATPAK_APP_ID) ||
    flatpakApplicationListed(`app.zen_browser.zen-beta\t123\t456\n`, ZEN_FLATPAK_APP_ID)
  ) fail("The exact Zen Flatpak process-list parser failed its self-test.");
  let malformedFlatpakRefused = false;
  try {
    flatpakApplicationListed("unexpected process-list columns", ZEN_FLATPAK_APP_ID);
  } catch (error) {
    malformedFlatpakRefused = error instanceof Error && error.message.includes("unexpected shape");
  }
  if (!malformedFlatpakRefused) fail("A malformed Flatpak process list did not fail closed.");
  let failedProbeRefused = false;
  try {
    zenApplicationRunning(() => ({ error: new Error("simulated probe failure"), status: null, stdout: "" }));
  } catch (error) {
    failedProbeRefused = error instanceof Error && error.message.includes("could not verify");
  }
  if (!failedProbeRefused) fail("A failed Zen process probe did not fail closed.");
  const matchingGroup = detachedProcessGroupOwned(4321, () => ({ status: 0, stdout: "4321\n" }));
  const mismatchedGroup = detachedProcessGroupOwned(4321, () => ({ status: 0, stdout: "9876\n" }));
  if (!matchingGroup || mismatchedGroup) fail("Detached process-group ownership matching failed its self-test.");
  const before = {
    oldService: serviceActive(OLD_SERVICE),
    newService: serviceActive(NEW_SERVICE),
    defaultWebSocket: await portListening(32_110),
    defaultIpc: await portListening(32_111)
  };
  let alternatePorts = [];
  await withParallelRuntime(state, async (context) => {
    alternatePorts = [context.webSocketPort, context.ipcPort];
    if (alternatePorts.some((port) => port === 32_110 || port === 32_111)) {
      fail("A parallel self-test selected a default BrowseWeave port.");
    }
    if (!(await portListening(context.webSocketPort)) || !(await portListening(context.ipcPort))) {
      fail("The authenticated temporary daemon is not listening on both alternate ports.");
    }
    const manifest = JSON.parse(await readFile(path.join(context.extensionDirectory, "manifest.json"), "utf8"));
    if (!JSON.stringify(manifest).includes(`ws://127.0.0.1:${context.webSocketPort}`)) {
      fail("The temporary extension manifest does not contain its alternate WebSocket port.");
    }
    await verifyGuidedSetupControlPlane(context, browser);
    const refusalSource = path.join(context.temporaryRoot, "refusal-source");
    await cp(state.extensionDirectory, refusalSource, { recursive: true, errorOnExist: true, force: false });
    await writeFile(path.join(refusalSource, "unexpected-default-port.txt"), DEFAULT_DISPLAY_LITERAL, "utf8");
    let unsafePatchRefused = false;
    try {
      await makeParallelExtensionCopy(
        refusalSource,
        path.join(context.temporaryRoot, "refusal-output"),
        context.webSocketPort
      );
    } catch (error) {
      if (error instanceof Error && error.message.includes("unexpected 32110 occurrence")) unsafePatchRefused = true;
      else throw error;
    }
    if (!unsafePatchRefused) fail("The temporary extension patcher accepted an unexpected default-port literal.");
    process.stdout.write(
      `Parallel self-test authenticated protocol v3 on temporary ports ${context.webSocketPort}/${context.ipcPort}.\n`
    );
  });
  const after = {
    oldService: serviceActive(OLD_SERVICE),
    newService: serviceActive(NEW_SERVICE),
    defaultWebSocket: await portListening(32_110),
    defaultIpc: await portListening(32_111)
  };
  if (JSON.stringify(before) !== JSON.stringify(after)) {
    fail("A default service or port changed during the parallel self-test.");
  }
  if ((await Promise.all(alternatePorts.map((port) => portListening(port)))).some(Boolean)) {
    fail("A parallel self-test port remained open after cleanup.");
  }
  process.stdout.write(
    "Parallel self-test passed: authenticated v3, guided setup begin/status/cancel, exact extension patch counts, unsafe-patch refusal, " +
    "fail-closed Zen process probes, detached process-group ownership checks, temporary owner-only secrets, unchanged services/default ports, " +
    "closed alternate ports, and deleted temporary root.\n"
  );
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const state = await preflight(options);
  if (options.mode === "preflight") {
    process.stdout.write(
      state.oldActive
        ? "Preflight only: blocked as expected while the legacy service owns port 32110. No browser was launched and nothing was changed.\n"
        : "Preflight passed. Add --run only after the controlled BrowseWeave service cutover.\n"
    );
    return;
  }
  if (options.mode === "run") {
    await runBrowser(options, state);
    return;
  }
  if (options.mode === "parallel-self-test") {
    await runParallelSelfTest(state, options.browser);
    return;
  }
  await runParallelBrowser(options, state);
}

main().catch((error) => {
  process.stderr.write(`Isolated live-QA launcher failed: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
