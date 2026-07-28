import { constants as fsConstants } from "node:fs";
import { access, lstat, readFile } from "node:fs/promises";
import { userInfo } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { callBridge } from "./ipc-client.js";
import {
  createServicePlan,
  matchesWindowsTask,
  serviceDefinitionState,
  type ServiceCommand,
  type ServicePlan
} from "./service-plan.js";
import {
  authorizeServiceMutation,
  isExactBrowseWeaveHealth,
  waitForExactBridgeHealth,
  type ServiceMutationAuthorizationInput
} from "./service-install-guard.js";

const MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024;
const COMMAND_TIMEOUT_MS = 10_000;

interface CapturedCommand {
  code: number;
  stdout: string;
}

export interface ExactOwnedServiceStartInput {
  plan: ServicePlan;
  definitionContents: string;
  windowsTaskXml?: string;
  status(): Promise<unknown>;
  start(command: ServiceCommand): Promise<void>;
  probePort?: ServiceMutationAuthorizationInput["probePort"];
}

function safeAbsoluteHome(platform: NodeJS.Platform): string {
  const home = userInfo().homedir;
  const pathApi = platform === "win32" ? path.win32 : path.posix;
  if (!pathApi.isAbsolute(home) || /[\0\r\n]/u.test(home)) {
    throw new Error("The operating system did not provide a safe user home directory.");
  }
  return pathApi.normalize(home);
}

/** A native host never inherits temporary bridge ports, tokens, or XDG roots. */
export function nativeServiceEnvironment(
  platform: NodeJS.Platform = process.platform,
  uid = typeof process.getuid === "function" ? process.getuid() : undefined
): NodeJS.ProcessEnv {
  const accountHome = safeAbsoluteHome(platform);
  if (platform === "linux") {
    if (!Number.isInteger(uid) || (uid ?? -1) < 0) throw new Error("A Linux user ID is required.");
    return {
      HOME: accountHome,
      PATH: "/usr/local/bin:/usr/bin:/bin",
      XDG_CONFIG_HOME: path.posix.join(accountHome, ".config"),
      XDG_STATE_HOME: path.posix.join(accountHome, ".local", "state"),
      XDG_RUNTIME_DIR: `/run/user/${uid}`,
      DBUS_SESSION_BUS_ADDRESS: `unix:path=/run/user/${uid}/bus`,
      LANG: "C.UTF-8"
    };
  }
  if (platform === "darwin") {
    return {
      HOME: accountHome,
      PATH: "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
      LANG: "en_US.UTF-8"
    };
  }
  if (platform === "win32") {
    const systemRoot = process.env.SystemRoot || process.env.WINDIR || "C:\\Windows";
    if (!path.win32.isAbsolute(systemRoot) || /[\0\r\n]/u.test(systemRoot)) {
      throw new Error("The Windows system directory is invalid.");
    }
    return {
      USERPROFILE: accountHome,
      LOCALAPPDATA: path.win32.join(accountHome, "AppData", "Local"),
      SystemRoot: path.win32.normalize(systemRoot),
      WINDIR: path.win32.normalize(systemRoot),
      PATH: path.win32.join(path.win32.normalize(systemRoot), "System32")
    };
  }
  throw new Error(`Unsupported operating system: ${platform}`);
}

function fixedSystemExecutable(command: string, platform: NodeJS.Platform, env: NodeJS.ProcessEnv): string {
  if (platform === "linux" && command === "systemctl") return "/usr/bin/systemctl";
  if (platform === "darwin" && command === "launchctl") return "/bin/launchctl";
  if (platform === "win32" && (command === "schtasks.exe" || command === "whoami.exe")) {
    const systemRoot = env.SystemRoot;
    if (!systemRoot || !path.win32.isAbsolute(systemRoot)) throw new Error("The Windows system directory is unavailable.");
    return path.win32.join(systemRoot, "System32", command);
  }
  throw new Error("The managed service requested an unsupported executable.");
}

async function runCapturedFixed(
  command: string,
  args: readonly string[],
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv
): Promise<CapturedCommand> {
  const executable = fixedSystemExecutable(command, platform, env);
  if (platform !== "win32") await access(executable, fsConstants.X_OK);
  return await new Promise<CapturedCommand>((resolve, reject) => {
    const child = spawn(executable, [...args], {
      shell: false,
      windowsHide: true,
      env,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = Buffer.alloc(0);
    let stderrBytes = 0;
    let settled = false;
    const finish = (error?: Error, code = -1): void => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timer);
      if (error) reject(error);
      else resolve({ code, stdout: stdout.toString("utf8") });
    };
    const timer = globalThis.setTimeout(() => {
      child.kill();
      finish(new Error("A fixed managed-service command timed out."));
    }, COMMAND_TIMEOUT_MS);
    timer.unref();
    child.once("error", () => finish(new Error("A fixed managed-service command could not start.")));
    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      stdout = Buffer.concat([stdout, chunk]);
      if (stdout.byteLength + stderrBytes > MAX_COMMAND_OUTPUT_BYTES) {
        child.kill();
        finish(new Error("A fixed managed-service command exceeded the safe output limit."));
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (settled) return;
      stderrBytes += chunk.byteLength;
      if (stdout.byteLength + stderrBytes > MAX_COMMAND_OUTPUT_BYTES) {
        child.kill();
        finish(new Error("A fixed managed-service command exceeded the safe output limit."));
      }
    });
    child.once("close", (code) => finish(undefined, typeof code === "number" ? code : -1));
  });
}

async function windowsSid(platform: NodeJS.Platform, env: NodeJS.ProcessEnv): Promise<string | undefined> {
  if (platform !== "win32") return undefined;
  const result = await runCapturedFixed("whoami.exe", ["/user", "/fo", "csv", "/nh"], platform, env);
  const sid = result.stdout.match(/S-\d-\d+(?:-\d+)+/u)?.[0];
  if (result.code !== 0 || !sid) throw new Error("The current Windows user could not be verified.");
  return sid;
}

export async function currentNativeServicePlan(
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = nativeServiceEnvironment(platform)
): Promise<ServicePlan> {
  if (platform !== "win32" && typeof process.getuid === "function" && process.getuid() === 0) {
    throw new Error("BrowseWeave native setup does not run as root.");
  }
  const accountHome = safeAbsoluteHome(platform);
  const daemonPath = fileURLToPath(new URL("./daemon.js", import.meta.url));
  const currentUserId = await windowsSid(platform, env);
  return createServicePlan({
    platform,
    home: accountHome,
    nodePath: process.execPath,
    daemonPath,
    ...(platform === "linux" ? { configHome: path.posix.join(accountHome, ".config") } : {}),
    ...(platform === "win32" ? {
      localAppData: path.win32.join(accountHome, "AppData", "Local"),
      ...(currentUserId ? { userId: currentUserId } : {})
    } : {}),
    ...(typeof process.getuid === "function" ? { uid: process.getuid() } : {})
  });
}

async function readExactOwnedDefinition(plan: ServicePlan): Promise<string> {
  if (!plan.definitionPath || plan.definitionContent === undefined) {
    throw new Error("The managed service definition is unavailable.");
  }
  const info = await lstat(plan.definitionPath);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error("The managed service definition is unsafe.");
  if (process.platform !== "win32" && typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error("The managed service definition has the wrong owner.");
  }
  if (process.platform !== "win32" && (info.mode & 0o077) !== 0) {
    throw new Error("The managed service definition permissions are too broad.");
  }
  return await readFile(plan.definitionPath, "utf8");
}

/**
 * Start is permitted only for the exact current BrowseWeave service identity.
 * This function never installs, repairs, rewrites, deletes, or shells out.
 */
export async function ensureExactOwnedServiceReady(input: ExactOwnedServiceStartInput): Promise<void> {
  if (
    input.plan.definitionContent === undefined ||
    serviceDefinitionState(input.plan, input.definitionContents) !== "exact"
  ) throw new Error("The installed BrowseWeave service must be repaired before local setup.");
  if (input.plan.platform === "win32") {
    if (typeof input.windowsTaskXml !== "string" || !matchesWindowsTask(input.plan, input.windowsTaskXml)) {
      throw new Error("The installed BrowseWeave Windows task must be repaired before local setup.");
    }
  }

  try {
    if (isExactBrowseWeaveHealth(await input.status())) return;
  } catch {
    // The authenticated port guard below distinguishes stopped from occupied.
  }
  await authorizeServiceMutation({
    authenticateStatus: input.status,
    ...(input.probePort ? { probePort: input.probePort } : {})
  });
  for (const command of input.plan.startCommands) await input.start(command);
  await waitForExactBridgeHealth({ status: input.status });
}

export async function ensureManagedNativeServiceReady(): Promise<void> {
  const platform = process.platform;
  const env = nativeServiceEnvironment(platform);
  const plan = await currentNativeServicePlan(platform, env);
  const definitionContents = await readExactOwnedDefinition(plan);
  let windowsTaskXml: string | undefined;
  if (platform === "win32") {
    if (!plan.inspectionCommand) throw new Error("The BrowseWeave Windows task inspection is unavailable.");
    const inspected = await runCapturedFixed(
      plan.inspectionCommand.command,
      plan.inspectionCommand.args,
      platform,
      env
    );
    if (inspected.code !== 0) throw new Error("The installed BrowseWeave Windows task is unavailable.");
    windowsTaskXml = inspected.stdout;
  }
  await ensureExactOwnedServiceReady({
    plan,
    definitionContents,
    ...(windowsTaskXml !== undefined ? { windowsTaskXml } : {}),
    status: async () => await callBridge("status", {}, 2_000, env),
    start: async (command) => {
      const result = await runCapturedFixed(command.command, command.args, platform, env);
      if (result.code !== 0 && command.allowFailure !== true) {
        throw new Error("The exact BrowseWeave service could not be started.");
      }
    }
  });
}
