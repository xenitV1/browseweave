import { createHash } from "node:crypto";
import path from "node:path";

export const SERVICE_MARKER = "Managed by BrowseWeave. Do not edit while managed." as const;
const SERVICE_HASH_LABEL = "BrowseWeave-Definition-SHA256: " as const;

export interface ServiceCommand {
  command: string;
  args: string[];
  allowFailure?: boolean;
}

export interface WindowsTaskIdentity {
  taskName: string;
  userId: string;
  command: string;
  arguments: string;
  workingDirectory: string;
  description: string;
}

export interface ServicePlan {
  platform: NodeJS.Platform;
  identifier: string;
  definitionPath?: string;
  definitionContent?: string;
  inspectionCommand?: ServiceCommand;
  startCommands: ServiceCommand[];
  installCommands: ServiceCommand[];
  refreshCommands?: ServiceCommand[];
  replacePreparationCommands?: ServiceCommand[];
  uninstallCommands: ServiceCommand[];
  postUninstallCommands?: ServiceCommand[];
  windowsTask?: WindowsTaskIdentity;
}

export interface ServicePlanInput {
  platform: NodeJS.Platform;
  home: string;
  nodePath: string;
  daemonPath: string;
  configHome?: string;
  localAppData?: string;
  uid?: number;
  userId?: string;
}

export interface ManagedServiceEnvironmentInput {
  platform: NodeJS.Platform;
  home: string;
  uid?: number;
  env: Readonly<Record<string, string | undefined>>;
}

const TRANSIENT_BRIDGE_ENVIRONMENT_KEYS = [
  "BROWSER_MCP_BRIDGE_TOKEN",
  "ZEN_CODEX_BRIDGE_TOKEN",
  "BROWSER_MCP_BRIDGE_IPC_TOKEN",
  "BROWSER_MCP_BRIDGE_WS_PORT",
  "BROWSER_MCP_BRIDGE_IPC_PORT",
  "BROWSER_MCP_BRIDGE_ALLOWED_ORIGINS",
  "ZEN_CODEX_BRIDGE_ALLOWED_ORIGINS"
] as const;

/**
 * A managed background service does not inherit one-off terminal overrides.
 * Refuse a split-brain install instead of writing credentials or transient
 * paths into the service definition.
 */
export function assertManagedServiceEnvironment(input: ManagedServiceEnvironmentInput): void {
  const environmentValue = (key: string): string | undefined => {
    if (input.platform !== "win32") return input.env[key];
    const match = Object.entries(input.env).find(([name]) => name.toUpperCase() === key.toUpperCase());
    return match?.[1];
  };
  const transient = TRANSIENT_BRIDGE_ENVIRONMENT_KEYS.filter((key) => (environmentValue(key) ?? "").trim() !== "");
  if (transient.length > 0) {
    throw new Error(
      `Managed BrowseWeave setup cannot use temporary bridge settings (${transient.join(", ")}). ` +
      "Open a normal terminal without those overrides and run setup again."
    );
  }

  const pathApi = input.platform === "win32" ? path.win32 : path.posix;
  const samePath = (left: string, right: string): boolean => {
    const normalizedLeft = pathApi.normalize(left);
    const normalizedRight = pathApi.normalize(right);
    return input.platform === "win32"
      ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
      : normalizedLeft === normalizedRight;
  };
  const expected: Record<string, string | undefined> = input.platform === "linux"
    ? {
        HOME: input.home,
        XDG_CONFIG_HOME: path.posix.join(input.home, ".config"),
        XDG_DATA_HOME: path.posix.join(input.home, ".local", "share"),
        XDG_STATE_HOME: path.posix.join(input.home, ".local", "state"),
        XDG_RUNTIME_DIR: Number.isInteger(input.uid) && (input.uid ?? -1) >= 0
          ? `/run/user/${input.uid}`
          : undefined
      }
    : input.platform === "darwin"
      ? { HOME: input.home }
      : input.platform === "win32"
        ? {
            USERPROFILE: input.home,
            LOCALAPPDATA: path.win32.join(input.home, "AppData", "Local")
          }
        : {};
  for (const [key, fallback] of Object.entries(expected)) {
    const configured = environmentValue(key);
    if (configured === undefined || configured.trim() === "") continue;
    if (!fallback || !pathApi.isAbsolute(configured) || !samePath(configured, fallback)) {
      throw new Error(
        `Managed BrowseWeave setup cannot preserve the temporary ${key} path. ` +
        "Open a normal terminal and run setup again."
      );
    }
  }
}

/** Existing managed services must be refreshed so upgraded code is actually loaded. */
export function serviceInstallCommands(plan: ServicePlan, definitionExisted: boolean): ServiceCommand[] {
  return definitionExisted && plan.refreshCommands ? plan.refreshCommands : plan.installCommands;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function assertSafePath(value: string, label: string, pathApi: typeof path.posix | typeof path.win32): void {
  if (!pathApi.isAbsolute(value)) throw new Error(`${label} must be absolute.`);
  if (/[\0\r\n]/u.test(value)) throw new Error(`${label} contains an unsupported control character.`);
  if (pathApi === path.win32 && /^(?:\\\\[.?]\\|\\\\)/u.test(value)) {
    throw new Error(`${label} must use a local drive path, not a device or network path.`);
  }
}

function systemdQuote(value: string): string {
  return `"${value.replace(/%/gu, "%%").replace(/\\/gu, "\\\\").replace(/"/gu, '\\"')}"`;
}

function xml(value: string): string {
  return value
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&apos;");
}

function managedTextDefinition(body: string): string {
  return `# ${SERVICE_MARKER}\n# ${SERVICE_HASH_LABEL}${sha256(body)}\n${body}`;
}

function managedXmlDefinition(body: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!-- ${SERVICE_MARKER} -->\n<!-- ${SERVICE_HASH_LABEL}${sha256(body)} -->\n${body}`;
}

/** Detect a definition written by BrowseWeave and reject marker-only modified files. */
export function isManagedServiceDefinition(content: string): boolean {
  const textPrefix = `# ${SERVICE_MARKER}\n# ${SERVICE_HASH_LABEL}`;
  if (content.startsWith(textPrefix)) {
    const digestEnd = content.indexOf("\n", textPrefix.length);
    if (digestEnd < 0) return false;
    const digest = content.slice(textPrefix.length, digestEnd);
    const body = content.slice(digestEnd + 1);
    return /^[a-f0-9]{64}$/u.test(digest) && sha256(body) === digest;
  }

  const xmlPrefix = `<?xml version="1.0" encoding="UTF-8"?>\n<!-- ${SERVICE_MARKER} -->\n<!-- ${SERVICE_HASH_LABEL}`;
  if (!content.startsWith(xmlPrefix)) return false;
  const digestEnd = content.indexOf(" -->\n", xmlPrefix.length);
  if (digestEnd < 0) return false;
  const digest = content.slice(xmlPrefix.length, digestEnd);
  const body = content.slice(digestEnd + " -->\n".length);
  return /^[a-f0-9]{64}$/u.test(digest) && sha256(body) === digest;
}

export function serviceDefinitionState(
  plan: ServicePlan,
  content: string
): "exact" | "owned" | "foreign" {
  if (content === plan.definitionContent) return "exact";
  return isManagedServiceDefinition(content) ? "owned" : "foreign";
}

/** Quote one argv element using CommandLineToArgvW-compatible rules. */
export function quoteWindowsArgument(value: string): string {
  if (/[\0\r\n]/u.test(value)) throw new Error("Windows arguments cannot contain NUL or line breaks.");
  let output = '"';
  let slashes = 0;
  for (const character of value) {
    if (character === "\\") {
      slashes += 1;
      continue;
    }
    if (character === '"') {
      output += "\\".repeat(slashes * 2 + 1) + '"';
      slashes = 0;
      continue;
    }
    output += "\\".repeat(slashes) + character;
    slashes = 0;
  }
  return output + "\\".repeat(slashes * 2) + '"';
}

function decodeXml(value: string): string | null {
  try {
    return value.replace(/&(?:#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/giu, (entity) => {
      if (entity === "&amp;") return "&";
      if (entity === "&lt;") return "<";
      if (entity === "&gt;") return ">";
      if (entity === "&quot;") return '"';
      if (entity === "&apos;") return "'";
      const hexadecimal = entity.startsWith("&#x") || entity.startsWith("&#X");
      const digits = entity.slice(hexadecimal ? 3 : 2, -1);
      const codePoint = Number.parseInt(digits, hexadecimal ? 16 : 10);
      if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > 0x10ffff) throw new Error("Invalid XML entity.");
      return String.fromCodePoint(codePoint);
    });
  } catch {
    return null;
  }
}

function xmlTagValues(document: string, tag: string): string[] | null {
  const values: string[] = [];
  const pattern = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, "gu");
  for (const match of document.matchAll(pattern)) {
    const decoded = decodeXml(match[1] ?? "");
    if (decoded === null) return null;
    values.push(decoded);
  }
  return values;
}

function oneXmlValue(document: string, tag: string): string | null {
  const values = xmlTagValues(document, tag);
  return values?.length === 1 ? values[0]! : null;
}

function matchesWindowsTaskIdentity(expected: WindowsTaskIdentity, taskXml: string): boolean {
  if (taskXml.length > 1024 * 1024 || /<!ENTITY|<!DOCTYPE/iu.test(taskXml)) return false;

  const userIds = xmlTagValues(taskXml, "UserId");
  const requiredSettings: Record<string, string> = {
    Description: expected.description,
    URI: `\\${expected.taskName}`,
    LogonType: "InteractiveToken",
    RunLevel: "LeastPrivilege",
    MultipleInstancesPolicy: "IgnoreNew",
    ExecutionTimeLimit: "PT0S",
    Interval: "PT1M",
    Count: "5",
    Command: expected.command,
    Arguments: expected.arguments,
    WorkingDirectory: expected.workingDirectory
  };
  if (!userIds || userIds.length !== 2 || userIds.some((value) => value !== expected.userId)) return false;
  for (const [tag, expectedValue] of Object.entries(requiredSettings)) {
    if (oneXmlValue(taskXml, tag) !== expectedValue) return false;
  }

  const requiredSingletons = ["LogonTrigger", "Principal", "Actions", "Exec", "RestartOnFailure"];
  if (requiredSingletons.some((tag) => xmlTagValues(taskXml, tag)?.length !== 1)) return false;
  return !/<(?:BootTrigger|CalendarTrigger|EventTrigger|SessionStateChangeTrigger|TimeTrigger|ComHandler|SendEmail|ShowMessage)(?:\s|>)/u.test(taskXml);
}

/** Verify that an exported task exactly matches the current BrowseWeave plan. */
export function matchesWindowsTask(plan: ServicePlan, taskXml: string): boolean {
  return plan.windowsTask ? matchesWindowsTaskIdentity(plan.windowsTask, taskXml) : false;
}

/** Verify an older task against its intact BrowseWeave-owned definition during upgrades. */
export function matchesWindowsTaskDefinition(definitionContent: string, taskXml: string): boolean {
  if (!isManagedServiceDefinition(definitionContent)) return false;
  const taskNameValue = oneXmlValue(definitionContent, "URI");
  const userIds = xmlTagValues(definitionContent, "UserId");
  const command = oneXmlValue(definitionContent, "Command");
  const args = oneXmlValue(definitionContent, "Arguments");
  const workingDirectory = oneXmlValue(definitionContent, "WorkingDirectory");
  const description = oneXmlValue(definitionContent, "Description");
  if (
    !taskNameValue || !/^\\BrowseWeave Daemon [a-f0-9]{12}$/u.test(taskNameValue) ||
    !userIds || userIds.length !== 2 || userIds.some((value) => value !== userIds[0]) ||
    !/^S-\d-\d+(?:-\d+)+$/u.test(userIds[0] ?? "") ||
    !command || !args || !workingDirectory || !description
  ) return false;
  try {
    assertSafePath(command, "Stored Windows task executable", path.win32);
    assertSafePath(workingDirectory, "Stored Windows task working directory", path.win32);
  } catch {
    return false;
  }
  const expected: WindowsTaskIdentity = {
    taskName: taskNameValue.slice(1),
    userId: userIds[0]!,
    command,
    arguments: args,
    workingDirectory,
    description
  };
  const expectedOwnership = sha256(JSON.stringify({
    taskName: expected.taskName,
    userId: expected.userId,
    command: expected.command,
    arguments: expected.arguments,
    workingDirectory: expected.workingDirectory
  }));
  if (description !== `${SERVICE_MARKER} Ownership-SHA256: ${expectedOwnership}`) return false;
  return matchesWindowsTaskIdentity(expected, taskXml);
}

export function createServicePlan(input: ServicePlanInput): ServicePlan {
  const pathApi = input.platform === "win32" ? path.win32 : path.posix;
  assertSafePath(input.home, "User home", pathApi);
  assertSafePath(input.nodePath, "Service executable path", pathApi);
  assertSafePath(input.daemonPath, "Daemon path", pathApi);

  if (input.platform === "linux") {
    const configHome = input.configHome || pathApi.join(input.home, ".config");
    assertSafePath(configHome, "XDG config directory", pathApi);
    const definitionPath = pathApi.join(configHome, "systemd", "user", "browseweave-daemon.service");
    const body = `[Unit]
Description=BrowseWeave browser bridge daemon

[Service]
Type=simple
ExecStart=${systemdQuote(input.nodePath)} ${systemdQuote(input.daemonPath)}
Restart=on-failure
RestartSec=2
TimeoutStopSec=10
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=default.target
`;
    return {
      platform: input.platform,
      identifier: "browseweave-daemon.service",
      definitionPath,
      definitionContent: managedTextDefinition(body),
      startCommands: [
        { command: "systemctl", args: ["--user", "start", "browseweave-daemon.service"] }
      ],
      installCommands: [
        { command: "systemctl", args: ["--user", "daemon-reload"] },
        { command: "systemctl", args: ["--user", "enable", "--now", "browseweave-daemon.service"] }
      ],
      refreshCommands: [
        { command: "systemctl", args: ["--user", "daemon-reload"] },
        { command: "systemctl", args: ["--user", "restart", "browseweave-daemon.service"] }
      ],
      uninstallCommands: [
        { command: "systemctl", args: ["--user", "disable", "--now", "browseweave-daemon.service"], allowFailure: true }
      ],
      postUninstallCommands: [
        { command: "systemctl", args: ["--user", "daemon-reload"] },
        { command: "systemctl", args: ["--user", "reset-failed", "browseweave-daemon.service"], allowFailure: true }
      ]
    };
  }

  if (input.platform === "darwin") {
    if (!Number.isInteger(input.uid) || (input.uid ?? -1) < 0) {
      throw new Error("A numeric user ID is required for a macOS LaunchAgent plan.");
    }
    const definitionPath = pathApi.join(input.home, "Library", "LaunchAgents", "io.browseweave.daemon.plist");
    const body = `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.browseweave.daemon</string>
  <key>ProgramArguments</key>
  <array><string>${xml(input.nodePath)}</string><string>${xml(input.daemonPath)}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>ThrottleInterval</key><integer>2</integer>
</dict>
</plist>
`;
    const domain = `gui/${input.uid}`;
    return {
      platform: input.platform,
      identifier: "io.browseweave.daemon",
      definitionPath,
      definitionContent: managedXmlDefinition(body),
      startCommands: [
        { command: "launchctl", args: ["kickstart", `${domain}/io.browseweave.daemon`] }
      ],
      installCommands: [
        { command: "launchctl", args: ["bootstrap", domain, definitionPath] }
      ],
      refreshCommands: [
        { command: "launchctl", args: ["bootout", `${domain}/io.browseweave.daemon`], allowFailure: true },
        { command: "launchctl", args: ["bootstrap", domain, definitionPath] }
      ],
      uninstallCommands: [
        { command: "launchctl", args: ["bootout", `${domain}/io.browseweave.daemon`], allowFailure: true }
      ]
    };
  }

  if (input.platform === "win32") {
    if (!input.userId || !/^S-\d-\d+(?:-\d+)+$/u.test(input.userId)) {
      throw new Error("A numeric current-user SID is required for a Windows task plan.");
    }
    const localAppData = input.localAppData || pathApi.join(input.home, "AppData", "Local");
    assertSafePath(localAppData, "Local application data directory", pathApi);
    const taskSuffix = sha256(input.userId).slice(0, 12);
    const taskName = `BrowseWeave Daemon ${taskSuffix}`;
    const taskArguments = quoteWindowsArgument(input.daemonPath);
    const workingDirectory = pathApi.dirname(input.daemonPath);
    const ownership = sha256(JSON.stringify({
      taskName,
      userId: input.userId,
      command: input.nodePath,
      arguments: taskArguments,
      workingDirectory
    }));
    const description = `${SERVICE_MARKER} Ownership-SHA256: ${ownership}`;
    const definitionPath = pathApi.join(localAppData, "BrowseWeave", "Config", `task-${taskSuffix}.xml`);
    const body = `<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>${xml(description)}</Description>
    <URI>${xml(`\\${taskName}`)}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>${xml(input.userId)}</UserId></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>${xml(input.userId)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure><Interval>PT1M</Interval><Count>5</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>${xml(input.nodePath)}</Command>
      <Arguments>${xml(taskArguments)}</Arguments>
      <WorkingDirectory>${xml(workingDirectory)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`;
    const windowsTask: WindowsTaskIdentity = {
      taskName,
      userId: input.userId,
      command: input.nodePath,
      arguments: taskArguments,
      workingDirectory,
      description
    };
    return {
      platform: input.platform,
      identifier: taskName,
      definitionPath,
      definitionContent: managedXmlDefinition(body),
      inspectionCommand: { command: "schtasks.exe", args: ["/Query", "/TN", taskName, "/XML"] },
      startCommands: [
        { command: "schtasks.exe", args: ["/Run", "/TN", taskName] }
      ],
      installCommands: [
        { command: "schtasks.exe", args: ["/Create", "/TN", taskName, "/XML", definitionPath] },
        { command: "schtasks.exe", args: ["/Run", "/TN", taskName] }
      ],
      refreshCommands: [
        { command: "schtasks.exe", args: ["/End", "/TN", taskName], allowFailure: true },
        { command: "schtasks.exe", args: ["/Run", "/TN", taskName] }
      ],
      replacePreparationCommands: [
        { command: "schtasks.exe", args: ["/End", "/TN", taskName], allowFailure: true },
        { command: "schtasks.exe", args: ["/Delete", "/F", "/TN", taskName] }
      ],
      uninstallCommands: [
        { command: "schtasks.exe", args: ["/End", "/TN", taskName], allowFailure: true },
        { command: "schtasks.exe", args: ["/Delete", "/F", "/TN", taskName] }
      ],
      windowsTask
    };
  }

  throw new Error(`Unsupported operating system: ${input.platform}`);
}
