import { describe, expect, it } from "vitest";
import {
  SERVICE_MARKER,
  assertManagedServiceEnvironment,
  createServicePlan,
  isManagedServiceDefinition,
  matchesWindowsTask,
  matchesWindowsTaskDefinition,
  quoteWindowsArgument,
  serviceInstallCommands,
  serviceDefinitionState
} from "../src/native/service-plan.js";

describe("cross-platform per-user daemon service plans", () => {
  it("rejects terminal-only service credentials, ports, and mismatched Linux XDG paths", () => {
    const base = { platform: "linux" as const, home: "/home/ada", uid: 1000 };
    expect(() => assertManagedServiceEnvironment({
      ...base,
      env: { BROWSER_MCP_BRIDGE_WS_PORT: "40771" }
    })).toThrow(/temporary bridge settings/iu);
    expect(() => assertManagedServiceEnvironment({
      ...base,
      env: { BROWSER_MCP_BRIDGE_TOKEN: "not-written-to-service" }
    })).toThrow(/temporary bridge settings/iu);
    expect(() => assertManagedServiceEnvironment({
      ...base,
      env: { XDG_CONFIG_HOME: "/tmp/isolated-config" }
    })).toThrow(/XDG_CONFIG_HOME/iu);
    expect(() => assertManagedServiceEnvironment({
      ...base,
      env: { XDG_RUNTIME_DIR: "/tmp/isolated-runtime" }
    })).toThrow(/XDG_RUNTIME_DIR/iu);
    expect(() => assertManagedServiceEnvironment({
      ...base,
      env: { XDG_DATA_HOME: "/tmp/isolated-data" }
    })).toThrow(/XDG_DATA_HOME/iu);
    expect(() => assertManagedServiceEnvironment({
      ...base,
      env: { HOME: "/tmp/isolated-home" }
    })).toThrow(/HOME/iu);
  });

  it("allows unset or normalized default Linux service paths", () => {
    const base = { platform: "linux" as const, home: "/home/ada", uid: 1000 };
    expect(() => assertManagedServiceEnvironment({ ...base, env: {} })).not.toThrow();
    expect(() => assertManagedServiceEnvironment({
      ...base,
      env: {
        XDG_CONFIG_HOME: "/home/ada/.config/.",
        XDG_STATE_HOME: "/home/ada/.local/state",
        XDG_RUNTIME_DIR: "/run/user/1000"
      }
    })).not.toThrow();
    expect(() => assertManagedServiceEnvironment({
      platform: "win32",
      home: "C:\\Users\\Ada",
      env: { LOCALAPPDATA: "C:\\Users\\Ada\\AppData\\Local" }
    })).not.toThrow();
    expect(() => assertManagedServiceEnvironment({
      platform: "win32",
      home: "C:\\Users\\Ada",
      env: { LocalAppData: "D:\\Temporary", UserProfile: "C:\\Users\\Ada" }
    })).toThrow(/LOCALAPPDATA/iu);
    expect(() => assertManagedServiceEnvironment({
      platform: "win32",
      home: "C:\\Users\\Ada",
      env: {
        UserProfile: "D:\\Temporary",
        LocalAppData: "D:\\Temporary\\AppData\\Local"
      }
    })).toThrow(/USERPROFILE/iu);
    expect(() => assertManagedServiceEnvironment({
      platform: "darwin",
      home: "/Users/Ada",
      uid: 501,
      env: { HOME: "/tmp/isolated-home" }
    })).toThrow(/HOME/iu);
  });

  it("creates a hardened, self-identifying Linux user unit and escapes systemd paths", () => {
    const plan = createServicePlan({
      platform: "linux",
      home: "/home/Ada User",
      nodePath: "/home/Ada User/100% Runtime/node",
      daemonPath: '/home/Ada User/Browse"Weave/dist/daemon.js'
    });
    expect(plan.definitionPath).toBe("/home/Ada User/.config/systemd/user/browseweave-daemon.service");
    expect(plan.definitionContent).toContain(SERVICE_MARKER);
    expect(plan.definitionContent).toContain('ExecStart="/home/Ada User/100%% Runtime/node"');
    expect(plan.definitionContent).toContain('"/home/Ada User/Browse\\"Weave/dist/daemon.js"');
    expect(plan.definitionContent).toContain("UMask=0077");
    expect(isManagedServiceDefinition(plan.definitionContent!)).toBe(true);
    expect(serviceDefinitionState(plan, plan.definitionContent!)).toBe("exact");
    expect(plan.installCommands[1]).toMatchObject({
      command: "systemctl",
      args: ["--user", "enable", "--now", "browseweave-daemon.service"]
    });
    expect(plan.startCommands).toEqual([
      { command: "systemctl", args: ["--user", "start", "browseweave-daemon.service"] }
    ]);
    expect(plan.refreshCommands?.[1]).toMatchObject({
      command: "systemctl",
      args: ["--user", "restart", "browseweave-daemon.service"]
    });
    expect(serviceInstallCommands(plan, false)).toBe(plan.installCommands);
    expect(serviceInstallCommands(plan, true)).toBe(plan.refreshCommands);
    expect(plan.postUninstallCommands?.[0]?.args).toEqual(["--user", "daemon-reload"]);
  });

  it("does not trust a copied marker after a Linux definition is modified", () => {
    const plan = createServicePlan({
      platform: "linux",
      home: "/home/ada",
      nodePath: "/opt/browseweave/node",
      daemonPath: "/opt/browseweave/daemon.js"
    });
    const modified = plan.definitionContent!.replace("RestartSec=2", "RestartSec=3");
    expect(modified).toContain(SERVICE_MARKER);
    expect(isManagedServiceDefinition(modified)).toBe(false);
    expect(serviceDefinitionState(plan, modified)).toBe("foreign");
  });

  it("creates an XML-safe macOS LaunchAgent and separates initial install from refresh", () => {
    const plan = createServicePlan({
      platform: "darwin",
      home: "/Users/Ada & Lin",
      nodePath: "/Applications/BrowseWeave Runtime/node",
      daemonPath: "/Users/Ada & Lin/BrowseWeave/daemon.js",
      uid: 501
    });
    expect(plan.definitionContent).toContain("/Applications/BrowseWeave Runtime/node");
    expect(plan.definitionContent).toContain("/Users/Ada &amp; Lin/BrowseWeave/daemon.js");
    expect(isManagedServiceDefinition(plan.definitionContent!)).toBe(true);
    expect(plan.installCommands).toEqual([
      { command: "launchctl", args: ["bootstrap", "gui/501", plan.definitionPath] }
    ]);
    expect(plan.startCommands).toEqual([
      { command: "launchctl", args: ["kickstart", "gui/501/io.browseweave.daemon"] }
    ]);
    expect(plan.refreshCommands?.[0]?.args).toEqual(["bootout", "gui/501/io.browseweave.daemon"]);
    expect(serviceInstallCommands(plan, true)).toBe(plan.refreshCommands);
    expect(plan.uninstallCommands[0]?.args).toEqual(["bootout", "gui/501/io.browseweave.daemon"]);
  });

  it("creates a per-SID least-privilege Windows XML task without /F overwrite", () => {
    const plan = createServicePlan({
      platform: "win32",
      home: "C:\\Users\\Ada",
      localAppData: "C:\\Users\\Ada\\AppData\\Local",
      nodePath: "C:\\Program Files\\BrowseWeave\\node.exe",
      daemonPath: "C:\\Users\\Ada\\BrowseWeave App\\daemon.js",
      userId: "S-1-5-21-111111111-222222222-333333333-1001"
    });
    expect(plan.definitionPath).toMatch(/^C:\\Users\\Ada\\AppData\\Local\\BrowseWeave\\Config\\task-[a-f0-9]{12}\.xml$/u);
    expect(plan.definitionContent).toContain("<LogonType>InteractiveToken</LogonType>");
    expect(plan.definitionContent).toContain("<RunLevel>LeastPrivilege</RunLevel>");
    expect(plan.definitionContent).toContain("<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>");
    expect(plan.definitionContent).toContain("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>");
    expect(plan.installCommands[0]).toMatchObject({ command: "schtasks.exe" });
    expect(plan.installCommands[0]?.args).not.toContain("/F");
    expect(plan.installCommands[0]?.args).not.toContain("/TR");
    expect(plan.installCommands[0]?.args).toEqual([
      "/Create", "/TN", plan.identifier, "/XML", plan.definitionPath
    ]);
    expect(plan.startCommands).toEqual([
      { command: "schtasks.exe", args: ["/Run", "/TN", plan.identifier] }
    ]);
    expect(plan.refreshCommands).toEqual([
      { command: "schtasks.exe", args: ["/End", "/TN", plan.identifier], allowFailure: true },
      { command: "schtasks.exe", args: ["/Run", "/TN", plan.identifier] }
    ]);
    expect(plan.replacePreparationCommands).toEqual([
      { command: "schtasks.exe", args: ["/End", "/TN", plan.identifier], allowFailure: true },
      { command: "schtasks.exe", args: ["/Delete", "/F", "/TN", plan.identifier] }
    ]);
    expect(matchesWindowsTask(plan, plan.definitionContent!)).toBe(true);
    expect(matchesWindowsTask(plan, plan.definitionContent!.replace("PT0S", "PT72H"))).toBe(false);
  });

  it("recognizes an intact older managed Windows task during a path upgrade", () => {
    const common = {
      platform: "win32" as const,
      home: "C:\\Users\\Ada",
      localAppData: "C:\\Users\\Ada\\AppData\\Local",
      userId: "S-1-5-21-111111111-222222222-333333333-1001"
    };
    const oldPlan = createServicePlan({
      ...common,
      nodePath: "C:\\Program Files\\NodeJS 22\\node.exe",
      daemonPath: "C:\\Users\\Ada\\Old BrowseWeave\\daemon.js"
    });
    const newPlan = createServicePlan({
      ...common,
      nodePath: "C:\\Program Files\\NodeJS 24\\node.exe",
      daemonPath: "C:\\Users\\Ada\\New BrowseWeave\\daemon.js"
    });

    expect(oldPlan.identifier).toBe(newPlan.identifier);
    expect(matchesWindowsTask(newPlan, oldPlan.definitionContent!)).toBe(false);
    expect(matchesWindowsTaskDefinition(oldPlan.definitionContent!, oldPlan.definitionContent!)).toBe(true);
    expect(matchesWindowsTaskDefinition(
      oldPlan.definitionContent!,
      oldPlan.definitionContent!.replace("NodeJS 22", "NodeJS 24")
    )).toBe(false);
  });

  it("quotes Windows argv edge cases and rejects control characters", () => {
    expect(quoteWindowsArgument("")).toBe('""');
    expect(quoteWindowsArgument("plain.exe")).toBe('"plain.exe"');
    expect(quoteWindowsArgument("C:\\A Folder\\")).toBe('"C:\\A Folder\\\\"');
    expect(quoteWindowsArgument('C:\\A "quoted" Folder\\')).toBe('"C:\\A \\\"quoted\\\" Folder\\\\"');
    expect(() => quoteWindowsArgument("bad\nargument")).toThrow(/line breaks/iu);
  });

  it("requires a numeric Windows SID and local absolute non-network paths", () => {
    const base = {
      platform: "win32" as const,
      home: "C:\\Users\\Ada",
      nodePath: "C:\\BrowseWeave\\node.exe",
      daemonPath: "C:\\BrowseWeave\\daemon.js"
    };
    expect(() => createServicePlan({ ...base, userId: "Ada" })).toThrow(/numeric current-user SID/iu);
    expect(() => createServicePlan({
      ...base,
      userId: "S-1-5-21-1-2-3-1001",
      nodePath: "\\\\server\\share\\node.exe"
    })).toThrow(/network path/iu);
    expect(() => createServicePlan({
      platform: "linux",
      home: "/home/ada",
      nodePath: "/opt/node\nother",
      daemonPath: "/opt/daemon.js"
    })).toThrow(/control character/iu);
  });
});
