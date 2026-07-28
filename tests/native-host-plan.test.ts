import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  NATIVE_HOST_DESCRIPTION,
  NATIVE_HOST_LAUNCHER_MARKER,
  createNativeHostRegistrationPlan,
  isManagedNativeHostLauncher,
  nativeHostLauncherState,
  nativeHostManifestState,
  quotePosixNativeHostPath,
  windowsNativeHostRegistryState,
  type NativeHostRegistrationPlanInput,
  type WindowsNativeHostRegistrySpec
} from "../src/native/host-plan.js";
import { NATIVE_SETUP_HOST_NAME } from "../src/native/setup-protocol.js";

const FIREFOX_ID_A = "browseweave@local.invalid";
const FIREFOX_ID_B = "addon@example.invalid";
const CHROME_ORIGIN_A = `chrome-extension://${"a".repeat(32)}/`;
const CHROME_ORIGIN_B = `chrome-extension://${"b".repeat(32)}/`;

function linuxInput(
  overrides: Partial<NativeHostRegistrationPlanInput> = {}
): NativeHostRegistrationPlanInput {
  return {
    platform: "linux",
    home: "/home/Ada O'Brien",
    nodePath: "/opt/Node Runtime/bin/node",
    nativeHostScriptPath: "/home/Ada O'Brien/BrowseWeave/dist/src/native-host.js",
    firefoxExtensionIds: [FIREFOX_ID_B, FIREFOX_ID_A],
    chromiumExtensionOrigins: [CHROME_ORIGIN_B, CHROME_ORIGIN_A],
    ...overrides
  };
}

function managedLauncherForBody(body: string): string {
  const digest = createHash("sha256").update(body, "utf8").digest("hex");
  return `#!/bin/sh\n# ${NATIVE_HOST_LAUNCHER_MARKER}\n# BrowseWeave-Launcher-SHA256: ${digest}\n${body}`;
}

describe("Linux per-user native host plan", () => {
  it("creates the fixed Firefox/Zen and optional Google Chrome registrations", () => {
    const plan = createNativeHostRegistrationPlan(linuxInput());
    expect(plan.platform).toBe("linux");
    expect(plan.hostName).toBe(NATIVE_SETUP_HOST_NAME);
    expect(plan.hostExecutablePath).toBe(
      "/home/Ada O'Brien/.local/share/browseweave/native-host/browseweave-native-host"
    );
    expect(plan.launcher).toMatchObject({
      path: plan.hostExecutablePath,
      mode: 0o700,
      nodePath: "/opt/Node Runtime/bin/node",
      nativeHostScriptPath: "/home/Ada O'Brien/BrowseWeave/dist/src/native-host.js"
    });
    expect(plan.windowsRegistry).toEqual([]);

    const firefox = plan.manifests[0]!;
    expect(firefox.browser).toBe("firefox");
    expect(firefox.path).toBe(
      "/home/Ada O'Brien/.mozilla/native-messaging-hosts/io.browseweave.setup.json"
    );
    expect(firefox.mode).toBe(0o600);
    expect(firefox.manifest).toEqual({
      name: NATIVE_SETUP_HOST_NAME,
      description: NATIVE_HOST_DESCRIPTION,
      path: plan.hostExecutablePath,
      type: "stdio",
      allowed_extensions: [FIREFOX_ID_B, FIREFOX_ID_A]
    });
    expect(firefox.content).toBe(`${JSON.stringify(firefox.manifest, null, 2)}\n`);

    const chrome = plan.manifests[1]!;
    expect(chrome.browser).toBe("chrome");
    expect(chrome.path).toBe(
      "/home/Ada O'Brien/.config/google-chrome/NativeMessagingHosts/io.browseweave.setup.json"
    );
    expect(chrome.mode).toBe(0o600);
    expect(chrome.manifest).toEqual({
      name: NATIVE_SETUP_HOST_NAME,
      description: NATIVE_HOST_DESCRIPTION,
      path: plan.hostExecutablePath,
      type: "stdio",
      allowed_origins: [CHROME_ORIGIN_A, CHROME_ORIGIN_B]
    });
    expect(chrome.content).toBe(`${JSON.stringify(chrome.manifest, null, 2)}\n`);
  });

  it("builds a single-command, hash-verifiable launcher with literal safe paths", () => {
    const plan = createNativeHostRegistrationPlan(linuxInput());
    const launcher = plan.launcher!;
    expect(launcher.content).toContain(`# ${NATIVE_HOST_LAUNCHER_MARKER}\n`);
    expect(launcher.content).toContain("# BrowseWeave-Launcher-SHA256: ");
    expect(launcher.content).toContain(
      `exec '/opt/Node Runtime/bin/node' '/home/Ada O'\"'\"'Brien/BrowseWeave/dist/src/native-host.js' "$@"\n`
    );
    expect(isManagedNativeHostLauncher(launcher.content)).toBe(true);
    expect(launcher.content.match(/^exec /gmu)).toHaveLength(1);
  });

  it("quotes shell metacharacters without expansion", () => {
    expect(quotePosixNativeHostPath("/opt/$HOME/`cmd`/$(other)/O'Brien/node")).toBe(
      `'/opt/$HOME/\`cmd\`/$(other)/O'\"'\"'Brien/node'`
    );
    expect(() => quotePosixNativeHostPath("relative/node")).toThrow(/canonical absolute POSIX/iu);
    expect(() => quotePosixNativeHostPath("/opt/bad\nnode")).toThrow(/control characters/iu);
  });

  it("omits Chrome entirely instead of emitting an empty or wildcard policy", () => {
    const plan = createNativeHostRegistrationPlan(linuxInput({
      chromiumExtensionOrigins: undefined
    }));
    expect(plan.manifests).toHaveLength(1);
    expect(plan.manifests[0]?.browser).toBe("firefox");
    expect(plan.manifests[0]?.content).not.toContain("allowed_origins");
  });

  it("copies and canonicalizes allowlists so caller mutation cannot change the plan", () => {
    const firefoxIds = [FIREFOX_ID_A, FIREFOX_ID_B];
    const chromeOrigins = [CHROME_ORIGIN_B, CHROME_ORIGIN_A];
    const first = createNativeHostRegistrationPlan(linuxInput({
      firefoxExtensionIds: firefoxIds,
      chromiumExtensionOrigins: chromeOrigins
    }));
    const second = createNativeHostRegistrationPlan(linuxInput({
      firefoxExtensionIds: [...firefoxIds].reverse(),
      chromiumExtensionOrigins: [...chromeOrigins].reverse()
    }));
    firefoxIds.push("later@example.invalid");
    chromeOrigins.push(`chrome-extension://${"c".repeat(32)}/`);
    expect(first).toEqual(second);
    expect(first.manifests[0]?.content).not.toContain("later@example.invalid");
    expect(first.manifests[1]?.content).not.toContain("c".repeat(32));
  });
});

describe("macOS per-user native host plan", () => {
  it("uses the official Mozilla and Google Chrome user manifest directories", () => {
    const plan = createNativeHostRegistrationPlan({
      platform: "darwin",
      home: "/Users/Ada",
      nodePath: "/Applications/BrowseWeave Runtime/node",
      nativeHostScriptPath: "/Users/Ada/Library/Application Support/BrowseWeave/dist/native-host.js",
      firefoxExtensionIds: [FIREFOX_ID_A],
      chromiumExtensionOrigins: [CHROME_ORIGIN_A]
    });
    expect(plan.hostExecutablePath).toBe(
      "/Users/Ada/Library/Application Support/BrowseWeave/NativeMessaging/browseweave-native-host"
    );
    expect(plan.manifests.map((manifest) => manifest.path)).toEqual([
      "/Users/Ada/Library/Application Support/Mozilla/NativeMessagingHosts/io.browseweave.setup.json",
      "/Users/Ada/Library/Application Support/Google/Chrome/NativeMessagingHosts/io.browseweave.setup.json"
    ]);
    expect(plan.manifests.every((manifest) => manifest.mode === 0o600)).toBe(true);
    expect(plan.windowsRegistry).toEqual([]);
    expect(isManagedNativeHostLauncher(plan.launcher!.content)).toBe(true);
  });
});

describe("Windows per-user native host plan", () => {
  const executable = "C:\\Users\\Ada\\AppData\\Local\\BrowseWeave\\bin\\browseweave-native-host.exe";

  function windowsInput(
    overrides: Partial<NativeHostRegistrationPlanInput> = {}
  ): NativeHostRegistrationPlanInput {
    return {
      platform: "win32",
      home: "C:\\Users\\Ada",
      windowsHostExecutablePath: executable,
      firefoxExtensionIds: [FIREFOX_ID_A],
      chromiumExtensionOrigins: [CHROME_ORIGIN_A],
      ...overrides
    };
  }

  it("requires an executable host and returns exact HKCU Firefox/Chrome registrations", () => {
    const plan = createNativeHostRegistrationPlan(windowsInput());
    expect(plan.hostExecutablePath).toBe(executable);
    expect(plan.launcher).toBeUndefined();
    expect(plan.manifests.map((manifest) => manifest.path)).toEqual([
      "C:\\Users\\Ada\\AppData\\Local\\BrowseWeave\\NativeMessagingHosts\\Firefox\\io.browseweave.setup.json",
      "C:\\Users\\Ada\\AppData\\Local\\BrowseWeave\\NativeMessagingHosts\\Chrome\\io.browseweave.setup.json"
    ]);
    expect(plan.manifests.every((manifest) => manifest.mode === undefined)).toBe(true);
    expect(plan.manifests.every((manifest) => manifest.manifest.path === executable)).toBe(true);
    expect(plan.windowsRegistry).toEqual([
      {
        hive: "HKEY_CURRENT_USER",
        keyPath: "Software\\Mozilla\\NativeMessagingHosts\\io.browseweave.setup",
        valueName: "",
        valueType: "REG_SZ",
        valueData: plan.manifests[0]!.path
      },
      {
        hive: "HKEY_CURRENT_USER",
        keyPath: "Software\\Google\\Chrome\\NativeMessagingHosts\\io.browseweave.setup",
        valueName: "",
        valueType: "REG_SZ",
        valueData: plan.manifests[1]!.path
      }
    ]);
  });

  it("uses an explicit canonical LocalAppData root and can omit Chrome", () => {
    const plan = createNativeHostRegistrationPlan(windowsInput({
      localAppData: "D:\\Profiles\\Ada\\LocalData",
      chromiumExtensionOrigins: undefined,
      windowsHostExecutablePath: "D:\\BrowseWeave\\Host.EXE"
    }));
    expect(plan.hostExecutablePath).toBe("D:\\BrowseWeave\\Host.EXE");
    expect(plan.manifests).toHaveLength(1);
    expect(plan.manifests[0]?.path).toBe(
      "D:\\Profiles\\Ada\\LocalData\\BrowseWeave\\NativeMessagingHosts\\Firefox\\io.browseweave.setup.json"
    );
    expect(plan.windowsRegistry).toHaveLength(1);
  });

  it.each([
    { windowsHostExecutablePath: undefined },
    { windowsHostExecutablePath: "browseweave-native-host.exe" },
    { windowsHostExecutablePath: "C:\\BrowseWeave\\host.cmd" },
    { windowsHostExecutablePath: "C:\\BrowseWeave\\host.bat" },
    { windowsHostExecutablePath: "\\\\server\\share\\host.exe" },
    { windowsHostExecutablePath: "C:\\BrowseWeave\\..\\Other\\host.exe" },
    { windowsHostExecutablePath: "C:/BrowseWeave/host.exe" },
    { windowsHostExecutablePath: "C:\\BrowseWeave\\bad\nhost.exe" }
  ])("rejects a non-fixed Windows executable %#", (overrides) => {
    expect(() => createNativeHostRegistrationPlan(windowsInput(overrides))).toThrow(/Windows|executable/iu);
  });

  it("rejects Node/script wrappers on Windows and Windows-only paths on POSIX", () => {
    expect(() => createNativeHostRegistrationPlan(windowsInput({
      nodePath: "C:\\Program Files\\nodejs\\node.exe",
      nativeHostScriptPath: "C:\\BrowseWeave\\native-host.js"
    }))).toThrow(/not Node or a script wrapper/iu);
    expect(() => createNativeHostRegistrationPlan(linuxInput({
      windowsHostExecutablePath: "C:\\BrowseWeave\\host.exe"
    }))).toThrow(/Windows-only/iu);
  });
});

describe("exact browser caller allowlists", () => {
  it("accepts Firefox email-style and braced UUID IDs without wildcards", () => {
    const uuid = "{12345678-1234-1234-1234-123456789abc}";
    const plan = createNativeHostRegistrationPlan(linuxInput({
      firefoxExtensionIds: [uuid, FIREFOX_ID_A]
    }));
    expect(plan.manifests[0]?.manifest).toMatchObject({
      allowed_extensions: [FIREFOX_ID_A, uuid]
    });
  });

  it.each([
    [],
    ["*"],
    ["browseweave"],
    ["@example.invalid"],
    ["bad\nid@example.invalid"],
    [FIREFOX_ID_A, FIREFOX_ID_A],
    Array.from({ length: 9 }, (_, index) => `addon${index}@example.invalid`)
  ])("rejects an unsafe Firefox allowlist %#", (firefoxExtensionIds) => {
    expect(() => createNativeHostRegistrationPlan(linuxInput({ firefoxExtensionIds }))).toThrow(
      /Firefox extension IDs/iu
    );
  });

  it.each([
    ["chrome-extension://*/"],
    [`chrome-extension://${"A".repeat(32)}/`],
    [`chrome-extension://${"a".repeat(32)}`],
    [`chrome-extension://${"a".repeat(32)}/settings.html`],
    [`https://${"a".repeat(32)}/`],
    [CHROME_ORIGIN_A, CHROME_ORIGIN_A],
    Array.from({ length: 9 }, (_, index) =>
      `chrome-extension://${String.fromCharCode(97 + index).repeat(32)}/`
    )
  ])("rejects an unsafe Chrome allowlist %#", (chromiumExtensionOrigins) => {
    expect(() => createNativeHostRegistrationPlan(linuxInput({ chromiumExtensionOrigins }))).toThrow(
      /Chrome extension origins/iu
    );
  });

  it("rejects an explicitly empty Chrome allowlist", () => {
    expect(() => createNativeHostRegistrationPlan(linuxInput({ chromiumExtensionOrigins: [] }))).toThrow(
      /Chrome extension origins/iu
    );
  });
});

describe("launcher and registration ownership states", () => {
  it("distinguishes absent, exact, intact older, and foreign launchers", () => {
    const current = createNativeHostRegistrationPlan(linuxInput());
    const older = createNativeHostRegistrationPlan(linuxInput({
      nodePath: "/opt/Node 22/bin/node",
      nativeHostScriptPath: "/opt/BrowseWeave 0.0.9/native-host.js"
    }));
    expect(nativeHostLauncherState(current.launcher!, undefined)).toBe("absent");
    expect(nativeHostLauncherState(current.launcher!, current.launcher!.content)).toBe("exact");
    expect(nativeHostLauncherState(current.launcher!, older.launcher!.content)).toBe("owned");
    expect(nativeHostLauncherState(current.launcher!, "#!/bin/sh\necho foreign\n")).toBe("foreign");
  });

  it("rejects marker-only edits, digest edits, extra commands, and forged non-launcher bodies", () => {
    const content = createNativeHostRegistrationPlan(linuxInput()).launcher!.content;
    expect(isManagedNativeHostLauncher(content.replace("bin/node", "bin/node2"))).toBe(false);
    expect(isManagedNativeHostLauncher(content.replace(/[a-f0-9]{64}/u, "f".repeat(64)))).toBe(false);
    expect(isManagedNativeHostLauncher(managedLauncherForBody("echo owned\n"))).toBe(false);
    expect(isManagedNativeHostLauncher(managedLauncherForBody(
      `exec '/opt/node' '/opt/native-host.js' "$@"\necho extra\n`
    ))).toBe(false);
    expect(isManagedNativeHostLauncher(managedLauncherForBody(
      `exec 'relative/node' '/opt/native-host.js' "$@"\n`
    ))).toBe(false);
    expect(isManagedNativeHostLauncher(managedLauncherForBody(
      `exec '/opt/node' '/opt/not-the-host.js' "$@"\n`
    ))).toBe(false);
    expect(isManagedNativeHostLauncher(`\ufeff${content}`)).toBe(false);
    expect(isManagedNativeHostLauncher(content.replaceAll("\n", "\r\n"))).toBe(false);
    expect(isManagedNativeHostLauncher("x".repeat(33 * 1024))).toBe(false);
  });

  it("trusts manifests only by byte-exact plan content", () => {
    const current = createNativeHostRegistrationPlan(linuxInput());
    const older = createNativeHostRegistrationPlan(linuxInput({
      firefoxExtensionIds: ["older@example.invalid"]
    }));
    const manifest = current.manifests[0]!;
    expect(nativeHostManifestState(manifest, undefined)).toBe("absent");
    expect(nativeHostManifestState(manifest, manifest.content)).toBe("exact");
    expect(nativeHostManifestState(manifest, manifest.content.trim())).toBe("foreign");
    expect(nativeHostManifestState(manifest, older.manifests[0]!.content)).toBe("foreign");
    const reordered = `${JSON.stringify({
      type: "stdio",
      ...manifest.manifest
    }, null, 2)}\n`;
    expect(nativeHostManifestState(manifest, reordered)).toBe("foreign");
  });

  it("trusts only an exact Windows HKCU default-value registration", () => {
    const plan = createNativeHostRegistrationPlan({
      platform: "win32",
      home: "C:\\Users\\Ada",
      windowsHostExecutablePath: "C:\\BrowseWeave\\host.exe",
      firefoxExtensionIds: [FIREFOX_ID_A]
    });
    const expected = plan.windowsRegistry[0]!;
    expect(windowsNativeHostRegistryState(expected, undefined)).toBe("absent");
    expect(windowsNativeHostRegistryState(expected, expected)).toBe("exact");
    const changed: WindowsNativeHostRegistrySpec = {
      ...expected,
      valueData: "C:\\Foreign\\manifest.json"
    };
    expect(windowsNativeHostRegistryState(expected, changed)).toBe("foreign");
  });
});

describe("fail-closed native host plan validation", () => {
  it.each([
    { platform: "freebsd" },
    { home: "relative/home" },
    { home: "/home/ada/../other" },
    { nodePath: "node" },
    { nodePath: "/opt/node\tother" },
    { nativeHostScriptPath: "/opt/not-native-host.js" },
    { nativeHostScriptPath: "/opt/dir/../native-host.js" }
  ])("rejects unsupported or noncanonical POSIX input %#", (overrides) => {
    expect(() => createNativeHostRegistrationPlan(linuxInput(overrides))).toThrow();
  });

  it("does not silently accept a non-object registration input", () => {
    expect(() => createNativeHostRegistrationPlan(null as unknown as NativeHostRegistrationPlanInput))
      .toThrow(/must be an object/iu);
  });
});
