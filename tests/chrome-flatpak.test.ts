import { describe, expect, it } from "vitest";
import {
  CHROME_FLATPAK_APP_ID,
  CHROME_FLATPAK_SPAWN_GRANT_COMMAND,
  chromeFlatpakAppRoot,
  chromeFlatpakExtensionParentPath,
  chromeFlatpakManifestPath,
  chromeFlatpakSessionBusPolicy,
  chromeFlatpakUserDataPath,
  chromeFlatpakWrapperPath,
  isManagedChromeFlatpakWrapper,
  managedChromeFlatpakWrapperContent
} from "../src/native/chrome-flatpak.js";
import {
  chromeFlatpakWrapperState,
  createNativeHostRegistrationPlan
} from "../src/native/host-plan.js";

const HOME = "/home/example";
const LAUNCHER = "/home/example/.local/share/browseweave/native-host/browseweave-native-host";
const ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop/";

function linuxInput(chromeFlatpak: boolean) {
  return {
    platform: "linux" as const,
    home: HOME,
    nodePath: "/usr/bin/node",
    nativeHostScriptPath: "/home/example/.local/lib/node_modules/browseweave/dist/src/native-host.js",
    firefoxExtensionIds: ["browseweave@local.invalid"],
    chromiumExtensionOrigins: [ORIGIN],
    ...(chromeFlatpak ? { chromeFlatpak: true } : {})
  };
}

describe("Chrome Flatpak locations", () => {
  it("places every sandbox-visible artifact under the Flatpak application root", () => {
    expect(CHROME_FLATPAK_APP_ID).toBe("com.google.Chrome");
    expect(chromeFlatpakAppRoot(HOME)).toBe(`${HOME}/.var/app/com.google.Chrome`);
    expect(chromeFlatpakUserDataPath(HOME)).toBe(`${HOME}/.var/app/com.google.Chrome/config/google-chrome`);
    expect(chromeFlatpakExtensionParentPath(HOME)).toBe(`${HOME}/.var/app/com.google.Chrome/browseweave`);
    expect(chromeFlatpakWrapperPath(HOME)).toBe(
      `${HOME}/.var/app/com.google.Chrome/browseweave/browseweave-native-host-chrome-flatpak`
    );
    expect(chromeFlatpakManifestPath(HOME)).toBe(
      `${HOME}/.var/app/com.google.Chrome/config/google-chrome/NativeMessagingHosts/io.browseweave.setup.json`
    );
    expect(CHROME_FLATPAK_SPAWN_GRANT_COMMAND).toBe(
      "flatpak override --user --talk-name=org.freedesktop.Flatpak com.google.Chrome"
    );
  });
});

describe("Chrome Flatpak sandbox wrapper", () => {
  it("accepts only its own generated content for the exact host launcher", () => {
    const content = managedChromeFlatpakWrapperContent(LAUNCHER);
    expect(content).toContain("exec flatpak-spawn --host '");
    expect(isManagedChromeFlatpakWrapper(content, LAUNCHER)).toBe(true);
    expect(isManagedChromeFlatpakWrapper(content, "/usr/local/bin/other-launcher")).toBe(false);
    expect(isManagedChromeFlatpakWrapper(content.replace("flatpak-spawn", "host-spawn"), LAUNCHER)).toBe(false);
    expect(isManagedChromeFlatpakWrapper(content.slice(0, -2), LAUNCHER)).toBe(false);
    expect(isManagedChromeFlatpakWrapper("#!/bin/sh\nexec flatpak-spawn --host x\n", LAUNCHER)).toBe(false);
  });

  it("round-trips a launcher path that contains a single quote", () => {
    const quoted = `${HOME}/w'ird/browseweave-native-host`;
    const content = managedChromeFlatpakWrapperContent(quoted);
    expect(content).not.toContain(`'${quoted}'`);
    expect(isManagedChromeFlatpakWrapper(content, quoted)).toBe(true);
  });

  it("classifies wrapper artifact states exactly like the host launcher", () => {
    const content = managedChromeFlatpakWrapperContent(LAUNCHER);
    const plan = { path: chromeFlatpakWrapperPath(HOME), content, mode: 0o700 as const, hostLauncherPath: LAUNCHER };
    expect(chromeFlatpakWrapperState(plan, undefined)).toBe("absent");
    expect(chromeFlatpakWrapperState(plan, content)).toBe("exact");
    expect(chromeFlatpakWrapperState(plan, content.replace("#!/bin/sh", "#!/bin/sh "))).toBe("foreign");
    const owned = content.replace(`--host '${LAUNCHER}'`, `--host '${LAUNCHER}-owned'`);
    expect(chromeFlatpakWrapperState(plan, owned)).toBe("foreign");
  });
});

describe("Chrome Flatpak session-bus permission parsing", () => {
  it("grants spawn access only from the Session Bus Policy section", () => {
    expect(chromeFlatpakSessionBusPolicy(
      "[Context]\nfilesystems=xdg-download;\n\n[Session Bus Policy]\norg.freedesktop.Flatpak=talk\n"
    ).spawnHostGranted).toBe(true);
    expect(chromeFlatpakSessionBusPolicy(
      "[Session Bus Policy]\norg.freedesktop.Flatpak=own\n"
    ).spawnHostGranted).toBe(true);
    expect(chromeFlatpakSessionBusPolicy(
      "[Session Bus Policy]\norg.kde.plasma.browser.integration=talk\n"
    ).spawnHostGranted).toBe(false);
    expect(chromeFlatpakSessionBusPolicy(
      "[System Bus Policy]\norg.freedesktop.Flatpak=talk\n"
    ).spawnHostGranted).toBe(false);
    expect(chromeFlatpakSessionBusPolicy("").spawnHostGranted).toBe(false);
  });
});

describe("Chrome Flatpak native host registration plan", () => {
  it("writes the Chrome manifest and wrapper inside the sandbox application root", () => {
    const plan = createNativeHostRegistrationPlan(linuxInput(true));
    expect(plan.platform).toBe("linux");
    expect(plan.chromeFlatpakWrapper).toBeDefined();
    const wrapper = plan.chromeFlatpakWrapper!;
    expect(wrapper.path).toBe(chromeFlatpakWrapperPath(HOME));
    expect(wrapper.mode).toBe(0o700);
    expect(wrapper.hostLauncherPath).toBe(plan.launcher?.path);
    expect(isManagedChromeFlatpakWrapper(wrapper.content, plan.launcher!.path)).toBe(true);

    const chrome = plan.manifests.find((manifest) => manifest.browser === "chrome");
    expect(chrome?.path).toBe(chromeFlatpakManifestPath(HOME));
    expect(chrome?.manifest.path).toBe(wrapper.path);
    expect(chrome?.manifest.allowed_origins).toEqual([ORIGIN]);
    const firefox = plan.manifests.find((manifest) => manifest.browser === "firefox");
    expect(firefox?.path).toBe(`${HOME}/.mozilla/native-messaging-hosts/io.browseweave.setup.json`);
  });

  it("keeps the default Chrome manifest untouched without the Flatpak flag", () => {
    const plan = createNativeHostRegistrationPlan(linuxInput(false));
    expect(plan.chromeFlatpakWrapper).toBeUndefined();
    const chrome = plan.manifests.find((manifest) => manifest.browser === "chrome");
    expect(chrome?.path).toBe(`${HOME}/.config/google-chrome/NativeMessagingHosts/io.browseweave.setup.json`);
    expect(chrome?.manifest.path).toBe(plan.launcher?.path);
  });

  it("leaves the flag inert when Chrome is not being registered", () => {
    const plan = createNativeHostRegistrationPlan({ ...linuxInput(true), chromiumExtensionOrigins: undefined });
    expect(plan.chromeFlatpakWrapper).toBeUndefined();
    expect(plan.manifests.map(({ browser }) => browser)).toEqual(["firefox"]);
  });

  it("rejects Flatpak registration outside Linux", () => {
    expect(() => createNativeHostRegistrationPlan({
      ...linuxInput(true),
      platform: "darwin"
    })).toThrow("Linux only");
    expect(() => createNativeHostRegistrationPlan({
      platform: "win32",
      home: "C:\\Users\\example",
      windowsHostExecutablePath: "C:\\Users\\example\\AppData\\Local\\BrowseWeave\\native-host.exe",
      firefoxExtensionIds: ["browseweave@local.invalid"],
      chromiumExtensionOrigins: [ORIGIN],
      chromeFlatpak: true
    })).toThrow("not available on Windows");
  });
});
