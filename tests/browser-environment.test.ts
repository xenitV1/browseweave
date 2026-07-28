import { describe, expect, it } from "vitest";
import { browserLaunchEnvironment, browserSystemPath } from "../src/browser-environment.js";

describe("browser launch environment", () => {
  it("replaces an npm or project-controlled Linux PATH while preserving desktop session values", () => {
    const environment = browserLaunchEnvironment({
      PATH: "/work/project/node_modules/.bin:/home/ada/.npm/_npx/123/node_modules/.bin:/usr/bin",
      DISPLAY: ":0",
      WAYLAND_DISPLAY: "wayland-0",
      DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus",
      HOME: "/home/ada",
      npm_execpath: "/work/project/node_modules/npm/bin/npm-cli.js",
      NODE_OPTIONS: "--require=/tmp/payload.cjs",
      LD_PRELOAD: "/tmp/payload.so",
      GIT_SSH_COMMAND: "/tmp/payload"
    }, "linux");

    expect(environment.PATH).toBe("/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    expect(environment.DISPLAY).toBe(":0");
    expect(environment.WAYLAND_DISPLAY).toBe("wayland-0");
    expect(environment.DBUS_SESSION_BUS_ADDRESS).toBe("unix:path=/run/user/1000/bus");
    expect(environment.HOME).toBe("/home/ada");
    expect(environment).not.toHaveProperty("npm_execpath");
    expect(environment).not.toHaveProperty("NODE_OPTIONS");
    expect(environment).not.toHaveProperty("LD_PRELOAD");
    expect(environment).not.toHaveProperty("GIT_SSH_COMMAND");
  });

  it("uses only macOS system command directories", () => {
    expect(browserSystemPath("darwin")?.value).toBe("/usr/bin:/bin:/usr/sbin:/sbin");
  });

  it("does not trust any caller-provided Windows command search paths", () => {
    const environment = browserLaunchEnvironment({
      Path: "C:\\work\\node_modules\\.bin;C:\\Windows\\System32",
      SystemRoot: "C:\\work\\fake-windows",
      WINDIR: "D:\\Windows\\",
      COMSPEC: "C:\\work\\cmd.exe",
      USERPROFILE: "C:\\Users\\Ada"
    }, "win32");

    expect(browserSystemPath("win32")).toBeUndefined();
    expect(environment).not.toHaveProperty("Path");
    expect(environment).not.toHaveProperty("PATH");
    expect(environment).not.toHaveProperty("SystemRoot");
    expect(environment).not.toHaveProperty("WINDIR");
    expect(environment).not.toHaveProperty("COMSPEC");
    expect(environment).not.toHaveProperty("PATHEXT");
  });
});
