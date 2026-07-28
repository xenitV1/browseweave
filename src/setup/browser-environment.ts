const FORWARDED_BROWSER_ENVIRONMENT_KEYS = new Set([
  "HOME", "USER", "LOGNAME", "SHELL", "LANG", "TZ",
  "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS",
  "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP",
  "XDG_DATA_HOME", "XDG_DATA_DIRS", "DESKTOP_SESSION", "GDK_BACKEND",
  "QT_QPA_PLATFORM", "OZONE_PLATFORM", "OZONE_PLATFORM_HINT", "MOZ_ENABLE_WAYLAND",
  "PULSE_SERVER", "PIPEWIRE_REMOTE", "FONTCONFIG_PATH", "FONTCONFIG_FILE", "GTK_THEME",
  "TEMP", "TMP", "TMPDIR", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"
]);

export function browserSystemPath(
  platform: NodeJS.Platform
): { key: "PATH"; value: string } | undefined {
  // Windows browser executables are launched by absolute path. Omitting PATH,
  // SystemRoot and COMSPEC is safer than trusting caller-controlled values.
  if (platform === "win32") return undefined;
  if (platform === "darwin") {
    return { key: "PATH", value: "/usr/bin:/bin:/usr/sbin:/sbin" };
  }
  return {
    key: "PATH",
    value: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  };
}

export function browserLaunchEnvironment(
  source: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform
): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined) continue;
    if (FORWARDED_BROWSER_ENVIRONMENT_KEYS.has(key) || /^LC_[A-Z_]+$/u.test(key)) {
      environment[key] = value;
    }
  }

  const systemPath = browserSystemPath(platform);
  if (systemPath) environment[systemPath.key] = systemPath.value;
  return environment;
}
