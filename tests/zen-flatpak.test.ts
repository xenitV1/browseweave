import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { configureZenFlatpakNativeMessaging } from "../src/zen-flatpak.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => await rm(root, { recursive: true, force: true })));
});

async function fixture(): Promise<{ home: string; root: string; profile: string }> {
  const home = await mkdtemp(path.join(tmpdir(), "browseweave-zen-flatpak-"));
  roots.push(home);
  const root = path.join(home, ".var", "app", "app.zen_browser.zen", ".zen");
  const profile = path.join(root, "abcd.Default (release)");
  await mkdir(profile, { recursive: true, mode: 0o700 });
  await writeFile(path.join(root, "profiles.ini"), [
    "[Profile0]",
    "Name=Default (release)",
    "IsRelative=1",
    "Path=abcd.Default (release)",
    "",
    "[InstallABCDEF]",
    "Default=abcd.Default (release)",
    "Locked=1",
    ""
  ].join("\n"), { mode: 0o600 });
  return { home, root, profile };
}

describe("Zen Flatpak native-messaging portal configuration", () => {
  it("preserves other user preferences and enables the portal idempotently", async () => {
    const value = await fixture();
    const userJs = path.join(value.profile, "user.js");
    await writeFile(userJs, 'user_pref("browser.tabs.warnOnClose", false);\n', { mode: 0o644 });
    await expect(configureZenFlatpakNativeMessaging({ home: value.home })).resolves.toEqual({
      status: "configured",
      restartRequired: true
    });
    expect(await readFile(userJs, "utf8")).toBe(
      'user_pref("browser.tabs.warnOnClose", false);\n' +
      'user_pref("widget.use-xdg-desktop-portal.native-messaging", 1);\n'
    );
    expect((await lstat(userJs)).mode & 0o777).toBe(0o600);
    await expect(configureZenFlatpakNativeMessaging({ home: value.home })).resolves.toEqual({
      status: "unchanged",
      restartRequired: false
    });
  });

  it("replaces earlier values so the final preference is enabled", async () => {
    const value = await fixture();
    const userJs = path.join(value.profile, "user.js");
    await writeFile(userJs, [
      'user_pref("widget.use-xdg-desktop-portal.native-messaging", 0);',
      'user_pref("browser.tabs.warnOnClose", false);',
      ""
    ].join("\n"), { mode: 0o600 });
    await configureZenFlatpakNativeMessaging({ home: value.home });
    const contents = await readFile(userJs, "utf8");
    expect(contents).not.toContain("native-messaging\", 0");
    expect(contents.endsWith('user_pref("widget.use-xdg-desktop-portal.native-messaging", 1);\n')).toBe(true);
  });

  it("fails closed for an unsafe selected profile", async () => {
    const value = await fixture();
    await rm(value.profile, { recursive: true, force: true });
    await symlink(tmpdir(), value.profile);
    await expect(configureZenFlatpakNativeMessaging({ home: value.home })).rejects.toThrow(/safe directory/iu);
  });

  it("reports an unused installation without creating browser profile data", async () => {
    const home = await mkdtemp(path.join(tmpdir(), "browseweave-zen-flatpak-empty-"));
    roots.push(home);
    await expect(configureZenFlatpakNativeMessaging({ home })).resolves.toEqual({
      status: "unavailable",
      restartRequired: false
    });
  });
});
