import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, link, lstat, open, realpath, rename, rm, unlink, type FileHandle } from "node:fs/promises";
import path from "node:path";

const PORTAL_PREFERENCE = 'user_pref("widget.use-xdg-desktop-portal.native-messaging", 1);';
const MAX_PROFILE_METADATA_BYTES = 1024 * 1024;
const PORTAL_PREFERENCE_LINE = /^[\t ]*user_pref\([\t ]*["']widget\.use-xdg-desktop-portal\.native-messaging["'][\t ]*,[^;\r\n]*\);[\t ]*(?:\r?\n|$)/gmu;

export interface ZenFlatpakPortalResult {
  readonly status: "configured" | "unchanged" | "unavailable";
  readonly restartRequired: boolean;
}

interface OwnedFile {
  readonly content: string;
  readonly dev: number;
  readonly ino: number;
  readonly mode: number;
}

function currentUid(): number | undefined {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}

async function readOwnedFile(filePath: string, allowMissing = false): Promise<OwnedFile | undefined> {
  let info;
  try {
    info = await lstat(filePath);
  } catch (error) {
    if (allowMissing && (error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_PROFILE_METADATA_BYTES) {
    throw new Error("The Zen profile metadata is not a safe regular file.");
  }
  if (currentUid() !== undefined && info.uid !== currentUid()) {
    throw new Error("The Zen profile metadata is not owned by the current user.");
  }
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (
      !opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino ||
      opened.size !== info.size
    ) throw new Error("The Zen profile metadata changed while it was inspected.");
    return {
      content: await handle.readFile("utf8"),
      dev: opened.dev,
      ino: opened.ino,
      mode: opened.mode
    };
  } finally {
    await handle.close();
  }
}

function activeProfilePath(contents: string): string {
  if (contents.length === 0 || /\0/u.test(contents)) throw new Error("Zen profiles.ini is invalid.");
  let section = "";
  const installDefaults = new Set<string>();
  const profileDefaults = new Set<string>();
  let profilePath: string | undefined;
  let profileIsDefault = false;

  const commitProfile = (): void => {
    if (section.startsWith("Profile") && profileIsDefault && profilePath) profileDefaults.add(profilePath);
    profilePath = undefined;
    profileIsDefault = false;
  };

  for (const rawLine of contents.split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line === "" || line.startsWith(";") || line.startsWith("#")) continue;
    const heading = /^\[([^\]\r\n]{1,200})\]$/u.exec(line);
    if (heading) {
      commitProfile();
      section = heading[1]!;
      continue;
    }
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (section.startsWith("Install") && key === "Default" && value) installDefaults.add(value);
    if (section.startsWith("Profile") && key === "Path") profilePath = value;
    if (section.startsWith("Profile") && key === "Default" && value === "1") profileIsDefault = true;
  }
  commitProfile();

  const candidates = installDefaults.size > 0 ? installDefaults : profileDefaults;
  if (candidates.size !== 1) {
    throw new Error("BrowseWeave could not identify exactly one active Zen profile.");
  }
  return [...candidates][0]!;
}

function safeProfileDirectory(root: string, relative: string): string {
  if (
    relative === "" || path.posix.isAbsolute(relative) || /[\0\r\n]/u.test(relative) ||
    path.posix.normalize(relative) !== relative || relative === ".." || relative.startsWith("../")
  ) throw new Error("Zen profiles.ini contains an unsafe active profile path.");
  const profile = path.posix.join(root, relative);
  const fromRoot = path.posix.relative(root, profile);
  if (fromRoot === "" || fromRoot.startsWith("..") || path.posix.isAbsolute(fromRoot)) {
    throw new Error("The active Zen profile escapes its profile root.");
  }
  return profile;
}

function portalPreferenceContents(current: string): string {
  const withoutManagedPreference = current.replace(PORTAL_PREFERENCE_LINE, "");
  const separator = withoutManagedPreference === "" || withoutManagedPreference.endsWith("\n") ? "" : "\n";
  return `${withoutManagedPreference}${separator}${PORTAL_PREFERENCE}\n`;
}

async function writeOwnerOnly(filePath: string, contents: string, existing?: OwnedFile): Promise<void> {
  const directory = path.posix.dirname(filePath);
  const temporary = path.posix.join(
    directory,
    `.${path.posix.basename(filePath)}.${process.pid}-${randomBytes(8).toString("hex")}.tmp`
  );
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      temporary,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
      0o600
    );
    await handle.writeFile(contents, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    if (!existing) {
      await link(temporary, filePath);
      await unlink(temporary);
    } else {
      const current = await lstat(filePath);
      const opened = await readOwnedFile(filePath);
      if (
        !current.isFile() || current.isSymbolicLink() || current.dev !== existing.dev ||
        current.ino !== existing.ino || opened === undefined || opened.content !== existing.content
      ) throw new Error("Zen user.js changed while BrowseWeave was preparing the portal setting.");
      await rename(temporary, filePath);
    }
    await chmod(filePath, 0o600);
  } catch (error) {
    await handle?.close();
    await rm(temporary, { force: true });
    throw error;
  }
}

/** Enable Firefox's user-consented native-messaging portal for the selected Zen Flatpak profile. */
export async function configureZenFlatpakNativeMessaging(input: {
  readonly home: string;
  readonly profilesRoot?: string;
}): Promise<ZenFlatpakPortalResult> {
  if (!path.posix.isAbsolute(input.home) || /[\0\r\n]/u.test(input.home)) {
    throw new Error("The current user home directory is unsafe.");
  }
  const root = path.posix.normalize(
    input.profilesRoot ?? path.posix.join(input.home, ".var", "app", "app.zen_browser.zen", ".zen")
  );
  const relativeRoot = path.posix.relative(input.home, root);
  if (
    !path.posix.isAbsolute(root) || relativeRoot === "" || relativeRoot.startsWith("..") ||
    path.posix.isAbsolute(relativeRoot)
  ) throw new Error("The Zen Flatpak profile root is outside the current user account.");

  try {
    const canonicalRoot = await realpath(root);
    const rootInfo = await lstat(root);
    if (canonicalRoot !== root || !rootInfo.isDirectory() || rootInfo.isSymbolicLink()) {
      throw new Error("The Zen Flatpak profile root is unsafe.");
    }
    if (currentUid() !== undefined && rootInfo.uid !== currentUid()) {
      throw new Error("The Zen Flatpak profile root is not owned by the current user.");
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { status: "unavailable", restartRequired: false };
    }
    throw error;
  }

  let profilesIni: OwnedFile | undefined;
  try {
    profilesIni = await readOwnedFile(path.posix.join(root, "profiles.ini"), true);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { status: "unavailable", restartRequired: false };
    throw error;
  }
  if (!profilesIni) return { status: "unavailable", restartRequired: false };
  const profileDirectory = safeProfileDirectory(root, activeProfilePath(profilesIni.content));
  const profileInfo = await lstat(profileDirectory);
  if (!profileInfo.isDirectory() || profileInfo.isSymbolicLink()) {
    throw new Error("The active Zen profile is not a safe directory.");
  }
  if (currentUid() !== undefined && profileInfo.uid !== currentUid()) {
    throw new Error("The active Zen profile is not owned by the current user.");
  }

  const userJsPath = path.posix.join(profileDirectory, "user.js");
  const existing = await readOwnedFile(userJsPath, true);
  const updated = portalPreferenceContents(existing?.content ?? "");
  if (existing?.content === updated) {
    if ((existing.mode & 0o077) !== 0) await chmod(userJsPath, 0o600);
    return { status: "unchanged", restartRequired: false };
  }
  await writeOwnerOnly(userJsPath, updated, existing);
  return { status: "configured", restartRequired: true };
}
