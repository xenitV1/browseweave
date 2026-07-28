import { randomBytes } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { chmod, link, lstat, mkdir, open, readFile, rename, rm, unlink, type FileHandle } from "node:fs/promises";
import path from "node:path";
import {
  nativeHostLauncherState,
  nativeHostManifestState,
  type NativeHostLauncherPlan,
  type NativeHostManifestPlan,
  type NativeHostRegistrationPlan
} from "./host-plan.js";

interface ExistingFile {
  readonly content: string;
  readonly dev: number;
  readonly ino: number;
}

function currentUid(): number | undefined {
  return typeof process.getuid === "function" ? process.getuid() : undefined;
}

async function ensureOwnedDirectoryChain(home: string, target: string): Promise<void> {
  const pathApi = process.platform === "win32" ? path.win32 : path.posix;
  const homeInfo = await lstat(home);
  if (!homeInfo.isDirectory() || homeInfo.isSymbolicLink() ||
    (currentUid() !== undefined && homeInfo.uid !== currentUid())) {
    throw new Error("The current user home directory is unsafe.");
  }
  const relative = pathApi.relative(home, target);
  if (relative === "" || relative.startsWith("..") || pathApi.isAbsolute(relative)) {
    throw new Error("The native host directory must stay inside the current user account.");
  }
  let current = home;
  for (const component of relative.split(pathApi.sep)) {
    if (!component || component === "." || component === "..") {
      throw new Error("The native host directory contains an unsafe component.");
    }
    current = pathApi.join(current, component);
    try {
      const info = await lstat(current);
      if (!info.isDirectory() || info.isSymbolicLink()) {
        throw new Error("A native host directory component is not a real directory.");
      }
      if (currentUid() !== undefined && info.uid !== currentUid()) {
        throw new Error("A native host directory component has the wrong owner.");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await mkdir(current, { mode: 0o700 });
      const created = await lstat(current);
      if (!created.isDirectory() || created.isSymbolicLink() ||
        (currentUid() !== undefined && created.uid !== currentUid())) {
        throw new Error("BrowseWeave could not create a safe native host directory.");
      }
      if (process.platform !== "win32") await chmod(current, 0o700);
    }
  }
}

async function readOwnedRegularFile(filePath: string, maximumBytes = 64 * 1024): Promise<ExistingFile | undefined> {
  let info;
  try {
    info = await lstat(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  if (!info.isFile() || info.isSymbolicLink() || info.size > maximumBytes) {
    throw new Error("An existing native host artifact is unsafe.");
  }
  if (currentUid() !== undefined && info.uid !== currentUid()) {
    throw new Error("An existing native host artifact has the wrong owner.");
  }
  const handle = await open(filePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino || opened.size !== info.size) {
      throw new Error("A native host artifact changed while it was being inspected.");
    }
    return { content: await handle.readFile("utf8"), dev: opened.dev, ino: opened.ino };
  } finally {
    await handle.close();
  }
}

async function writeOwnedArtifact(input: {
  filePath: string;
  content: string;
  mode: number;
  existing?: ExistingFile;
}): Promise<void> {
  const directory = path.dirname(input.filePath);
  const temporaryPath = path.join(
    directory,
    `.${path.basename(input.filePath)}.${process.pid}-${randomBytes(8).toString("hex")}.tmp`
  );
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      temporaryPath,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
      input.mode
    );
    await handle.writeFile(input.content, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    if (input.existing === undefined) {
      await link(temporaryPath, input.filePath);
      await unlink(temporaryPath);
    } else {
      const current = await lstat(input.filePath);
      if (
        !current.isFile() || current.isSymbolicLink() ||
        current.dev !== input.existing.dev || current.ino !== input.existing.ino ||
        await readFile(input.filePath, "utf8") !== input.existing.content
      ) throw new Error("A native host artifact changed while BrowseWeave was preparing its update.");
      await rename(temporaryPath, input.filePath);
    }
    if (process.platform !== "win32") await chmod(input.filePath, input.mode);
  } catch (error) {
    await handle?.close();
    await rm(temporaryPath, { force: true });
    throw error;
  }
}

async function installLauncher(home: string, launcher: NativeHostLauncherPlan): Promise<void> {
  await ensureOwnedDirectoryChain(home, path.dirname(launcher.path));
  const existing = await readOwnedRegularFile(launcher.path);
  const state = nativeHostLauncherState(launcher, existing?.content);
  if (state === "foreign") throw new Error("A foreign native host launcher was not overwritten.");
  if (state === "exact") {
    if (process.platform !== "win32") await chmod(launcher.path, launcher.mode);
    return;
  }
  await writeOwnedArtifact({
    filePath: launcher.path,
    content: launcher.content,
    mode: launcher.mode,
    ...(existing ? { existing } : {})
  });
}

async function installManifest(home: string, manifest: NativeHostManifestPlan): Promise<void> {
  await ensureOwnedDirectoryChain(home, path.dirname(manifest.path));
  const existing = await readOwnedRegularFile(manifest.path);
  const state = nativeHostManifestState(manifest, existing?.content);
  if (state === "foreign") throw new Error(`A foreign ${manifest.browser} native host manifest was not overwritten.`);
  if (state === "exact") {
    if (manifest.mode !== undefined && process.platform !== "win32") await chmod(manifest.path, manifest.mode);
    return;
  }
  await writeOwnedArtifact({
    filePath: manifest.path,
    content: manifest.content,
    mode: manifest.mode ?? 0o600
  });
}

/** Install only exact per-user artifacts; registry registration is handled by the signed Windows installer. */
export async function installNativeHostRegistration(
  plan: NativeHostRegistrationPlan,
  home: string
): Promise<void> {
  if (plan.platform !== process.platform) throw new Error("The native host plan does not match this operating system.");
  if (plan.platform === "win32") {
    throw new Error("Windows native host registration requires the signed BrowseWeave executable installer.");
  }
  if (!plan.launcher) throw new Error("The POSIX native host launcher plan is missing.");
  await installLauncher(home, plan.launcher);
  for (const manifest of plan.manifests) await installManifest(home, manifest);
}

export async function uninstallNativeHostRegistration(
  plan: NativeHostRegistrationPlan,
  home: string
): Promise<void> {
  if (plan.platform !== process.platform) throw new Error("The native host plan does not match this operating system.");
  if (plan.platform === "win32") {
    throw new Error("Windows native host removal requires the signed BrowseWeave executable installer.");
  }
  for (const manifest of plan.manifests) {
    const existing = await readOwnedRegularFile(manifest.path);
    const state = nativeHostManifestState(manifest, existing?.content);
    if (state === "foreign") throw new Error(`A foreign ${manifest.browser} native host manifest was not removed.`);
    if (state === "exact") await unlink(manifest.path);
  }
  if (plan.launcher) {
    const existing = await readOwnedRegularFile(plan.launcher.path);
    const state = nativeHostLauncherState(plan.launcher, existing?.content);
    if (state === "foreign") throw new Error("A foreign native host launcher was not removed.");
    if (state === "exact" || state === "owned") await unlink(plan.launcher.path);
  }
  // Empty parent directories are intentionally preserved; they may contain other browser hosts.
  void home;
}
