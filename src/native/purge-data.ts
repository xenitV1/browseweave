import { lstat, realpath, rm } from "node:fs/promises";
import path from "node:path";

const ALLOWED_APPLICATION_DIRECTORY_NAMES = new Set(["browseweave", "BrowseWeave", "zen-codex-bridge"]);

function pathApiFor(platform: NodeJS.Platform): typeof path.posix | typeof path.win32 {
  return platform === "win32" ? path.win32 : path.posix;
}

function sameOrInside(
  parent: string,
  candidate: string,
  pathApi: typeof path.posix | typeof path.win32
): boolean {
  const relative = pathApi.relative(parent, candidate);
  return relative === "" || (!relative.startsWith("..") && !pathApi.isAbsolute(relative));
}

export function minimizePurgeTargets(
  candidates: readonly string[],
  platform: NodeJS.Platform = process.platform
): readonly string[] {
  if (candidates.length < 1 || candidates.length > 8) {
    throw new Error("BrowseWeave data purge requires between one and eight exact application directories.");
  }
  const pathApi = pathApiFor(platform);
  const normalized = [...new Set(candidates.map((candidate) => {
    if (
      typeof candidate !== "string" || /[\0\r\n]/u.test(candidate) ||
      !pathApi.isAbsolute(candidate) || pathApi.normalize(candidate) !== candidate ||
      candidate === pathApi.parse(candidate).root
    ) throw new Error("BrowseWeave refused an unsafe data-purge path.");
    return candidate;
  }))].sort((left, right) => left.length - right.length || left.localeCompare(right));

  const minimal: string[] = [];
  for (const candidate of normalized) {
    if (!minimal.some((parent) => sameOrInside(parent, candidate, pathApi))) minimal.push(candidate);
  }
  for (const candidate of minimal) {
    if (!ALLOWED_APPLICATION_DIRECTORY_NAMES.has(pathApi.basename(candidate))) {
      throw new Error(`BrowseWeave refused a data-purge directory with an unexpected name: ${candidate}`);
    }
  }
  return minimal;
}

/** Remove only canonical, current-user-owned BrowseWeave application directories. */
export async function purgeOwnedApplicationDirectories(
  candidates: readonly string[],
  platform: NodeJS.Platform = process.platform
): Promise<readonly string[]> {
  const targets = minimizePurgeTargets(candidates, platform);
  const removed: string[] = [];
  for (const target of targets) {
    let info;
    try {
      info = await lstat(target);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error(`BrowseWeave data is not a safe application directory and was preserved: ${target}`);
    }
    if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
      throw new Error(`BrowseWeave data is not owned by the current user and was preserved: ${target}`);
    }
    if (await realpath(target) !== target) {
      throw new Error(`BrowseWeave data uses a redirected path and was preserved: ${target}`);
    }
    await rm(target, { recursive: true, force: false });
    removed.push(target);
  }
  return removed;
}
