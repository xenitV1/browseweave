import { createHash, randomBytes } from "node:crypto";
import {
  constants as fsConstants,
  chmod,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  type FileHandle
} from "node:fs/promises";
import path from "node:path";

const SKILL_NAME = "browseweave";
const MARKER_NAME = ".browseweave-skill.json";
const SKILL_FILE_NAME = "SKILL.md";
const MAX_SKILL_BYTES = 128 * 1024;

export interface InstalledAgentSkill {
  client: "codex" | "claude-code";
  path: string;
  status: "installed" | "updated" | "unchanged";
}

interface ManagedSkillMarker {
  managed_by: "BrowseWeave";
  marker_version: 1;
  skill_name: "browseweave";
  package_version: string;
  content_sha256: string;
}

interface ExistingSkill {
  state: "missing" | "exact-unmanaged" | "managed";
  skillContents?: string;
  markerContents?: string;
  marker?: ManagedSkillMarker;
}

interface SkillTarget {
  client: InstalledAgentSkill["client"];
  parentSegments: readonly string[];
  path: string;
}

function sha256(contents: string): string {
  return createHash("sha256").update(contents, "utf8").digest("hex");
}

function ownerMatches(info: Awaited<ReturnType<typeof lstat>>): boolean {
  return typeof process.getuid !== "function" || info.uid === process.getuid();
}

async function safeDirectory(directory: string, create: boolean): Promise<void> {
  if (create) {
    try {
      await mkdir(directory, { mode: 0o700 });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  }
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || !ownerMatches(info)) {
    throw new Error(`Refusing an unsafe agent-skill directory: ${directory}`);
  }
}

async function prepareParent(home: string, segments: readonly string[]): Promise<string> {
  await safeDirectory(home, false);
  let current = home;
  for (const segment of segments) {
    current = path.join(current, segment);
    await safeDirectory(current, true);
  }
  return current;
}

function parseMarker(contents: string): ManagedSkillMarker {
  let value: unknown;
  try {
    value = JSON.parse(contents) as unknown;
  } catch {
    throw new Error("An installed BrowseWeave skill marker is invalid; the skill was not overwritten.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("An installed BrowseWeave skill marker is invalid; the skill was not overwritten.");
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(",") !==
      "content_sha256,managed_by,marker_version,package_version,skill_name" ||
    record.managed_by !== "BrowseWeave" ||
    record.marker_version !== 1 ||
    record.skill_name !== SKILL_NAME ||
    typeof record.package_version !== "string" ||
    !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(record.package_version) ||
    typeof record.content_sha256 !== "string" ||
    !/^[a-f0-9]{64}$/u.test(record.content_sha256)
  ) {
    throw new Error("An installed BrowseWeave skill marker is invalid; the skill was not overwritten.");
  }
  return record as unknown as ManagedSkillMarker;
}

async function regularOwnedFile(file: string, label: string): Promise<void> {
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink() || !ownerMatches(info)) {
    throw new Error(`The installed BrowseWeave ${label} is unsafe; it was not overwritten.`);
  }
}

async function regularPackagedFile(file: string): Promise<void> {
  const info = await lstat(file);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error("The packaged BrowseWeave SKILL.md is unsafe.");
  }
}

async function inspectExistingSkill(target: string, expectedContents: string): Promise<ExistingSkill> {
  let directoryInfo;
  try {
    directoryInfo = await lstat(target);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { state: "missing" };
    throw error;
  }
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink() || !ownerMatches(directoryInfo)) {
    throw new Error(`A foreign or unsafe ${SKILL_NAME} skill already exists at ${target}; it was not overwritten.`);
  }
  const entries = await readdir(target, { withFileTypes: true });
  const unexpected = entries.find((entry) =>
    entry.name !== SKILL_FILE_NAME && entry.name !== MARKER_NAME
  );
  if (unexpected) {
    throw new Error(`A foreign ${SKILL_NAME} skill already exists at ${target}; unexpected entry ${unexpected.name} was preserved.`);
  }

  const skillPath = path.join(target, SKILL_FILE_NAME);
  try {
    await regularOwnedFile(skillPath, "SKILL.md");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`An incomplete ${SKILL_NAME} skill already exists at ${target}; it was not overwritten.`);
    }
    throw error;
  }
  const skillContents = await readFile(skillPath, "utf8");
  const markerPath = path.join(target, MARKER_NAME);
  let markerContents: string;
  try {
    await regularOwnedFile(markerPath, "marker");
    markerContents = await readFile(markerPath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" && skillContents === expectedContents) {
      return { state: "exact-unmanaged", skillContents };
    }
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`A user-managed ${SKILL_NAME} skill already exists at ${target}; it was not overwritten.`);
    }
    throw error;
  }
  const marker = parseMarker(markerContents);
  if (sha256(skillContents) !== marker.content_sha256) {
    throw new Error(`The managed ${SKILL_NAME} skill at ${target} was modified; it was not overwritten.`);
  }
  return { state: "managed", skillContents, markerContents, marker };
}

async function writeExclusive(file: string, contents: string): Promise<void> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      file,
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
      0o600
    );
    await handle.writeFile(contents, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    if (process.platform !== "win32") await chmod(file, 0o600);
  } catch (error) {
    await handle?.close();
    await rm(file, { force: true });
    throw error;
  }
}

function markerContents(version: string, digest: string): string {
  const marker: ManagedSkillMarker = {
    managed_by: "BrowseWeave",
    marker_version: 1,
    skill_name: SKILL_NAME,
    package_version: version,
    content_sha256: digest
  };
  return `${JSON.stringify(marker)}\n`;
}

async function buildCandidate(parent: string, version: string, contents: string, digest: string): Promise<string> {
  const candidate = path.join(parent, `.${SKILL_NAME}.install-${process.pid}-${randomBytes(8).toString("hex")}`);
  await mkdir(candidate, { mode: 0o700 });
  try {
    await writeExclusive(path.join(candidate, SKILL_FILE_NAME), contents);
    await writeExclusive(path.join(candidate, MARKER_NAME), markerContents(version, digest));
    return candidate;
  } catch (error) {
    await rm(candidate, { recursive: true, force: true });
    throw error;
  }
}

async function installTarget(
  target: SkillTarget,
  existing: ExistingSkill,
  version: string,
  contents: string,
  digest: string
): Promise<InstalledAgentSkill> {
  const parent = path.dirname(target.path);
  if (existing.state === "exact-unmanaged") {
    await writeExclusive(path.join(target.path, MARKER_NAME), markerContents(version, digest));
    return { client: target.client, path: target.path, status: "installed" };
  }
  if (
    existing.state === "managed" &&
    existing.skillContents === contents &&
    existing.marker?.package_version === version &&
    existing.marker.content_sha256 === digest
  ) {
    return { client: target.client, path: target.path, status: "unchanged" };
  }

  const candidate = await buildCandidate(parent, version, contents, digest);
  if (existing.state === "missing") {
    try {
      await rename(candidate, target.path);
      return { client: target.client, path: target.path, status: "installed" };
    } catch (error) {
      await rm(candidate, { recursive: true, force: true });
      throw error;
    }
  }

  const backup = path.join(parent, `.${SKILL_NAME}.backup-${process.pid}-${randomBytes(8).toString("hex")}`);
  try {
    const current = await inspectExistingSkill(target.path, contents);
    if (
      current.state !== "managed" ||
      current.skillContents !== existing.skillContents ||
      current.markerContents !== existing.markerContents
    ) throw new Error(`The managed ${SKILL_NAME} skill changed during update; it was not overwritten.`);
    await rename(target.path, backup);
    try {
      await rename(candidate, target.path);
    } catch (error) {
      await rename(backup, target.path);
      throw error;
    }
    await rm(backup, { recursive: true });
    return { client: target.client, path: target.path, status: "updated" };
  } catch (error) {
    await rm(candidate, { recursive: true, force: true });
    throw error;
  }
}

function targetsForHome(home: string): SkillTarget[] {
  return [
    {
      client: "codex",
      parentSegments: [".agents", "skills"],
      path: path.join(home, ".agents", "skills", SKILL_NAME)
    },
    {
      client: "claude-code",
      parentSegments: [".claude", "skills"],
      path: path.join(home, ".claude", "skills", SKILL_NAME)
    }
  ];
}

/** Installs the npm-bundled guide without overwriting foreign or modified skills. */
export async function installBundledAgentSkills(input: {
  packageRoot: string;
  home: string;
  version: string;
}): Promise<InstalledAgentSkill[]> {
  if (!path.isAbsolute(input.packageRoot) || !path.isAbsolute(input.home)) {
    throw new Error("BrowseWeave skill installation requires absolute package and home paths.");
  }
  const source = path.join(input.packageRoot, "skills", SKILL_NAME, SKILL_FILE_NAME);
  await regularPackagedFile(source);
  const sourceInfo = await lstat(source);
  if (sourceInfo.size < 1 || sourceInfo.size > MAX_SKILL_BYTES) {
    throw new Error("The packaged BrowseWeave skill has an invalid size.");
  }
  const contents = await readFile(source, "utf8");
  if (!contents.startsWith("---\nname: browseweave\n") || !contents.includes("\n## Applicability contract\n")) {
    throw new Error("The packaged BrowseWeave skill has an invalid contract.");
  }
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(input.version)) {
    throw new Error("The BrowseWeave package version is invalid.");
  }
  const digest = sha256(contents);
  const targets = targetsForHome(input.home);
  for (const target of targets) await prepareParent(input.home, target.parentSegments);
  const existing = await Promise.all(targets.map((target) => inspectExistingSkill(target.path, contents)));
  const installed: InstalledAgentSkill[] = [];
  for (const [index, target] of targets.entries()) {
    installed.push(await installTarget(target, existing[index]!, input.version, contents, digest));
  }
  return installed;
}
