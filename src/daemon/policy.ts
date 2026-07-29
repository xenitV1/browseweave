/**
 * Reads the owner-only policy document that enables the capabilities which are
 * off by default. It is a plain file rather than anything the daemon or an MCP
 * caller can write, so widening BrowseWeave's authority always requires a
 * deliberate human edit outside the running system.
 */
import { constants as fsConstants, lstat, open } from "node:fs/promises";
import path from "node:path";

export const POLICY_FILE_NAME = "policy.json" as const;
const MAX_POLICY_BYTES = 8 * 1024;

export function policyPath(configDir: string): string {
  return path.join(configDir, POLICY_FILE_NAME);
}

/**
 * Returns the parsed document, or undefined when no policy file exists. A file
 * that exists but is unsafe or malformed throws instead of falling back to a
 * default, so a damaged policy can never silently widen authority.
 */
export async function readPolicyDocument(configDir: string): Promise<Record<string, unknown> | undefined> {
  const file = policyPath(configDir);
  let info;
  try {
    info = await lstat(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`The BrowseWeave policy file is not a safe regular file: ${file}`);
  }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error(`The BrowseWeave policy file is not owned by the current user: ${file}`);
  }
  if (process.platform !== "win32" && (info.mode & 0o077) !== 0) {
    throw new Error(`The BrowseWeave policy file permissions are unsafe. Restrict it to its owner: ${file}`);
  }
  if (info.size > MAX_POLICY_BYTES) {
    throw new Error(`The BrowseWeave policy file exceeds ${MAX_POLICY_BYTES} bytes: ${file}`);
  }
  const handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let contents: string;
  try {
    contents = await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
  let value: unknown;
  try {
    value = JSON.parse(contents) as unknown;
  } catch {
    throw new Error("The BrowseWeave policy file is not valid JSON.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The BrowseWeave policy file must contain a JSON object.");
  }
  return value as Record<string, unknown>;
}

/** Reads one named section, rejecting a present-but-wrong-shaped entry. */
export function policySection(
  document: Record<string, unknown> | undefined,
  name: string
): Record<string, unknown> | undefined {
  const section = document?.[name];
  if (section === undefined) return undefined;
  if (!section || typeof section !== "object" || Array.isArray(section)) {
    throw new Error(`${name} must be a JSON object.`);
  }
  return section as Record<string, unknown>;
}
