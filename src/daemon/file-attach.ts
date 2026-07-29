/**
 * Path policy and safe reading for local files an MCP caller may attach to a
 * web form.
 *
 * This is the only place in BrowseWeave that reads a file the user did not
 * hand to it directly, so it is the primary defence for the whole feature.
 * Attachment always requires a bound human decision in the MCP client session
 * in addition to this policy. The policy still fails closed so an injected
 * instruction cannot turn a generic confirmation into arbitrary file access.
 *
 * Default deny: with no policy file, nothing is attachable.
 */
import { createHash } from "node:crypto";
import { constants as fsConstants, lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { policySection, readPolicyDocument } from "./policy.js";

export const DEFAULT_MAX_FILE_BYTES = 6 * 1024 * 1024;
/** Bounded by the WebSocket frame limit once base64 expansion is accounted for. */
export const MAX_ALLOWED_FILE_BYTES = 8 * 1024 * 1024;

/**
 * Extension-to-type map. An extension that is not listed is not attachable, so
 * this doubles as the allowed-type list; there is no sniffing fallback.
 */
const MIME_TYPES: ReadonlyMap<string, string> = new Map(Object.entries({
  txt: "text/plain",
  md: "text/markdown",
  csv: "text/csv",
  json: "application/json",
  pdf: "application/pdf",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  svg: "image/svg+xml",
  heic: "image/heic",
  zip: "application/zip",
  doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ppt: "application/vnd.ms-powerpoint",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  mp3: "audio/mpeg",
  mp4: "video/mp4",
  mov: "video/quicktime"
}));

/**
 * Names that are never attachable regardless of the allowlist. Any path
 * segment beginning with a dot is rejected separately, which already covers
 * `.ssh`, `.gnupg`, `.aws`, `.env`, and `.npmrc`; this list catches the
 * secrets that live under ordinary names.
 */
const DENIED_NAME_PATTERN = /(?:^|[._-])(?:id_rsa|id_ecdsa|id_ed25519|authorized_keys|known_hosts|shadow|passwd|credentials?|tokens?|keychain|kdbx|wallet|seed|mnemonic)(?:$|[._-])/iu;
const DENIED_EXTENSIONS: ReadonlySet<string> = new Set([
  "pem", "key", "pfx", "p12", "jks", "keystore", "asc", "gpg", "pgp", "kdbx", "ppk", "crt", "cer", "der"
]);
// Assemble these signatures at runtime so the publish-time secret scanner can
// keep treating any complete private-key header in the archive as a hard fail.
const DENIED_CONTENT_MARKERS = [
  ["-----BEGIN", "PRIVATE", "KEY-----"],
  ["-----BEGIN", "RSA", "PRIVATE", "KEY-----"],
  ["-----BEGIN", "EC", "PRIVATE", "KEY-----"],
  ["-----BEGIN", "OPENSSH", "PRIVATE", "KEY-----"],
  ["-----BEGIN", "PGP", "PRIVATE", "KEY", "BLOCK-----"]
].map((parts) => Buffer.from(parts.join(" "), "utf8"));

export interface FileAttachPolicy {
  readonly enabled: boolean;
  /** Absolute, symlink-resolved directories the owner opted in. Empty means off. */
  readonly allowedDirectories: readonly string[];
  readonly maxFileBytes: number;
  /** Lowercase extensions without a dot; empty means every known type is allowed. */
  readonly allowedExtensions: ReadonlySet<string>;
}

export const DISABLED_FILE_ATTACH_POLICY: FileAttachPolicy = {
  enabled: false,
  allowedDirectories: [],
  maxFileBytes: DEFAULT_MAX_FILE_BYTES,
  allowedExtensions: new Set<string>()
};

export interface AttachableFile {
  /** Symlink-resolved absolute path that passed every check. */
  readonly resolvedPath: string;
  readonly name: string;
  readonly mimeType: string;
  readonly size: number;
  readonly sha256: string;
  readonly base64: string;
}

export class FileAttachError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

function parsePolicy(section: Record<string, unknown> | undefined): FileAttachPolicy {
  if (section === undefined) return DISABLED_FILE_ATTACH_POLICY;
  if (typeof section.enabled !== "boolean") {
    throw new Error("file_attach.enabled must be true or false.");
  }
  if (!section.enabled) return DISABLED_FILE_ATTACH_POLICY;

  const rawDirectories = section.allowed_directories;
  if (!Array.isArray(rawDirectories) || rawDirectories.length === 0) {
    throw new Error("file_attach.allowed_directories must list at least one absolute directory.");
  }
  const allowedDirectories: string[] = [];
  for (const entry of rawDirectories) {
    if (typeof entry !== "string" || !path.isAbsolute(entry) || /[\0\r\n]/u.test(entry)) {
      throw new Error("file_attach.allowed_directories entries must be safe absolute paths.");
    }
    allowedDirectories.push(path.resolve(entry));
  }

  const maxFileBytes = section.max_file_bytes ?? DEFAULT_MAX_FILE_BYTES;
  if (
    typeof maxFileBytes !== "number" || !Number.isSafeInteger(maxFileBytes) ||
    maxFileBytes < 1 || maxFileBytes > MAX_ALLOWED_FILE_BYTES
  ) {
    throw new Error(`file_attach.max_file_bytes must be between 1 and ${MAX_ALLOWED_FILE_BYTES}.`);
  }

  if (section.max_files_per_command !== undefined && section.max_files_per_command !== 1) {
    throw new Error("file_attach.max_files_per_command must be exactly 1; each command attaches one file.");
  }

  const rawExtensions = section.allowed_extensions;
  const allowedExtensions = new Set<string>();
  if (rawExtensions !== undefined) {
    if (!Array.isArray(rawExtensions) || rawExtensions.length === 0) {
      throw new Error("file_attach.allowed_extensions must be a non-empty array when present.");
    }
    for (const entry of rawExtensions) {
      if (typeof entry !== "string") throw new Error("file_attach.allowed_extensions entries must be strings.");
      const normalized = entry.replace(/^\./u, "").toLowerCase();
      if (!MIME_TYPES.has(normalized)) {
        throw new Error(`file_attach.allowed_extensions contains an unsupported file type: ${entry}`);
      }
      allowedExtensions.add(normalized);
    }
  }

  return {
    enabled: true,
    allowedDirectories,
    maxFileBytes,
    allowedExtensions
  };
}

export async function loadFileAttachPolicy(configDir: string): Promise<FileAttachPolicy> {
  return parsePolicy(policySection(await readPolicyDocument(configDir), "file_attach"));
}

function withinDirectory(candidate: string, directory: string): boolean {
  const relative = path.relative(directory, candidate);
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

function assertPathContentsAllowed(candidatePath: string, policy: FileAttachPolicy): void {
  const segments = candidatePath.split(path.sep).filter(Boolean);
  if (segments.some((segment) => segment.startsWith("."))) {
    throw new FileAttachError(
      "file_attach_denied",
      "Hidden files and directories are never attachable. This covers credential stores such as .ssh, .gnupg, .aws, .env, and .npmrc."
    );
  }
  const name = path.basename(candidatePath);
  const extension = path.extname(name).replace(/^\./u, "").toLowerCase();
  if (DENIED_EXTENSIONS.has(extension) || DENIED_NAME_PATTERN.test(name)) {
    throw new FileAttachError("file_attach_denied", "That file looks like key or credential material and is never attachable.");
  }
  if (!MIME_TYPES.has(extension)) {
    throw new FileAttachError("file_attach_unsupported_type", `Files of type ".${extension || "(none)"}" cannot be attached.`);
  }
  if (policy.allowedExtensions.size > 0 && !policy.allowedExtensions.has(extension)) {
    throw new FileAttachError("file_attach_unsupported_type", `Your policy does not allow attaching ".${extension}" files.`);
  }
}

function assertResolvedLocationAllowed(
  resolvedPath: string,
  allowedDirectories: readonly string[],
  reservedDirectories: readonly string[]
): void {
  for (const reserved of reservedDirectories) {
    if (withinDirectory(resolvedPath, reserved) || resolvedPath === reserved) {
      throw new FileAttachError("file_attach_denied", "BrowseWeave's own configuration and state are never attachable.");
    }
  }
  if (!allowedDirectories.some((directory) => withinDirectory(resolvedPath, directory))) {
    throw new FileAttachError(
      "file_attach_outside_allowlist",
      "That path is outside every directory your BrowseWeave policy allows attaching from."
    );
  }
}

async function canonicalDirectory(directory: string): Promise<string> {
  return await realpath(directory).catch(() => path.resolve(directory));
}

/**
 * Resolves, validates, and reads one file. The open uses O_NOFOLLOW on the
 * already-resolved path and the ownership and mode are re-checked through the
 * open handle, so the path cannot be swapped between the check and the read.
 */
export async function readAttachableFile(
  requestedPath: unknown,
  policy: FileAttachPolicy,
  reservedDirectories: readonly string[] = []
): Promise<AttachableFile> {
  if (!policy.enabled) {
    throw new FileAttachError(
      "file_attach_disabled",
      "Attaching local files is turned off. The owner must enable file_attach in the BrowseWeave policy file."
    );
  }
  if (typeof requestedPath !== "string" || !path.isAbsolute(requestedPath) || /[\0\r\n]/u.test(requestedPath)) {
    throw new FileAttachError("file_attach_invalid_path", "The file path must be a safe absolute path.");
  }

  let resolvedPath: string;
  try {
    resolvedPath = await realpath(requestedPath);
  } catch {
    throw new FileAttachError("file_attach_not_found", "That file does not exist or is not readable.");
  }
  // Both the path as written and the path after resolution must pass the name
  // and type rules, so a symlink cannot hide denied material. Location checks
  // use canonical paths on both sides: macOS exposes /var through /private/var,
  // and Windows realpath may canonicalise casing or short path segments.
  assertPathContentsAllowed(path.resolve(requestedPath), policy);
  assertPathContentsAllowed(resolvedPath, policy);
  const [allowedDirectories, canonicalReservedDirectories] = await Promise.all([
    Promise.all(policy.allowedDirectories.map(canonicalDirectory)),
    Promise.all(reservedDirectories.map(canonicalDirectory))
  ]);
  assertResolvedLocationAllowed(resolvedPath, allowedDirectories, canonicalReservedDirectories);

  const info = await lstat(resolvedPath);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new FileAttachError("file_attach_invalid_path", "Only regular files can be attached.");
  }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new FileAttachError("file_attach_denied", "Only files owned by the current user can be attached.");
  }
  if (info.nlink !== 1) {
    throw new FileAttachError(
      "file_attach_denied",
      "Files with multiple filesystem names (hardlinks) are never attachable."
    );
  }
  if (info.size > policy.maxFileBytes) {
    throw new FileAttachError(
      "file_attach_too_large",
      `That file is ${info.size} bytes; your policy allows at most ${policy.maxFileBytes}.`
    );
  }

  const handle = await open(resolvedPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let bytes: Buffer;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.ino !== info.ino || opened.dev !== info.dev || opened.nlink !== 1) {
      throw new FileAttachError("file_attach_changed", "The file changed while BrowseWeave was reading it.");
    }
    bytes = await handle.readFile();
  } finally {
    await handle.close();
  }
  if (bytes.byteLength > policy.maxFileBytes) {
    throw new FileAttachError("file_attach_too_large", "The file grew past the allowed size while it was read.");
  }
  if (DENIED_CONTENT_MARKERS.some((marker) => bytes.includes(marker))) {
    throw new FileAttachError("file_attach_denied", "That file contains recognizable private-key material and is never attachable.");
  }

  const name = path.basename(resolvedPath);
  const extension = path.extname(name).replace(/^\./u, "").toLowerCase();
  return {
    resolvedPath,
    name,
    mimeType: MIME_TYPES.get(extension) as string,
    size: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    base64: bytes.toString("base64")
  };
}

/** Stable, non-reversible identifier for the audit log, which never records a path. */
export function auditPathDigest(resolvedPath: string): string {
  return createHash("sha256").update(resolvedPath, "utf8").digest("hex");
}

/**
 * Extracts the identity of an attached file from approved command parameters so
 * a confirmation prompt can show which file is about to be uploaded. Returns
 * undefined for any other action.
 */
export function attachedFileFacts(
  params: unknown
): { file: { name: string; mime_type: string; sha256: string; size: number } } | undefined {
  if (!params || typeof params !== "object" || Array.isArray(params)) return undefined;
  const file = (params as Record<string, unknown>).file;
  if (!file || typeof file !== "object" || Array.isArray(file)) return undefined;
  const record = file as Record<string, unknown>;
  if (
    typeof record.name !== "string" || typeof record.mime_type !== "string" ||
    typeof record.sha256 !== "string" || typeof record.size !== "number"
  ) {
    return undefined;
  }
  return {
    file: { name: record.name, mime_type: record.mime_type, sha256: record.sha256, size: record.size }
  };
}
