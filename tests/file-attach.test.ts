import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  DISABLED_FILE_ATTACH_POLICY,
  FileAttachError,
  attachedFileFacts,
  auditPathDigest,
  loadFileAttachPolicy,
  readAttachableFile,
  type FileAttachPolicy
} from "../src/daemon/file-attach.js";
import { policyPath } from "../src/daemon/policy.js";

const roots: string[] = [];

async function makeRoot(): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "browseweave-attach-"));
  roots.push(root);
  return root;
}

async function writePolicy(root: string, section: unknown): Promise<string> {
  const configDir = path.join(root, "config");
  await mkdir(configDir, { recursive: true, mode: 0o700 });
  await writeFile(policyPath(configDir), JSON.stringify({ file_attach: section }), { mode: 0o600 });
  await chmod(policyPath(configDir), 0o600);
  return configDir;
}

function policyFor(directory: string, overrides: Partial<FileAttachPolicy> = {}): FileAttachPolicy {
  return {
    enabled: true,
    allowedDirectories: [directory],
    maxFileBytes: 1024 * 1024,
    maxFilesPerCommand: 1,
    allowedExtensions: new Set<string>(),
    ...overrides
  };
}

afterEach(async () => {
  while (roots.length) {
    const root = roots.pop();
    if (root) await rm(root, { recursive: true, force: true });
  }
});

describe("file attach policy", () => {
  it("is off until the owner writes a policy", async () => {
    const root = await makeRoot();
    await mkdir(path.join(root, "config"), { recursive: true, mode: 0o700 });
    expect(await loadFileAttachPolicy(path.join(root, "config"))).toEqual(DISABLED_FILE_ATTACH_POLICY);
  });

  it("requires at least one absolute allowed directory when enabled", async () => {
    const root = await makeRoot();
    const configDir = await writePolicy(root, { enabled: true });
    await expect(loadFileAttachPolicy(configDir)).rejects.toThrow(/at least one absolute directory/);

    const relative = await writePolicy(await makeRoot(), { enabled: true, allowed_directories: ["documents"] });
    await expect(loadFileAttachPolicy(relative)).rejects.toThrow(/safe absolute paths/);
  });

  it("refuses a size cap beyond the transport ceiling and an unknown extension", async () => {
    const tooBig = await writePolicy(await makeRoot(), {
      enabled: true,
      allowed_directories: ["/tmp"],
      max_file_bytes: 999_999_999
    });
    await expect(loadFileAttachPolicy(tooBig)).rejects.toThrow(/max_file_bytes must be between/);

    const unknownType = await writePolicy(await makeRoot(), {
      enabled: true,
      allowed_directories: ["/tmp"],
      allowed_extensions: ["exe"]
    });
    await expect(loadFileAttachPolicy(unknownType)).rejects.toThrow(/unsupported file type/);
  });
});

describe("attachable file reading", () => {
  it("refuses everything while the feature is disabled", async () => {
    const root = await makeRoot();
    const file = path.join(root, "note.txt");
    await writeFile(file, "hello");
    await expect(readAttachableFile(file, DISABLED_FILE_ATTACH_POLICY))
      .rejects.toThrow(/turned off/);
  });

  it("reads an allowed file and reports its exact identity", async () => {
    const root = await makeRoot();
    const file = path.join(root, "report.txt");
    await writeFile(file, "hello world");
    const attachable = await readAttachableFile(file, policyFor(root));
    expect(attachable.name).toBe("report.txt");
    expect(attachable.mimeType).toBe("text/plain");
    expect(attachable.size).toBe(11);
    expect(attachable.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(Buffer.from(attachable.base64, "base64").toString("utf8")).toBe("hello world");
  });

  it("refuses a path outside every allowed directory", async () => {
    const allowed = await makeRoot();
    const elsewhere = await makeRoot();
    const file = path.join(elsewhere, "report.txt");
    await writeFile(file, "hello");
    await expect(readAttachableFile(file, policyFor(allowed)))
      .rejects.toThrow(/outside every directory/);
  });

  it("refuses a relative path and a path with control characters", async () => {
    const root = await makeRoot();
    await expect(readAttachableFile("report.txt", policyFor(root))).rejects.toThrow(/safe absolute path/);
    await expect(readAttachableFile(`${root}/re\nport.txt`, policyFor(root))).rejects.toThrow(/safe absolute path/);
    await expect(readAttachableFile(42, policyFor(root))).rejects.toThrow(/safe absolute path/);
  });

  it("never attaches a hidden file or anything under a hidden directory", async () => {
    const root = await makeRoot();
    await writeFile(path.join(root, ".env"), "SECRET=1");
    await expect(readAttachableFile(path.join(root, ".env"), policyFor(root)))
      .rejects.toThrow(/Hidden files and directories/);

    await mkdir(path.join(root, ".ssh"), { recursive: true });
    await writeFile(path.join(root, ".ssh", "notes.txt"), "key material");
    await expect(readAttachableFile(path.join(root, ".ssh", "notes.txt"), policyFor(root)))
      .rejects.toThrow(/Hidden files and directories/);
  });

  it("never attaches key material even under an ordinary name", async () => {
    const root = await makeRoot();
    for (const name of ["server.pem", "client.key", "store.p12", "id_rsa.txt", "backup_wallet.txt"]) {
      await writeFile(path.join(root, name), "secret");
      await expect(readAttachableFile(path.join(root, name), policyFor(root)))
        .rejects.toThrow(/key or credential material|cannot be attached/);
    }
  });

  it("refuses an unsupported type and a type outside the owner's list", async () => {
    const root = await makeRoot();
    await writeFile(path.join(root, "tool.bin"), "x");
    await expect(readAttachableFile(path.join(root, "tool.bin"), policyFor(root)))
      .rejects.toThrow(/cannot be attached/);

    await writeFile(path.join(root, "sheet.csv"), "a,b");
    await expect(readAttachableFile(
      path.join(root, "sheet.csv"),
      policyFor(root, { allowedExtensions: new Set(["pdf"]) })
    )).rejects.toThrow(/does not allow attaching/);
  });

  it("refuses a file larger than the policy cap", async () => {
    const root = await makeRoot();
    await writeFile(path.join(root, "big.txt"), "x".repeat(2048));
    await expect(readAttachableFile(path.join(root, "big.txt"), policyFor(root, { maxFileBytes: 1024 })))
      .rejects.toThrow(/allows at most/);
  });

  it("refuses BrowseWeave's own configuration and state", async () => {
    const root = await makeRoot();
    const stateDir = path.join(root, "state");
    await mkdir(stateDir, { recursive: true });
    await writeFile(path.join(stateDir, "audit.txt"), "metadata");
    await expect(readAttachableFile(path.join(stateDir, "audit.txt"), policyFor(root), [stateDir]))
      .rejects.toThrow(/own configuration and state/);
  });

  it.runIf(process.platform !== "win32")("resolves symlinks before deciding, so a link cannot escape the allowlist", async () => {
    const allowed = await makeRoot();
    const elsewhere = await makeRoot();
    const secret = path.join(elsewhere, "secret.txt");
    await writeFile(secret, "outside");
    await symlink(secret, path.join(allowed, "innocent.txt"));
    await expect(readAttachableFile(path.join(allowed, "innocent.txt"), policyFor(allowed)))
      .rejects.toThrow(/outside every directory/);
  });

  it.runIf(process.platform !== "win32")("canonicalises an allowed directory before comparing a resolved file", async () => {
    const actual = await makeRoot();
    const aliasParent = await makeRoot();
    const alias = path.join(aliasParent, "documents");
    await symlink(actual, alias);
    await writeFile(path.join(actual, "report.txt"), "allowed through the directory alias");

    const attachable = await readAttachableFile(path.join(alias, "report.txt"), policyFor(alias));
    expect(attachable.name).toBe("report.txt");
  });

  it.runIf(process.platform !== "win32")("refuses a link whose target is denied, even from an allowed name", async () => {
    const allowed = await makeRoot();
    const key = path.join(allowed, "server.pem");
    await writeFile(key, "-----BEGIN PRIVATE KEY-----");
    await symlink(key, path.join(allowed, "notes.txt"));
    await expect(readAttachableFile(path.join(allowed, "notes.txt"), policyFor(allowed)))
      .rejects.toThrow(/key or credential material/);
  });

  it("refuses a directory and a missing path", async () => {
    const root = await makeRoot();
    await mkdir(path.join(root, "folder.txt"), { recursive: true });
    await expect(readAttachableFile(path.join(root, "folder.txt"), policyFor(root)))
      .rejects.toThrow(/regular files/);
    await expect(readAttachableFile(path.join(root, "missing.txt"), policyFor(root)))
      .rejects.toThrow(/does not exist/);
  });

  it("reports a typed error code so callers can distinguish refusals", async () => {
    const root = await makeRoot();
    await writeFile(path.join(root, ".env"), "SECRET=1");
    await expect(readAttachableFile(path.join(root, ".env"), policyFor(root)))
      .rejects.toBeInstanceOf(FileAttachError);
  });
});

describe("attachment audit and confirmation facts", () => {
  it("digests the path instead of recording it", () => {
    const digest = auditPathDigest("/home/user/Documents/report.pdf");
    expect(digest).toMatch(/^[a-f0-9]{16}$/u);
    expect(digest).not.toContain("report");
    expect(auditPathDigest("/home/user/Documents/report.pdf")).toBe(digest);
    expect(auditPathDigest("/home/user/Documents/other.pdf")).not.toBe(digest);
  });

  it("surfaces file identity only for attachment parameters", () => {
    expect(attachedFileFacts({ file: { name: "a.pdf", sha256: "ab".repeat(32), size: 10, base64: "eA==" } }))
      .toEqual({ file: { name: "a.pdf", sha256: "ab".repeat(32), size: 10 } });
    expect(attachedFileFacts({ ref: "bw-1" })).toBeUndefined();
    expect(attachedFileFacts(undefined)).toBeUndefined();
    expect(attachedFileFacts({ file: "not-an-object" })).toBeUndefined();
  });

  it("does not carry file bytes into the confirmation facts", () => {
    const facts = attachedFileFacts({ file: { name: "a.pdf", sha256: "cd".repeat(32), size: 4, base64: "SEVMTA==" } });
    expect(JSON.stringify(facts)).not.toContain("SEVMTA==");
  });
});
