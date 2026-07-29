/**
 * Durable per-installation public-key registry. A key is pinned on first
 * enrolment, so knowing the pairing secret later is not enough to replace the
 * public key an installation authenticates with.
 */
import { constants as fsConstants, chmod, lstat, open, readFile, rename, unlink, type FileHandle } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import {
  canonicalPublicJwk,
  isInstallationId,
  isJsonObject,
  type JsonValue,
  type P256PublicJwk
} from "../core/protocol.js";
import { browserIdForInstallation, hasExactFields, isExactP256PublicJwk } from "./crypto.js";

const MAX_KEY_REGISTRY_BYTES = 1024 * 1024;
/** Bounds both stored installations and live connections to the same value. */
export const MAX_CONNECTED_BROWSERS = 16;
const REGISTRY_VERSION = 2 as const;
const LEGACY_REGISTRY_VERSION = 1 as const;

export type ExtensionAuthenticationMode = "legacy" | "derived-v1";

export interface StoredExtensionKey {
  browserId: string;
  publicKey: P256PublicJwk;
  enrolledAt: string;
  authMode: ExtensionAuthenticationMode;
}

export class ExtensionKeyRegistry {
  readonly #path: string;
  readonly #entries = new Map<string, StoredExtensionKey>();
  #mutationQueue: Promise<void> = Promise.resolve();

  constructor(path: string) {
    this.#path = path;
  }

  get(installationId: string): StoredExtensionKey | undefined {
    return this.#entries.get(installationId);
  }

  get size(): number {
    return this.#entries.size;
  }

  async load(): Promise<void> {
    let info;
    try {
      info = await lstat(this.#path);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error(`The extension public-key registry is not a safe regular file: ${this.#path}`);
    }
    if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
      throw new Error(`The extension public-key registry is not owned by the current user: ${this.#path}`);
    }
    if (process.platform !== "win32" && (info.mode & 0o077) !== 0) {
      throw new Error(`The extension public-key registry permissions are unsafe: ${this.#path}`);
    }
    if (info.size > MAX_KEY_REGISTRY_BYTES) {
      throw new Error("The extension public-key registry exceeds the safe size limit.");
    }

    const parsed = JSON.parse(await readFile(this.#path, "utf8")) as unknown;
    if (
      !isJsonObject(parsed) ||
      !hasExactFields(parsed, new Set(["version", "installations"])) ||
      (parsed.version !== LEGACY_REGISTRY_VERSION && parsed.version !== REGISTRY_VERSION) ||
      !isJsonObject(parsed.installations)
    ) {
      throw new Error("The extension public-key registry has an invalid format.");
    }
    const legacyRegistry = parsed.version === LEGACY_REGISTRY_VERSION;
    const rows = Object.entries(parsed.installations);
    if (rows.length > MAX_CONNECTED_BROWSERS * 4) {
      throw new Error("The extension public-key registry contains too many installations.");
    }
    const loaded = new Map<string, StoredExtensionKey>();
    for (const [installationId, rawEntry] of rows) {
      if (!isInstallationId(installationId) || !isJsonObject(rawEntry)) {
        throw new Error("The extension public-key registry contains an invalid installation.");
      }
      const expectedFields = legacyRegistry
        ? new Set(["browser_id", "public_key", "enrolled_at"])
        : new Set(["browser_id", "public_key", "enrolled_at", "auth_mode"]);
      const enrolledAt = typeof rawEntry.enrolled_at === "string" ? Date.parse(rawEntry.enrolled_at) : Number.NaN;
      if (
        !hasExactFields(rawEntry, expectedFields) ||
        rawEntry.browser_id !== browserIdForInstallation(installationId) ||
        typeof rawEntry.enrolled_at !== "string" ||
        !Number.isFinite(enrolledAt) ||
        new Date(enrolledAt).toISOString() !== rawEntry.enrolled_at ||
        !isExactP256PublicJwk(rawEntry.public_key) ||
        (!legacyRegistry && rawEntry.auth_mode !== "legacy" && rawEntry.auth_mode !== "derived-v1")
      ) {
        throw new Error("The extension public-key registry contains an invalid key entry.");
      }
      loaded.set(installationId, {
        browserId: rawEntry.browser_id,
        publicKey: rawEntry.public_key,
        enrolledAt: rawEntry.enrolled_at,
        authMode: legacyRegistry ? "legacy" : rawEntry.auth_mode as ExtensionAuthenticationMode
      });
    }
    this.#entries.clear();
    for (const [installationId, entry] of loaded) this.#entries.set(installationId, entry);
    if (legacyRegistry) await this.#save();
  }

  async pin(
    installationId: string,
    publicKey: P256PublicJwk,
    authMode: ExtensionAuthenticationMode
  ): Promise<StoredExtensionKey> {
    return await this.#serializeMutation(async () => {
      const existing = this.#entries.get(installationId);
      if (existing !== undefined) {
        if (canonicalPublicJwk(existing.publicKey) !== canonicalPublicJwk(publicKey)) {
          throw new Error("The extension signing key does not match the pinned key.");
        }
        if (existing.authMode === authMode) return existing;
        if (existing.authMode === "derived-v1" || authMode !== "derived-v1") {
          throw new Error("The extension authentication mode cannot be downgraded.");
        }
        const upgraded: StoredExtensionKey = { ...existing, authMode: "derived-v1" };
        this.#entries.set(installationId, upgraded);
        try {
          await this.#save();
        } catch (error) {
          this.#entries.set(installationId, existing);
          throw error;
        }
        return upgraded;
      }
      if (this.#entries.size >= MAX_CONNECTED_BROWSERS * 4) {
        throw new Error("The extension public-key registry is full.");
      }
      const entry: StoredExtensionKey = {
        browserId: browserIdForInstallation(installationId),
        publicKey,
        enrolledAt: new Date().toISOString(),
        authMode
      };
      this.#entries.set(installationId, entry);
      try {
        await this.#save();
      } catch (error) {
        if (this.#entries.get(installationId) === entry) this.#entries.delete(installationId);
        throw error;
      }
      return entry;
    });
  }

  async #serializeMutation<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#mutationQueue.then(operation);
    this.#mutationQueue = result.then(() => undefined, () => undefined);
    return await result;
  }

  async #save(): Promise<void> {
    const installations: Record<string, JsonValue> = Object.create(null) as Record<string, JsonValue>;
    for (const installationId of [...this.#entries.keys()].sort()) {
      const entry = this.#entries.get(installationId);
      if (entry === undefined) continue;
      installations[installationId] = {
        browser_id: entry.browserId,
        public_key: entry.publicKey,
        enrolled_at: entry.enrolledAt,
        auth_mode: entry.authMode
      };
    }
    const contents = `${JSON.stringify({ version: REGISTRY_VERSION, installations })}\n`;
    const temporaryPath = `${this.#path}.${process.pid}.${randomUUID()}.tmp`;
    let handle: FileHandle | undefined;
    try {
      handle = await open(
        temporaryPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600
      );
      await handle.writeFile(contents, "utf8");
      await handle.sync();
      await handle.close();
      handle = undefined;
      await rename(temporaryPath, this.#path);
      if (process.platform !== "win32") await chmod(this.#path, 0o600);
    } catch (error) {
      await handle?.close();
      await unlink(temporaryPath).catch(() => undefined);
      throw error;
    }
  }
}
