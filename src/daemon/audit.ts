/**
 * Bounded metadata audit log. It deliberately records no page-controlled text,
 * page contents, typed values, credentials, pairing tokens, or approval
 * descriptions, and coalesces unauthenticated rejections so a hostile peer
 * cannot turn logging into an amplification channel.
 */
import { constants as fsConstants, lstat, open, rename, unlink, type FileHandle } from "node:fs/promises";
import type { BrowserAction } from "../core/protocol.js";

const DEFAULT_MAX_AUDIT_QUEUE_ENTRIES = 512;
const DEFAULT_MAX_AUDIT_FILE_BYTES = 5 * 1024 * 1024;
const MIN_AUDIT_FILE_BYTES = 512;
const AUDIT_LABEL_PATTERN = /^[a-z][a-z0-9_]{0,119}$/u;
const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/u;
const MIME_TYPE_PATTERN = /^[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*$/iu;
const UNAUTHENTICATED_AUDIT_WINDOW_MS = 1_000;
const UNAUTHENTICATED_AUDIT_BURST_PER_OUTCOME = 2;
const MAX_UNAUTHENTICATED_AUDIT_OUTCOMES = 16;
const OTHER_UNAUTHENTICATED_OUTCOME = "unauthenticated_rejection_other";

export interface SafeAuditEvent {
  event: "command" | "approval" | "connection";
  action?: BrowserAction;
  outcome: string;
  code?: string;
  duration_ms?: number;
  count?: number;
  /** Structured attachment metadata; raw paths and file contents are forbidden. */
  file_sha256?: string;
  file_size?: number;
  file_mime_type?: string;
  file_path_sha256?: string;
}


export interface SafeAuditLoggerOptions {
  maxQueueEntries?: number;
  maxFileBytes?: number;
}

function safeAuditLabel(value: string): string {
  return AUDIT_LABEL_PATTERN.test(value) ? value : "invalid_audit_label";
}

function safeAuditLine(event: SafeAuditEvent): string {
  const safeRecord: Record<string, string | number> = {
    timestamp: new Date().toISOString(),
    event: event.event,
    outcome: safeAuditLabel(event.outcome)
  };
  if (event.action !== undefined) safeRecord.action = event.action;
  if (event.code !== undefined) safeRecord.code = safeAuditLabel(event.code);
  if (event.duration_ms !== undefined && Number.isFinite(event.duration_ms)) {
    safeRecord.duration_ms = Math.max(0, Math.min(Number.MAX_SAFE_INTEGER, Math.round(event.duration_ms)));
  }
  if (event.count !== undefined && Number.isSafeInteger(event.count) && event.count > 0) {
    safeRecord.count = event.count;
  }
  if (event.file_sha256 !== undefined && SHA256_HEX_PATTERN.test(event.file_sha256)) {
    safeRecord.file_sha256 = event.file_sha256;
  }
  if (
    event.file_size !== undefined && Number.isSafeInteger(event.file_size) &&
    event.file_size >= 0 && event.file_size <= 8 * 1024 * 1024
  ) safeRecord.file_size = event.file_size;
  if (
    event.file_mime_type !== undefined && event.file_mime_type.length <= 192 &&
    MIME_TYPE_PATTERN.test(event.file_mime_type)
  ) safeRecord.file_mime_type = event.file_mime_type.toLowerCase();
  if (event.file_path_sha256 !== undefined && SHA256_HEX_PATTERN.test(event.file_path_sha256)) {
    safeRecord.file_path_sha256 = event.file_path_sha256;
  }
  return `${JSON.stringify(safeRecord)}\n`;
}

export class SafeAuditLogger {
  readonly #path: string;
  readonly #rotatedPath: string;
  readonly #maxQueueEntries: number;
  readonly #maxFileBytes: number;
  #handle: FileHandle | undefined;
  #fileBytes = 0;
  readonly #queuedLines: string[] = [];
  #droppedEvents = 0;
  #drainPromise: Promise<void> | undefined;
  #accepting = false;
  lastError: string | undefined;

  constructor(path: string, options: SafeAuditLoggerOptions = {}) {
    const maxQueueEntries = options.maxQueueEntries ?? DEFAULT_MAX_AUDIT_QUEUE_ENTRIES;
    const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_AUDIT_FILE_BYTES;
    if (!Number.isSafeInteger(maxQueueEntries) || maxQueueEntries < 1 || maxQueueEntries > 100_000) {
      throw new Error("The audit queue limit must be between 1 and 100000 entries.");
    }
    if (!Number.isSafeInteger(maxFileBytes) || maxFileBytes < MIN_AUDIT_FILE_BYTES || maxFileBytes > 1024 ** 3) {
      throw new Error(`The audit file limit must be between ${MIN_AUDIT_FILE_BYTES} bytes and 1 GiB.`);
    }
    this.#path = path;
    this.#rotatedPath = `${path}.1`;
    this.#maxQueueEntries = maxQueueEntries;
    this.#maxFileBytes = maxFileBytes;
  }

  async start(): Promise<void> {
    if (this.#handle !== undefined) return;
    const opened = await this.#openCurrentFile();
    this.#handle = opened.handle;
    this.#fileBytes = opened.size;
    this.#accepting = true;
    if (this.#fileBytes >= this.#maxFileBytes) await this.#rotate();
  }

  async #openCurrentFile(): Promise<{ handle: FileHandle; size: number }> {
    const handle = await open(
      this.#path,
      fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
      0o600
    );
    try {
      const info = await handle.stat();
      if (
        !info.isFile() ||
        !Number.isSafeInteger(info.size) ||
        info.size < 0 ||
        (typeof process.getuid === "function" && info.uid !== process.getuid())
      ) {
        throw new Error(`The audit log is not a safe user-owned file: ${this.#path}`);
      }
      if (process.platform !== "win32") await handle.chmod(0o600);
      return { handle, size: info.size };
    } catch (error) {
      await handle.close();
      throw error;
    }
  }

  record(event: SafeAuditEvent): void {
    if (!this.#accepting || this.#handle === undefined) return;
    if (this.#queuedLines.length >= this.#maxQueueEntries) {
      this.#droppedEvents = Math.min(Number.MAX_SAFE_INTEGER, this.#droppedEvents + 1);
      return;
    }
    this.#queuedLines.push(safeAuditLine(event));
    this.#ensureDrain();
  }

  async close(): Promise<void> {
    this.#accepting = false;
    while (this.#drainPromise !== undefined || this.#queuedLines.length > 0 || this.#droppedEvents > 0) {
      this.#ensureDrain();
      await this.#drainPromise;
    }
    await this.#handle?.close();
    this.#handle = undefined;
    this.#fileBytes = 0;
  }

  #ensureDrain(): void {
    if (
      this.#drainPromise !== undefined ||
      this.#handle === undefined ||
      (this.#queuedLines.length === 0 && this.#droppedEvents === 0)
    ) return;
    const promise = this.#drain().finally(() => {
      if (this.#drainPromise !== promise) return;
      this.#drainPromise = undefined;
      if (this.#queuedLines.length > 0 || this.#droppedEvents > 0) this.#ensureDrain();
    });
    this.#drainPromise = promise;
  }

  async #drain(): Promise<void> {
    while (this.#queuedLines.length > 0) {
      const line = this.#queuedLines.shift();
      if (line !== undefined) await this.#appendSafely(line);
    }
    if (this.#droppedEvents > 0) {
      const count = this.#droppedEvents;
      this.#droppedEvents = 0;
      await this.#appendSafely(safeAuditLine({
        event: "connection",
        outcome: "audit_events_dropped",
        count
      }));
    }
  }

  async #appendSafely(line: string): Promise<void> {
    try {
      const lineBytes = Buffer.byteLength(line, "utf8");
      if (lineBytes > this.#maxFileBytes) throw new Error("An audit record exceeds the audit file size limit.");
      if (this.#fileBytes > 0 && this.#fileBytes + lineBytes > this.#maxFileBytes) await this.#rotate();
      if (this.#handle === undefined) throw new Error("The audit log is not open.");
      await this.#handle.appendFile(line, "utf8");
      this.#fileBytes += lineBytes;
    } catch (error) {
      this.lastError = error instanceof Error ? error.message : "audit_write_failed";
    }
  }

  async #rotate(): Promise<void> {
    const handle = this.#handle;
    if (handle === undefined) throw new Error("The audit log is not open for rotation.");
    await handle.close();
    this.#handle = undefined;
    try {
      try {
        const previous = await lstat(this.#rotatedPath);
        if (
          !previous.isFile() ||
          previous.isSymbolicLink() ||
          (typeof process.getuid === "function" && previous.uid !== process.getuid())
        ) {
          throw new Error(`The rotated audit log is not a safe user-owned file: ${this.#rotatedPath}`);
        }
        await unlink(this.#rotatedPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
      await rename(this.#path, this.#rotatedPath);
      const opened = await this.#openCurrentFile();
      this.#handle = opened.handle;
      this.#fileBytes = opened.size;
    } catch (error) {
      try {
        const reopened = await this.#openCurrentFile();
        this.#handle = reopened.handle;
        this.#fileBytes = reopened.size;
      } catch {
        this.#fileBytes = 0;
      }
      throw error;
    }
  }
}

interface UnauthenticatedAuditWindow {
  windowEndsAt: number;
  emitted: number;
  suppressed: number;
}

export class UnauthenticatedAuditCoalescer {
  readonly #audit: SafeAuditLogger;
  readonly #windows = new Map<string, UnauthenticatedAuditWindow>();
  #timer: ReturnType<typeof setTimeout> | undefined;
  #active = false;

  constructor(audit: SafeAuditLogger) {
    this.#audit = audit;
  }

  start(): void {
    this.#active = true;
  }

  record(outcome: string, now = Date.now()): void {
    if (!this.#active) return;
    let key = safeAuditLabel(outcome);
    if (!this.#windows.has(key) && this.#windows.size >= MAX_UNAUTHENTICATED_AUDIT_OUTCOMES - 1) {
      key = OTHER_UNAUTHENTICATED_OUTCOME;
    }
    let window = this.#windows.get(key);
    if (window === undefined || now >= window.windowEndsAt) {
      if (window !== undefined) this.#flushWindow(key, window);
      window = {
        windowEndsAt: now + UNAUTHENTICATED_AUDIT_WINDOW_MS,
        emitted: 0,
        suppressed: 0
      };
      this.#windows.set(key, window);
    }
    if (window.emitted < UNAUTHENTICATED_AUDIT_BURST_PER_OUTCOME) {
      window.emitted += 1;
      this.#audit.record({ event: "connection", outcome: key });
      return;
    }
    window.suppressed = Math.min(Number.MAX_SAFE_INTEGER, window.suppressed + 1);
    this.#scheduleFlush();
  }

  close(): void {
    this.#active = false;
    if (this.#timer !== undefined) clearTimeout(this.#timer);
    this.#timer = undefined;
    for (const [outcome, window] of this.#windows) this.#flushWindow(outcome, window);
    this.#windows.clear();
  }

  #flushWindow(outcome: string, window: UnauthenticatedAuditWindow): void {
    if (window.suppressed <= 0) return;
    this.#audit.record({
      event: "connection",
      outcome: "unauthenticated_rejections_coalesced",
      code: outcome,
      count: window.suppressed
    });
    window.suppressed = 0;
  }

  #scheduleFlush(): void {
    if (this.#timer !== undefined) return;
    let earliest = Number.POSITIVE_INFINITY;
    for (const window of this.#windows.values()) {
      if (window.suppressed > 0) earliest = Math.min(earliest, window.windowEndsAt);
    }
    if (!Number.isFinite(earliest)) return;
    this.#timer = setTimeout(() => {
      this.#timer = undefined;
      const now = Date.now();
      for (const [outcome, window] of this.#windows) {
        if (now < window.windowEndsAt) continue;
        this.#flushWindow(outcome, window);
        this.#windows.delete(outcome);
      }
      if ([...this.#windows.values()].some((window) => window.suppressed > 0)) this.#scheduleFlush();
    }, Math.max(1, earliest - Date.now()));
    this.#timer.unref();
  }
}
