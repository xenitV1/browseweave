#!/usr/bin/env node

import {
  createCipheriv,
  createHash,
  createHmac,
  createPublicKey,
  hkdfSync,
  randomBytes,
  randomUUID,
  timingSafeEqual,
  verify as verifySignature,
  type KeyObject
} from "node:crypto";
import {
  constants as fsConstants,
  chmod,
  lstat,
  open,
  readFile,
  rename,
  unlink,
  type FileHandle
} from "node:fs/promises";
import {
  createServer,
  type Server as NetServer,
  type Socket
} from "node:net";
import WebSocket, {
  WebSocketServer,
  type RawData,
  type VerifyClientCallbackSync
} from "ws";
import {
  DEFAULT_IPC_HOST,
  DEFAULT_WS_HOST,
  MAX_COMMAND_TIMEOUT_MS,
  ensurePrivateDirectory,
  loadDaemonConfig,
  type DaemonConfig
} from "../core/config.js";
import {
  BASE64URL_PATTERN,
  PROTOCOL_VERSION,
  SETUP_ID_PATTERN,
  SETUP_VERSION,
  approvalDecisionSigningPayload,
  canonicalPublicJwk,
  extensionClientProofPayload,
  extensionServerProofPayload,
  helloSigningPayload,
  ipcClientProofPayload,
  ipcServerProofPayload,
  isApprovalFingerprint,
  isBrowserAction,
  isInstallationId,
  isJsonObject,
  isJsonValue,
  isP256PublicJwk,
  setupPairingAadPayload,
  setupPairingClientProofPayload,
  setupPairingKeySalt,
  type ApprovalDecision,
  type ApprovalRequiredResult,
  type BridgeStatus,
  type BrowserAction,
  type BrowserFamily,
  type BrowserIdentity,
  type ConnectedBrowserSummary,
  type ExtensionApprovalDecision,
  type ExtensionApprovalRequest,
  type ExtensionCommand,
  type ExtensionError,
  type ExtensionResult,
  type IpcClientHello,
  type IpcRequest,
  type IpcResponse,
  type IpcServerChallenge,
  type JsonObject,
  type JsonValue,
  type P256PublicJwk,
  type SetupPairingResponse,
  type SetupPairingStatus,
  type SetupAuthenticationPhase
} from "../core/protocol.js";

const IPC_ENVELOPE_OVERHEAD_BYTES = 16 * 1024;
const MAX_REQUEST_ID_LENGTH = 128;
const MAX_METHOD_LENGTH = 64;
const MAX_UNAUTHENTICATED_CONNECTIONS = 8;
const MAX_CONNECTED_BROWSERS = 16;
const MAX_IPC_CONNECTIONS = 128;
const MAX_KEY_REGISTRY_BYTES = 1024 * 1024;
const HEARTBEAT_INTERVAL_MS = 20_000;
const BASE64URL_256_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const MAX_REPLAY_NONCES = 4_096;
const REPLAY_NONCE_TTL_MS = 10 * 60_000;
const MAX_IPC_HELLO_BYTES = 4 * 1024;
const SAFE_CLOSE_REASON = "policy violation";
const REGISTRY_VERSION = 2 as const;
const LEGACY_REGISTRY_VERSION = 1 as const;
const SETUP_SECRET_PATTERN = /^[a-f0-9]{64}$/u;
const SETUP_MAX_TTL_MS = 5 * 60_000;
const SETUP_ENCRYPTION_KEY_INFO = "BrowseWeave setup encryption key v1";
const SETUP_IV_BYTES = 12;
const SETUP_AUTH_TAG_BYTES = 16;
const DEFAULT_MAX_AUDIT_QUEUE_ENTRIES = 512;
const DEFAULT_MAX_AUDIT_FILE_BYTES = 5 * 1024 * 1024;
const MIN_AUDIT_FILE_BYTES = 512;
const AUDIT_LABEL_PATTERN = /^[a-z][a-z0-9_]{0,119}$/u;
const UNAUTHENTICATED_AUDIT_WINDOW_MS = 1_000;
const UNAUTHENTICATED_AUDIT_BURST_PER_OUTCOME = 2;
const MAX_UNAUTHENTICATED_AUDIT_OUTCOMES = 16;
const OTHER_UNAUTHENTICATED_OUTCOME = "unauthenticated_rejection_other";

interface PendingCommand {
  commandId: string;
  requestId: string;
  client: Socket;
  browserId: string;
  action: BrowserAction;
  params: JsonObject;
  approved: boolean;
  revalidateOnly: boolean;
  revalidatingApprovalId?: string;
  approvedGrantId?: string;
  approvalFingerprint?: string;
  startedAt: number;
  timer: ReturnType<typeof setTimeout>;
}

type ApprovalState = "pending" | "approved";

interface PendingApproval {
  approvalId: string;
  approvalNonce: string;
  browserId: string;
  targetTabId: number;
  targetFrameId: number;
  action: BrowserAction;
  params: JsonObject;
  canonicalParams: string;
  paramsSha256: string;
  approvalFingerprint: string;
  risk: string;
  description: string;
  expiresAt: number;
  expiresAtIso: string;
  state: ApprovalState;
  timer: ReturnType<typeof setTimeout>;
}

type IpcPhase = "await_client_hello" | "await_request" | "accepted";

interface IpcClientState {
  buffer: Buffer;
  phase: IpcPhase;
  timer: ReturnType<typeof setTimeout>;
  clientNonce?: string;
  serverNonce?: string;
  serverProof?: string;
}

interface ExtensionHandshakeState {
  clientNonce: string;
  serverNonce: string;
  serverProof: string;
  identity: BrowserIdentity;
  publicKey: P256PublicJwk;
  keyObject: KeyObject;
  authenticationSecret: string;
  authMode: ExtensionAuthenticationMode;
  legacyEnrollmentId?: string;
  setupId?: string;
  setupPhase?: SetupAuthenticationPhase;
}

type ExtensionAuthenticationMode = "legacy" | "derived-v1";

interface StoredExtensionKey {
  browserId: string;
  publicKey: P256PublicJwk;
  enrolledAt: string;
  authMode: ExtensionAuthenticationMode;
}

interface SetupPairingSession {
  setupId: string;
  setupSecret: string;
  expiresAt: number;
  expiresAtIso: string;
  browserFamily: BrowserFamily;
  timer: ReturnType<typeof setTimeout>;
  enrollment?: PendingSetupEnrollment;
  provisionedAtIso?: string;
  completedAtIso?: string;
  commitInProgress?: boolean;
}

interface PendingSetupEnrollment {
  browserId: string;
  identity: BrowserIdentity;
  publicKey: P256PublicJwk;
}

interface LegacyPairingSession {
  id: string;
  expiresAt: number;
  expiresAtIso: string;
  browserFamily: BrowserFamily;
  timer: ReturnType<typeof setTimeout>;
}

interface BrowserSession {
  browserId: string;
  identity: BrowserIdentity;
  origin: string;
  publicKey: P256PublicJwk;
  keyObject: KeyObject;
  socket: WebSocket;
  connectedAt: string;
  awaitingPongTimestamp?: number;
  setupProvisioning?: true;
}

export interface SafeAuditEvent {
  event: "command" | "approval" | "connection";
  action?: BrowserAction;
  outcome: string;
  code?: string;
  duration_ms?: number;
  count?: number;
}

export interface DaemonStatusSnapshot {
  websocketListening: boolean;
  ipcListening: boolean;
  connectedBrowsers: ConnectedBrowserSummary[];
  pendingCommands: number;
  pendingApprovals: number;
  uptimeSeconds: number;
  lastAuditError?: string;
}

export interface DaemonAddresses {
  websocketHost: string;
  websocketPort: number;
  ipcHost: string;
  ipcPort: number;
}

function own(record: JsonObject, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function hasExactFields(record: JsonObject, fields: ReadonlySet<string>): boolean {
  const keys = Object.keys(record);
  return keys.length === fields.size && keys.every((key) => fields.has(key));
}

function jsonObjectWithout(record: JsonObject, excluded: ReadonlySet<string>): JsonObject {
  const output = Object.create(null) as JsonObject;
  for (const [key, value] of Object.entries(record)) {
    if (!excluded.has(key)) output[key] = value;
  }
  return output;
}

export function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isJsonObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] ?? null)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function randomBase64Url(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function framedField(name: string, value: string): string {
  return `${name}:${Buffer.byteLength(value, "utf8")}:${value}\n`;
}

function installationAuthenticationSecretPayload(
  installationId: string,
  publicKey: P256PublicJwk
): string {
  return "BrowseWeave installation authentication secret v1\n" +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("installation_id", installationId) +
    framedField("public_key", canonicalPublicJwk(publicKey));
}

function deriveInstallationAuthenticationSecret(
  masterSecret: string,
  installationId: string,
  publicKey: P256PublicJwk
): string {
  return createHmac("sha256", Buffer.from(masterSecret, "utf8"))
    .update(installationAuthenticationSecretPayload(installationId, publicKey), "utf8")
    .digest("base64url");
}

function isExactP256PublicJwk(value: unknown): value is P256PublicJwk {
  if (!isP256PublicJwk(value)) return false;
  return hasExactFields(value, new Set(["kty", "crv", "x", "y", "ext", "key_ops"]));
}

function canonicalFutureExpiry(
  value: unknown,
  now = Date.now()
): { expiresAt: number; expiresAtIso: string } | undefined {
  if (typeof value !== "string") return undefined;
  const expiresAt = Date.parse(value);
  if (
    !Number.isFinite(expiresAt) ||
    new Date(expiresAt).toISOString() !== value ||
    expiresAt <= now ||
    expiresAt > now + SETUP_MAX_TTL_MS
  ) return undefined;
  return { expiresAt, expiresAtIso: value };
}

function encryptSetupPairingToken(input: {
  setupSecret: string;
  setupId: string;
  clientNonce: string;
  serverNonce: string;
  daemonInstanceId: string;
  origin: string;
  identity: BrowserIdentity;
  publicKey: P256PublicJwk;
  expiresAt: string;
  pairingToken: string;
}): { iv: string; encryptedPairingToken: string } {
  const key = Buffer.from(hkdfSync(
    "sha256",
    Buffer.from(input.setupSecret, "utf8"),
    Buffer.from(setupPairingKeySalt({
      setupId: input.setupId,
      clientNonce: input.clientNonce,
      serverNonce: input.serverNonce
    }), "utf8"),
    Buffer.from(SETUP_ENCRYPTION_KEY_INFO, "utf8"),
    32
  ));
  const iv = randomBytes(SETUP_IV_BYTES);
  const aad = setupPairingAadPayload({
    setupId: input.setupId,
    clientNonce: input.clientNonce,
    serverNonce: input.serverNonce,
    daemonInstanceId: input.daemonInstanceId,
    origin: input.origin,
    identity: input.identity,
    publicKey: input.publicKey,
    expiresAt: input.expiresAt
  });
  const plaintext = Buffer.from(input.pairingToken, "utf8");
  try {
    const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: SETUP_AUTH_TAG_BYTES });
    cipher.setAAD(Buffer.from(aad, "utf8"), { plaintextLength: plaintext.byteLength });
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
    return {
      iv: iv.toString("base64url"),
      encryptedPairingToken: ciphertext.toString("base64url")
    };
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
}

function browserIdForInstallation(installationId: string): string {
  return `browser-${createHash("sha256").update(installationId, "utf8").digest("hex").slice(0, 24)}`;
}

export function isAllowedExtensionOrigin(
  origin: string | undefined,
  allowedOrigins: readonly string[] = []
): origin is string {
  if (origin === undefined) return false;
  const firefox = /^moz-extension:\/\/[A-Za-z0-9-]{8,128}$/u.test(origin);
  const chromium = /^chrome-extension:\/\/[a-p]{32}$/u.test(origin);
  if (!firefox && !chromium) return false;
  return allowedOrigins.length === 0 || allowedOrigins.includes(origin);
}

function originMatchesBrowserFamily(origin: string, browserFamily: BrowserFamily): boolean {
  return browserFamily === "firefox"
    ? origin.startsWith("moz-extension://")
    : origin.startsWith("chrome-extension://");
}

function isCanonicalNonce(value: unknown): value is string {
  if (typeof value !== "string" || !BASE64URL_256_PATTERN.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.byteLength === 32 && decoded.toString("base64url") === value;
}

function hmacProof(secret: string, payload: string): string {
  return createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(payload, "utf8")
    .digest("base64url");
}

function proofMatches(candidate: unknown, expected: string): candidate is string {
  if (!isCanonicalNonce(candidate) || !isCanonicalNonce(expected)) return false;
  const candidateBytes = Buffer.from(candidate, "base64url");
  const expectedBytes = Buffer.from(expected, "base64url");
  return timingSafeEqual(candidateBytes, expectedBytes);
}

class ReplayNonceCache {
  readonly #entries = new Map<string, number>();

  claim(role: "extension" | "ipc" | "setup", nonce: string, now = Date.now()): boolean {
    this.#prune(now);
    const key = `${role}:${nonce}`;
    if (this.#entries.has(key)) return false;
    while (this.#entries.size >= MAX_REPLAY_NONCES) {
      const oldest = this.#entries.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
    this.#entries.set(key, now + REPLAY_NONCE_TTL_MS);
    return true;
  }

  clear(): void {
    this.#entries.clear();
  }

  #prune(now: number): void {
    for (const [key, expiresAt] of this.#entries) {
      if (expiresAt > now) continue;
      this.#entries.delete(key);
    }
  }
}

/** Parse and bound a request envelope. Its HMAC is verified by the connection state machine. */
export function parseIpcRequest(line: string, maxPayloadBytes: number): IpcRequest {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line) as unknown;
  } catch {
    throw new Error("The IPC request is not valid JSON.");
  }
  if (!isJsonObject(parsed)) throw new Error("The IPC request must be a JSON object.");

  const allowedFields = new Set([
    "type",
    "protocol_version",
    "endpoint_role",
    "id",
    "method",
    "params",
    "client_nonce",
    "server_nonce",
    "daemon_instance_id",
    "client_proof"
  ]);
  if (Object.keys(parsed).some((field) => !allowedFields.has(field))) {
    throw new Error("The IPC request contains an unsupported field.");
  }
  if (
    parsed.type !== "ipc_request" ||
    parsed.protocol_version !== PROTOCOL_VERSION ||
    parsed.endpoint_role !== "ipc"
  ) {
    throw new Error("The IPC request protocol envelope is invalid.");
  }

  const { id, method, params } = parsed;
  if (typeof id !== "string" || id.length < 1 || id.length > MAX_REQUEST_ID_LENGTH) {
    throw new Error("The IPC request ID must contain 1-128 characters.");
  }
  if (
    typeof method !== "string" ||
    method.length < 1 ||
    method.length > MAX_METHOD_LENGTH ||
    !/^[a-z][a-z0-9_]*$/u.test(method)
  ) {
    throw new Error("The IPC method name is invalid.");
  }
  if (!isJsonObject(params) || !isJsonValue(params)) {
    throw new Error("The IPC params field must contain finite JSON values.");
  }
  if (Buffer.byteLength(JSON.stringify(params), "utf8") > maxPayloadBytes) {
    throw new Error(`The IPC params exceed the safe size limit (${maxPayloadBytes} bytes).`);
  }

  if (
    !isCanonicalNonce(parsed.client_nonce) ||
    !isCanonicalNonce(parsed.server_nonce) ||
    typeof parsed.daemon_instance_id !== "string" ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u.test(
      parsed.daemon_instance_id
    ) ||
    !isCanonicalNonce(parsed.client_proof)
  ) {
    throw new Error("The IPC authentication proof is invalid.");
  }
  return {
    type: "ipc_request",
    protocol_version: PROTOCOL_VERSION,
    endpoint_role: "ipc",
    id,
    method,
    params,
    client_nonce: parsed.client_nonce,
    server_nonce: parsed.server_nonce,
    daemon_instance_id: parsed.daemon_instance_id,
    client_proof: parsed.client_proof
  };
}

function rawDataToBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (Array.isArray(data)) return Buffer.concat(data);
  throw new Error("Unsupported WebSocket data type.");
}

function parseExtensionResult(value: JsonObject): ExtensionResult | undefined {
  if (value.type !== "result" || typeof value.id !== "string") return undefined;
  if (value.ok === true) {
    const result = own(value, "result") ? value.result : null;
    return isJsonValue(result) ? { type: "result", id: value.id, ok: true, result } : undefined;
  }
  if (value.ok !== false || !isJsonObject(value.error)) return undefined;
  const error = value.error;
  if (typeof error.code !== "string" || typeof error.message !== "string") return undefined;
  if (own(error, "category") && typeof error.category !== "string") return undefined;
  if (own(error, "approval_fingerprint") && typeof error.approval_fingerprint !== "string") {
    return undefined;
  }
  if (
    own(error, "target_tab_id") &&
    (typeof error.target_tab_id !== "number" || !Number.isSafeInteger(error.target_tab_id) || error.target_tab_id <= 0)
  ) return undefined;
  if (
    own(error, "target_frame_id") &&
    (typeof error.target_frame_id !== "number" || !Number.isSafeInteger(error.target_frame_id) || error.target_frame_id < 0)
  ) return undefined;
  if (own(error, "details") && !isJsonObject(error.details)) return undefined;

  const normalized: ExtensionError = { code: error.code, message: error.message };
  if (typeof error.category === "string") normalized.category = error.category;
  if (typeof error.approval_fingerprint === "string") {
    normalized.approval_fingerprint = error.approval_fingerprint;
  }
  if (typeof error.target_tab_id === "number") normalized.target_tab_id = error.target_tab_id;
  if (typeof error.target_frame_id === "number") normalized.target_frame_id = error.target_frame_id;
  if (isJsonObject(error.details)) normalized.details = error.details;
  return { type: "result", id: value.id, ok: false, error: normalized };
}

function parseBrowserIdentity(value: unknown): BrowserIdentity | undefined {
  if (
    !isJsonObject(value) ||
    !hasExactFields(value, new Set([
      "installation_id",
      "browser_family",
      "browser_name",
      "browser_version",
      "extension_version"
    ])) ||
    !isInstallationId(value.installation_id)
  ) return undefined;
  if (value.browser_family !== "firefox" && value.browser_family !== "chromium") return undefined;
  for (const field of ["browser_name", "browser_version", "extension_version"] as const) {
    const candidate = value[field];
    if (
      typeof candidate !== "string" ||
      candidate.length < 1 ||
      candidate.length > 120 ||
      /[\p{Cc}\p{Cf}]/u.test(candidate)
    ) return undefined;
  }
  return {
    installation_id: value.installation_id,
    browser_family: value.browser_family,
    browser_name: value.browser_name as string,
    browser_version: value.browser_version as string,
    extension_version: value.extension_version as string
  };
}

function decodeP1363Signature(value: unknown): Buffer | undefined {
  if (typeof value !== "string" || value.length !== 86 || !BASE64URL_PATTERN.test(value)) {
    return undefined;
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== 64 || decoded.toString("base64url") !== value) return undefined;
  return decoded;
}

function publicKeyObject(jwk: P256PublicJwk): KeyObject {
  return createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
}

function verifyP256(key: KeyObject, payload: string, signature: unknown): boolean {
  const decoded = decodeP1363Signature(signature);
  if (decoded === undefined) return false;
  try {
    return verifySignature(
      "sha256",
      Buffer.from(payload, "utf8"),
      { key, dsaEncoding: "ieee-p1363" },
      decoded
    );
  } catch {
    return false;
  }
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

class UnauthenticatedAuditCoalescer {
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

class ExtensionKeyRegistry {
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

function validateConfig(config: DaemonConfig): void {
  if (config.wsHost !== DEFAULT_WS_HOST) {
    throw new Error("The WebSocket server may listen only on 127.0.0.1.");
  }
  if (config.ipcHost !== DEFAULT_IPC_HOST) {
    throw new Error("The IPC server may listen only on 127.0.0.1.");
  }
  for (const [label, port] of [["WebSocket", config.wsPort], ["IPC", config.ipcPort]] as const) {
    if (!Number.isInteger(port) || port < 0 || port > 65_535) {
      throw new Error(`${label} port must be between 0 and 65535.`);
    }
  }
  if (config.helloTimeoutMs < 1 || config.helloTimeoutMs > 10_000) {
    throw new Error("The hello timeout must be between 1 and 10000 ms.");
  }
  if (config.commandTimeoutMs < 1 || config.commandTimeoutMs > MAX_COMMAND_TIMEOUT_MS) {
    throw new Error(`The command timeout may not exceed ${MAX_COMMAND_TIMEOUT_MS} ms.`);
  }
  if (config.approvalTtlMs < 1 || config.approvalTtlMs > 5 * 60_000) {
    throw new Error("The approval lifetime may not exceed five minutes.");
  }
  if (config.pairingToken.length < 32 || config.pairingToken.length > 256) {
    throw new Error("The BrowseWeave pairing token is invalid.");
  }
  if (config.ipcToken.length < 32 || config.ipcToken.length > 256) {
    throw new Error("The BrowseWeave IPC authentication secret is invalid.");
  }
  if (config.pairingToken === config.ipcToken) {
    throw new Error("The extension pairing and IPC authentication secrets must be different.");
  }
}

function safeExtensionError(error: ExtensionError, action?: BrowserAction): string {
  if (action === "credential_fill") {
    return `The browser extension could not complete the one-time credential operation (${error.code.slice(0, 100)}).`;
  }
  const message = error.message.replace(/[\r\n]+/gu, " ").slice(0, 500);
  return `The browser extension could not complete the operation (${error.code}): ${message}`;
}

function sanitizeApprovalText(value: unknown, maxLength: number): string | undefined {
  if (typeof value !== "string") return undefined;
  const sanitized = value.replace(/[\p{Cc}\p{Cf}]+/gu, " ").replace(/\s+/gu, " ").trim();
  return sanitized.length > 0 ? sanitized.slice(0, maxLength) : undefined;
}

function approvalDescription(error: ExtensionError): string {
  const summaries: string[] = [];
  const navigationUrl = sanitizeApprovalText(error.details?.url, 160);
  if (navigationUrl !== undefined) summaries.push(`URL: ${navigationUrl}`);
  const targets = error.details?.targets;
  if (Array.isArray(targets)) {
    for (const candidate of targets) {
      if (summaries.length >= 3) break;
      if (!isJsonObject(candidate)) continue;
      const target = sanitizeApprovalText(candidate.target, 120);
      if (target !== undefined && !summaries.includes(target)) summaries.push(target);
    }
  }
  const untrusted = summaries.length > 0
    ? ` Untrusted page-supplied target text: ${summaries.join(" | ")}`
    : "";
  const base = sanitizeApprovalText(error.message, Math.max(1, 500 - untrusted.length)) ??
    "This sensitive operation requires human approval.";
  return `${base}${untrusted}`.slice(0, 500);
}

function listenTcpServer(server: NetServer, host: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = (): void => {
      server.off("listening", onListening);
      server.off("error", onError);
    };
    const onListening = (): void => {
      cleanup();
      resolve();
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    server.once("listening", onListening);
    server.once("error", onError);
    try {
      server.listen({ host, port, exclusive: true });
    } catch (error) {
      cleanup();
      reject(error);
    }
  });
}

function withBrowserId(result: JsonValue, browserId: string): JsonValue {
  if (!isJsonObject(result)) return { browser_id: browserId, value: result };
  const enriched: JsonObject = { ...result, browser_id: browserId };
  if (Array.isArray(result.tabs)) {
    enriched.tabs = result.tabs.map((tab) => isJsonObject(tab) ? { ...tab, browser_id: browserId } : tab);
  }
  return enriched;
}

export class BrowseWeaveDaemon {
  readonly #config: DaemonConfig;
  readonly #audit: SafeAuditLogger;
  readonly #unauthenticatedAudit: UnauthenticatedAuditCoalescer;
  readonly #keyRegistry: ExtensionKeyRegistry;
  readonly #daemonInstanceId = randomUUID();
  readonly #replayNonces = new ReplayNonceCache();
  readonly #ipcClients = new Map<Socket, IpcClientState>();
  readonly #unauthenticatedSockets = new Set<WebSocket>();
  readonly #setupProvisioningSockets = new Set<WebSocket>();
  readonly #browserSessions = new Map<string, BrowserSession>();
  readonly #browserIdByInstallation = new Map<string, string>();
  readonly #pendingCommands = new Map<string, PendingCommand>();
  readonly #pendingApprovals = new Map<string, PendingApproval>();
  #setupPairingSession: SetupPairingSession | undefined;
  #legacyPairingSession: LegacyPairingSession | undefined;
  #wsServer: WebSocketServer | undefined;
  #ipcServer: NetServer | undefined;
  #heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  #startedAt = 0;
  #started = false;
  #stopping = false;

  constructor(config: DaemonConfig) {
    validateConfig(config);
    this.#config = config;
    this.#audit = new SafeAuditLogger(config.auditLogPath);
    this.#unauthenticatedAudit = new UnauthenticatedAuditCoalescer(this.#audit);
    this.#keyRegistry = new ExtensionKeyRegistry(config.extensionKeyPath);
  }

  async start(): Promise<DaemonAddresses> {
    if (this.#started) return this.addresses();
    if (this.#stopping) throw new Error("BrowseWeave cannot restart while it is stopping.");

    await ensurePrivateDirectory(this.#config.runtimeDir);
    await ensurePrivateDirectory(this.#config.configDir);
    await ensurePrivateDirectory(this.#config.stateDir);
    await this.#keyRegistry.load();
    this.#startedAt = Date.now();
    try {
      await this.#audit.start();
      this.#unauthenticatedAudit.start();
      await this.#startWebSocketServer();
      await this.#startIpcServer();
      this.#startHeartbeat();
      this.#started = true;
      return this.addresses();
    } catch (error) {
      await this.stop("startup_failed");
      throw error;
    }
  }

  addresses(): DaemonAddresses {
    const wsAddress = this.#wsServer?.address();
    const ipcAddress = this.#ipcServer?.address();
    return {
      websocketHost: this.#config.wsHost,
      websocketPort: wsAddress && typeof wsAddress === "object" ? wsAddress.port : this.#config.wsPort,
      ipcHost: this.#config.ipcHost,
      ipcPort: ipcAddress && typeof ipcAddress === "object" ? ipcAddress.port : this.#config.ipcPort
    };
  }

  statusSnapshot(): DaemonStatusSnapshot {
    const snapshot: DaemonStatusSnapshot = {
      websocketListening: this.#wsServer !== undefined,
      ipcListening: this.#ipcServer !== undefined,
      connectedBrowsers: this.#connectedBrowserSummaries(),
      pendingCommands: this.#pendingCommands.size,
      pendingApprovals: this.#pendingApprovals.size,
      uptimeSeconds: this.#startedAt === 0 ? 0 : Math.max(0, (Date.now() - this.#startedAt) / 1000)
    };
    if (this.#audit.lastError !== undefined) snapshot.lastAuditError = this.#audit.lastError;
    return snapshot;
  }

  async stop(reason = "shutdown"): Promise<void> {
    if (this.#stopping) return;
    this.#stopping = true;
    this.#started = false;

    if (this.#heartbeatTimer !== undefined) {
      clearInterval(this.#heartbeatTimer);
      this.#heartbeatTimer = undefined;
    }
    this.#failAllCommands(`BrowseWeave stopped (${reason}).`, "daemon_stopped");
    this.#clearAllApprovals("cancelled");
    this.#clearSetupPairingSession();
    this.#clearLegacyPairingSession();

    for (const socket of this.#unauthenticatedSockets) socket.terminate();
    this.#unauthenticatedSockets.clear();
    for (const socket of this.#setupProvisioningSockets) socket.terminate();
    this.#setupProvisioningSockets.clear();
    for (const session of this.#browserSessions.values()) session.socket.terminate();
    this.#browserSessions.clear();
    this.#browserIdByInstallation.clear();
    for (const socket of this.#ipcClients.keys()) socket.destroy();
    this.#ipcClients.clear();

    const wsServer = this.#wsServer;
    this.#wsServer = undefined;
    if (wsServer !== undefined) await new Promise<void>((resolve) => wsServer.close(() => resolve()));
    const ipcServer = this.#ipcServer;
    this.#ipcServer = undefined;
    if (ipcServer !== undefined) await new Promise<void>((resolve) => ipcServer.close(() => resolve()));
    this.#unauthenticatedAudit.close();
    await this.#audit.close();
    this.#stopping = false;
  }

  #connectedBrowserSummaries(): ConnectedBrowserSummary[] {
    return [...this.#browserSessions.values()]
      .map((session) => ({
        browser_id: session.browserId,
        browser_family: session.identity.browser_family,
        browser_name: session.identity.browser_name,
        browser_version: session.identity.browser_version,
        extension_version: session.identity.extension_version,
        connected_at: session.connectedAt
      }))
      .sort((left, right) => left.browser_id.localeCompare(right.browser_id));
  }

  async #startWebSocketServer(): Promise<void> {
    const server = new WebSocketServer({
      host: this.#config.wsHost,
      port: this.#config.wsPort,
      maxPayload: this.#config.maxWsPayloadBytes,
      perMessageDeflate: false,
      clientTracking: true,
      verifyClient: ((info) => {
        if (!isAllowedExtensionOrigin(info.origin, this.#config.allowedOrigins)) {
          this.#unauthenticatedAudit.record("extension_origin_rejected");
          return false;
        }
        if (
          this.#unauthenticatedSockets.size >= MAX_UNAUTHENTICATED_CONNECTIONS ||
          this.#setupProvisioningSockets.size >= MAX_UNAUTHENTICATED_CONNECTIONS ||
          this.#browserSessions.size >= MAX_CONNECTED_BROWSERS
        ) {
          this.#unauthenticatedAudit.record("extension_connection_limit_rejected");
          return false;
        }
        return true;
      }) satisfies VerifyClientCallbackSync
    });
    this.#wsServer = server;
    server.on("connection", (socket, request) => this.#handleWebSocket(socket, request.headers.origin));
    await new Promise<void>((resolve, reject) => {
      server.once("listening", resolve);
      server.once("error", reject);
    });
    server.on("error", () => this.#audit.record({ event: "connection", outcome: "websocket_server_error" }));
  }

  async #startIpcServer(): Promise<void> {
    const server = createServer((socket) => {
      if (this.#ipcClients.size >= MAX_IPC_CONNECTIONS) {
        this.#unauthenticatedAudit.record("ipc_connection_limit_rejected");
        socket.destroy();
        return;
      }
      this.#handleIpcClient(socket);
    });
    await listenTcpServer(server, this.#config.ipcHost, this.#config.ipcPort);
    this.#ipcServer = server;
    server.on("error", () => this.#audit.record({ event: "connection", outcome: "ipc_server_error" }));
  }

  #startHeartbeat(): void {
    this.#heartbeatTimer = setInterval(() => {
      for (const session of this.#browserSessions.values()) {
        if (session.awaitingPongTimestamp !== undefined) {
          this.#audit.record({ event: "connection", outcome: "heartbeat_timeout" });
          session.socket.terminate();
          continue;
        }
        const timestamp = Date.now();
        session.awaitingPongTimestamp = timestamp;
        try {
          session.socket.send(JSON.stringify({ type: "ping", timestamp }));
        } catch {
          session.socket.terminate();
        }
      }
    }, HEARTBEAT_INTERVAL_MS);
    this.#heartbeatTimer.unref();
  }

  #handleWebSocket(socket: WebSocket, origin: string | undefined): void {
    if (!isAllowedExtensionOrigin(origin, this.#config.allowedOrigins)) {
      this.#unauthenticatedAudit.record("extension_origin_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }
    this.#unauthenticatedSockets.add(socket);
    let handshake: ExtensionHandshakeState | undefined;
    let session: BrowserSession | undefined;
    let setupAttempted = false;
    let queue: Promise<void> = Promise.resolve();
    const helloTimer = setTimeout(() => {
      if (session === undefined) {
        this.#unauthenticatedAudit.record("extension_hello_timeout");
        socket.close(1008, "hello timeout");
      }
    }, this.#config.helloTimeoutMs);
    helloTimer.unref();

    socket.on("message", (data, isBinary) => {
      queue = queue
        .then(async () => {
          if (isBinary) {
            if (session === undefined) this.#unauthenticatedAudit.record("extension_binary_message_rejected");
            socket.close(1003, "text messages required");
            return;
          }
          const raw = rawDataToBuffer(data);
          if (raw.byteLength > this.#config.maxWsPayloadBytes) {
            if (session === undefined) this.#unauthenticatedAudit.record("extension_message_too_large");
            socket.close(1009, "message too large");
            return;
          }
          let parsed: unknown;
          try {
            parsed = JSON.parse(raw.toString("utf8")) as unknown;
          } catch {
            if (session === undefined) this.#unauthenticatedAudit.record("extension_invalid_json_rejected");
            socket.close(1007, "invalid json");
            return;
          }
          if (!isJsonObject(parsed)) {
            if (session === undefined) this.#unauthenticatedAudit.record("extension_invalid_message_rejected");
            socket.close(1007, "invalid message");
            return;
          }
          if (session === undefined) {
            if (handshake === undefined) {
              if (setupAttempted) {
                this.#unauthenticatedAudit.record("setup_pairing_replayed");
                socket.close(1008, SAFE_CLOSE_REASON);
                return;
              }
              if (parsed.type === "setup_pair_request") {
                setupAttempted = true;
                await this.#handleSetupPairingRequest(socket, origin, parsed);
                return;
              }
              handshake = this.#beginExtensionHandshake(socket, origin, parsed);
              return;
            }
            session = await this.#authenticateExtension(socket, origin, handshake, parsed);
            if (session !== undefined) {
              clearTimeout(helloTimer);
              this.#unauthenticatedSockets.delete(socket);
            }
            return;
          }
          await this.#handleAuthenticatedExtensionMessage(session, parsed);
        })
        .catch(() => {
          if (session === undefined) this.#unauthenticatedAudit.record("extension_handshake_processing_rejected");
          socket.close(1008, SAFE_CLOSE_REASON);
        });
    });

    socket.once("close", () => {
      clearTimeout(helloTimer);
      if (handshake !== undefined) handshake.authenticationSecret = "";
      this.#unauthenticatedSockets.delete(socket);
      this.#setupProvisioningSockets.delete(socket);
      if (session !== undefined) this.#disconnectBrowser(session, "extension_disconnected");
    });
    socket.once("error", () => {
      if (session === undefined) this.#unauthenticatedAudit.record("extension_transport_rejected");
    });
  }

  async #handleSetupPairingRequest(
    socket: WebSocket,
    origin: string,
    message: JsonObject
  ): Promise<void> {
    const fields = new Set([
      "type",
      "protocol_version",
      "setup_version",
      "setup_id",
      "client_nonce",
      "origin",
      "identity",
      "public_key",
      "client_proof"
    ]);
    const identity = parseBrowserIdentity(message.identity);
    const active = this.#activeSetupPairingSession();
    if (
      !hasExactFields(message, fields) ||
      message.type !== "setup_pair_request" ||
      message.protocol_version !== PROTOCOL_VERSION ||
      message.setup_version !== SETUP_VERSION ||
      typeof message.setup_id !== "string" ||
      !SETUP_ID_PATTERN.test(message.setup_id) ||
      !isCanonicalNonce(message.client_nonce) ||
      message.origin !== origin ||
      identity === undefined ||
      !originMatchesBrowserFamily(origin, identity.browser_family) ||
      !isExactP256PublicJwk(message.public_key) ||
      !isCanonicalNonce(message.client_proof) ||
      active === undefined ||
      active.setupId !== message.setup_id ||
      active.browserFamily !== identity.browser_family
    ) {
      this.#unauthenticatedAudit.record("setup_pairing_request_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }

    const expectedProof = hmacProof(active.setupSecret, setupPairingClientProofPayload({
      setupId: active.setupId,
      clientNonce: message.client_nonce,
      origin,
      installationId: identity.installation_id,
      publicKey: message.public_key
    }));
    if (
      !proofMatches(message.client_proof, expectedProof) ||
      !this.#replayNonces.claim("setup", message.client_nonce) ||
      this.#activeSetupPairingSession() !== active
    ) {
      this.#unauthenticatedAudit.record("setup_pairing_proof_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }

    try {
      publicKeyObject(message.public_key);
    } catch {
      this.#unauthenticatedAudit.record("setup_pairing_public_key_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }

    const existing = this.#keyRegistry.get(identity.installation_id);
    if (
      active.completedAtIso !== undefined ||
      active.commitInProgress === true ||
      (existing !== undefined && canonicalPublicJwk(existing.publicKey) !== canonicalPublicJwk(message.public_key))
    ) {
      this.#unauthenticatedAudit.record("setup_pairing_key_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }
    const enrollment: PendingSetupEnrollment = active.enrollment ?? {
      browserId: browserIdForInstallation(identity.installation_id),
      identity: { ...identity },
      publicKey: message.public_key
    };
    if (
      active.enrollment !== undefined &&
      (
        canonicalJson(active.enrollment.identity) !== canonicalJson(identity) ||
        canonicalPublicJwk(active.enrollment.publicKey) !== canonicalPublicJwk(message.public_key)
      )
    ) {
      this.#unauthenticatedAudit.record("setup_pairing_key_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }
    active.enrollment = enrollment;
    if (active.expiresAt <= Date.now()) {
      this.#unauthenticatedAudit.record("setup_pairing_expired");
      socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }

    const setupSecret = active.setupSecret;
    const pairingToken = deriveInstallationAuthenticationSecret(
      this.#config.pairingToken,
      identity.installation_id,
      message.public_key
    );
    const serverNonce = randomBase64Url();
    let encrypted: { iv: string; encryptedPairingToken: string };
    try {
      encrypted = encryptSetupPairingToken({
        setupSecret,
        setupId: active.setupId,
        clientNonce: message.client_nonce,
        serverNonce,
        daemonInstanceId: this.#daemonInstanceId,
        origin,
        identity,
        publicKey: message.public_key,
        expiresAt: active.expiresAtIso,
        pairingToken
      });
    } catch {
      this.#unauthenticatedAudit.record("setup_pairing_encryption_failed");
      socket.close(1011, SAFE_CLOSE_REASON);
      return;
    }

    const response: SetupPairingResponse = {
      type: "setup_pair_response",
      protocol_version: PROTOCOL_VERSION,
      setup_version: SETUP_VERSION,
      setup_id: active.setupId,
      client_nonce: message.client_nonce,
      server_nonce: serverNonce,
      daemon_instance_id: this.#daemonInstanceId,
      expires_at: active.expiresAtIso,
      iv: encrypted.iv,
      encrypted_pairing_token: encrypted.encryptedPairingToken
    };
    this.#audit.record({ event: "connection", outcome: "setup_pairing_token_issued" });
    try {
      socket.send(JSON.stringify(response), (error) => {
        if (error) socket.terminate();
        else socket.close(1000, "setup complete");
      });
    } catch {
      socket.terminate();
    }
  }

  #beginExtensionHandshake(
    socket: WebSocket,
    origin: string,
    message: JsonObject
  ): ExtensionHandshakeState | undefined {
    const baseFields = [
      "type",
      "protocol_version",
      "endpoint_role",
      "client_nonce",
      "origin",
      "identity",
      "public_key"
    ];
    const stagedSetup = own(message, "authentication_mode") || own(message, "setup_id") || own(message, "setup_phase");
    const allowedFields = new Set(stagedSetup
      ? [...baseFields, "authentication_mode", "setup_id", "setup_phase"]
      : baseFields);
    const identity = parseBrowserIdentity(message.identity);
    if (
      !hasExactFields(message, allowedFields) ||
      message.type !== "client_hello" ||
      message.protocol_version !== PROTOCOL_VERSION ||
      message.endpoint_role !== "extension" ||
      message.origin !== origin ||
      !isCanonicalNonce(message.client_nonce) ||
      identity === undefined ||
      !originMatchesBrowserFamily(origin, identity.browser_family) ||
      !isExactP256PublicJwk(message.public_key) ||
      (stagedSetup && (
        message.authentication_mode !== "derived-v1" ||
        typeof message.setup_id !== "string" ||
        !SETUP_ID_PATTERN.test(message.setup_id) ||
        (message.setup_phase !== "provisioning" && message.setup_phase !== "persisted")
      ))
    ) {
      this.#unauthenticatedAudit.record("extension_client_hello_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return undefined;
    }

    const pinned = this.#keyRegistry.get(identity.installation_id);
    let authenticationSecret: string;
    let authMode: ExtensionAuthenticationMode;
    let legacyEnrollmentId: string | undefined;
    let setupId: string | undefined;
    let setupPhase: SetupAuthenticationPhase | undefined;
    if (stagedSetup) {
      const active = this.#activeSetupPairingSession();
      const enrollment = active?.enrollment;
      if (
        active === undefined ||
        (active.completedAtIso !== undefined && message.setup_phase !== "persisted") ||
        enrollment === undefined ||
        (message.setup_phase === "persisted" && active.provisionedAtIso === undefined) ||
        active.setupId !== message.setup_id ||
        active.browserFamily !== identity.browser_family ||
        canonicalJson(enrollment.identity) !== canonicalJson(identity) ||
        canonicalPublicJwk(enrollment.publicKey) !== canonicalPublicJwk(message.public_key) ||
        (active.completedAtIso !== undefined && (
          pinned === undefined ||
          pinned.authMode !== "derived-v1" ||
          canonicalPublicJwk(pinned.publicKey) !== canonicalPublicJwk(message.public_key)
        ))
      ) {
        this.#unauthenticatedAudit.record("extension_setup_binding_rejected");
        socket.close(1008, SAFE_CLOSE_REASON);
        return undefined;
      }
      authMode = "derived-v1";
      setupId = active.setupId;
      setupPhase = message.setup_phase as SetupAuthenticationPhase;
      authenticationSecret = deriveInstallationAuthenticationSecret(
        this.#config.pairingToken,
        identity.installation_id,
        message.public_key
      );
    } else if (pinned !== undefined) {
      if (canonicalPublicJwk(pinned.publicKey) !== canonicalPublicJwk(message.public_key)) {
        this.#unauthenticatedAudit.record("extension_key_rejected");
        socket.close(1008, SAFE_CLOSE_REASON);
        return undefined;
      }
      authMode = pinned.authMode;
      authenticationSecret = authMode === "derived-v1"
        ? deriveInstallationAuthenticationSecret(
          this.#config.pairingToken,
          identity.installation_id,
          message.public_key
        )
        : this.#config.pairingToken;
    } else {
      const legacyEnrollment = this.#activeLegacyPairingSession();
      if (legacyEnrollment === undefined || legacyEnrollment.browserFamily !== identity.browser_family) {
        this.#unauthenticatedAudit.record("extension_unknown_installation_rejected");
        socket.close(1008, SAFE_CLOSE_REASON);
        return undefined;
      }
      authMode = "legacy";
      authenticationSecret = this.#config.pairingToken;
      legacyEnrollmentId = legacyEnrollment.id;
    }
    if (!this.#replayNonces.claim("extension", message.client_nonce)) {
      this.#unauthenticatedAudit.record("extension_client_hello_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return undefined;
    }

    let keyObject: KeyObject;
    try {
      keyObject = publicKeyObject(message.public_key);
    } catch {
      this.#unauthenticatedAudit.record("extension_public_key_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return undefined;
    }
    const serverNonce = randomBase64Url();
    const serverProof = hmacProof(authenticationSecret, extensionServerProofPayload({
      clientNonce: message.client_nonce,
      serverNonce,
      daemonInstanceId: this.#daemonInstanceId,
      origin,
      installationId: identity.installation_id,
      publicKey: message.public_key,
      ...(setupId === undefined ? {} : { setupId, setupPhase: setupPhase as SetupAuthenticationPhase })
    }));
    const handshake: ExtensionHandshakeState = {
      clientNonce: message.client_nonce,
      serverNonce,
      serverProof,
      identity,
      publicKey: message.public_key,
      keyObject,
      authenticationSecret,
      authMode
    };
    if (legacyEnrollmentId !== undefined) handshake.legacyEnrollmentId = legacyEnrollmentId;
    if (setupId !== undefined) handshake.setupId = setupId;
    if (setupPhase !== undefined) handshake.setupPhase = setupPhase;
    socket.send(JSON.stringify({
      type: "challenge",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "extension",
      client_nonce: handshake.clientNonce,
      server_nonce: handshake.serverNonce,
      daemon_instance_id: this.#daemonInstanceId,
      server_proof: handshake.serverProof
    }));
    return handshake;
  }

  async #authenticateExtension(
    socket: WebSocket,
    origin: string,
    handshake: ExtensionHandshakeState,
    message: JsonObject
  ): Promise<BrowserSession | undefined> {
    const allowedFields = new Set([
      "type",
      "protocol_version",
      "endpoint_role",
      "client_nonce",
      "server_nonce",
      "origin",
      "daemon_instance_id",
      "identity",
      "public_key",
      "client_proof",
      "signature"
    ]);
    const identity = parseBrowserIdentity(message.identity);
    if (
      !hasExactFields(message, allowedFields) ||
      message.type !== "hello" ||
      message.protocol_version !== PROTOCOL_VERSION ||
      message.endpoint_role !== "extension" ||
      message.origin !== origin ||
      message.client_nonce !== handshake.clientNonce ||
      message.server_nonce !== handshake.serverNonce ||
      message.daemon_instance_id !== this.#daemonInstanceId ||
      identity === undefined ||
      canonicalJson(identity) !== canonicalJson(handshake.identity) ||
      !isExactP256PublicJwk(message.public_key) ||
      canonicalPublicJwk(message.public_key) !== canonicalPublicJwk(handshake.publicKey)
    ) {
      handshake.authenticationSecret = "";
      this.#unauthenticatedAudit.record("extension_hello_envelope_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return undefined;
    }

    const authenticationSecret = handshake.authenticationSecret;
    handshake.authenticationSecret = "";
    const expectedClientProof = hmacProof(authenticationSecret, extensionClientProofPayload({
      clientNonce: handshake.clientNonce,
      serverNonce: handshake.serverNonce,
      daemonInstanceId: this.#daemonInstanceId,
      origin,
      installationId: handshake.identity.installation_id,
      publicKey: handshake.publicKey,
      serverProof: handshake.serverProof,
      ...(handshake.setupId === undefined ? {} : {
        setupId: handshake.setupId,
        setupPhase: handshake.setupPhase as SetupAuthenticationPhase
      })
    }));
    if (!proofMatches(message.client_proof, expectedClientProof)) {
      this.#unauthenticatedAudit.record("extension_client_proof_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return undefined;
    }
    const signedPayload = helloSigningPayload({
      clientNonce: handshake.clientNonce,
      serverNonce: handshake.serverNonce,
      daemonInstanceId: this.#daemonInstanceId,
      origin,
      installationId: identity.installation_id,
      publicKey: message.public_key,
      clientProof: message.client_proof,
      ...(handshake.setupId === undefined ? {} : {
        setupId: handshake.setupId,
        setupPhase: handshake.setupPhase as SetupAuthenticationPhase
      })
    });
    if (!verifyP256(handshake.keyObject, signedPayload, message.signature)) {
      this.#unauthenticatedAudit.record("hello_signature_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return undefined;
    }

    let setupSession: SetupPairingSession | undefined;
    if (handshake.setupId !== undefined) {
      const active = this.#activeSetupPairingSession();
      const enrollment = active?.enrollment;
      if (
        active === undefined ||
        active.setupId !== handshake.setupId ||
        (active.completedAtIso !== undefined && handshake.setupPhase !== "persisted") ||
        active.commitInProgress === true ||
        enrollment === undefined ||
        (handshake.setupPhase === "persisted" && active.provisionedAtIso === undefined) ||
        canonicalJson(enrollment.identity) !== canonicalJson(identity) ||
        canonicalPublicJwk(enrollment.publicKey) !== canonicalPublicJwk(message.public_key)
      ) {
        this.#unauthenticatedAudit.record("extension_setup_binding_rejected");
        socket.close(1008, SAFE_CLOSE_REASON);
        return undefined;
      }
      if (handshake.setupPhase === "persisted" && active.completedAtIso === undefined) {
        active.commitInProgress = true;
      }
      setupSession = active;
    }

    if (setupSession !== undefined && handshake.setupPhase === "provisioning") {
      const enrollment = setupSession.enrollment;
      if (enrollment === undefined) {
        this.#unauthenticatedAudit.record("extension_setup_binding_rejected");
        socket.close(1008, SAFE_CLOSE_REASON);
        return undefined;
      }
      const provisionalSession: BrowserSession = {
        browserId: enrollment.browserId,
        identity,
        origin,
        publicKey: enrollment.publicKey,
        keyObject: handshake.keyObject,
        socket,
        connectedAt: new Date().toISOString(),
        setupProvisioning: true
      };
      socket.send(JSON.stringify({
        type: "hello_ack",
        protocol_version: PROTOCOL_VERSION,
        browser_id: provisionalSession.browserId
      }));
      for (const existing of this.#setupProvisioningSockets) {
        if (existing !== socket) existing.close(1000, "replaced by setup reconnect");
      }
      this.#setupProvisioningSockets.clear();
      this.#setupProvisioningSockets.add(socket);
      setupSession.provisionedAtIso = new Date().toISOString();
      this.#audit.record({ event: "connection", outcome: "setup_pairing_provisioned" });
      return provisionalSession;
    }

    if (handshake.legacyEnrollmentId !== undefined) {
      const legacyEnrollment = this.#activeLegacyPairingSession();
      if (
        legacyEnrollment === undefined ||
        legacyEnrollment.id !== handshake.legacyEnrollmentId ||
        legacyEnrollment.browserFamily !== identity.browser_family
      ) {
        this.#unauthenticatedAudit.record("legacy_pairing_window_rejected");
        socket.close(1008, SAFE_CLOSE_REASON);
        return undefined;
      }
      this.#clearLegacyPairingSession(legacyEnrollment);
    }

    let pinned: StoredExtensionKey;
    try {
      pinned = await this.#keyRegistry.pin(identity.installation_id, message.public_key, handshake.authMode);
    } catch {
      if (setupSession !== undefined) setupSession.commitInProgress = false;
      this.#unauthenticatedAudit.record("extension_key_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return undefined;
    }
    if (setupSession !== undefined && pinned.authMode !== "derived-v1") {
      setupSession.commitInProgress = false;
      this.#unauthenticatedAudit.record("extension_setup_commit_rejected");
      socket.close(1008, SAFE_CLOSE_REASON);
      return undefined;
    }
    const session: BrowserSession = {
      browserId: pinned.browserId,
      identity,
      origin,
      publicKey: pinned.publicKey,
      keyObject: handshake.keyObject,
      socket,
      connectedAt: new Date().toISOString()
    };
    const previous = this.#browserSessions.get(session.browserId);
    if (previous !== undefined && previous.socket !== socket) {
      this.#failCommandsForBrowser(
        previous.browserId,
        "The browser reconnected before the operation completed.",
        "extension_session_replaced"
      );
      this.#clearApprovalsForBrowser(previous.browserId, "cancelled");
    }
    this.#browserSessions.set(session.browserId, session);
    this.#browserIdByInstallation.set(identity.installation_id, session.browserId);
    socket.send(JSON.stringify({
      type: "hello_ack",
      protocol_version: PROTOCOL_VERSION,
      browser_id: session.browserId
    }));
    if (setupSession !== undefined) {
      if (setupSession.completedAtIso === undefined) {
        setupSession.completedAtIso = new Date().toISOString();
        setupSession.setupSecret = "";
        this.#audit.record({ event: "connection", outcome: "setup_pairing_committed" });
      }
      delete setupSession.commitInProgress;
    }
    if (previous !== undefined && previous.socket !== socket) {
      this.#audit.record({ event: "connection", outcome: "extension_session_replaced" });
      previous.socket.close(1000, "replaced by authenticated reconnect");
    }
    this.#audit.record({ event: "connection", outcome: "extension_authenticated" });
    return session;
  }

  async #handleAuthenticatedExtensionMessage(session: BrowserSession, message: JsonObject): Promise<void> {
    if (session.setupProvisioning === true) {
      session.socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }
    if (message.type === "pong") {
      if (
        typeof message.timestamp !== "number" ||
        !Number.isSafeInteger(message.timestamp) ||
        session.awaitingPongTimestamp !== message.timestamp
      ) {
        session.socket.close(1008, SAFE_CLOSE_REASON);
        return;
      }
      delete session.awaitingPongTimestamp;
      return;
    }
    if (message.type === "approval_decision") {
      await this.#handleApprovalDecision(session, message);
      return;
    }
    const result = parseExtensionResult(message);
    if (result === undefined) {
      session.socket.close(1007, "invalid extension message");
      return;
    }
    this.#handleExtensionResult(session, result);
  }

  #disconnectBrowser(session: BrowserSession, code: string): void {
    if (this.#browserSessions.get(session.browserId)?.socket !== session.socket) return;
    this.#browserSessions.delete(session.browserId);
    this.#browserIdByInstallation.delete(session.identity.installation_id);
    this.#failCommandsForBrowser(
      session.browserId,
      "The target browser extension disconnected before the operation completed.",
      code
    );
    this.#clearApprovalsForBrowser(session.browserId, "cancelled");
    this.#audit.record({ event: "connection", outcome: code });
  }

  #handleIpcClient(socket: Socket): void {
    const timer = setTimeout(() => {
      this.#unauthenticatedAudit.record("ipc_handshake_timeout");
      socket.destroy();
    }, this.#config.helloTimeoutMs);
    timer.unref();
    const state: IpcClientState = {
      buffer: Buffer.alloc(0),
      phase: "await_client_hello",
      timer
    };
    this.#ipcClients.set(socket, state);
    socket.setNoDelay(true);
    socket.on("data", (chunk: Buffer) => this.#handleIpcData(socket, chunk));
    socket.once("close", () => {
      clearTimeout(state.timer);
      this.#ipcClients.delete(socket);
      for (const [commandId, pending] of this.#pendingCommands) {
        if (pending.client !== socket) continue;
        clearTimeout(pending.timer);
        this.#pendingCommands.delete(commandId);
        if (pending.approvedGrantId !== undefined) {
          const session = this.#browserSessions.get(pending.browserId);
          if (session !== undefined) {
            this.#cancelApprovedDelivery(
              session,
              pending.approvedGrantId,
              pending.action,
              "approved_delivery_client_disconnected"
            );
          }
        }
        this.#audit.record({
          event: "command",
          action: pending.action,
          outcome: "client_disconnected",
          duration_ms: Date.now() - pending.startedAt
        });
      }
    });
    socket.once("error", () => undefined);
  }

  #handleIpcData(socket: Socket, chunk: Buffer): void {
    const state = this.#ipcClients.get(socket);
    if (state === undefined) return;
    if (state.phase === "accepted") {
      this.#rejectIpc(socket, "ipc_extra_data_rejected");
      return;
    }
    state.buffer = Buffer.concat([state.buffer, chunk]);
    const requestLimit = Math.min(
      this.#config.maxIpcMessageBytes,
      this.#config.maxCommandPayloadBytes + IPC_ENVELOPE_OVERHEAD_BYTES
    );
    const inboundLimit = state.phase === "await_client_hello" ? MAX_IPC_HELLO_BYTES : requestLimit;
    if (state.buffer.byteLength > inboundLimit && state.buffer.indexOf(0x0a) < 0) {
      this.#rejectIpc(socket, "ipc_message_too_large");
      return;
    }
    const newlineIndex = state.buffer.indexOf(0x0a);
    if (newlineIndex < 0) return;
    const rawLine = state.buffer.subarray(0, newlineIndex);
    const trailing = state.buffer.subarray(newlineIndex + 1);
    state.buffer = Buffer.alloc(0);
    if (rawLine.byteLength > inboundLimit || trailing.byteLength !== 0) {
      this.#rejectIpc(socket, trailing.byteLength === 0 ? "ipc_message_too_large" : "ipc_pipelining_rejected");
      return;
    }
    const line = rawLine.toString("utf8").replace(/\r$/u, "");
    if (state.phase === "await_client_hello") {
      this.#acceptIpcClientHello(socket, state, line);
      return;
    }
    try {
      const request = parseIpcRequest(line, this.#config.maxCommandPayloadBytes);
      if (
        request.client_nonce !== state.clientNonce ||
        request.server_nonce !== state.serverNonce ||
        request.daemon_instance_id !== this.#daemonInstanceId ||
        state.serverProof === undefined
      ) {
        this.#rejectIpc(socket, "ipc_binding_rejected");
        return;
      }
      const expectedClientProof = hmacProof(this.#config.ipcToken, ipcClientProofPayload({
        clientNonce: request.client_nonce,
        serverNonce: request.server_nonce,
        daemonInstanceId: request.daemon_instance_id,
        serverProof: state.serverProof,
        requestId: request.id,
        method: request.method,
        paramsSha256: sha256(canonicalJson(request.params))
      }));
      if (!proofMatches(request.client_proof, expectedClientProof)) {
        this.#rejectIpc(socket, "ipc_client_proof_rejected");
        return;
      }
      state.phase = "accepted";
      clearTimeout(state.timer);
      this.#handleIpcRequest(socket, request);
    } catch {
      this.#rejectIpc(socket, "ipc_request_rejected");
    }
  }

  #acceptIpcClientHello(socket: Socket, state: IpcClientState, line: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line) as unknown;
    } catch {
      this.#rejectIpc(socket, "ipc_client_hello_rejected");
      return;
    }
    if (!isJsonObject(parsed)) {
      this.#rejectIpc(socket, "ipc_client_hello_rejected");
      return;
    }
    const allowedFields = new Set(["type", "protocol_version", "endpoint_role", "client_nonce"]);
    if (
      Object.keys(parsed).some((field) => !allowedFields.has(field)) ||
      parsed.type !== "ipc_client_hello" ||
      parsed.protocol_version !== PROTOCOL_VERSION ||
      parsed.endpoint_role !== "ipc" ||
      !isCanonicalNonce(parsed.client_nonce) ||
      !this.#replayNonces.claim("ipc", parsed.client_nonce)
    ) {
      this.#rejectIpc(socket, "ipc_client_hello_rejected");
      return;
    }

    const hello: IpcClientHello = {
      type: "ipc_client_hello",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "ipc",
      client_nonce: parsed.client_nonce
    };
    const serverNonce = randomBase64Url();
    const serverProof = hmacProof(this.#config.ipcToken, ipcServerProofPayload({
      clientNonce: hello.client_nonce,
      serverNonce,
      daemonInstanceId: this.#daemonInstanceId
    }));
    state.clientNonce = hello.client_nonce;
    state.serverNonce = serverNonce;
    state.serverProof = serverProof;
    state.phase = "await_request";
    const challenge: IpcServerChallenge = {
      type: "ipc_challenge",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "ipc",
      client_nonce: hello.client_nonce,
      server_nonce: serverNonce,
      daemon_instance_id: this.#daemonInstanceId,
      server_proof: serverProof
    };
    socket.write(`${JSON.stringify(challenge)}\n`);
  }

  #rejectIpc(socket: Socket, outcome: string): void {
    const state = this.#ipcClients.get(socket);
    if (state !== undefined) clearTimeout(state.timer);
    if (state?.phase === "accepted") {
      this.#audit.record({ event: "connection", outcome });
    } else {
      this.#unauthenticatedAudit.record(outcome);
    }
    socket.destroy();
  }

  #handleIpcRequest(socket: Socket, request: IpcRequest): void {
    if (request.method === "status") {
      const status = this.statusSnapshot();
      const result: BridgeStatus = {
        service: "browseweave",
        protocol_version: PROTOCOL_VERSION,
        websocket_listening: status.websocketListening,
        connected_browsers: status.connectedBrowsers,
        pending_commands: status.pendingCommands,
        pending_approvals: status.pendingApprovals,
        uptime_seconds: Math.round(status.uptimeSeconds * 1000) / 1000
      };
      this.#writeSuccess(socket, request.id, result);
      return;
    }
    if (request.method === "setup_pairing_begin") {
      this.#handleSetupPairingBegin(socket, request.id, request.params);
      return;
    }
    if (request.method === "setup_pairing_status") {
      this.#handleSetupPairingStatus(socket, request.id, request.params);
      return;
    }
    if (request.method === "setup_pairing_cancel") {
      this.#handleSetupPairingCancel(socket, request.id, request.params);
      return;
    }
    if (request.method === "legacy_pairing_begin") {
      this.#handleLegacyPairingBegin(socket, request.id, request.params);
      return;
    }
    if (!isBrowserAction(request.method)) {
      this.#writeFailure(socket, request.id, `Unsupported BrowseWeave method: ${request.method}`);
      return;
    }
    const hasUntrustedApprovalAuthority = Object.keys(request.params).some((field) =>
      field === "approved" ||
      field === "revalidate_only" ||
      field.startsWith("approval_") ||
      field.startsWith("user_") ||
      field.startsWith("confirm_")
    );
    if (hasUntrustedApprovalAuthority) {
      this.#writeFailure(socket, request.id, "Approval authority cannot be supplied through IPC parameters.");
      return;
    }

    const session = this.#resolveBrowserSession(request.params.browser_id);
    if (session instanceof Error) {
      this.#writeFailure(socket, request.id, session.message);
      return;
    }
    const actionParams = jsonObjectWithout(request.params, new Set(["browser_id"]));
    const approvedGrant = this.#findApprovalForParams(
      session.browserId,
      request.method,
      actionParams,
      "approved"
    );
    this.#routeCommand(
      socket,
      request.id,
      session,
      request.method,
      actionParams,
      false,
      undefined,
      approvedGrant !== undefined,
      approvedGrant?.approvalId
    );
  }

  #handleSetupPairingBegin(socket: Socket, requestId: string, params: JsonObject): void {
    const fields = new Set(["setup_id", "setup_secret", "expires_at", "browser_family"]);
    const expiry = canonicalFutureExpiry(params.expires_at);
    if (
      !hasExactFields(params, fields) ||
      typeof params.setup_id !== "string" ||
      !SETUP_ID_PATTERN.test(params.setup_id) ||
      typeof params.setup_secret !== "string" ||
      !SETUP_SECRET_PATTERN.test(params.setup_secret) ||
      expiry === undefined ||
      (params.browser_family !== "firefox" && params.browser_family !== "chromium")
    ) {
      this.#writeFailure(socket, requestId, "The local setup request is invalid or expired.");
      return;
    }
    let active = this.#activeSetupPairingSession();
    if (active?.completedAtIso !== undefined) {
      this.#clearSetupPairingSession(active);
      active = undefined;
    }
    if (active !== undefined) {
      if (
        active.setupId !== params.setup_id ||
        active.setupSecret !== params.setup_secret ||
        active.expiresAtIso !== expiry.expiresAtIso ||
        active.browserFamily !== params.browser_family
      ) {
        this.#writeFailure(socket, requestId, "A different local setup session is already active.");
        return;
      }
      this.#writeSuccess(socket, requestId, {
        setup_pairing_ready: true,
        setup_id: active.setupId,
        expires_at: active.expiresAtIso,
        browser_family: active.browserFamily
      });
      return;
    }

    const session: SetupPairingSession = {
      setupId: params.setup_id,
      setupSecret: params.setup_secret,
      expiresAt: expiry.expiresAt,
      expiresAtIso: expiry.expiresAtIso,
      browserFamily: params.browser_family,
      timer: setTimeout(() => {
        this.#clearSetupPairingSession(session);
      }, Math.max(1, expiry.expiresAt - Date.now()))
    };
    session.timer.unref();
    this.#setupPairingSession = session;
    this.#audit.record({ event: "connection", outcome: "setup_pairing_ready" });
    this.#writeSuccess(socket, requestId, {
      setup_pairing_ready: true,
      setup_id: session.setupId,
      expires_at: session.expiresAtIso,
      browser_family: session.browserFamily
    });
  }

  #handleSetupPairingCancel(socket: Socket, requestId: string, params: JsonObject): void {
    if (
      !hasExactFields(params, new Set(["setup_id"])) ||
      typeof params.setup_id !== "string" ||
      !SETUP_ID_PATTERN.test(params.setup_id)
    ) {
      this.#writeFailure(socket, requestId, "The local setup cancellation is invalid.");
      return;
    }
    const active = this.#activeSetupPairingSession();
    if (active?.setupId === params.setup_id) {
      if (active.commitInProgress === true) {
        this.#writeFailure(socket, requestId, "The authenticated setup commit is already in progress.");
        return;
      }
      this.#clearSetupPairingSession(active);
      this.#audit.record({ event: "connection", outcome: "setup_pairing_cancelled" });
    }
    this.#writeSuccess(socket, requestId, {
      setup_pairing_cancelled: true,
      setup_id: params.setup_id
    });
  }

  #handleSetupPairingStatus(socket: Socket, requestId: string, params: JsonObject): void {
    if (
      !hasExactFields(params, new Set(["setup_id"])) ||
      typeof params.setup_id !== "string" ||
      !SETUP_ID_PATTERN.test(params.setup_id)
    ) {
      this.#writeFailure(socket, requestId, "The local setup status request is invalid.");
      return;
    }
    const active = this.#activeSetupPairingSession();
    if (active?.setupId !== params.setup_id) {
      const missing: SetupPairingStatus = {
        setup_pairing_status: "not_found",
        setup_id: params.setup_id
      };
      this.#writeSuccess(socket, requestId, missing);
      return;
    }
    const enrollment = active.enrollment;
    if (enrollment === undefined) {
      const waiting: SetupPairingStatus = {
        setup_pairing_status: "waiting",
        setup_id: active.setupId,
        expires_at: active.expiresAtIso,
        browser_family: active.browserFamily
      };
      this.#writeSuccess(socket, requestId, waiting);
      return;
    }
    const receipt = {
      setup_id: active.setupId,
      expires_at: active.expiresAtIso,
      browser_id: enrollment.browserId,
      browser_family: enrollment.identity.browser_family,
      browser_name: enrollment.identity.browser_name,
      browser_version: enrollment.identity.browser_version,
      extension_version: enrollment.identity.extension_version
    } as const;
    if (active.completedAtIso === undefined) {
      const pending: SetupPairingStatus = { setup_pairing_status: "pending", ...receipt };
      this.#writeSuccess(socket, requestId, pending);
      return;
    }
    const completed: SetupPairingStatus = {
      setup_pairing_status: "completed",
      ...receipt,
      completed_at: active.completedAtIso
    };
    this.#writeSuccess(socket, requestId, completed);
  }

  #handleLegacyPairingBegin(socket: Socket, requestId: string, params: JsonObject): void {
    const expiry = canonicalFutureExpiry(params.expires_at);
    if (
      !hasExactFields(params, new Set(["expires_at", "browser_family"])) ||
      expiry === undefined ||
      (params.browser_family !== "firefox" && params.browser_family !== "chromium")
    ) {
      this.#writeFailure(socket, requestId, "The legacy pairing window is invalid or expired.");
      return;
    }
    const active = this.#activeLegacyPairingSession();
    if (active !== undefined) {
      if (active.expiresAtIso !== expiry.expiresAtIso || active.browserFamily !== params.browser_family) {
        this.#writeFailure(socket, requestId, "A different legacy pairing window is already active.");
        return;
      }
      this.#writeSuccess(socket, requestId, {
        legacy_pairing_ready: true,
        expires_at: active.expiresAtIso,
        browser_family: active.browserFamily
      });
      return;
    }

    const session: LegacyPairingSession = {
      id: randomUUID(),
      expiresAt: expiry.expiresAt,
      expiresAtIso: expiry.expiresAtIso,
      browserFamily: params.browser_family,
      timer: setTimeout(() => {
        this.#clearLegacyPairingSession(session);
      }, Math.max(1, expiry.expiresAt - Date.now()))
    };
    session.timer.unref();
    this.#legacyPairingSession = session;
    this.#audit.record({ event: "connection", outcome: "legacy_pairing_ready" });
    this.#writeSuccess(socket, requestId, {
      legacy_pairing_ready: true,
      expires_at: session.expiresAtIso,
      browser_family: session.browserFamily
    });
  }

  #activeSetupPairingSession(now = Date.now()): SetupPairingSession | undefined {
    const session = this.#setupPairingSession;
    if (session === undefined) return undefined;
    if (session.expiresAt > now) return session;
    this.#clearSetupPairingSession(session);
    return undefined;
  }

  #activeLegacyPairingSession(now = Date.now()): LegacyPairingSession | undefined {
    const session = this.#legacyPairingSession;
    if (session === undefined) return undefined;
    if (session.expiresAt > now) return session;
    this.#clearLegacyPairingSession(session);
    return undefined;
  }

  #clearSetupPairingSession(expected?: SetupPairingSession): void {
    const session = this.#setupPairingSession;
    if (session === undefined || (expected !== undefined && session !== expected)) return;
    clearTimeout(session.timer);
    session.setupSecret = "";
    for (const socket of this.#setupProvisioningSockets) socket.terminate();
    this.#setupProvisioningSockets.clear();
    this.#setupPairingSession = undefined;
  }

  #clearLegacyPairingSession(expected?: LegacyPairingSession): void {
    const session = this.#legacyPairingSession;
    if (session === undefined || (expected !== undefined && session !== expected)) return;
    clearTimeout(session.timer);
    this.#legacyPairingSession = undefined;
  }

  #resolveBrowserSession(browserId: JsonValue | undefined): BrowserSession | Error {
    if (browserId !== undefined) {
      if (typeof browserId !== "string" || browserId.length < 1 || browserId.length > 80) {
        return new Error("browser_id is invalid.");
      }
      return this.#browserSessions.get(browserId) ?? new Error("The requested browser is not connected.");
    }
    const sessions = [...this.#browserSessions.values()];
    if (sessions.length === 0) return new Error("No authenticated browser extension is connected.");
    if (sessions.length > 1) {
      return new Error("More than one browser is connected; provide browser_id from BrowseWeave status or tab results.");
    }
    return sessions[0] as BrowserSession;
  }

  #routeCommand(
    client: Socket,
    requestId: string,
    session: BrowserSession,
    action: BrowserAction,
    params: JsonObject,
    approved: boolean,
    approvalFingerprint?: string,
    revalidateOnly = false,
    revalidatingApprovalId?: string,
    approvedGrantId?: string
  ): void {
    if (session.socket.readyState !== WebSocket.OPEN) {
      if (approvedGrantId !== undefined) {
        this.#cancelApprovedDelivery(session, approvedGrantId, action, "approved_delivery_disconnected");
      }
      this.#writeFailure(client, requestId, "The requested browser extension is not connected.");
      return;
    }
    if (this.#pendingCommands.size >= this.#config.maxPendingCommands) {
      if (approvedGrantId !== undefined) {
        this.#cancelApprovedDelivery(session, approvedGrantId, action, "approved_delivery_capacity_rejected");
      }
      this.#writeFailure(client, requestId, "BrowseWeave reached its concurrent-command limit.");
      return;
    }

    const commandId = randomUUID();
    let command: ExtensionCommand;
    if (approved) {
      if (
        !isApprovalFingerprint(approvalFingerprint) ||
        typeof approvedGrantId !== "string" ||
        !/^[a-f0-9-]{36}$/u.test(approvedGrantId)
      ) {
        if (approvedGrantId !== undefined) {
          this.#cancelApprovedDelivery(session, approvedGrantId, action, "approved_delivery_invalid");
        }
        this.#writeFailure(client, requestId, "An approved command requires a valid live-target fingerprint.");
        return;
      }
      command = {
        type: "command",
        id: commandId,
        action,
        payload: params,
        revalidate_only: false,
        approved: true,
        approval_id: approvedGrantId,
        approval_fingerprint: approvalFingerprint
      };
    } else {
      command = {
        type: "command",
        id: commandId,
        action,
        payload: params,
        revalidate_only: revalidateOnly,
        approved: false
      };
    }
    const serialized = JSON.stringify(command);
    if (Buffer.byteLength(serialized, "utf8") > this.#config.maxCommandPayloadBytes) {
      if (approvedGrantId !== undefined) {
        this.#cancelApprovedDelivery(session, approvedGrantId, action, "approved_delivery_too_large");
      }
      this.#writeFailure(client, requestId, "The browser command exceeds the safe size limit.");
      return;
    }

    const startedAt = Date.now();
    const timer = setTimeout(() => {
      const pending = this.#pendingCommands.get(commandId);
      if (pending === undefined) return;
      this.#pendingCommands.delete(commandId);
      if (pending.approvedGrantId !== undefined) {
        this.#cancelApprovedDelivery(
          session,
          pending.approvedGrantId,
          pending.action,
          "approved_delivery_timeout"
        );
      }
      this.#writeFailure(
        pending.client,
        pending.requestId,
        `The browser extension did not respond within ${Math.round(this.#config.commandTimeoutMs / 1000)} seconds.`
      );
      this.#audit.record({
        event: "command",
        action: pending.action,
        outcome: "timeout",
        code: "command_timeout",
        duration_ms: Date.now() - pending.startedAt
      });
    }, this.#config.commandTimeoutMs);
    timer.unref();
    const pending: PendingCommand = {
      commandId,
      requestId,
      client,
      browserId: session.browserId,
      action,
      params,
      approved,
      revalidateOnly,
      startedAt,
      timer
    };
    if (revalidatingApprovalId !== undefined) pending.revalidatingApprovalId = revalidatingApprovalId;
    if (approvedGrantId !== undefined) pending.approvedGrantId = approvedGrantId;
    if (command.approved) pending.approvalFingerprint = command.approval_fingerprint;
    this.#pendingCommands.set(commandId, pending);
    const failSend = (): void => {
      const current = this.#pendingCommands.get(commandId);
      if (current === undefined) return;
      clearTimeout(current.timer);
      this.#pendingCommands.delete(commandId);
      if (current.approvedGrantId !== undefined) {
        this.#cancelApprovedDelivery(
          session,
          current.approvedGrantId,
          current.action,
          "approved_delivery_send_failed"
        );
      }
      this.#writeFailure(current.client, current.requestId, "The command could not be sent to the browser extension.");
      this.#audit.record({
        event: "command",
        action: current.action,
        outcome: "send_failed",
        code: "extension_send_failed",
        duration_ms: Date.now() - current.startedAt
      });
    };
    try {
      session.socket.send(serialized, (error) => {
        if (error) failSend();
      });
    } catch {
      failSend();
    }
  }

  #handleExtensionResult(session: BrowserSession, result: ExtensionResult): void {
    const pending = this.#pendingCommands.get(result.id);
    if (pending === undefined) return;
    if (pending.browserId !== session.browserId) {
      session.socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }
    clearTimeout(pending.timer);
    this.#pendingCommands.delete(result.id);
    const duration = Date.now() - pending.startedAt;
    if (pending.approvedGrantId !== undefined) {
      this.#sendApprovalResolved(session, pending.approvedGrantId, "consumed");
      this.#audit.record({ event: "approval", action: pending.action, outcome: "consumed" });
    }

    if (result.ok) {
      if (pending.revalidateOnly) {
        this.#cancelRevalidatedApproval(session, pending, "approval_recheck_executed");
        this.#writeFailure(
          pending.client,
          pending.requestId,
          "The extension returned an execution result during an approval-only recheck. The action was not authorized."
        );
        this.#audit.record({
          event: "command",
          action: pending.action,
          outcome: "failed",
          code: "approval_recheck_executed",
          duration_ms: duration
        });
        return;
      }
      const safeResult = pending.action === "credential_fill"
        ? { credential_fill_completed: true }
        : result.result;
      this.#writeSuccess(pending.client, pending.requestId, withBrowserId(safeResult, session.browserId));
      this.#audit.record({ event: "command", action: pending.action, outcome: "success", duration_ms: duration });
      return;
    }
    if (pending.action === "credential_fill" && result.error.code === "approval_required") {
      this.#writeFailure(
        pending.client,
        pending.requestId,
        "The one-time credential operation cannot enter the normal approval channel. Use an extension-owned remote-login permission."
      );
      this.#audit.record({
        event: "command",
        action: pending.action,
        outcome: "failed",
        code: "credential_approval_channel_rejected",
        duration_ms: duration
      });
      return;
    }
    if (result.error.code !== "approval_required") {
      if (pending.revalidateOnly) this.#cancelRevalidatedApproval(session, pending, "approval_context_changed");
      this.#writeFailure(pending.client, pending.requestId, safeExtensionError(result.error, pending.action));
      this.#audit.record({
        event: "command",
        action: pending.action,
        outcome: "failed",
        code: "extension_error",
        duration_ms: duration
      });
      return;
    }

    const fingerprint = result.error.approval_fingerprint;
    if (!isApprovalFingerprint(fingerprint)) {
      this.#writeFailure(pending.client, pending.requestId, "The extension did not produce a valid approval fingerprint.");
      this.#audit.record({
        event: "command",
        action: pending.action,
        outcome: "failed",
        code: "invalid_approval_context",
        duration_ms: duration
      });
      return;
    }
    if (pending.approved && pending.approvalFingerprint === fingerprint) {
      this.#writeFailure(pending.client, pending.requestId, "The extension did not honor the consumed one-time approval.");
      this.#audit.record({
        event: "command",
        action: pending.action,
        outcome: "failed",
        code: "approval_not_honored",
        duration_ms: duration
      });
      return;
    }

    if (!pending.approved) {
      const grant = pending.revalidateOnly && pending.revalidatingApprovalId !== undefined
        ? this.#pendingApprovals.get(pending.revalidatingApprovalId)
        : this.#findApproval(session.browserId, pending.action, pending.params, fingerprint, "approved");
      if (grant !== undefined) {
        const exactGrant = grant.expiresAt > Date.now() &&
          grant.state === "approved" &&
          grant.browserId === session.browserId &&
          grant.action === pending.action &&
          grant.canonicalParams === canonicalJson(pending.params) &&
          grant.approvalFingerprint === fingerprint;
        if (exactGrant) {
          const consumedGrant = this.#takeApproval(grant.approvalId);
          if (consumedGrant === undefined) {
            this.#writeFailure(pending.client, pending.requestId, "The one-time approval is no longer available.");
            return;
          }
          this.#routeCommand(
            pending.client,
            pending.requestId,
            session,
            pending.action,
            pending.params,
            true,
            fingerprint,
            false,
            undefined,
            consumedGrant.approvalId
          );
          return;
        }
        if (pending.revalidateOnly) {
          this.#cancelRevalidatedApproval(session, pending, "approval_context_changed");
        }
      }
      const existing = this.#findApproval(session.browserId, pending.action, pending.params, fingerprint, "pending");
      if (existing !== undefined) {
        this.#writeApprovalRequired(pending.client, pending.requestId, existing);
        return;
      }
    }
    this.#createApproval(session, pending, result.error, fingerprint);
  }

  #findApproval(
    browserId: string,
    action: BrowserAction,
    params: JsonObject,
    fingerprint: string,
    state: ApprovalState
  ): PendingApproval | undefined {
    const canonicalParams = canonicalJson(params);
    for (const approval of this.#pendingApprovals.values()) {
      if (approval.expiresAt <= Date.now()) {
        this.#expireApproval(approval.approvalId);
        continue;
      }
      if (
        approval.state === state &&
        approval.browserId === browserId &&
        approval.action === action &&
        approval.canonicalParams === canonicalParams &&
        approval.approvalFingerprint === fingerprint
      ) return approval;
    }
    return undefined;
  }

  #findApprovalForParams(
    browserId: string,
    action: BrowserAction,
    params: JsonObject,
    state: ApprovalState
  ): PendingApproval | undefined {
    const canonicalParams = canonicalJson(params);
    for (const approval of this.#pendingApprovals.values()) {
      if (approval.expiresAt <= Date.now()) {
        this.#expireApproval(approval.approvalId);
        continue;
      }
      if (
        approval.state === state &&
        approval.browserId === browserId &&
        approval.action === action &&
        approval.canonicalParams === canonicalParams
      ) return approval;
    }
    return undefined;
  }

  #cancelRevalidatedApproval(
    session: BrowserSession,
    pending: PendingCommand,
    outcome: string
  ): void {
    if (pending.revalidatingApprovalId === undefined) return;
    const approval = this.#takeApproval(pending.revalidatingApprovalId);
    if (approval === undefined) return;
    this.#sendApprovalResolved(session, approval.approvalId, "cancelled");
    this.#audit.record({ event: "approval", action: approval.action, outcome });
  }

  #cancelApprovedDelivery(
    session: BrowserSession,
    approvalId: string,
    action: BrowserAction,
    outcome: string
  ): void {
    this.#sendApprovalResolved(session, approvalId, "cancelled");
    this.#audit.record({ event: "approval", action, outcome });
  }

  #createApproval(
    session: BrowserSession,
    pending: PendingCommand,
    error: ExtensionError,
    fingerprint: string
  ): void {
    if (this.#pendingApprovals.size >= this.#config.maxPendingApprovals) {
      this.#writeFailure(pending.client, pending.requestId, "BrowseWeave reached its pending-approval limit.");
      return;
    }
    if (
      typeof error.target_tab_id !== "number" || !Number.isSafeInteger(error.target_tab_id) || error.target_tab_id <= 0 ||
      typeof error.target_frame_id !== "number" || !Number.isSafeInteger(error.target_frame_id) || error.target_frame_id < 0
    ) {
      this.#writeFailure(
        pending.client,
        pending.requestId,
        "The extension did not bind the approval to an exact live browser tab and frame."
      );
      this.#audit.record({
        event: "command",
        action: pending.action,
        outcome: "failed",
        code: "invalid_approval_target"
      });
      return;
    }
    const approvalId = randomUUID();
    const expiresAt = Date.now() + this.#config.approvalTtlMs;
    const expiresAtIso = new Date(expiresAt).toISOString();
    const canonicalParams = canonicalJson(pending.params);
    const approval: PendingApproval = {
      approvalId,
      approvalNonce: randomBase64Url(),
      browserId: session.browserId,
      targetTabId: error.target_tab_id,
      targetFrameId: error.target_frame_id,
      action: pending.action,
      params: pending.params,
      canonicalParams,
      paramsSha256: sha256(canonicalParams),
      approvalFingerprint: fingerprint,
      risk: error.category?.slice(0, 100) || "sensitive_action",
      description: approvalDescription(error),
      expiresAt,
      expiresAtIso,
      state: "pending",
      timer: setTimeout(() => this.#expireApproval(approvalId), this.#config.approvalTtlMs)
    };
    approval.timer.unref();
    this.#pendingApprovals.set(approvalId, approval);

    const request: ExtensionApprovalRequest = {
      type: "approval_request",
      approval_id: approvalId,
      approval_nonce: approval.approvalNonce,
      browser_id: session.browserId,
      target_tab_id: approval.targetTabId,
      target_frame_id: approval.targetFrameId,
      action: approval.action,
      risk: approval.risk,
      description: approval.description,
      params_sha256: approval.paramsSha256,
      approval_fingerprint: approval.approvalFingerprint,
      expires_at: approval.expiresAtIso
    };
    try {
      session.socket.send(JSON.stringify(request));
    } catch {
      this.#takeApproval(approvalId);
      this.#writeFailure(pending.client, pending.requestId, "The approval request could not be sent to the browser extension.");
      return;
    }
    this.#writeApprovalRequired(pending.client, pending.requestId, approval);
    this.#audit.record({ event: "command", action: pending.action, outcome: "approval_required", code: "approval_required" });
  }

  #writeApprovalRequired(client: Socket, requestId: string, approval: PendingApproval): void {
    const result: ApprovalRequiredResult = {
      approval_required: true,
      approval_id: approval.approvalId,
      approval_ui: "browser_extension",
      browser_id: approval.browserId,
      target_tab_id: approval.targetTabId,
      target_frame_id: approval.targetFrameId,
      risk: approval.risk,
      description: approval.description,
      action: approval.action,
      expires_at: approval.expiresAtIso,
      message: "Approve or reject this operation in the target browser extension, then retry the same action."
    };
    this.#writeSuccess(client, requestId, result);
  }

  async #handleApprovalDecision(session: BrowserSession, message: JsonObject): Promise<void> {
    if (
      typeof message.approval_id !== "string" ||
      (message.decision !== "approve" && message.decision !== "reject") ||
      typeof message.signature !== "string"
    ) {
      session.socket.close(1007, "invalid approval decision");
      return;
    }
    const approval = this.#pendingApprovals.get(message.approval_id);
    if (approval === undefined || approval.browserId !== session.browserId) {
      this.#audit.record({ event: "approval", outcome: "decision_replayed_or_unknown" });
      return;
    }
    if (approval.expiresAt <= Date.now()) {
      this.#expireApproval(approval.approvalId);
      return;
    }
    if (approval.state !== "pending") {
      this.#audit.record({ event: "approval", action: approval.action, outcome: "decision_replayed" });
      return;
    }

    const decision = message.decision as ApprovalDecision;
    const payload = approvalDecisionSigningPayload({
      daemonInstanceId: this.#daemonInstanceId,
      approvalId: approval.approvalId,
      approvalNonce: approval.approvalNonce,
      browserId: approval.browserId,
      targetTabId: approval.targetTabId,
      targetFrameId: approval.targetFrameId,
      decision,
      action: approval.action,
      paramsSha256: approval.paramsSha256,
      approvalFingerprint: approval.approvalFingerprint,
      expiresAt: approval.expiresAtIso
    });
    if (!verifyP256(session.keyObject, payload, message.signature)) {
      this.#audit.record({ event: "approval", action: approval.action, outcome: "signature_rejected" });
      session.socket.close(1008, SAFE_CLOSE_REASON);
      return;
    }

    if (decision === "reject") {
      this.#takeApproval(approval.approvalId);
      this.#sendApprovalResolved(session, approval.approvalId, "rejected");
      this.#audit.record({ event: "approval", action: approval.action, outcome: "rejected" });
      return;
    }
    approval.state = "approved";
    this.#sendApprovalResolved(session, approval.approvalId, "approved");
    this.#audit.record({ event: "approval", action: approval.action, outcome: "approved" });
  }

  #sendApprovalResolved(
    session: BrowserSession,
    approvalId: string,
    outcome: "approved" | "rejected" | "consumed" | "cancelled" | "expired"
  ): void {
    if (session.socket.readyState !== WebSocket.OPEN) return;
    try {
      session.socket.send(JSON.stringify({ type: "approval_resolved", approval_id: approvalId, outcome }));
    } catch {
      // Resolution messages are advisory; the daemon remains authoritative.
    }
  }

  #expireApproval(approvalId: string): void {
    const approval = this.#takeApproval(approvalId);
    if (approval === undefined) return;
    const session = this.#browserSessions.get(approval.browserId);
    if (session !== undefined) this.#sendApprovalResolved(session, approvalId, "expired");
    this.#audit.record({ event: "approval", action: approval.action, outcome: "expired" });
  }

  #takeApproval(approvalId: string): PendingApproval | undefined {
    const approval = this.#pendingApprovals.get(approvalId);
    if (approval === undefined) return undefined;
    clearTimeout(approval.timer);
    this.#pendingApprovals.delete(approvalId);
    return approval;
  }

  #clearApprovalsForBrowser(
    browserId: string,
    outcome: "cancelled" | "expired"
  ): void {
    for (const approval of [...this.#pendingApprovals.values()]) {
      if (approval.browserId !== browserId) continue;
      this.#takeApproval(approval.approvalId);
      this.#audit.record({ event: "approval", action: approval.action, outcome });
    }
  }

  #clearAllApprovals(outcome: "cancelled" | "expired"): void {
    for (const approval of [...this.#pendingApprovals.values()]) {
      this.#takeApproval(approval.approvalId);
      this.#audit.record({ event: "approval", action: approval.action, outcome });
    }
  }

  #failCommandsForBrowser(browserId: string, message: string, code: string): void {
    for (const [commandId, pending] of this.#pendingCommands) {
      if (pending.browserId !== browserId) continue;
      clearTimeout(pending.timer);
      this.#pendingCommands.delete(commandId);
      this.#writeFailure(pending.client, pending.requestId, message);
      this.#audit.record({
        event: "command",
        action: pending.action,
        outcome: "failed",
        code,
        duration_ms: Date.now() - pending.startedAt
      });
    }
  }

  #failAllCommands(message: string, code: string): void {
    for (const pending of this.#pendingCommands.values()) {
      clearTimeout(pending.timer);
      this.#writeFailure(pending.client, pending.requestId, message);
      this.#audit.record({
        event: "command",
        action: pending.action,
        outcome: "failed",
        code,
        duration_ms: Date.now() - pending.startedAt
      });
    }
    this.#pendingCommands.clear();
  }

  #writeSuccess(socket: Socket, id: string, result: JsonValue): void {
    this.#writeResponse(socket, { id, ok: true, result });
  }

  #writeFailure(socket: Socket, id: string, error: string): void {
    this.#writeResponse(socket, { id, ok: false, error });
  }

  #writeResponse(socket: Socket, response: IpcResponse): void {
    if (socket.destroyed || !socket.writable) return;
    let line = JSON.stringify(response);
    if (Buffer.byteLength(line, "utf8") > this.#config.maxIpcMessageBytes) {
      line = JSON.stringify({
        id: response.id,
        ok: false,
        error: `The BrowseWeave response exceeds the safe size limit (${this.#config.maxIpcMessageBytes} bytes).`
      } satisfies IpcResponse);
    }
    socket.end(`${line}\n`);
  }
}

export async function createDaemon(config?: DaemonConfig): Promise<BrowseWeaveDaemon> {
  return new BrowseWeaveDaemon(config ?? (await loadDaemonConfig()));
}

export async function main(): Promise<void> {
  const daemon = await createDaemon();
  const addresses = await daemon.start();
  console.error(
    `BrowseWeave is ready: ws://${addresses.websocketHost}:${addresses.websocketPort}, ` +
    `tcp://${addresses.ipcHost}:${addresses.ipcPort}`
  );
  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    await daemon.stop(signal);
  };
  process.once("SIGINT", () => void shutdown("SIGINT"));
  process.once("SIGTERM", () => void shutdown("SIGTERM"));
  if (process.platform === "win32") process.once("SIGBREAK", () => void shutdown("SIGBREAK"));
}
