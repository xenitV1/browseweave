import {
  BASE64URL_PATTERN,
  PROTOCOL_VERSION,
  SETUP_ID_PATTERN,
  SETUP_VERSION,
  isInstallationId,
  isP256PublicJwk,
  setupPairingAadPayload,
  setupPairingClientProofPayload,
  setupPairingKeySalt,
  type BrowserIdentity,
  type P256PublicJwk,
  type SetupPairingRequest,
  type SetupPairingResponse
} from "../../../src/core/protocol";
import { RELEASE_VERSION_PATTERN } from "../../../src/core/version";

export const SETUP_PAIRING_TIMEOUT_MS = 15_000;
export const SETUP_ENCRYPTION_KEY_INFO = "BrowseWeave setup encryption key v1";
export const SETUP_ROOT_ID = "browseweave-setup";
export const SETUP_CONNECT_BUTTON_ID = "browseweave-connect";
export const SETUP_STATUS_ID = "browseweave-setup-status";
export const SETUP_CONNECT_BUTTON_TEXT = "Connect this browser";
export const SETUP_SUCCESS_TEXT = "BrowseWeave is connected. You can close this page.";
export const SETUP_ERROR_TEXT = "BrowseWeave could not connect. Return to the installer and try again.";
export const SETUP_CONNECTING_TEXT = "Connecting this browser to BrowseWeave...";
export const SETUP_TICKET_PATH = "setup-ticket.json";
export const SETUP_TICKET_MAX_TTL_MS = 5 * 60_000;

const SETUP_SECRET_PATTERN = /^[a-f0-9]{64}$/u;
const NONCE_LENGTH = 43;
const IV_LENGTH = 16;
const MIN_ENCRYPTED_TOKEN_LENGTH = 64;
const MAX_ENCRYPTED_TOKEN_LENGTH = 1_500;
const MIN_PAIRING_TOKEN_CHARS = 32;
const MAX_PAIRING_TOKEN_CHARS = 256;
const DAEMON_INSTANCE_ID_PATTERN = /^[A-Za-z0-9_-]{1,256}$/u;
const RESPONSE_FIELDS = new Set([
  "type",
  "protocol_version",
  "setup_version",
  "setup_id",
  "client_nonce",
  "server_nonce",
  "daemon_instance_id",
  "expires_at",
  "iv",
  "encrypted_pairing_token"
]);

export interface SetupPageAddress {
  setupId: string;
  origin: string;
  href: string;
}

export interface SetupDomContractInput {
  rootId: string;
  setupIdAttribute: string | null;
  buttonId: string;
  buttonText: string;
  statusId: string;
}

export interface SetupTicket {
  version: typeof SETUP_VERSION;
  setup_id: string;
  setup_secret: string;
  expires_at: string;
}

export interface SetupSenderInput {
  extensionId: string;
  senderId?: string;
  senderUrl?: string;
  frameId?: number;
  setupId: string;
}

export interface SetupAuthenticationState {
  expectedGeneration: number;
  currentGeneration: number;
  expectedInstallationId: string;
  currentInstallationId: string | undefined;
  authenticated: boolean;
  phase: string;
  socketOpen: boolean;
}

export interface SetupPairingTransportSocket {
  readyState: number;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  send(data: string): void;
  close(code?: number, reason?: string): void;
}

export interface SetupPairingTransportExchange {
  result: Promise<string>;
  cancel(): void;
}

interface SetupPairingTransportInput {
  createSocket(): SetupPairingTransportSocket;
  createRequest(): Promise<SetupPairingRequest>;
  acceptResponse(response: unknown): Promise<string>;
  cancelAuthentication(): void;
  cancelled(): boolean;
  openReadyState: number;
}

export type StoredTokenSnapshot = { present: false } | { present: true; value: unknown };

export function storedTokenSnapshotsEqual(left: StoredTokenSnapshot, right: StoredTokenSnapshot): boolean {
  return left.present === right.present && (!left.present || (right.present && left.value === right.value));
}

export function storedTokenSnapshotHasValue(snapshot: StoredTokenSnapshot, expectedValue: string): boolean {
  return snapshot.present && snapshot.value === expectedValue;
}

/**
 * Runs the one-response setup exchange without allowing a clean server close
 * to preempt authentication already in progress. Cancellation remains the
 * bound for a response whose cryptographic verification never settles.
 */
export function startSetupPairingTransport(
  input: SetupPairingTransportInput
): SetupPairingTransportExchange {
  let socket: SetupPairingTransportSocket | undefined;
  let settled = false;
  let responseState: "waiting" | "processing" = "waiting";
  let requestStarted = false;
  let cancel = (): void => undefined;
  const result = new Promise<string>((resolve, reject) => {
    const finish = (outcome: { token: string } | { error: Error }): void => {
      if (settled) return;
      settled = true;
      if ("error" in outcome) {
        try {
          input.cancelAuthentication();
        } catch {
          // Transport cleanup must still settle even if authentication cleanup fails.
        }
      }
      if (socket) {
        socket.onopen = null;
        socket.onmessage = null;
        socket.onerror = null;
        socket.onclose = null;
        try {
          socket.close(1000, "setup complete");
        } catch {
          // The short-lived setup socket may already be closed.
        }
      }
      if ("token" in outcome) resolve(outcome.token);
      else reject(outcome.error);
    };
    cancel = () => finish({ error: new Error("The local setup attempt timed out.") });

    try {
      socket = input.createSocket();
    } catch {
      finish({ error: new Error("The local setup service could not be reached.") });
      return;
    }

    socket.onopen = () => {
      if (requestStarted) {
        finish({ error: new Error("The local setup request could not be created.") });
        return;
      }
      requestStarted = true;
      void Promise.resolve().then(() => input.createRequest()).then((request) => {
        if (input.cancelled() || settled) return;
        if (socket?.readyState !== input.openReadyState) {
          finish({ error: new Error("The local setup connection closed.") });
          return;
        }
        socket.send(JSON.stringify(request));
      }).catch(() => {
        finish({ error: new Error("The local setup request could not be created.") });
      });
    };
    socket.onmessage = (event) => {
      if (
        input.cancelled() || settled || responseState !== "waiting" ||
        typeof event.data !== "string" || event.data.length > 8_192
      ) {
        finish({ error: new Error("The local setup response could not be authenticated.") });
        return;
      }
      responseState = "processing";
      let response: unknown;
      try {
        response = JSON.parse(event.data);
      } catch {
        finish({ error: new Error("The local setup response could not be authenticated.") });
        return;
      }
      void Promise.resolve().then(() => input.acceptResponse(response)).then((token) => {
        finish({ token });
      }).catch(() => {
        finish({ error: new Error("The local setup response could not be authenticated.") });
      });
    };
    socket.onerror = () => {
      if (responseState === "processing") return;
      finish({ error: new Error("The local setup service could not be reached.") });
    };
    socket.onclose = () => {
      if (responseState === "processing") return;
      finish({ error: new Error("The local setup connection closed.") });
    };
  });
  return { result, cancel: () => cancel() };
}

interface SetupPairingContext {
  setupId: string;
  setupSecret: string;
  origin: string;
  identity: BrowserIdentity;
  publicKey: P256PublicJwk;
}

type SetupPairingPhase = "idle" | "creating_request" | "awaiting_response" | "decrypting" | "complete" | "failed";

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

function base64UrlToBytes(value: string, expectedLength?: number): Uint8Array<ArrayBuffer> {
  if (!BASE64URL_PATTERN.test(value)) throw new Error("The local setup response is invalid.");
  const standard = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const padded = standard.padEnd(Math.ceil(standard.length / 4) * 4, "=");
  let binary: string;
  try {
    binary = globalThis.atob(padded);
  } catch {
    throw new Error("The local setup response is invalid.");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if (expectedLength !== undefined && bytes.byteLength !== expectedLength) {
    throw new Error("The local setup response is invalid.");
  }
  if (bytesToBase64Url(bytes) !== value) throw new Error("The local setup response is invalid.");
  return bytes;
}

function isNonce(value: unknown): value is string {
  if (typeof value !== "string" || value.length !== NONCE_LENGTH || !BASE64URL_PATTERN.test(value)) return false;
  try {
    base64UrlToBytes(value, 32);
    return true;
  } catch {
    return false;
  }
}

function isExactBrowserIdentity(value: BrowserIdentity): boolean {
  return Object.keys(value).length === 5 &&
    isInstallationId(value.installation_id) &&
    (value.browser_family === "firefox" || value.browser_family === "chromium") &&
    typeof value.browser_name === "string" && value.browser_name.length >= 1 && value.browser_name.length <= 80 &&
    typeof value.browser_version === "string" && value.browser_version.length >= 1 && value.browser_version.length <= 80 &&
    typeof value.extension_version === "string" && RELEASE_VERSION_PATTERN.test(value.extension_version);
}

function isExtensionOrigin(value: string): boolean {
  return /^(?:chrome|moz)-extension:\/\/[A-Za-z0-9@._-]{1,256}$/u.test(value);
}

function assertSetupContext(context: SetupPairingContext): void {
  if (
    !SETUP_ID_PATTERN.test(context.setupId) ||
    !SETUP_SECRET_PATTERN.test(context.setupSecret) ||
    !isExtensionOrigin(context.origin) ||
    !isExactBrowserIdentity(context.identity) ||
    !isP256PublicJwk(context.publicKey)
  ) throw new Error("The local setup data is invalid.");
}

async function importSetupIkm(setupSecret: string, usage: "hmac" | "hkdf"): Promise<CryptoKey> {
  if (!SETUP_SECRET_PATTERN.test(setupSecret)) throw new Error("The local setup data is invalid.");
  const bytes = new TextEncoder().encode(setupSecret);
  return globalThis.crypto.subtle.importKey(
    "raw",
    bytes,
    usage === "hmac" ? { name: "HMAC", hash: "SHA-256" } : "HKDF",
    false,
    usage === "hmac" ? ["sign"] : ["deriveKey"]
  );
}

async function createClientProof(setupSecret: string, payload: string): Promise<string> {
  const key = await importSetupIkm(setupSecret, "hmac");
  const proof = await globalThis.crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return bytesToBase64Url(new Uint8Array(proof));
}

async function deriveDecryptionKey(
  setupSecret: string,
  setupId: string,
  clientNonce: string,
  serverNonce: string
): Promise<CryptoKey> {
  const ikm = await importSetupIkm(setupSecret, "hkdf");
  return globalThis.crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(setupPairingKeySalt({ setupId, clientNonce, serverNonce })),
      info: new TextEncoder().encode(SETUP_ENCRYPTION_KEY_INFO)
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

function strictResponse(value: unknown, context: SetupPairingContext, clientNonce: string): SetupPairingResponse {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The local setup response is invalid.");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== RESPONSE_FIELDS.size || keys.some((key) => !RESPONSE_FIELDS.has(key))) {
    throw new Error("The local setup response is invalid.");
  }
  if (
    record.type !== "setup_pair_response" ||
    record.protocol_version !== PROTOCOL_VERSION ||
    record.setup_version !== SETUP_VERSION ||
    record.setup_id !== context.setupId ||
    record.client_nonce !== clientNonce ||
    !isNonce(record.server_nonce) ||
    record.server_nonce === clientNonce ||
    typeof record.daemon_instance_id !== "string" || !DAEMON_INSTANCE_ID_PATTERN.test(record.daemon_instance_id) ||
    typeof record.expires_at !== "string" ||
    typeof record.iv !== "string" || record.iv.length !== IV_LENGTH ||
    typeof record.encrypted_pairing_token !== "string" ||
    record.encrypted_pairing_token.length < MIN_ENCRYPTED_TOKEN_LENGTH ||
    record.encrypted_pairing_token.length > MAX_ENCRYPTED_TOKEN_LENGTH ||
    !BASE64URL_PATTERN.test(record.encrypted_pairing_token)
  ) throw new Error("The local setup response is invalid.");

  const expiresAt = Date.parse(record.expires_at);
  if (!Number.isFinite(expiresAt) || new Date(expiresAt).toISOString() !== record.expires_at || expiresAt <= Date.now()) {
    throw new Error("The local setup response is invalid or expired.");
  }
  base64UrlToBytes(record.iv, 12);
  const encrypted = base64UrlToBytes(record.encrypted_pairing_token);
  if (encrypted.byteLength < 48 || encrypted.byteLength > 1_040) {
    throw new Error("The local setup response is invalid.");
  }
  return record as unknown as SetupPairingResponse;
}

/** Parse only the explicit top-frame loopback setup URL accepted by the extension. */
export function parseSetupPageUrl(value: string, isTopFrame: boolean): SetupPageAddress | null {
  if (!isTopFrame || typeof value !== "string" || value.length > 2_048) return null;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (
    parsed.protocol !== "http:" || parsed.hostname !== "127.0.0.1" || !parsed.port ||
    parsed.username || parsed.password || parsed.search || parsed.hash
  ) return null;
  const port = Number(parsed.port);
  if (!Number.isInteger(port) || port < 1_024 || port > 65_535) return null;
  const match = /^\/setup\/([a-f0-9]{24})$/u.exec(parsed.pathname);
  if (!match?.[1] || !SETUP_ID_PATTERN.test(match[1]) || parsed.href !== value) return null;
  return { setupId: match[1], origin: parsed.origin, href: parsed.href };
}

export function setupDomContractMatches(input: SetupDomContractInput, expectedSetupId: string): boolean {
  return SETUP_ID_PATTERN.test(expectedSetupId) &&
    input.rootId === SETUP_ROOT_ID &&
    input.setupIdAttribute === expectedSetupId &&
    input.buttonId === SETUP_CONNECT_BUTTON_ID &&
    input.buttonText === SETUP_CONNECT_BUTTON_TEXT &&
    input.statusId === SETUP_STATUS_ID;
}

/**
 * The installer writes one deterministic, owner-only extension ticket. Exact
 * serialization rejects duplicate keys, comments, escapes, and trailing data.
 */
export function parseSetupTicketText(
  text: string,
  expectedSetupId: string,
  now = Date.now()
): SetupTicket {
  if (typeof text !== "string" || text.length > 512 || !SETUP_ID_PATTERN.test(expectedSetupId) || !Number.isFinite(now)) {
    throw new Error("The local setup ticket is invalid.");
  }
  const match = /^\{"version":1,"setup_id":"([a-f0-9]{24})","setup_secret":"([a-f0-9]{64})","expires_at":"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)"\}\n?$/u.exec(text);
  if (!match?.[1] || !match[2] || !match[3] || match[1] !== expectedSetupId) {
    throw new Error("The local setup ticket is invalid.");
  }
  const expiresAt = Date.parse(match[3]);
  if (
    !Number.isFinite(expiresAt) || new Date(expiresAt).toISOString() !== match[3] ||
    expiresAt <= now || expiresAt - now > SETUP_TICKET_MAX_TTL_MS
  ) throw new Error("The local setup ticket is invalid or expired.");
  return {
    version: SETUP_VERSION,
    setup_id: match[1],
    setup_secret: match[2],
    expires_at: match[3]
  };
}

export function trustedSetupClick(isTrusted: boolean, buttonId: string, buttonText: string): boolean {
  return isTrusted && buttonId === SETUP_CONNECT_BUTTON_ID && buttonText === SETUP_CONNECT_BUTTON_TEXT;
}

export function setupSenderMatches(input: SetupSenderInput): boolean {
  if (
    input.senderId !== input.extensionId || input.frameId !== 0 ||
    typeof input.senderUrl !== "string" || !SETUP_ID_PATTERN.test(input.setupId)
  ) return false;
  const page = parseSetupPageUrl(input.senderUrl, true);
  return page?.setupId === input.setupId;
}

export function setupAuthenticationMatches(input: SetupAuthenticationState): boolean {
  return Number.isInteger(input.expectedGeneration) &&
    input.currentGeneration === input.expectedGeneration &&
    isInstallationId(input.expectedInstallationId) &&
    input.currentInstallationId === input.expectedInstallationId &&
    input.authenticated === true && input.phase === "connected" && input.socketOpen === true;
}

/** Stateful one-use setup transcript. Duplicate and out-of-order operations permanently fail it. */
export class SetupPairingHandshake {
  readonly clientNonce: string;
  readonly setupId: string;
  readonly origin: string;
  readonly identity: BrowserIdentity;
  readonly publicKey: P256PublicJwk;
  #setupSecret: string;
  #phase: SetupPairingPhase = "idle";
  #deadline: number;

  constructor(
    context: SetupPairingContext,
    options: { clientNonce?: string; timeoutMs?: number; now?: number } = {}
  ) {
    assertSetupContext(context);
    const timeoutMs = options.timeoutMs ?? SETUP_PAIRING_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > SETUP_PAIRING_TIMEOUT_MS) {
      throw new Error("The local setup timeout is invalid.");
    }
    const now = options.now ?? Date.now();
    if (!Number.isFinite(now)) throw new Error("The local setup clock is invalid.");
    const nonce = options.clientNonce ?? bytesToBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    if (!isNonce(nonce)) throw new Error("The local setup data is invalid.");
    this.clientNonce = nonce;
    this.setupId = context.setupId;
    this.origin = context.origin;
    this.identity = { ...context.identity };
    this.publicKey = { ...context.publicKey, key_ops: ["verify"] };
    this.#setupSecret = context.setupSecret;
    this.#deadline = now + timeoutMs;
  }

  get phase(): SetupPairingPhase {
    return this.#phase;
  }

  cancel(): void {
    if (this.#phase === "complete" || this.#phase === "failed") return;
    this.#phase = "failed";
    this.#setupSecret = "";
  }

  #assertBeforeDeadline(): void {
    if (Date.now() >= this.#deadline) {
      this.#phase = "failed";
      this.#setupSecret = "";
      throw new Error("The local setup attempt expired.");
    }
  }

  async createRequest(): Promise<SetupPairingRequest> {
    if (this.#phase !== "idle") {
      this.#phase = "failed";
      this.#setupSecret = "";
      throw new Error("A duplicate or out-of-order local setup request was rejected.");
    }
    this.#assertBeforeDeadline();
    this.#phase = "creating_request";
    try {
      const clientProof = await createClientProof(
        this.#setupSecret,
        setupPairingClientProofPayload({
          setupId: this.setupId,
          clientNonce: this.clientNonce,
          origin: this.origin,
          installationId: this.identity.installation_id,
          publicKey: this.publicKey
        })
      );
      this.#assertBeforeDeadline();
      if (this.#phase !== "creating_request") throw new Error("The local setup state changed unexpectedly.");
      this.#phase = "awaiting_response";
      return {
        type: "setup_pair_request",
        protocol_version: PROTOCOL_VERSION,
        setup_version: SETUP_VERSION,
        setup_id: this.setupId,
        client_nonce: this.clientNonce,
        origin: this.origin,
        identity: this.identity,
        public_key: this.publicKey,
        client_proof: clientProof
      };
    } catch (error) {
      this.#phase = "failed";
      this.#setupSecret = "";
      throw error;
    }
  }

  async acceptResponse(value: unknown): Promise<string> {
    if (this.#phase !== "awaiting_response") {
      this.#phase = "failed";
      this.#setupSecret = "";
      throw new Error("A replayed or out-of-order local setup response was rejected.");
    }
    this.#assertBeforeDeadline();
    this.#phase = "decrypting";
    try {
      const response = strictResponse(value, {
        setupId: this.setupId,
        setupSecret: this.#setupSecret,
        origin: this.origin,
        identity: this.identity,
        publicKey: this.publicKey
      }, this.clientNonce);
      const key = await deriveDecryptionKey(
        this.#setupSecret,
        this.setupId,
        this.clientNonce,
        response.server_nonce
      );
      this.#assertBeforeDeadline();
      if (this.#phase !== "decrypting") throw new Error("The local setup state changed unexpectedly.");
      const aad = setupPairingAadPayload({
        setupId: this.setupId,
        clientNonce: this.clientNonce,
        serverNonce: response.server_nonce,
        daemonInstanceId: response.daemon_instance_id,
        origin: this.origin,
        identity: this.identity,
        publicKey: this.publicKey,
        expiresAt: response.expires_at
      });
      const plaintext = await globalThis.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: base64UrlToBytes(response.iv, 12),
          additionalData: new TextEncoder().encode(aad),
          tagLength: 128
        },
        key,
        base64UrlToBytes(response.encrypted_pairing_token)
      );
      this.#assertBeforeDeadline();
      if (this.#phase !== "decrypting") throw new Error("The local setup state changed unexpectedly.");
      const pairingToken = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
      if (
        pairingToken.length < MIN_PAIRING_TOKEN_CHARS || pairingToken.length > MAX_PAIRING_TOKEN_CHARS ||
        /[\0\r\n\u2028\u2029]/u.test(pairingToken)
      ) throw new Error("The local setup response contained invalid key material.");
      this.#phase = "complete";
      this.#setupSecret = "";
      return pairingToken;
    } catch {
      this.#phase = "failed";
      this.#setupSecret = "";
      throw new Error("BrowseWeave could not authenticate the local setup response.");
    }
  }
}
