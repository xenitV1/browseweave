/**
 * Nonce, proof, and setup-encryption primitives shared by the daemon's
 * connection state machines. This module holds no connection state so the
 * other daemon files can depend on it without a cycle.
 */
import { createCipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import {
  PROTOCOL_VERSION,
  canonicalPublicJwk,
  isJsonObject,
  isP256PublicJwk,
  setupPairingAadPayload,
  setupPairingKeySalt,
  type BrowserFamily,
  type BrowserIdentity,
  type JsonObject,
  type JsonValue,
  type P256PublicJwk
} from "../core/protocol.js";

const BASE64URL_256_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const MAX_REPLAY_NONCES = 4_096;
const REPLAY_NONCE_TTL_MS = 10 * 60_000;
const SETUP_MAX_TTL_MS = 5 * 60_000;
const SETUP_ENCRYPTION_KEY_INFO = "BrowseWeave setup encryption key v1";
const SETUP_IV_BYTES = 12;
const SETUP_AUTH_TAG_BYTES = 16;

export function own(record: JsonObject, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

export function hasExactFields(record: JsonObject, fields: ReadonlySet<string>): boolean {
  const keys = Object.keys(record);
  return keys.length === fields.size && keys.every((key) => fields.has(key));
}

export function jsonObjectWithout(record: JsonObject, excluded: ReadonlySet<string>): JsonObject {
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

export function sha256(value: string): string {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

export function randomBase64Url(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function framedField(name: string, value: string): string {
  return `${name}:${Buffer.byteLength(value, "utf8")}:${value}\n`;
}

export function installationAuthenticationSecretPayload(
  installationId: string,
  publicKey: P256PublicJwk
): string {
  return "BrowseWeave installation authentication secret v1\n" +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("installation_id", installationId) +
    framedField("public_key", canonicalPublicJwk(publicKey));
}

export function deriveInstallationAuthenticationSecret(
  masterSecret: string,
  installationId: string,
  publicKey: P256PublicJwk
): string {
  return createHmac("sha256", Buffer.from(masterSecret, "utf8"))
    .update(installationAuthenticationSecretPayload(installationId, publicKey), "utf8")
    .digest("base64url");
}

export function isExactP256PublicJwk(value: unknown): value is P256PublicJwk {
  if (!isP256PublicJwk(value)) return false;
  return hasExactFields(value, new Set(["kty", "crv", "x", "y", "ext", "key_ops"]));
}

export function canonicalFutureExpiry(
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

export function encryptSetupPairingToken(input: {
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

export function browserIdForInstallation(installationId: string): string {
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

export function originMatchesBrowserFamily(origin: string, browserFamily: BrowserFamily): boolean {
  return browserFamily === "firefox"
    ? origin.startsWith("moz-extension://")
    : origin.startsWith("chrome-extension://");
}

export function isCanonicalNonce(value: unknown): value is string {
  if (typeof value !== "string" || !BASE64URL_256_PATTERN.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.byteLength === 32 && decoded.toString("base64url") === value;
}

export function hmacProof(secret: string, payload: string): string {
  return createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(payload, "utf8")
    .digest("base64url");
}

export function proofMatches(candidate: unknown, expected: string): candidate is string {
  if (!isCanonicalNonce(candidate) || !isCanonicalNonce(expected)) return false;
  const candidateBytes = Buffer.from(candidate, "base64url");
  const expectedBytes = Buffer.from(expected, "base64url");
  return timingSafeEqual(candidateBytes, expectedBytes);
}

export class ReplayNonceCache {
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

