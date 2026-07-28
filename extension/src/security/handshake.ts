import {
  BASE64URL_PATTERN,
  PROTOCOL_VERSION,
  SETUP_ID_PATTERN,
  extensionClientProofPayload,
  extensionServerProofPayload,
  helloSigningPayload,
  type BrowserIdentity,
  type ExtensionClientHello,
  type ExtensionHello,
  type P256PublicJwk,
  type SetupAuthenticationPhase
} from "../../../src/core/protocol";

const NONCE_BYTES = 32;
const HMAC_SHA256_BASE64URL_LENGTH = 43;
const P256_SIGNATURE_MIN_LENGTH = 80;
const P256_SIGNATURE_MAX_LENGTH = 128;

type HandshakePhase =
  | "idle"
  | "awaiting_challenge"
  | "verifying_challenge"
  | "challenge_verified"
  | "awaiting_ack"
  | "authenticated"
  | "failed";

interface HandshakeContext {
  origin: string;
  identity: BrowserIdentity;
  publicKey: P256PublicJwk;
  stagedSetupId?: string;
  stagedSetupPhase?: SetupAuthenticationPhase;
}

interface VerifiedChallenge {
  serverNonce: string;
  daemonInstanceId: string;
  serverProof: string;
  clientProof: string;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return globalThis.btoa(binary).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/gu, "");
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
  if (!BASE64URL_PATTERN.test(value)) throw new Error("The proof is not valid base64url data.");
  const standard = value.replace(/-/gu, "+").replace(/_/gu, "/");
  const padded = standard.padEnd(Math.ceil(standard.length / 4) * 4, "=");
  const binary = globalThis.atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function isNonce(value: unknown): value is string {
  return typeof value === "string" && value.length === HMAC_SHA256_BASE64URL_LENGTH && BASE64URL_PATTERN.test(value);
}

function isDaemonInstanceId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,256}$/u.test(value);
}

async function importHmacKey(pairingSecret: string): Promise<CryptoKey> {
  if (pairingSecret.length < 16) throw new Error("The pairing key is missing or too short.");
  return globalThis.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pairingSecret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

export function freshClientNonce(): string {
  return bytesToBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES)));
}

/** HMAC uses the UTF-8 bytes of the stored pairing-key string, never decoded hex/base64 bytes. */
export async function hmacSha256Base64Url(pairingSecret: string, payload: string): Promise<string> {
  const key = await importHmacKey(pairingSecret);
  const proof = await globalThis.crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return bytesToBase64Url(new Uint8Array(proof));
}

async function verifyHmacSha256Base64Url(
  key: CryptoKey,
  payload: string,
  proof: unknown
): Promise<boolean> {
  if (typeof proof !== "string" || proof.length !== HMAC_SHA256_BASE64URL_LENGTH || !BASE64URL_PATTERN.test(proof)) {
    return false;
  }
  let proofBytes: Uint8Array<ArrayBuffer>;
  try {
    proofBytes = base64UrlToBytes(proof);
  } catch {
    return false;
  }
  if (proofBytes.byteLength !== 32) return false;
  return globalThis.crypto.subtle.verify("HMAC", key, proofBytes, new TextEncoder().encode(payload));
}

/**
 * Stateful mutual-auth transcript. Phase transitions reject duplicate,
 * reordered, and replayed challenges before any browser command is accepted.
 */
export class ExtensionHandshake {
  readonly clientNonce: string;
  readonly origin: string;
  readonly identity: BrowserIdentity;
  readonly publicKey: P256PublicJwk;
  readonly stagedSetupId?: string;
  readonly stagedSetupPhase?: SetupAuthenticationPhase;
  #phase: HandshakePhase = "idle";
  #verified?: VerifiedChallenge;

  constructor(context: HandshakeContext, clientNonce = freshClientNonce()) {
    if (!isNonce(clientNonce)) throw new Error("The extension client nonce is invalid.");
    if (context.stagedSetupId !== undefined && !SETUP_ID_PATTERN.test(context.stagedSetupId)) {
      throw new Error("The staged local setup ID is invalid.");
    }
    if ((context.stagedSetupId === undefined) !== (context.stagedSetupPhase === undefined)) {
      throw new Error("The staged local setup ID and phase must be supplied together.");
    }
    this.clientNonce = clientNonce;
    this.origin = context.origin;
    this.identity = { ...context.identity };
    this.publicKey = { ...context.publicKey, key_ops: ["verify"] };
    if (context.stagedSetupId !== undefined) this.stagedSetupId = context.stagedSetupId;
    if (context.stagedSetupPhase !== undefined) this.stagedSetupPhase = context.stagedSetupPhase;
  }

  get phase(): HandshakePhase {
    return this.#phase;
  }

  createClientHello(): ExtensionClientHello {
    if (this.#phase !== "idle") throw new Error("The extension client hello was already sent.");
    this.#phase = "awaiting_challenge";
    const hello: ExtensionClientHello = {
      type: "client_hello",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "extension",
      client_nonce: this.clientNonce,
      origin: this.origin,
      identity: this.identity,
      public_key: this.publicKey
    };
    if (this.stagedSetupId !== undefined && this.stagedSetupPhase !== undefined) {
      hello.authentication_mode = "derived-v1";
      hello.setup_id = this.stagedSetupId;
      hello.setup_phase = this.stagedSetupPhase;
    }
    return hello;
  }

  async verifyChallenge(message: unknown, pairingSecret: string): Promise<void> {
    if (this.#phase !== "awaiting_challenge") {
      this.#phase = "failed";
      throw new Error("A duplicate, replayed, or out-of-order daemon challenge was rejected.");
    }
    this.#phase = "verifying_challenge";
    try {
      if (!message || typeof message !== "object" || Array.isArray(message)) {
        throw new Error("The daemon challenge is invalid.");
      }
      const record = message as Record<string, unknown>;
      if (
        record.type !== "challenge" || record.protocol_version !== PROTOCOL_VERSION ||
        record.endpoint_role !== "extension" || record.client_nonce !== this.clientNonce ||
        !isNonce(record.server_nonce) || record.server_nonce === this.clientNonce ||
        !isDaemonInstanceId(record.daemon_instance_id) ||
        typeof record.server_proof !== "string" ||
        record.server_proof.length !== HMAC_SHA256_BASE64URL_LENGTH ||
        !BASE64URL_PATTERN.test(record.server_proof)
      ) {
        throw new Error("The daemon challenge transcript is invalid or does not match this connection.");
      }
      const key = await importHmacKey(pairingSecret);
      const serverPayload = extensionServerProofPayload({
        clientNonce: this.clientNonce,
        serverNonce: record.server_nonce,
        daemonInstanceId: record.daemon_instance_id,
        origin: this.origin,
        installationId: this.identity.installation_id,
        publicKey: this.publicKey,
        ...(this.stagedSetupId === undefined ? {} : {
          setupId: this.stagedSetupId,
          setupPhase: this.stagedSetupPhase
        })
      });
      if (!await verifyHmacSha256Base64Url(key, serverPayload, record.server_proof)) {
        throw new Error("The local service did not prove possession of the BrowseWeave pairing key.");
      }
      if (this.#phase !== "verifying_challenge") {
        throw new Error("The daemon challenge state changed during verification.");
      }
      const clientPayload = extensionClientProofPayload({
        clientNonce: this.clientNonce,
        serverNonce: record.server_nonce,
        daemonInstanceId: record.daemon_instance_id,
        origin: this.origin,
        installationId: this.identity.installation_id,
        publicKey: this.publicKey,
        serverProof: record.server_proof,
        ...(this.stagedSetupId === undefined ? {} : {
          setupId: this.stagedSetupId,
          setupPhase: this.stagedSetupPhase
        })
      });
      const clientProofBuffer = await globalThis.crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(clientPayload)
      );
      this.#verified = {
        serverNonce: record.server_nonce,
        daemonInstanceId: record.daemon_instance_id,
        serverProof: record.server_proof,
        clientProof: bytesToBase64Url(new Uint8Array(clientProofBuffer))
      };
      this.#phase = "challenge_verified";
    } catch (error) {
      this.#phase = "failed";
      throw error;
    }
  }

  helloSigningPayload(): string {
    if (this.#phase !== "challenge_verified" || !this.#verified) {
      throw new Error("A verified daemon challenge is required before signing the extension hello.");
    }
    return helloSigningPayload({
      clientNonce: this.clientNonce,
      serverNonce: this.#verified.serverNonce,
      daemonInstanceId: this.#verified.daemonInstanceId,
      origin: this.origin,
      installationId: this.identity.installation_id,
      publicKey: this.publicKey,
      clientProof: this.#verified.clientProof,
      ...(this.stagedSetupId === undefined ? {} : {
        setupId: this.stagedSetupId,
        setupPhase: this.stagedSetupPhase
      })
    });
  }

  createHello(signature: string): ExtensionHello {
    if (
      this.#phase !== "challenge_verified" || !this.#verified ||
      signature.length < P256_SIGNATURE_MIN_LENGTH || signature.length > P256_SIGNATURE_MAX_LENGTH ||
      !BASE64URL_PATTERN.test(signature)
    ) {
      this.#phase = "failed";
      throw new Error("The signed extension hello is invalid or out of order.");
    }
    this.#phase = "awaiting_ack";
    return {
      type: "hello",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "extension",
      client_nonce: this.clientNonce,
      server_nonce: this.#verified.serverNonce,
      origin: this.origin,
      daemon_instance_id: this.#verified.daemonInstanceId,
      identity: this.identity,
      public_key: this.publicKey,
      client_proof: this.#verified.clientProof,
      signature
    };
  }

  acceptHelloAck(message: unknown): string {
    if (this.#phase !== "awaiting_ack") {
      this.#phase = "failed";
      throw new Error("An out-of-order daemon acknowledgement was rejected.");
    }
    if (!message || typeof message !== "object" || Array.isArray(message)) {
      this.#phase = "failed";
      throw new Error("The daemon acknowledgement is invalid.");
    }
    const record = message as Record<string, unknown>;
    if (
      record.type !== "hello_ack" || record.protocol_version !== PROTOCOL_VERSION ||
      typeof record.browser_id !== "string" || !/^[A-Za-z0-9_-]{1,256}$/u.test(record.browser_id)
    ) {
      this.#phase = "failed";
      throw new Error("The daemon acknowledgement does not match the BrowseWeave protocol.");
    }
    this.#phase = "authenticated";
    return record.browser_id;
  }

  daemonInstanceId(): string {
    if (!this.#verified) throw new Error("The daemon identity has not been verified.");
    return this.#verified.daemonInstanceId;
  }
}
