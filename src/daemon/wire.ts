/**
 * Parsing and signature verification for the loopback wire formats. Every
 * function here validates untrusted bytes; none of them authorises anything.
 */
import { createPublicKey, verify as verifySignature, type KeyObject } from "node:crypto";
import type { RawData } from "ws";
import {
  BASE64URL_PATTERN,
  PROTOCOL_VERSION,
  isInstallationId,
  isJsonObject,
  isJsonValue,
  type BrowserIdentity,
  type ExtensionError,
  type ExtensionResult,
  type IpcRequest,
  type JsonObject,
  type P256PublicJwk
} from "../core/protocol.js";
import { hasExactFields, isCanonicalNonce, own } from "./crypto.js";

const MAX_REQUEST_ID_LENGTH = 128;
const MAX_METHOD_LENGTH = 64;

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

export function rawDataToBuffer(data: RawData): Buffer {
  if (Buffer.isBuffer(data)) return data;
  if (data instanceof ArrayBuffer) return Buffer.from(data);
  if (Array.isArray(data)) return Buffer.concat(data);
  throw new Error("Unsupported WebSocket data type.");
}

export function parseExtensionResult(value: JsonObject): ExtensionResult | undefined {
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

export function parseBrowserIdentity(value: unknown): BrowserIdentity | undefined {
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

export function decodeP1363Signature(value: unknown): Buffer | undefined {
  if (typeof value !== "string" || value.length !== 86 || !BASE64URL_PATTERN.test(value)) {
    return undefined;
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength !== 64 || decoded.toString("base64url") !== value) return undefined;
  return decoded;
}

export function publicKeyObject(jwk: P256PublicJwk): KeyObject {
  return createPublicKey({ key: jwk as JsonWebKey, format: "jwk" });
}

export function verifyP256(key: KeyObject, payload: string, signature: unknown): boolean {
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
