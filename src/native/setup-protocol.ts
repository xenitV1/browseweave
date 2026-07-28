import { endianness } from "node:os";
import path from "node:path";
import { parseTree, type Node, type ParseError } from "jsonc-parser";
import { SETUP_ID_PATTERN } from "../core/protocol.js";

/** Fixed browser native-messaging host name installed by BrowseWeave. */
export const NATIVE_SETUP_HOST_NAME = "io.browseweave.setup" as const;
export const NATIVE_SETUP_PROTOCOL_VERSION = 1 as const;

/**
 * Native-messaging implementations allow much larger messages. This host has
 * only two tiny operations, so a deliberately small limit reduces parser and
 * allocation exposure without constraining the protocol.
 */
export const MAX_NATIVE_MESSAGE_PAYLOAD_BYTES = 4 * 1024;
export const MAX_NATIVE_SETUP_TTL_MS = 5 * 60_000;
export const NATIVE_SETUP_SECRET_PATTERN = /^[a-f0-9]{64}$/u;

export type NativeByteOrder = "LE" | "BE";
export type NativeBrowserFamily = "firefox" | "chromium";

export interface NativeBeginSetupRequest {
  version: typeof NATIVE_SETUP_PROTOCOL_VERSION;
  type: "begin_setup";
  browser_family: NativeBrowserFamily;
}

export interface NativeCancelSetupRequest {
  version: typeof NATIVE_SETUP_PROTOCOL_VERSION;
  type: "cancel_setup";
  setup_id: string;
}

export type NativeSetupRequest = NativeBeginSetupRequest | NativeCancelSetupRequest;

export interface NativeBeginSetupSuccess {
  version: typeof NATIVE_SETUP_PROTOCOL_VERSION;
  ok: true;
  setup_id: string;
  setup_secret: string;
  expires_at: string;
  browser_family: NativeBrowserFamily;
}

export interface NativeCancelSetupSuccess {
  version: typeof NATIVE_SETUP_PROTOCOL_VERSION;
  ok: true;
  setup_id: string;
  setup_pairing_cancelled: true;
}

export const NATIVE_SETUP_FAILURE_CODES = [
  "unauthorized_caller",
  "invalid_request",
  "service_unavailable",
  "operation_failed",
  "internal_error"
] as const;

export type NativeSetupFailureCode = (typeof NATIVE_SETUP_FAILURE_CODES)[number];

export interface NativeSetupFailure {
  version: typeof NATIVE_SETUP_PROTOCOL_VERSION;
  ok: false;
  error_code: NativeSetupFailureCode;
}

export type NativeSetupResponse =
  | NativeBeginSetupSuccess
  | NativeCancelSetupSuccess
  | NativeSetupFailure;

export interface ChromiumNativeCallerPolicy {
  browser_family: "chromium";
  /** Exact, root-only origins such as chrome-extension://<32-character-id>/. */
  allowed_origins: readonly string[];
}

export interface FirefoxNativeCallerPolicy {
  browser_family: "firefox";
  /** Exact native-host manifest path Firefox supplies as argv[0]. */
  manifest_path: string;
  /** Exact manifest extension IDs Firefox may supply as argv[1]. */
  allowed_extension_ids: readonly string[];
}

export type NativeCallerPolicy = ChromiumNativeCallerPolicy | FirefoxNativeCallerPolicy;

export type NativeMessagingProtocolErrorCode =
  | "invalid_frame"
  | "message_too_large"
  | "multiple_requests"
  | "invalid_request"
  | "invalid_response"
  | "unauthorized_caller"
  | "invalid_configuration";

const PROTOCOL_ERROR_MESSAGES: Readonly<Record<NativeMessagingProtocolErrorCode, string>> = {
  invalid_frame: "The native message frame is invalid.",
  message_too_large: "The native message exceeds the safe size limit.",
  multiple_requests: "The one-shot native host accepts exactly one request.",
  invalid_request: "The native setup request is invalid.",
  invalid_response: "The native setup response is invalid.",
  unauthorized_caller: "The browser extension caller is not authorized.",
  invalid_configuration: "The native caller policy is invalid."
};

/** An intentionally detail-free error: untrusted bytes and secrets are never interpolated. */
export class NativeMessagingProtocolError extends Error {
  readonly code: NativeMessagingProtocolErrorCode;

  constructor(code: NativeMessagingProtocolErrorCode) {
    super(PROTOCOL_ERROR_MESSAGES[code]);
    this.name = "NativeMessagingProtocolError";
    this.code = code;
  }
}

export interface NativeSetupOperations {
  beginSetup(browserFamily: NativeBrowserFamily): Promise<{
    setup_id: string;
    setup_secret: string;
    expires_at: string;
    browser_family: NativeBrowserFamily;
  }>;
  cancelSetup(setupId: string): Promise<{
    setup_id: string;
    setup_pairing_cancelled: true;
  }>;
}

export interface ProcessNativeSetupFrameInput {
  frame: Uint8Array;
  argv: readonly string[];
  caller_policy: NativeCallerPolicy;
  operations: NativeSetupOperations;
  /** Injectable only for deterministic validation tests. */
  now?: () => number;
  /** Defaults to the operating system's native byte order. */
  byte_order?: NativeByteOrder;
}

function fail(code: NativeMessagingProtocolErrorCode): never {
  throw new NativeMessagingProtocolError(code);
}

export function nativeByteOrder(): NativeByteOrder {
  return endianness();
}

function assertByteOrder(value: NativeByteOrder): void {
  if (value !== "LE" && value !== "BE") fail("invalid_configuration");
}

function readFrameLength(header: Buffer, byteOrder: NativeByteOrder): number {
  return byteOrder === "LE" ? header.readUInt32LE(0) : header.readUInt32BE(0);
}

function writeFrameLength(header: Buffer, length: number, byteOrder: NativeByteOrder): void {
  if (byteOrder === "LE") header.writeUInt32LE(length, 0);
  else header.writeUInt32BE(length, 0);
}

/**
 * Bounded, one-shot decoder for the 4-byte native-endian native-messaging
 * frame. A second frame or any trailing byte is rejected.
 */
export class SingleNativeMessageDecoder {
  readonly #byteOrder: NativeByteOrder;
  readonly #storage = Buffer.alloc(4 + MAX_NATIVE_MESSAGE_PAYLOAD_BYTES);
  #received = 0;
  #expectedTotal: number | undefined;
  #completePayload: Buffer | undefined;
  #failed = false;

  constructor(byteOrder: NativeByteOrder = nativeByteOrder()) {
    assertByteOrder(byteOrder);
    this.#byteOrder = byteOrder;
  }

  push(chunk: Uint8Array): Buffer | undefined {
    if (!(chunk instanceof Uint8Array)) return fail("invalid_frame");
    if (this.#failed) return fail("invalid_frame");
    if (chunk.byteLength === 0) return this.#completePayload;
    if (this.#completePayload !== undefined) {
      this.#failed = true;
      return fail("multiple_requests");
    }
    if (chunk.byteLength > this.#storage.byteLength - this.#received) {
      this.#failed = true;
      return fail("message_too_large");
    }

    Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength).copy(this.#storage, this.#received);
    this.#received += chunk.byteLength;

    if (this.#expectedTotal === undefined && this.#received >= 4) {
      const payloadLength = readFrameLength(this.#storage, this.#byteOrder);
      if (payloadLength < 1) {
        this.#failed = true;
        return fail("invalid_frame");
      }
      if (payloadLength > MAX_NATIVE_MESSAGE_PAYLOAD_BYTES) {
        this.#failed = true;
        return fail("message_too_large");
      }
      this.#expectedTotal = 4 + payloadLength;
    }

    if (this.#expectedTotal !== undefined && this.#received > this.#expectedTotal) {
      this.#failed = true;
      return fail("multiple_requests");
    }
    if (this.#expectedTotal !== undefined && this.#received === this.#expectedTotal) {
      this.#completePayload = Buffer.from(this.#storage.subarray(4, this.#expectedTotal));
      return this.#completePayload;
    }
    return undefined;
  }

  finish(): Buffer {
    if (this.#failed) return fail("invalid_frame");
    if (this.#completePayload === undefined) return fail("invalid_frame");
    return this.#completePayload;
  }
}

function decodeSingleFrame(frame: Uint8Array, byteOrder: NativeByteOrder): Buffer {
  const decoder = new SingleNativeMessageDecoder(byteOrder);
  decoder.push(frame);
  return decoder.finish();
}

function encodePayloadFrame(payload: Buffer, byteOrder: NativeByteOrder): Buffer {
  assertByteOrder(byteOrder);
  if (payload.byteLength < 1) return fail("invalid_response");
  if (payload.byteLength > MAX_NATIVE_MESSAGE_PAYLOAD_BYTES) return fail("message_too_large");
  const header = Buffer.alloc(4);
  writeFrameLength(header, payload.byteLength, byteOrder);
  return Buffer.concat([header, payload], 4 + payload.byteLength);
}

function serializeForValidation(
  value: unknown,
  errorCode: "invalid_request" | "invalid_response"
): Buffer {
  let json: string | undefined;
  try {
    json = JSON.stringify(value);
  } catch {
    return fail(errorCode);
  }
  if (typeof json !== "string") return fail(errorCode);
  const payload = Buffer.from(json, "utf8");
  if (payload.byteLength < 1) return fail(errorCode);
  if (payload.byteLength > MAX_NATIVE_MESSAGE_PAYLOAD_BYTES) return fail("message_too_large");
  return payload;
}

function parseJsonObject(payload: Buffer, errorCode: "invalid_request" | "invalid_response"): Record<string, unknown> {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(payload);
  } catch {
    return fail(errorCode);
  }

  const errors: ParseError[] = [];
  const root = parseTree(text, errors, {
    allowEmptyContent: false,
    allowTrailingComma: false,
    disallowComments: true
  });
  if (errors.length > 0 || root?.type !== "object") return fail(errorCode);

  const seen = new Set<string>();
  for (const property of root.children ?? []) {
    const nameNode: Node | undefined = property.children?.[0];
    const name = nameNode?.value;
    if (property.type !== "property" || typeof name !== "string" || seen.has(name)) return fail(errorCode);
    seen.add(name);
  }

  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    return fail(errorCode);
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) return fail(errorCode);
  return value as Record<string, unknown>;
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isBrowserFamily(value: unknown): value is NativeBrowserFamily {
  return value === "firefox" || value === "chromium";
}

function parseRequestPayload(payload: Buffer): NativeSetupRequest {
  const value = parseJsonObject(payload, "invalid_request");
  if (value.version !== NATIVE_SETUP_PROTOCOL_VERSION) return fail("invalid_request");
  if (value.type === "begin_setup") {
    if (
      !hasExactKeys(value, ["version", "type", "browser_family"]) ||
      !isBrowserFamily(value.browser_family)
    ) return fail("invalid_request");
    return value as unknown as NativeBeginSetupRequest;
  }
  if (value.type === "cancel_setup") {
    if (
      !hasExactKeys(value, ["version", "type", "setup_id"]) ||
      typeof value.setup_id !== "string" ||
      !SETUP_ID_PATTERN.test(value.setup_id)
    ) return fail("invalid_request");
    return value as unknown as NativeCancelSetupRequest;
  }
  return fail("invalid_request");
}

function canonicalFutureExpiry(value: unknown, nowMs: number): value is string {
  if (typeof value !== "string") return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) &&
    new Date(parsed).toISOString() === value &&
    parsed > nowMs &&
    parsed <= nowMs + MAX_NATIVE_SETUP_TTL_MS;
}

function isFailureCode(value: unknown): value is NativeSetupFailureCode {
  return typeof value === "string" && (NATIVE_SETUP_FAILURE_CODES as readonly string[]).includes(value);
}

function parseResponsePayload(payload: Buffer, nowMs: number): NativeSetupResponse {
  const value = parseJsonObject(payload, "invalid_response");
  if (value.version !== NATIVE_SETUP_PROTOCOL_VERSION || typeof value.ok !== "boolean") {
    return fail("invalid_response");
  }
  if (value.ok === false) {
    if (!hasExactKeys(value, ["version", "ok", "error_code"]) || !isFailureCode(value.error_code)) {
      return fail("invalid_response");
    }
    return value as unknown as NativeSetupFailure;
  }
  if (value.setup_pairing_cancelled === true) {
    if (
      !hasExactKeys(value, ["version", "ok", "setup_id", "setup_pairing_cancelled"]) ||
      typeof value.setup_id !== "string" ||
      !SETUP_ID_PATTERN.test(value.setup_id)
    ) return fail("invalid_response");
    return value as unknown as NativeCancelSetupSuccess;
  }
  if (
    !hasExactKeys(value, ["version", "ok", "setup_id", "setup_secret", "expires_at", "browser_family"]) ||
    typeof value.setup_id !== "string" ||
    !SETUP_ID_PATTERN.test(value.setup_id) ||
    typeof value.setup_secret !== "string" ||
    !NATIVE_SETUP_SECRET_PATTERN.test(value.setup_secret) ||
    !canonicalFutureExpiry(value.expires_at, nowMs) ||
    !isBrowserFamily(value.browser_family)
  ) return fail("invalid_response");
  return value as unknown as NativeBeginSetupSuccess;
}

export function decodeNativeSetupRequestFrame(
  frame: Uint8Array,
  byteOrder: NativeByteOrder = nativeByteOrder()
): NativeSetupRequest {
  return parseRequestPayload(decodeSingleFrame(frame, byteOrder));
}

export function encodeNativeSetupRequestFrame(
  request: NativeSetupRequest,
  byteOrder: NativeByteOrder = nativeByteOrder()
): Buffer {
  const payload = serializeForValidation(request, "invalid_request");
  parseRequestPayload(payload);
  return encodePayloadFrame(payload, byteOrder);
}

export function decodeNativeSetupResponseFrame(
  frame: Uint8Array,
  nowMs = Date.now(),
  byteOrder: NativeByteOrder = nativeByteOrder()
): NativeSetupResponse {
  return parseResponsePayload(decodeSingleFrame(frame, byteOrder), nowMs);
}

export function encodeNativeSetupResponseFrame(
  response: NativeSetupResponse,
  nowMs = Date.now(),
  byteOrder: NativeByteOrder = nativeByteOrder()
): Buffer {
  const payload = serializeForValidation(response, "invalid_response");
  parseResponsePayload(payload, nowMs);
  return encodePayloadFrame(payload, byteOrder);
}

function isSafeString(value: unknown, maxBytes: number): value is string {
  return typeof value === "string" && value.length > 0 &&
    !/[\0\r\n]/u.test(value) && Buffer.byteLength(value, "utf8") <= maxBytes;
}

function validChromiumOrigin(origin: unknown): origin is string {
  return typeof origin === "string" && /^chrome-extension:\/\/[a-p]{32}\/$/u.test(origin);
}

function validFirefoxExtensionId(extensionId: unknown): extensionId is string {
  if (typeof extensionId !== "string" || extensionId.length > 128) return false;
  return /^(?:\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}|[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9.-]*)$/u.test(extensionId);
}

function assertExactUniqueList(values: readonly string[], validator: (value: unknown) => value is string): void {
  if (!Array.isArray(values) || values.length < 1 || values.length > 8) return fail("invalid_configuration");
  const unique = new Set<string>();
  for (const value of values) {
    if (!validator(value) || unique.has(value)) return fail("invalid_configuration");
    unique.add(value);
  }
}

/**
 * Authenticates the browser-owned argv contract before trusting any family
 * claimed inside the JSON request.
 *
 * Chromium: [extension origin] and, on Windows, an optional strict parent
 * window handle argument. Firefox/Zen: [native manifest path, extension ID].
 */
export function authenticateNativeCaller(
  argv: readonly string[],
  policy: NativeCallerPolicy
): NativeBrowserFamily {
  if (!Array.isArray(argv) || argv.some((value) => typeof value !== "string")) {
    return fail("unauthorized_caller");
  }
  if (policy === null || typeof policy !== "object" || Array.isArray(policy)) {
    return fail("invalid_configuration");
  }
  if (policy.browser_family === "chromium") {
    if (!hasExactKeys(policy as unknown as Record<string, unknown>, ["browser_family", "allowed_origins"])) {
      return fail("invalid_configuration");
    }
    assertExactUniqueList(policy.allowed_origins, validChromiumOrigin);
    if (
      (argv.length !== 1 && argv.length !== 2) ||
      !validChromiumOrigin(argv[0]) ||
      !policy.allowed_origins.includes(argv[0]) ||
      (argv.length === 2 && !/^--parent-window=\d{1,20}$/u.test(argv[1] ?? ""))
    ) return fail("unauthorized_caller");
    return "chromium";
  }

  if (policy.browser_family !== "firefox") return fail("invalid_configuration");
  if (
    !hasExactKeys(policy as unknown as Record<string, unknown>, [
      "browser_family",
      "manifest_path",
      "allowed_extension_ids"
    ]) ||
    !isSafeString(policy.manifest_path, 4_096) ||
    !path.isAbsolute(policy.manifest_path)
  ) return fail("invalid_configuration");
  assertExactUniqueList(policy.allowed_extension_ids, validFirefoxExtensionId);
  if (
    argv.length !== 2 ||
    argv[0] !== policy.manifest_path ||
    !validFirefoxExtensionId(argv[1]) ||
    !policy.allowed_extension_ids.includes(argv[1])
  ) return fail("unauthorized_caller");
  return "firefox";
}

export function createNativeSetupFailure(errorCode: NativeSetupFailureCode): NativeSetupFailure {
  if (!isFailureCode(errorCode)) return fail("invalid_response");
  return {
    version: NATIVE_SETUP_PROTOCOL_VERSION,
    ok: false,
    error_code: errorCode
  };
}

function safeFailureFrame(
  errorCode: NativeSetupFailureCode,
  nowMs: number,
  byteOrder: NativeByteOrder
): Buffer {
  return encodeNativeSetupResponseFrame(createNativeSetupFailure(errorCode), nowMs, byteOrder);
}

/**
 * Turns one native frame into exactly one framed response. It never returns
 * exception text, argv values, request bytes, or service error details.
 */
export async function processNativeSetupFrame(input: ProcessNativeSetupFrameInput): Promise<Buffer> {
  const byteOrder = input.byte_order ?? nativeByteOrder();
  const nowMs = (input.now ?? Date.now)();
  let callerFamily: NativeBrowserFamily;
  try {
    callerFamily = authenticateNativeCaller(input.argv, input.caller_policy);
  } catch (error) {
    const code = error instanceof NativeMessagingProtocolError && error.code === "invalid_configuration"
      ? "internal_error"
      : "unauthorized_caller";
    return safeFailureFrame(code, nowMs, byteOrder);
  }

  let request: NativeSetupRequest;
  try {
    request = decodeNativeSetupRequestFrame(input.frame, byteOrder);
    if (request.type === "begin_setup" && request.browser_family !== callerFamily) {
      return safeFailureFrame("invalid_request", nowMs, byteOrder);
    }
  } catch {
    return safeFailureFrame("invalid_request", nowMs, byteOrder);
  }

  try {
    if (request.type === "begin_setup") {
      const result = await input.operations.beginSetup(request.browser_family);
      const response: NativeBeginSetupSuccess = {
        version: NATIVE_SETUP_PROTOCOL_VERSION,
        ok: true,
        setup_id: result.setup_id,
        setup_secret: result.setup_secret,
        expires_at: result.expires_at,
        browser_family: result.browser_family
      };
      if (response.browser_family !== request.browser_family) {
        return safeFailureFrame("operation_failed", nowMs, byteOrder);
      }
      return encodeNativeSetupResponseFrame(response, nowMs, byteOrder);
    }

    const result = await input.operations.cancelSetup(request.setup_id);
    const response: NativeCancelSetupSuccess = {
      version: NATIVE_SETUP_PROTOCOL_VERSION,
      ok: true,
      setup_id: result.setup_id,
      setup_pairing_cancelled: result.setup_pairing_cancelled
    };
    if (response.setup_id !== request.setup_id) {
      return safeFailureFrame("operation_failed", nowMs, byteOrder);
    }
    return encodeNativeSetupResponseFrame(response, nowMs, byteOrder);
  } catch {
    return safeFailureFrame("operation_failed", nowMs, byteOrder);
  }
}
