export const NATIVE_SETUP_HOST_NAME = "io.browseweave.setup" as const;
export const NATIVE_SETUP_PROTOCOL_VERSION = 1 as const;
export const NATIVE_SETUP_REQUEST_TIMEOUT_MS = 60_000 as const;

export type NativeSetupBrowserFamily = "chromium" | "firefox";

export type NativeSetupErrorCode =
  | "helper_unavailable"
  | "service_unavailable"
  | "operation_failed"
  | "unauthorized_caller"
  | "invalid_request"
  | "internal_error";

export interface NativeSetupTicket {
  readonly setupId: string;
  readonly setupSecret: string;
  readonly expiresAt: number;
  readonly browserFamily: NativeSetupBrowserFamily;
}

export interface NativeSetupFailure {
  readonly ok: false;
  readonly errorCode: NativeSetupErrorCode;
}

const SETUP_ID_PATTERN = /^[a-f0-9]{24}$/u;
const SETUP_SECRET_PATTERN = /^[a-f0-9]{64}$/u;

const NATIVE_SETUP_ERROR_CODES = new Set<NativeSetupErrorCode>([
  "helper_unavailable",
  "service_unavailable",
  "operation_failed",
  "unauthorized_caller",
  "invalid_request",
  "internal_error"
]);

function exactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  return Object.keys(record).sort().join(",") === [...expected].sort().join(",");
}

function canonicalFutureExpiry(value: unknown, now: number): number | null {
  if (typeof value !== "string" || value.length < 20 || value.length > 32) return null;
  const expiry = Date.parse(value);
  if (
    !Number.isFinite(expiry) || new Date(expiry).toISOString() !== value ||
    expiry <= now || expiry > now + 5 * 60_000
  ) return null;
  return expiry;
}

export function nativeSetupBeginRequest(browserFamily: NativeSetupBrowserFamily): Record<string, unknown> {
  return {
    version: NATIVE_SETUP_PROTOCOL_VERSION,
    type: "begin_setup",
    browser_family: browserFamily
  };
}

export function nativeSetupCancelRequest(setupId: string): Record<string, unknown> {
  if (!SETUP_ID_PATTERN.test(setupId)) throw new Error("The local setup session ID is invalid.");
  return {
    version: NATIVE_SETUP_PROTOCOL_VERSION,
    type: "cancel_setup",
    setup_id: setupId
  };
}

export function parseNativeSetupBeginResponse(
  value: unknown,
  expectedFamily: NativeSetupBrowserFamily,
  now = Date.now()
): NativeSetupTicket | NativeSetupFailure {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, errorCode: "invalid_request" };
  }
  const record = value as Record<string, unknown>;
  if (record.ok === false) {
    if (
      !exactKeys(record, ["version", "ok", "error_code"]) ||
      record.version !== NATIVE_SETUP_PROTOCOL_VERSION ||
      typeof record.error_code !== "string" ||
      !NATIVE_SETUP_ERROR_CODES.has(record.error_code as NativeSetupErrorCode)
    ) return { ok: false, errorCode: "invalid_request" };
    return { ok: false, errorCode: record.error_code as NativeSetupErrorCode };
  }
  const expiry = canonicalFutureExpiry(record.expires_at, now);
  if (
    !exactKeys(record, [
      "version", "ok", "setup_id", "setup_secret", "expires_at", "browser_family"
    ]) ||
    record.version !== NATIVE_SETUP_PROTOCOL_VERSION || record.ok !== true ||
    typeof record.setup_id !== "string" || !SETUP_ID_PATTERN.test(record.setup_id) ||
    typeof record.setup_secret !== "string" || !SETUP_SECRET_PATTERN.test(record.setup_secret) ||
    record.browser_family !== expectedFamily || expiry === null
  ) return { ok: false, errorCode: "invalid_request" };
  return {
    setupId: record.setup_id,
    setupSecret: record.setup_secret,
    expiresAt: expiry,
    browserFamily: expectedFamily
  };
}

export function nativeSetupErrorMessage(code: NativeSetupErrorCode): string {
  if (code === "helper_unavailable") {
    return "The BrowseWeave helper is not installed or could not be opened. Run the BrowseWeave installer once, then try again.";
  }
  if (code === "service_unavailable") {
    return "The local BrowseWeave service could not be started. Open the installer and choose Repair, then try again.";
  }
  if (code === "unauthorized_caller") {
    return "This extension installation is not authorized to use the local BrowseWeave helper.";
  }
  if (code === "operation_failed") {
    return "The local service rejected this setup attempt. Try again; no pairing key was saved.";
  }
  return "BrowseWeave could not complete the local setup. No pairing key was saved.";
}

export function withNativeSetupTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number = NATIVE_SETUP_REQUEST_TIMEOUT_MS
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const timeout = globalThis.setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error("The local BrowseWeave helper did not respond in time."));
    }, Math.max(1, timeoutMs));
    operation.then(
      (value) => {
        if (settled) return;
        settled = true;
        globalThis.clearTimeout(timeout);
        resolve(value);
      },
      (error: unknown) => {
        if (settled) return;
        settled = true;
        globalThis.clearTimeout(timeout);
        reject(error);
      }
    );
  });
}
