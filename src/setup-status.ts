import { PROTOCOL_VERSION } from "./protocol.js";

export interface SetupBrowserStatus {
  browser_id: string;
  browser_family: "chromium" | "firefox";
  browser_name: string;
  browser_version: string;
  extension_version: string;
  connected_at: string;
}

export interface WaitingSetupReceipt {
  setup_pairing_status: "waiting";
  setup_id: string;
  expires_at: string;
  browser_family: SetupBrowserStatus["browser_family"];
}

export interface BoundSetupReceipt {
  setup_pairing_status: "pending" | "completed";
  setup_id: string;
  expires_at: string;
  browser_id: string;
  browser_family: SetupBrowserStatus["browser_family"];
  browser_name: string;
  browser_version: string;
  extension_version: string;
  completed_at?: string;
}

export interface MissingSetupReceipt {
  setup_pairing_status: "not_found";
  setup_id: string;
}

export type ParsedSetupReceipt = WaitingSetupReceipt | BoundSetupReceipt | MissingSetupReceipt;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  return Object.keys(value).sort().join("\0") === [...expected].sort().join("\0");
}

function canonicalDate(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 40) return false;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
}

function boundedLabel(value: unknown, maximum: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum && !/[\0\r\n]/u.test(value);
}

function parseBrowser(value: unknown): SetupBrowserStatus {
  if (!isRecord(value) || !hasExactKeys(value, [
    "browser_id", "browser_family", "browser_name", "browser_version", "extension_version", "connected_at"
  ]) || typeof value.browser_id !== "string" || !/^browser-[a-f0-9]{24}$/u.test(value.browser_id)
    || (value.browser_family !== "chromium" && value.browser_family !== "firefox")
    || !boundedLabel(value.browser_name, 80) || !boundedLabel(value.browser_version, 80)
    || !boundedLabel(value.extension_version, 40) || !canonicalDate(value.connected_at)) {
    throw new Error("BrowseWeave returned an invalid connected-browser identity.");
  }
  return {
    browser_id: value.browser_id,
    browser_family: value.browser_family,
    browser_name: value.browser_name,
    browser_version: value.browser_version,
    extension_version: value.extension_version,
    connected_at: value.connected_at
  };
}

export function parseSetupDaemonStatus(value: unknown): SetupBrowserStatus[] {
  if (!isRecord(value) || !hasExactKeys(value, [
    "service", "protocol_version", "websocket_listening", "connected_browsers",
    "pending_commands", "pending_approvals", "uptime_seconds"
  ]) || value.service !== "browseweave" || value.protocol_version !== PROTOCOL_VERSION
    || value.websocket_listening !== true || !Array.isArray(value.connected_browsers)
    || !Number.isInteger(value.pending_commands) || (value.pending_commands as number) < 0
    || !Number.isInteger(value.pending_approvals) || (value.pending_approvals as number) < 0
    || typeof value.uptime_seconds !== "number" || !Number.isFinite(value.uptime_seconds)
    || value.uptime_seconds < 0) {
    throw new Error("BrowseWeave returned an invalid or unhealthy setup status.");
  }
  const browsers = value.connected_browsers.map(parseBrowser);
  if (new Set(browsers.map((browser) => browser.browser_id)).size !== browsers.length) {
    throw new Error("BrowseWeave returned duplicate connected-browser identities.");
  }
  return browsers;
}

export function parseSetupPairingReceipt(input: {
  value: unknown;
  setupId: string;
  expiresAt: string;
  browserFamily: SetupBrowserStatus["browser_family"];
}): ParsedSetupReceipt {
  const { value } = input;
  if (!isRecord(value) || value.setup_id !== input.setupId) {
    throw new Error("BrowseWeave returned an invalid setup receipt.");
  }
  if (value.setup_pairing_status === "not_found") {
    if (!hasExactKeys(value, ["setup_pairing_status", "setup_id"])) {
      throw new Error("BrowseWeave returned an invalid missing-session receipt.");
    }
    return { setup_pairing_status: "not_found", setup_id: input.setupId };
  }
  if (value.setup_pairing_status === "waiting") {
    if (!hasExactKeys(value, ["setup_pairing_status", "setup_id", "expires_at", "browser_family"])
      || value.expires_at !== input.expiresAt || value.browser_family !== input.browserFamily) {
      throw new Error("BrowseWeave returned an invalid waiting setup receipt.");
    }
    return {
      setup_pairing_status: "waiting",
      setup_id: input.setupId,
      expires_at: input.expiresAt,
      browser_family: input.browserFamily
    };
  }
  const completed = value.setup_pairing_status === "completed";
  if (value.setup_pairing_status !== "pending" && !completed) {
    throw new Error("BrowseWeave returned an unknown setup receipt state.");
  }
  const keys = [
    "setup_pairing_status", "setup_id", "expires_at", "browser_id", "browser_family",
    "browser_name", "browser_version", "extension_version",
    ...(completed ? ["completed_at"] : [])
  ];
  if (!hasExactKeys(value, keys) || value.expires_at !== input.expiresAt
    || value.browser_family !== input.browserFamily
    || typeof value.browser_id !== "string" || !/^browser-[a-f0-9]{24}$/u.test(value.browser_id)
    || !boundedLabel(value.browser_name, 80) || !boundedLabel(value.browser_version, 80)
    || !boundedLabel(value.extension_version, 40)
    || (completed && (!canonicalDate(value.completed_at)
      || Date.parse(value.completed_at as string) > Date.parse(input.expiresAt)))) {
    throw new Error("BrowseWeave returned an invalid bound setup receipt.");
  }
  return {
    setup_pairing_status: completed ? "completed" : "pending",
    setup_id: input.setupId,
    expires_at: input.expiresAt,
    browser_id: value.browser_id,
    browser_family: input.browserFamily,
    browser_name: value.browser_name,
    browser_version: value.browser_version,
    extension_version: value.extension_version,
    ...(completed ? { completed_at: value.completed_at as string } : {})
  };
}

export function receiptMatchesConnectedBrowser(
  receipt: BoundSetupReceipt,
  browser: SetupBrowserStatus
): boolean {
  return receipt.setup_pairing_status === "completed"
    && receipt.browser_id === browser.browser_id
    && receipt.browser_family === browser.browser_family
    && receipt.browser_name === browser.browser_name
    && receipt.browser_version === browser.browser_version
    && receipt.extension_version === browser.extension_version;
}
