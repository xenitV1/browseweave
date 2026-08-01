import { describe, expect, it } from "vitest";
import { PROTOCOL_VERSION } from "../src/core/protocol.js";
import {
  parseSetupDaemonStatus,
  parseSetupPairingReceipt,
  receiptMatchesConnectedBrowser
} from "../src/bridge/setup-status.js";

const setupId = "0123456789abcdef01234567";
const expiresAt = "2026-07-28T16:00:00.000Z";
const browser = {
  browser_id: "browser-0123456789abcdef01234567",
  browser_family: "chromium" as const,
  browser_name: "Google Chrome",
  browser_version: "138.0.7204.97",
  extension_version: "0.1.0",
  connected_at: "2026-07-28T15:55:00.000Z"
};

function daemonStatus() {
  return {
    service: "browseweave",
    protocol_version: PROTOCOL_VERSION,
    websocket_listening: true,
    connected_browsers: [browser],
    pending_commands: 0,
    pending_approvals: 0,
    uptime_seconds: 1.5,
    autonomous_actions: { enabled: false, categories: [] as string[] }
  };
}

describe("exact one-click setup status", () => {
  it("accepts only an exact healthy daemon and complete browser identity", () => {
    expect(parseSetupDaemonStatus(daemonStatus())).toEqual([browser]);
    expect(() => parseSetupDaemonStatus({ ...daemonStatus(), service: "other" })).toThrow(/invalid or unhealthy/iu);
    expect(() => parseSetupDaemonStatus({ ...daemonStatus(), websocket_listening: false })).toThrow(/invalid or unhealthy/iu);
    expect(() => parseSetupDaemonStatus({
      ...daemonStatus(), connected_browsers: [{ ...browser, extra: true }]
    })).toThrow(/invalid connected-browser/iu);
    expect(parseSetupDaemonStatus({
      ...daemonStatus(), autonomous_actions: { enabled: true, categories: ["form_submit", "message"] }
    })).toEqual([browser]);
    for (const autonomous of [
      undefined,
      { enabled: true },
      { enabled: "yes", categories: [] },
      { enabled: true, categories: [""] },
      { enabled: true, categories: ["form_submit"], extra: true }
    ]) {
      expect(() => parseSetupDaemonStatus({ ...daemonStatus(), autonomous_actions: autonomous }))
        .toThrow(/invalid or unhealthy/iu);
    }
  });

  it("binds completion to the exact setup and connected browser", () => {
    const waiting = parseSetupPairingReceipt({
      value: { setup_pairing_status: "waiting", setup_id: setupId, expires_at: expiresAt, browser_family: "chromium" },
      setupId, expiresAt, browserFamily: "chromium"
    });
    expect(waiting.setup_pairing_status).toBe("waiting");
    const receipt = parseSetupPairingReceipt({
      value: {
        setup_pairing_status: "completed", setup_id: setupId, expires_at: expiresAt,
        browser_id: browser.browser_id, browser_family: browser.browser_family,
        browser_name: browser.browser_name, browser_version: browser.browser_version,
        extension_version: browser.extension_version, completed_at: "2026-07-28T15:59:00.000Z"
      },
      setupId, expiresAt, browserFamily: "chromium"
    });
    if (receipt.setup_pairing_status !== "completed") throw new Error("expected completed receipt");
    expect(receiptMatchesConnectedBrowser(receipt, browser)).toBe(true);
    expect(receiptMatchesConnectedBrowser(receipt, { ...browser, extension_version: "0.0.9" })).toBe(false);
  });

  it("rejects another session, family, expiry, extra field, or noncanonical completion time", () => {
    const base = {
      setup_pairing_status: "completed", setup_id: setupId, expires_at: expiresAt,
      browser_id: browser.browser_id, browser_family: browser.browser_family,
      browser_name: browser.browser_name, browser_version: browser.browser_version,
      extension_version: browser.extension_version, completed_at: "2026-07-28T15:59:00.000Z"
    };
    for (const value of [
      { ...base, setup_id: "1123456789abcdef01234567" },
      { ...base, browser_family: "firefox" },
      { ...base, expires_at: "2026-07-28T16:01:00.000Z" },
      { ...base, extra: true },
      { ...base, completed_at: "2026-07-28T15:59:00Z" }
    ]) expect(() => parseSetupPairingReceipt({ value, setupId, expiresAt, browserFamily: "chromium" })).toThrow();
  });
});
