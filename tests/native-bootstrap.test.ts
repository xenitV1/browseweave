import { describe, expect, it, vi } from "vitest";
import { NATIVE_SETUP_TTL_MS, createNativeSetupOperations } from "../src/native-bootstrap.js";

const NOW = Date.parse("2026-07-28T12:00:00.000Z");
const SETUP_ID = "a".repeat(24);
const SETUP_SECRET = "b".repeat(64);

describe("native setup daemon bootstrap", () => {
  it("starts only through the injected ownership guard and opens an exact short-lived session", async () => {
    const ensureServiceReady = vi.fn(async () => undefined);
    const call = vi.fn(async (method: string, params: Record<string, unknown>) => {
      expect(method).toBe("setup_pairing_begin");
      return {
        setup_pairing_ready: true,
        setup_id: params.setup_id,
        expires_at: params.expires_at,
        browser_family: params.browser_family
      };
    });
    const randomHex = vi.fn((bytes: number) => bytes === 12 ? SETUP_ID : SETUP_SECRET);
    const operations = createNativeSetupOperations({
      ensureServiceReady,
      call,
      now: () => NOW,
      randomHex
    });

    await expect(operations.beginSetup("firefox")).resolves.toEqual({
      setup_id: SETUP_ID,
      setup_secret: SETUP_SECRET,
      expires_at: new Date(NOW + NATIVE_SETUP_TTL_MS).toISOString(),
      browser_family: "firefox"
    });
    expect(ensureServiceReady).toHaveBeenCalledOnce();
    expect(randomHex.mock.calls).toEqual([[12], [32]]);
    expect(call).toHaveBeenCalledWith("setup_pairing_begin", {
      setup_id: SETUP_ID,
      setup_secret: SETUP_SECRET,
      expires_at: new Date(NOW + NATIVE_SETUP_TTL_MS).toISOString(),
      browser_family: "firefox"
    }, 5_000);
  });

  it("fails closed on invalid randomness or any expanded/mismatched daemon receipt", async () => {
    const base = {
      ensureServiceReady: async () => undefined,
      now: () => NOW
    };
    await expect(createNativeSetupOperations({
      ...base,
      randomHex: () => "wrong",
      call: async () => { throw new Error("must not be called"); }
    }).beginSetup("firefox")).rejects.toThrow(/random source/iu);

    for (const response of [
      null,
      { setup_pairing_ready: true, setup_id: "wrong", expires_at: new Date(NOW + NATIVE_SETUP_TTL_MS).toISOString(), browser_family: "firefox" },
      { setup_pairing_ready: true, setup_id: SETUP_ID, expires_at: new Date(NOW + NATIVE_SETUP_TTL_MS).toISOString(), browser_family: "chromium" },
      { setup_pairing_ready: true, setup_id: SETUP_ID, expires_at: new Date(NOW + NATIVE_SETUP_TTL_MS).toISOString(), browser_family: "firefox", extra: true }
    ]) {
      await expect(createNativeSetupOperations({
        ...base,
        randomHex: (bytes) => bytes === 12 ? SETUP_ID : SETUP_SECRET,
        call: async () => response
      }).beginSetup("firefox")).rejects.toThrow(/invalid|exact/iu);
    }
  });

  it("cancels only the exact session and rejects ambiguous cleanup receipts", async () => {
    const ensureServiceReady = vi.fn(async () => undefined);
    const call = vi.fn(async (_method: string, params: Record<string, unknown>) => ({
      setup_pairing_cancelled: true,
      setup_id: params.setup_id
    }));
    const operations = createNativeSetupOperations({ ensureServiceReady, call });
    await expect(operations.cancelSetup(SETUP_ID)).resolves.toEqual({
      setup_id: SETUP_ID,
      setup_pairing_cancelled: true
    });
    expect(call).toHaveBeenCalledWith("setup_pairing_cancel", { setup_id: SETUP_ID }, 3_000);

    await expect(createNativeSetupOperations({
      ensureServiceReady: async () => undefined,
      call: async () => ({ setup_pairing_cancelled: true, setup_id: SETUP_ID, detail: "extra" })
    }).cancelSetup(SETUP_ID)).rejects.toThrow(/exact/iu);
  });

  it("does not call the daemon when the exact-owned service guard refuses", async () => {
    const call = vi.fn(async () => ({}));
    const operations = createNativeSetupOperations({
      ensureServiceReady: async () => { throw new Error("foreign service"); },
      call
    });
    await expect(operations.beginSetup("chromium")).rejects.toThrow(/foreign service/iu);
    expect(call).not.toHaveBeenCalled();
  });
});
