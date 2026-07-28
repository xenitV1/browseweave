import { afterEach, describe, expect, it, vi } from "vitest";
import {
  NATIVE_SETUP_HOST_NAME,
  nativeSetupBeginRequest,
  nativeSetupCancelRequest,
  nativeSetupErrorMessage,
  parseNativeSetupBeginResponse,
  withNativeSetupTimeout
} from "../extension/src/setup/native-setup";

const NOW = Date.parse("2026-07-28T12:00:00.000Z");
const SETUP_ID = "0123456789abcdef01234567";
const SETUP_SECRET = "0123456789abcdef".repeat(4);

function success(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    version: 1,
    ok: true,
    setup_id: SETUP_ID,
    setup_secret: SETUP_SECRET,
    expires_at: new Date(NOW + 60_000).toISOString(),
    browser_family: "firefox",
    ...overrides
  };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("extension native one-click setup boundary", () => {
  it("uses a fixed host and emits only exact bounded operations", () => {
    expect(NATIVE_SETUP_HOST_NAME).toBe("io.browseweave.setup");
    expect(nativeSetupBeginRequest("firefox")).toEqual({
      version: 1,
      type: "begin_setup",
      browser_family: "firefox"
    });
    expect(nativeSetupCancelRequest(SETUP_ID)).toEqual({
      version: 1,
      type: "cancel_setup",
      setup_id: SETUP_ID
    });
    expect(() => nativeSetupCancelRequest("../wrong\nvalue")).toThrow(/session ID/iu);
  });

  it("accepts only an exact short-lived response for the requested browser family", () => {
    expect(parseNativeSetupBeginResponse(success(), "firefox", NOW)).toEqual({
      setupId: SETUP_ID,
      setupSecret: SETUP_SECRET,
      expiresAt: NOW + 60_000,
      browserFamily: "firefox"
    });
    expect(parseNativeSetupBeginResponse(success({ browser_family: "chromium" }), "firefox", NOW)).toEqual({
      ok: false,
      errorCode: "invalid_request"
    });
    expect(parseNativeSetupBeginResponse(success({ expires_at: new Date(NOW).toISOString() }), "firefox", NOW)).toEqual({
      ok: false,
      errorCode: "invalid_request"
    });
    expect(parseNativeSetupBeginResponse(success({ expires_at: "2026-07-28T12:01:00Z" }), "firefox", NOW)).toEqual({
      ok: false,
      errorCode: "invalid_request"
    });
    expect(parseNativeSetupBeginResponse(success({ extra: true }), "firefox", NOW)).toEqual({
      ok: false,
      errorCode: "invalid_request"
    });
  });

  it("allows only generic exact failure codes and never forwards host detail", () => {
    expect(parseNativeSetupBeginResponse({ version: 1, ok: false, error_code: "service_unavailable" }, "firefox", NOW))
      .toEqual({ ok: false, errorCode: "service_unavailable" });
    expect(parseNativeSetupBeginResponse({
      version: 1,
      ok: false,
      error_code: "service_unavailable",
      detail: "/private/path/secret"
    }, "firefox", NOW)).toEqual({ ok: false, errorCode: "invalid_request" });
    expect(parseNativeSetupBeginResponse({ version: 1, ok: false, error_code: "shell_failed" }, "firefox", NOW))
      .toEqual({ ok: false, errorCode: "invalid_request" });
    expect(nativeSetupErrorMessage("service_unavailable")).not.toMatch(/[\\/](?:home|Users|tmp)[\\/]/u);
  });

  it("times out a hung helper and ignores late settlement", async () => {
    vi.useFakeTimers();
    let resolve!: (value: string) => void;
    const operation = new Promise<string>((resolvePromise) => { resolve = resolvePromise; });
    const result = withNativeSetupTimeout(operation, 25);
    const expectation = expect(result).rejects.toThrow(/did not respond/iu);
    await vi.advanceTimersByTimeAsync(25);
    await expectation;
    resolve("late-secret-value");
    await vi.runAllTimersAsync();
  });
});
