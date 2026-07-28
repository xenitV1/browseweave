import { describe, expect, it, vi } from "vitest";
import {
  MAX_NATIVE_MESSAGE_PAYLOAD_BYTES,
  MAX_NATIVE_SETUP_TTL_MS,
  NATIVE_SETUP_HOST_NAME,
  NATIVE_SETUP_PROTOCOL_VERSION,
  NativeMessagingProtocolError,
  SingleNativeMessageDecoder,
  authenticateNativeCaller,
  createNativeSetupFailure,
  decodeNativeSetupRequestFrame,
  decodeNativeSetupResponseFrame,
  encodeNativeSetupRequestFrame,
  encodeNativeSetupResponseFrame,
  nativeByteOrder,
  processNativeSetupFrame,
  type NativeByteOrder,
  type NativeCallerPolicy,
  type NativeSetupOperations,
  type NativeSetupResponse
} from "../src/native-setup-protocol.js";

const NOW = Date.parse("2026-07-28T12:00:00.000Z");
const SETUP_ID = "a".repeat(24);
const SETUP_SECRET = "b".repeat(64);
const CHROMIUM_ORIGIN = `chrome-extension://${"c".repeat(32)}/`;
const FIREFOX_MANIFEST = "/home/test/.mozilla/native-messaging-hosts/io.browseweave.setup.json";
const FIREFOX_EXTENSION_ID = "browseweave@local.invalid";

const chromiumPolicy: NativeCallerPolicy = {
  browser_family: "chromium",
  allowed_origins: [CHROMIUM_ORIGIN]
};

const firefoxPolicy: NativeCallerPolicy = {
  browser_family: "firefox",
  manifest_path: FIREFOX_MANIFEST,
  allowed_extension_ids: [FIREFOX_EXTENSION_ID]
};

function writeLength(header: Buffer, length: number, byteOrder: NativeByteOrder): void {
  if (byteOrder === "LE") header.writeUInt32LE(length, 0);
  else header.writeUInt32BE(length, 0);
}

function rawFrame(value: unknown, byteOrder: NativeByteOrder = nativeByteOrder()): Buffer {
  return textFrame(JSON.stringify(value), byteOrder);
}

function textFrame(text: string, byteOrder: NativeByteOrder = nativeByteOrder()): Buffer {
  const payload = Buffer.from(text, "utf8");
  const header = Buffer.alloc(4);
  writeLength(header, payload.byteLength, byteOrder);
  return Buffer.concat([header, payload]);
}

function expectProtocolError(call: () => unknown, code: NativeMessagingProtocolError["code"]): void {
  try {
    call();
    throw new Error("Expected a NativeMessagingProtocolError.");
  } catch (error) {
    expect(error).toBeInstanceOf(NativeMessagingProtocolError);
    expect((error as NativeMessagingProtocolError).code).toBe(code);
  }
}

function beginRequest(family: "firefox" | "chromium" = "chromium") {
  return {
    version: NATIVE_SETUP_PROTOCOL_VERSION,
    type: "begin_setup" as const,
    browser_family: family
  };
}

function cancelRequest() {
  return {
    version: NATIVE_SETUP_PROTOCOL_VERSION,
    type: "cancel_setup" as const,
    setup_id: SETUP_ID
  };
}

function beginSuccess(family: "firefox" | "chromium" = "chromium") {
  return {
    version: NATIVE_SETUP_PROTOCOL_VERSION,
    ok: true as const,
    setup_id: SETUP_ID,
    setup_secret: SETUP_SECRET,
    expires_at: new Date(NOW + 60_000).toISOString(),
    browser_family: family
  };
}

function operations(overrides: Partial<NativeSetupOperations> = {}): NativeSetupOperations {
  return {
    beginSetup: async (browserFamily) => ({
      setup_id: SETUP_ID,
      setup_secret: SETUP_SECRET,
      expires_at: new Date(NOW + 60_000).toISOString(),
      browser_family: browserFamily
    }),
    cancelSetup: async (setupId) => ({
      setup_id: setupId,
      setup_pairing_cancelled: true
    }),
    ...overrides
  };
}

describe("native setup framing", () => {
  it("uses the fixed public host name and the operating system byte order", () => {
    expect(NATIVE_SETUP_HOST_NAME).toBe("io.browseweave.setup");
    expect(["LE", "BE"]).toContain(nativeByteOrder());
    const frame = encodeNativeSetupRequestFrame(beginRequest());
    const declared = nativeByteOrder() === "LE" ? frame.readUInt32LE(0) : frame.readUInt32BE(0);
    expect(declared).toBe(frame.byteLength - 4);
  });

  it.each(["LE", "BE"] as const)("round-trips a %s frame", (byteOrder) => {
    const frame = encodeNativeSetupRequestFrame(cancelRequest(), byteOrder);
    expect(decodeNativeSetupRequestFrame(frame, byteOrder)).toEqual(cancelRequest());
    const otherOrder = byteOrder === "LE" ? "BE" : "LE";
    expectProtocolError(() => decodeNativeSetupRequestFrame(frame, otherOrder), "message_too_large");
  });

  it("decodes arbitrarily fragmented input without returning partial JSON", () => {
    const frame = encodeNativeSetupRequestFrame(beginRequest());
    const decoder = new SingleNativeMessageDecoder();
    for (let index = 0; index < frame.byteLength - 1; index += 1) {
      expect(decoder.push(frame.subarray(index, index + 1))).toBeUndefined();
    }
    const payload = decoder.push(frame.subarray(frame.byteLength - 1));
    expect(payload?.toString("utf8")).toBe(JSON.stringify(beginRequest()));
    expect(decoder.finish()).toEqual(payload);
  });

  it("rejects zero-length, incomplete, and oversized frames", () => {
    const zero = Buffer.alloc(4);
    expectProtocolError(() => decodeNativeSetupRequestFrame(zero), "invalid_frame");

    const incompleteHeader = Buffer.from([1, 2, 3]);
    expectProtocolError(() => decodeNativeSetupRequestFrame(incompleteHeader), "invalid_frame");

    const incompletePayload = encodeNativeSetupRequestFrame(beginRequest()).subarray(0, -1);
    expectProtocolError(() => decodeNativeSetupRequestFrame(incompletePayload), "invalid_frame");

    const oversizedHeader = Buffer.alloc(4);
    writeLength(oversizedHeader, MAX_NATIVE_MESSAGE_PAYLOAD_BYTES + 1, nativeByteOrder());
    expectProtocolError(() => decodeNativeSetupRequestFrame(oversizedHeader), "message_too_large");

    const oversizedChunk = Buffer.alloc(MAX_NATIVE_MESSAGE_PAYLOAD_BYTES + 5);
    expectProtocolError(() => new SingleNativeMessageDecoder().push(oversizedChunk), "message_too_large");
  });

  it("rejects a second request, trailing bytes, and delayed data after completion", () => {
    const first = encodeNativeSetupRequestFrame(beginRequest());
    const second = encodeNativeSetupRequestFrame(cancelRequest());
    expectProtocolError(
      () => decodeNativeSetupRequestFrame(Buffer.concat([first, second])),
      "multiple_requests"
    );
    expectProtocolError(
      () => decodeNativeSetupRequestFrame(Buffer.concat([first, Buffer.from([0])])),
      "multiple_requests"
    );

    const decoder = new SingleNativeMessageDecoder();
    expect(decoder.push(first)).toBeDefined();
    expect(decoder.push(Buffer.alloc(0))).toBeDefined();
    expectProtocolError(() => decoder.push(second), "multiple_requests");
  });

  it("rejects invalid UTF-8 before JSON parsing", () => {
    const header = Buffer.alloc(4);
    writeLength(header, 2, nativeByteOrder());
    const frame = Buffer.concat([header, Buffer.from([0xc3, 0x28])]);
    expectProtocolError(() => decodeNativeSetupRequestFrame(frame), "invalid_request");
  });
});

describe("exact native request schemas", () => {
  it("accepts only the exact begin and cancel contracts", () => {
    expect(decodeNativeSetupRequestFrame(encodeNativeSetupRequestFrame(beginRequest("firefox"))))
      .toEqual(beginRequest("firefox"));
    expect(decodeNativeSetupRequestFrame(encodeNativeSetupRequestFrame(cancelRequest())))
      .toEqual(cancelRequest());
  });

  it("validates and frames the same single serialization", () => {
    let reads = 0;
    const request = {
      version: 1 as const,
      type: "begin_setup" as const,
      get browser_family() {
        reads += 1;
        return reads === 1 ? "chromium" as const : "firefox" as const;
      }
    };
    const frame = encodeNativeSetupRequestFrame(request);
    expect(reads).toBe(1);
    expect(decodeNativeSetupRequestFrame(frame)).toEqual(beginRequest("chromium"));
  });

  it("accepts harmless JSON whitespace and key order while rejecting duplicate keys", () => {
    const reordered = textFrame('{ "browser_family":"chromium", "type":"begin_setup", "version":1 }');
    expect(decodeNativeSetupRequestFrame(reordered)).toEqual(beginRequest());

    const duplicate = textFrame('{"version":1,"type":"cancel_setup","setup_id":"wrong","setup_id":"aaaaaaaaaaaaaaaaaaaaaaaa"}');
    expectProtocolError(() => decodeNativeSetupRequestFrame(duplicate), "invalid_request");
  });

  it.each([
    null,
    [],
    { version: 1, type: "unknown" },
    { version: 2, type: "begin_setup", browser_family: "chromium" },
    { version: 1, type: "begin_setup" },
    { version: 1, type: "begin_setup", browser_family: "chrome" },
    { version: 1, type: "begin_setup", browser_family: "chromium", extra: true },
    { version: 1, type: "cancel_setup", setup_id: "too-short" },
    { version: 1, type: "cancel_setup", setup_id: SETUP_ID, extra: true }
  ])("rejects malformed or expanded request %#", (value) => {
    expectProtocolError(() => decodeNativeSetupRequestFrame(rawFrame(value)), "invalid_request");
  });

  it.each([
    " ",
    "{} trailing",
    "// comment\n{}",
    '{"version":1,"type":"begin_setup","browser_family":"chromium",}'
  ])("rejects non-JSON protocol text %#", (value) => {
    expectProtocolError(() => decodeNativeSetupRequestFrame(textFrame(value)), "invalid_request");
  });
});

describe("native browser caller authentication", () => {
  it("accepts only an allowlisted root Chromium extension origin", () => {
    expect(authenticateNativeCaller([CHROMIUM_ORIGIN], chromiumPolicy)).toBe("chromium");
    expect(authenticateNativeCaller(
      [CHROMIUM_ORIGIN, "--parent-window=12345"],
      chromiumPolicy
    )).toBe("chromium");
  });

  it.each([
    [],
    [`chrome-extension://${"d".repeat(32)}/`],
    [CHROMIUM_ORIGIN.slice(0, -1)],
    [`https://${"c".repeat(32)}/`],
    [`${CHROMIUM_ORIGIN}settings.html`],
    [CHROMIUM_ORIGIN, "12345"],
    [CHROMIUM_ORIGIN, "--parent-window=-1"],
    [CHROMIUM_ORIGIN, "--parent-window=1", "extra"]
  ])("rejects unauthorized Chromium argv %#", (argv) => {
    expectProtocolError(() => authenticateNativeCaller(argv, chromiumPolicy), "unauthorized_caller");
  });

  it("accepts only Firefox's exact manifest path and exact extension ID pair", () => {
    expect(authenticateNativeCaller(
      [FIREFOX_MANIFEST, FIREFOX_EXTENSION_ID],
      firefoxPolicy
    )).toBe("firefox");
  });

  it.each([
    [FIREFOX_EXTENSION_ID],
    ["/wrong/manifest.json", FIREFOX_EXTENSION_ID],
    [FIREFOX_MANIFEST, "other@example.invalid"],
    [FIREFOX_MANIFEST, FIREFOX_EXTENSION_ID, "extra"],
    [FIREFOX_MANIFEST, "../../unsafe"]
  ])("rejects unauthorized Firefox argv %#", (argv) => {
    expectProtocolError(() => authenticateNativeCaller(argv, firefoxPolicy), "unauthorized_caller");
  });

  it("fails closed on wildcard, duplicate, or malformed trusted policy entries", () => {
    expectProtocolError(() => authenticateNativeCaller([CHROMIUM_ORIGIN], {
      browser_family: "chromium",
      allowed_origins: ["chrome-extension://*/"]
    }), "invalid_configuration");
    expectProtocolError(() => authenticateNativeCaller([CHROMIUM_ORIGIN], {
      browser_family: "chromium",
      allowed_origins: [CHROMIUM_ORIGIN, CHROMIUM_ORIGIN]
    }), "invalid_configuration");
    expectProtocolError(() => authenticateNativeCaller([FIREFOX_MANIFEST, FIREFOX_EXTENSION_ID], {
      browser_family: "firefox",
      manifest_path: `${FIREFOX_MANIFEST}\nignored`,
      allowed_extension_ids: [FIREFOX_EXTENSION_ID]
    }), "invalid_configuration");
    expectProtocolError(() => authenticateNativeCaller([FIREFOX_MANIFEST, FIREFOX_EXTENSION_ID], {
      browser_family: "firefox",
      manifest_path: "relative/manifest.json",
      allowed_extension_ids: [FIREFOX_EXTENSION_ID]
    }), "invalid_configuration");
    expectProtocolError(() => authenticateNativeCaller([CHROMIUM_ORIGIN], {
      browser_family: "chromium",
      allowed_origins: [CHROMIUM_ORIGIN],
      unexpected: true
    } as NativeCallerPolicy), "invalid_configuration");
  });
});

describe("exact native response schemas", () => {
  it("round-trips exact begin, cancel, and failure responses", () => {
    const responses: NativeSetupResponse[] = [
      beginSuccess(),
      {
        version: NATIVE_SETUP_PROTOCOL_VERSION,
        ok: true,
        setup_id: SETUP_ID,
        setup_pairing_cancelled: true
      },
      createNativeSetupFailure("service_unavailable")
    ];
    for (const response of responses) {
      const frame = encodeNativeSetupResponseFrame(response, NOW);
      expect(decodeNativeSetupResponseFrame(frame, NOW)).toEqual(response);
      const payload = frame.subarray(4);
      expect(frame.byteLength).toBe(4 + payload.byteLength);
      expect(payload.toString("utf8")).toBe(JSON.stringify(response));
      expect(payload.includes(0x0a)).toBe(false);
    }
  });

  it.each([
    { version: 1, ok: false, error_code: "unknown" },
    { version: 1, ok: false, error_code: "invalid_request", message: "details" },
    { version: 1, ok: true, setup_id: SETUP_ID, setup_pairing_cancelled: false },
    { ...beginSuccess(), setup_id: "bad" },
    { ...beginSuccess(), setup_secret: "bad" },
    { ...beginSuccess(), browser_family: "zen" },
    { ...beginSuccess(), extra: true }
  ])("rejects malformed or expanded response %#", (response) => {
    expectProtocolError(
      () => decodeNativeSetupResponseFrame(rawFrame(response), NOW),
      "invalid_response"
    );
  });

  it("requires a canonical, future expiry within the five-minute setup window", () => {
    const expired = { ...beginSuccess(), expires_at: new Date(NOW).toISOString() };
    const tooLong = { ...beginSuccess(), expires_at: new Date(NOW + MAX_NATIVE_SETUP_TTL_MS + 1).toISOString() };
    const noncanonical = { ...beginSuccess(), expires_at: "2026-07-28T12:01:00Z" };
    for (const response of [expired, tooLong, noncanonical]) {
      expectProtocolError(
        () => decodeNativeSetupResponseFrame(rawFrame(response), NOW),
        "invalid_response"
      );
    }
  });

  it("never includes rejected secret material in a validation error", () => {
    const marker = "DO-NOT-LEAK-NATIVE-SECRET";
    try {
      encodeNativeSetupResponseFrame({ ...beginSuccess(), setup_secret: marker }, NOW);
      throw new Error("Expected response validation to fail.");
    } catch (error) {
      expect(error).toBeInstanceOf(NativeMessagingProtocolError);
      expect((error as Error).message).not.toContain(marker);
    }
  });
});

describe("one-shot native setup processing", () => {
  it("authenticates and dispatches an exact begin request into one framed response", async () => {
    const beginSetup = vi.fn(operations().beginSetup);
    const cancelSetup = vi.fn(operations().cancelSetup);
    const frame = await processNativeSetupFrame({
      frame: encodeNativeSetupRequestFrame(beginRequest()),
      argv: [CHROMIUM_ORIGIN],
      caller_policy: chromiumPolicy,
      operations: { beginSetup, cancelSetup },
      now: () => NOW
    });

    expect(decodeNativeSetupResponseFrame(frame, NOW)).toEqual(beginSuccess());
    expect(beginSetup).toHaveBeenCalledOnce();
    expect(beginSetup).toHaveBeenCalledWith("chromium");
    expect(cancelSetup).not.toHaveBeenCalled();
  });

  it("dispatches cancellation only for the exact setup ID", async () => {
    const beginSetup = vi.fn(operations().beginSetup);
    const cancelSetup = vi.fn(operations().cancelSetup);
    const response = await processNativeSetupFrame({
      frame: encodeNativeSetupRequestFrame(cancelRequest()),
      argv: [FIREFOX_MANIFEST, FIREFOX_EXTENSION_ID],
      caller_policy: firefoxPolicy,
      operations: { beginSetup, cancelSetup },
      now: () => NOW
    });
    expect(decodeNativeSetupResponseFrame(response, NOW)).toEqual({
      version: 1,
      ok: true,
      setup_id: SETUP_ID,
      setup_pairing_cancelled: true
    });
    expect(cancelSetup).toHaveBeenCalledWith(SETUP_ID);
    expect(beginSetup).not.toHaveBeenCalled();
  });

  it("does not dispatch unauthorized, malformed, multiple, or family-spoofed requests", async () => {
    const beginSetup = vi.fn(operations().beginSetup);
    const cancelSetup = vi.fn(operations().cancelSetup);
    const shared = { operations: { beginSetup, cancelSetup }, now: () => NOW };
    const cases = [
      processNativeSetupFrame({
        ...shared,
        frame: encodeNativeSetupRequestFrame(beginRequest()),
        argv: [`chrome-extension://${"d".repeat(32)}/`],
        caller_policy: chromiumPolicy
      }),
      processNativeSetupFrame({
        ...shared,
        frame: rawFrame({ ...beginRequest(), extra: true }),
        argv: [CHROMIUM_ORIGIN],
        caller_policy: chromiumPolicy
      }),
      processNativeSetupFrame({
        ...shared,
        frame: Buffer.concat([
          encodeNativeSetupRequestFrame(beginRequest()),
          encodeNativeSetupRequestFrame(cancelRequest())
        ]),
        argv: [CHROMIUM_ORIGIN],
        caller_policy: chromiumPolicy
      }),
      processNativeSetupFrame({
        ...shared,
        frame: encodeNativeSetupRequestFrame(beginRequest("firefox")),
        argv: [CHROMIUM_ORIGIN],
        caller_policy: chromiumPolicy
      })
    ];
    const responses = await Promise.all(cases);
    expect(decodeNativeSetupResponseFrame(responses[0] as Buffer, NOW)).toEqual(createNativeSetupFailure("unauthorized_caller"));
    for (const response of responses.slice(1)) {
      expect(decodeNativeSetupResponseFrame(response, NOW)).toEqual(createNativeSetupFailure("invalid_request"));
    }
    expect(beginSetup).not.toHaveBeenCalled();
    expect(cancelSetup).not.toHaveBeenCalled();
  });

  it("converts thrown service details into a generic code without leaking them", async () => {
    const marker = `LEAK-ME-${SETUP_SECRET}`;
    const response = await processNativeSetupFrame({
      frame: encodeNativeSetupRequestFrame(beginRequest()),
      argv: [CHROMIUM_ORIGIN],
      caller_policy: chromiumPolicy,
      operations: operations({
        beginSetup: async () => { throw new Error(marker); }
      }),
      now: () => NOW
    });
    expect(decodeNativeSetupResponseFrame(response, NOW)).toEqual(createNativeSetupFailure("operation_failed"));
    expect(response.toString("utf8")).not.toContain(marker);
    expect(response.toString("utf8")).not.toContain(SETUP_SECRET);
  });

  it("fails closed when a service returns mismatched or invalid setup material", async () => {
    const mismatchedFamily = await processNativeSetupFrame({
      frame: encodeNativeSetupRequestFrame(beginRequest()),
      argv: [CHROMIUM_ORIGIN],
      caller_policy: chromiumPolicy,
      operations: operations({
        beginSetup: async () => ({ ...beginSuccess("firefox") })
      }),
      now: () => NOW
    });
    expect(decodeNativeSetupResponseFrame(mismatchedFamily, NOW))
      .toEqual(createNativeSetupFailure("operation_failed"));

    const mismatchedCancel = await processNativeSetupFrame({
      frame: encodeNativeSetupRequestFrame(cancelRequest()),
      argv: [FIREFOX_MANIFEST, FIREFOX_EXTENSION_ID],
      caller_policy: firefoxPolicy,
      operations: operations({
        cancelSetup: async () => ({
          setup_id: "d".repeat(24),
          setup_pairing_cancelled: true
        })
      }),
      now: () => NOW
    });
    expect(decodeNativeSetupResponseFrame(mismatchedCancel, NOW))
      .toEqual(createNativeSetupFailure("operation_failed"));
  });
});
