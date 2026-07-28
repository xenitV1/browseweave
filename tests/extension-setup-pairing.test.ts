import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import {
  PROTOCOL_VERSION,
  SETUP_VERSION,
  setupPairingAadPayload,
  setupPairingClientProofPayload,
  setupPairingKeySalt,
  type BrowserIdentity,
  type P256PublicJwk,
  type SetupPairingRequest,
  type SetupPairingResponse
} from "../src/protocol";
import { APP_VERSION } from "../src/version";
import {
  SETUP_CONNECT_BUTTON_ID,
  SETUP_CONNECT_BUTTON_TEXT,
  SETUP_ENCRYPTION_KEY_INFO,
  SETUP_ROOT_ID,
  SETUP_STATUS_ID,
  SETUP_TICKET_PATH,
  SetupPairingHandshake,
  parseSetupPageUrl,
  parseSetupTicketText,
  setupAuthenticationMatches,
  setupDomContractMatches,
  setupSenderMatches,
  startSetupPairingTransport,
  storedTokenSnapshotHasValue,
  storedTokenSnapshotsEqual,
  trustedSetupClick,
  type SetupPairingTransportSocket
} from "../extension/src/setup-pairing";

const SETUP_ID = "0123456789abcdef01234567";
const SETUP_SECRET = "0123456789abcdef".repeat(4);
const OTHER_SECRET = "fedcba9876543210".repeat(4);
const ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
const TOKEN = "pairing-key-abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFG";
const identity: BrowserIdentity = {
  installation_id: "12345678-1234-4234-8234-123456789abc",
  browser_family: "chromium",
  browser_name: "Chromium",
  browser_version: "150.0.0.0",
  extension_version: APP_VERSION
};
const publicKey: P256PublicJwk = {
  kty: "EC",
  crv: "P-256",
  x: "A".repeat(43),
  y: "A".repeat(43),
  ext: true,
  key_ops: ["verify"]
};

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function nonce(byte: number): string {
  return base64Url(new Uint8Array(32).fill(byte));
}

async function hmac(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))));
}

async function encryptedResponse(input: {
  setupSecret: string;
  clientNonce: string;
  token?: string;
  expiresAt?: string;
  serverNonce?: string;
}): Promise<SetupPairingResponse> {
  const serverNonce = input.serverNonce ?? nonce(2);
  const expiresAt = input.expiresAt ?? new Date(Date.now() + 10_000).toISOString();
  const daemonInstanceId = "daemon-test-instance";
  const ikm = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(input.setupSecret),
    "HKDF",
    false,
    ["deriveKey"]
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(setupPairingKeySalt({
        setupId: SETUP_ID,
        clientNonce: input.clientNonce,
        serverNonce
      })),
      info: new TextEncoder().encode(SETUP_ENCRYPTION_KEY_INFO)
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const iv = new Uint8Array(12).fill(7);
  const aad = setupPairingAadPayload({
    setupId: SETUP_ID,
    clientNonce: input.clientNonce,
    serverNonce,
    daemonInstanceId,
    origin: ORIGIN,
    identity,
    publicKey,
    expiresAt
  });
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad), tagLength: 128 },
    key,
    new TextEncoder().encode(input.token ?? TOKEN)
  );
  return {
    type: "setup_pair_response",
    protocol_version: PROTOCOL_VERSION,
    setup_version: SETUP_VERSION,
    setup_id: SETUP_ID,
    client_nonce: input.clientNonce,
    server_nonce: serverNonce,
    daemon_instance_id: daemonInstanceId,
    expires_at: expiresAt,
    iv: base64Url(iv),
    encrypted_pairing_token: base64Url(new Uint8Array(ciphertext))
  };
}

function handshake(secret = SETUP_SECRET): SetupPairingHandshake {
  return new SetupPairingHandshake(
    { setupId: SETUP_ID, setupSecret: secret, origin: ORIGIN, identity, publicKey },
    { clientNonce: nonce(1) }
  );
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(error: Error): void;
} {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

class FakeSetupSocket implements SetupPairingTransportSocket {
  readyState = 1;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: (() => void) | null = null;
  readonly sent: string[] = [];
  readonly closeCalls: Array<{ code?: number; reason?: string }> = [];

  send(data: string): void {
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    this.readyState = 3;
    this.closeCalls.push({ code, reason });
  }

  emitOpen(): void {
    this.onopen?.();
  }

  emitMessage(data: unknown): void {
    this.onmessage?.({ data });
  }

  emitError(): void {
    this.onerror?.();
  }

  emitClose(): void {
    this.readyState = 3;
    this.onclose?.();
  }
}

function setupTransport(
  socket: FakeSetupSocket,
  acceptResponse: (response: unknown) => Promise<string>,
  cancelAuthentication: () => void = () => undefined
) {
  return startSetupPairingTransport({
    createSocket: () => socket,
    createRequest: async (): Promise<SetupPairingRequest> => ({
      type: "setup_pair_request",
      protocol_version: PROTOCOL_VERSION,
      setup_version: SETUP_VERSION,
      setup_id: SETUP_ID,
      client_nonce: nonce(1),
      origin: ORIGIN,
      identity,
      public_key: publicKey,
      client_proof: nonce(3)
    }),
    acceptResponse,
    cancelAuthentication,
    cancelled: () => false,
    openReadyState: 1
  });
}

describe("one-click local setup protocol", () => {
  it("binds every required client-proof, salt, and encrypted-response field", () => {
    const clientInput = {
      setupId: SETUP_ID,
      clientNonce: nonce(1),
      origin: ORIGIN,
      installationId: identity.installation_id,
      publicKey
    };
    const clientPayload = setupPairingClientProofPayload(clientInput);
    expect(clientPayload).toContain("BrowseWeave setup client proof v1\n");
    expect(clientPayload).toContain("protocol_version:1:3\nsetup_version:1:1\n");
    expect([
      { ...clientInput, setupId: "1123456789abcdef01234567" },
      { ...clientInput, clientNonce: nonce(3) },
      { ...clientInput, origin: "moz-extension://different" },
      { ...clientInput, installationId: "22345678-1234-4234-8234-123456789abc" },
      { ...clientInput, publicKey: { ...publicKey, x: "B".repeat(43) } }
    ].map(setupPairingClientProofPayload)).not.toContain(clientPayload);

    const saltInput = { setupId: SETUP_ID, clientNonce: nonce(1), serverNonce: nonce(2) };
    const salt = setupPairingKeySalt(saltInput);
    expect(setupPairingKeySalt({ ...saltInput, setupId: "1123456789abcdef01234567" })).not.toBe(salt);
    expect(setupPairingKeySalt({ ...saltInput, clientNonce: nonce(3) })).not.toBe(salt);
    expect(setupPairingKeySalt({ ...saltInput, serverNonce: nonce(4) })).not.toBe(salt);

    const aadInput = {
      ...saltInput,
      daemonInstanceId: "daemon-test-instance",
      origin: ORIGIN,
      identity,
      publicKey,
      expiresAt: "2030-01-01T00:00:00.000Z"
    };
    const aad = setupPairingAadPayload(aadInput);
    const variants = [
      { ...aadInput, setupId: "1123456789abcdef01234567" },
      { ...aadInput, clientNonce: nonce(3) },
      { ...aadInput, serverNonce: nonce(4) },
      { ...aadInput, daemonInstanceId: "other-daemon" },
      { ...aadInput, origin: "moz-extension://different" },
      { ...aadInput, identity: { ...identity, browser_name: "Other" } },
      { ...aadInput, publicKey: { ...publicKey, y: "B".repeat(43) } },
      { ...aadInput, expiresAt: "2030-01-01T00:00:01.000Z" }
    ];
    expect(variants.every((variant) => setupPairingAadPayload(variant) !== aad)).toBe(true);
  });

  it("proves the request and decrypts the one-use AES-GCM response", async () => {
    const exchange = handshake();
    const request = await exchange.createRequest();
    expect(Object.keys(request).sort()).toEqual([
      "client_nonce", "client_proof", "identity", "origin", "protocol_version",
      "public_key", "setup_id", "setup_version", "type"
    ]);
    expect(JSON.stringify(request)).not.toContain(SETUP_SECRET);
    expect(request.client_proof).toBe(await hmac(SETUP_SECRET, setupPairingClientProofPayload({
      setupId: SETUP_ID,
      clientNonce: request.client_nonce,
      origin: ORIGIN,
      installationId: identity.installation_id,
      publicKey
    })));
    await expect(exchange.acceptResponse(await encryptedResponse({
      setupSecret: SETUP_SECRET,
      clientNonce: request.client_nonce
    }))).resolves.toBe(TOKEN);
    expect(exchange.phase).toBe("complete");
  });

  it("fails closed on a wrong secret, tampering, replay, unknown fields, and malformed responses", async () => {
    const wrong = handshake(OTHER_SECRET);
    const wrongRequest = await wrong.createRequest();
    const wrongResponse = await encryptedResponse({ setupSecret: SETUP_SECRET, clientNonce: wrongRequest.client_nonce });
    await expect(wrong.acceptResponse(wrongResponse)).rejects.not.toThrow(OTHER_SECRET);
    expect(wrong.phase).toBe("failed");

    const tampered = handshake();
    const tamperedRequest = await tampered.createRequest();
    const response = await encryptedResponse({ setupSecret: SETUP_SECRET, clientNonce: tamperedRequest.client_nonce });
    const ciphertext = Buffer.from(response.encrypted_pairing_token, "base64url");
    ciphertext[0] = (ciphertext[0] ?? 0) ^ 1;
    await expect(tampered.acceptResponse({
      ...response,
      encrypted_pairing_token: ciphertext.toString("base64url")
    })).rejects.toThrow(/authenticate/iu);

    const replayed = handshake();
    const replayRequest = await replayed.createRequest();
    const replayResponse = await encryptedResponse({ setupSecret: SETUP_SECRET, clientNonce: replayRequest.client_nonce });
    await replayed.acceptResponse(replayResponse);
    await expect(replayed.acceptResponse(replayResponse)).rejects.toThrow(/replayed|out-of-order/iu);

    const malformed = handshake();
    const malformedRequest = await malformed.createRequest();
    await expect(malformed.acceptResponse({
      ...await encryptedResponse({ setupSecret: SETUP_SECRET, clientNonce: malformedRequest.client_nonce }),
      unexpected: true
    })).rejects.toThrow(/authenticate/iu);
    await expect(malformed.createRequest()).rejects.toThrow(/duplicate|out-of-order/iu);

    const concurrent = handshake();
    const concurrentRequest = await concurrent.createRequest();
    const concurrentResponse = await encryptedResponse({
      setupSecret: SETUP_SECRET,
      clientNonce: concurrentRequest.client_nonce
    });
    const outcomes = await Promise.allSettled([
      concurrent.acceptResponse(concurrentResponse),
      concurrent.acceptResponse(concurrentResponse)
    ]);
    expect(outcomes.every((outcome) => outcome.status === "rejected")).toBe(true);
    expect(concurrent.phase).toBe("failed");
  });

  it("expires locally after no more than fifteen seconds", async () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date("2026-07-28T12:00:00.000Z"));
      const exchange = new SetupPairingHandshake(
        { setupId: SETUP_ID, setupSecret: SETUP_SECRET, origin: ORIGIN, identity, publicKey },
        { clientNonce: nonce(1), timeoutMs: 15_000 }
      );
      await exchange.createRequest();
      vi.advanceTimersByTime(15_000);
      await expect(exchange.acceptResponse({})).rejects.toThrow(/expired/iu);
      expect(exchange.phase).toBe("failed");
    } finally {
      vi.useRealTimers();
    }
  });

  it("cancels a setup transcript idempotently and fails it closed", async () => {
    const exchange = handshake();
    exchange.cancel();
    exchange.cancel();
    expect(exchange.phase).toBe("failed");
    await expect(exchange.createRequest()).rejects.toThrow(/duplicate|out-of-order/iu);
  });
});

describe("one-click setup page boundary", () => {
  it("accepts only an exact top-frame IPv4 loopback setup URL on a non-privileged port", () => {
    const valid = `http://127.0.0.1:32110/setup/${SETUP_ID}`;
    expect(parseSetupPageUrl(valid, true)).toEqual({
      setupId: SETUP_ID,
      origin: "http://127.0.0.1:32110",
      href: valid
    });
    expect(parseSetupPageUrl(`http://127.0.0.1:1024/setup/${SETUP_ID}`, true)).not.toBeNull();
    expect(parseSetupPageUrl(`http://127.0.0.1:65535/setup/${SETUP_ID}`, true)).not.toBeNull();
    for (const invalid of [
      `https://127.0.0.1:32110/setup/${SETUP_ID}`,
      `http://localhost:32110/setup/${SETUP_ID}`,
      `http://127.0.0.1:1023/setup/${SETUP_ID}`,
      `http://127.0.0.1:32110/setup/${SETUP_ID}?again=1`,
      `http://127.0.0.1:32110/setup/${SETUP_ID}#fragment`,
      `http://127.0.0.1:32110/setup/${SETUP_ID.toUpperCase()}`
    ]) expect(parseSetupPageUrl(invalid, true)).toBeNull();
    expect(parseSetupPageUrl(valid, false)).toBeNull();
  });

  it("locks the exact DOM marker, trusted click, and extension-content sender contract", () => {
    const dom = {
      rootId: SETUP_ROOT_ID,
      setupIdAttribute: SETUP_ID,
      buttonId: SETUP_CONNECT_BUTTON_ID,
      buttonText: SETUP_CONNECT_BUTTON_TEXT,
      statusId: SETUP_STATUS_ID
    };
    expect(setupDomContractMatches(dom, SETUP_ID)).toBe(true);
    expect(setupDomContractMatches({ ...dom, setupIdAttribute: "1123456789abcdef01234567" }, SETUP_ID)).toBe(false);
    expect(setupDomContractMatches({ ...dom, buttonText: "Connect" }, SETUP_ID)).toBe(false);
    expect(trustedSetupClick(true, SETUP_CONNECT_BUTTON_ID, SETUP_CONNECT_BUTTON_TEXT)).toBe(true);
    expect(trustedSetupClick(false, SETUP_CONNECT_BUTTON_ID, SETUP_CONNECT_BUTTON_TEXT)).toBe(false);

    const sender = {
      extensionId: "extension-id",
      senderId: "extension-id",
      senderUrl: `http://127.0.0.1:32110/setup/${SETUP_ID}`,
      frameId: 0,
      setupId: SETUP_ID
    };
    expect(setupSenderMatches(sender)).toBe(true);
    expect(setupSenderMatches({ ...sender, senderId: "other" })).toBe(false);
    expect(setupSenderMatches({ ...sender, frameId: 1 })).toBe(false);
    expect(setupSenderMatches({ ...sender, setupId: "1123456789abcdef01234567" })).toBe(false);
  });

  it("accepts setup success only for the exact authenticated main-connection generation and installation", () => {
    const connected = {
      expectedGeneration: 7,
      currentGeneration: 7,
      expectedInstallationId: identity.installation_id,
      currentInstallationId: identity.installation_id,
      authenticated: true,
      phase: "connected",
      socketOpen: true
    };
    expect(setupAuthenticationMatches(connected)).toBe(true);
    expect(setupAuthenticationMatches({ ...connected, currentGeneration: 8 })).toBe(false);
    expect(setupAuthenticationMatches({ ...connected, currentInstallationId: "22345678-1234-4234-8234-123456789abc" })).toBe(false);
    expect(setupAuthenticationMatches({ ...connected, authenticated: false })).toBe(false);
    expect(setupAuthenticationMatches({ ...connected, phase: "authenticating" })).toBe(false);
    expect(setupAuthenticationMatches({ ...connected, socketOpen: false })).toBe(false);
  });

  it("restores a setup token only while storage still contains that attempt's exact value", () => {
    const missing = { present: false } as const;
    const prior = { present: true, value: "old-token" } as const;
    const staged = { present: true, value: TOKEN } as const;
    const concurrentSettingsChange = { present: true, value: "user-changed-token" } as const;
    expect(storedTokenSnapshotsEqual(missing, { present: false })).toBe(true);
    expect(storedTokenSnapshotsEqual(prior, { present: true, value: "old-token" })).toBe(true);
    expect(storedTokenSnapshotsEqual(prior, staged)).toBe(false);
    expect(storedTokenSnapshotHasValue(staged, TOKEN)).toBe(true);
    expect(storedTokenSnapshotHasValue(concurrentSettingsChange, TOKEN)).toBe(false);
    expect(storedTokenSnapshotHasValue(missing, TOKEN)).toBe(false);
  });

  it("removes the single trusted installer refresh directive only after setup controls validate", () => {
    const contentSource = readFileSync(new URL("../extension/src/content.ts", import.meta.url), "utf8");
    const setupStart = contentSource.indexOf("function initializeSetupPage");
    const setupEnd = contentSource.indexOf("if (!window.__browseWeaveContentReady", setupStart);
    const setup = contentSource.slice(setupStart, setupEnd);
    const validation = setup.indexOf("if (!valid || !root || !button || !status)");
    const refreshLookup = setup.indexOf('document.querySelectorAll<HTMLMetaElement>("#browseweave-auto-refresh")');
    const refreshRemoval = setup.indexOf("refreshDirectives[0].remove()", refreshLookup);
    const clickListener = setup.indexOf('button.addEventListener("click"', refreshRemoval);
    expect(validation).toBeGreaterThan(-1);
    expect(refreshLookup).toBeGreaterThan(validation);
    expect(refreshRemoval).toBeGreaterThan(refreshLookup);
    expect(clickListener).toBeGreaterThan(refreshRemoval);
    expect(setup).toContain('refreshDirectives.length === 1 && refreshDirectives[0]?.tagName === "META"');
  });

  it("accepts only an exact, short-lived, same-ID extension ticket", () => {
    const now = Date.parse("2026-07-28T12:00:00.000Z");
    const expiresAt = "2026-07-28T12:04:00.000Z";
    const exact = JSON.stringify({
      version: 1,
      setup_id: SETUP_ID,
      setup_secret: SETUP_SECRET,
      expires_at: expiresAt
    });
    expect(parseSetupTicketText(exact, SETUP_ID, now)).toEqual({
      version: 1,
      setup_id: SETUP_ID,
      setup_secret: SETUP_SECRET,
      expires_at: expiresAt
    });
    expect(parseSetupTicketText(`${exact}\n`, SETUP_ID, now)).toEqual(expect.objectContaining({ setup_id: SETUP_ID }));
    for (const invalid of [
      JSON.stringify({ version: 1, setup_id: SETUP_ID, setup_secret: SETUP_SECRET, expires_at: "2026-07-28T12:06:00.000Z" }),
      JSON.stringify({ version: 1, setup_id: SETUP_ID, setup_secret: SETUP_SECRET, expires_at: "2026-07-28T11:59:59.000Z" }),
      `{ "version": 1, "setup_id": "${SETUP_ID}", "setup_secret": "${SETUP_SECRET}", "expires_at": "${expiresAt}" }`,
      `{"version":1,"version":1,"setup_id":"${SETUP_ID}","setup_secret":"${SETUP_SECRET}","expires_at":"${expiresAt}"}`,
      JSON.stringify({ version: 1, setup_id: SETUP_ID, setup_secret: SETUP_SECRET.toUpperCase(), expires_at: expiresAt })
    ]) expect(() => parseSetupTicketText(invalid, SETUP_ID, now)).toThrow(/ticket/iu);
    expect(() => parseSetupTicketText(exact, "1123456789abcdef01234567", now)).toThrow(/ticket/iu);
  });

  it("keeps setup material out of the loopback page, messages, logs, and public results", () => {
    const contentSource = readFileSync(new URL("../extension/src/content.ts", import.meta.url), "utf8");
    const backgroundSource = readFileSync(new URL("../extension/src/background.ts", import.meta.url), "utf8");
    const setupSource = readFileSync(new URL("../extension/src/setup-pairing.ts", import.meta.url), "utf8");
    const chromiumManifest = readFileSync(new URL("../extension/manifests/chromium-mv3.json", import.meta.url), "utf8");
    const firefoxManifest = readFileSync(new URL("../extension/manifests/firefox-mv2.json", import.meta.url), "utf8");
    const clickStart = contentSource.indexOf('button.addEventListener("click"');
    const clickEnd = contentSource.indexOf("}, { capture: true });", clickStart);
    const click = contentSource.slice(clickStart, clickEnd);
    expect(click).toContain('kind: "setup:pair"');
    expect(click).toContain("setup_id: page.setupId");
    expect(click).not.toContain("setup_secret");
    expect(contentSource).not.toContain("data-setup-secret");
    expect(contentSource).not.toContain("setup_secret");
    expect(click).not.toContain("innerHTML");
    expect(`${contentSource}\n${backgroundSource}\n${setupSource}`).not.toMatch(/console\.(?:log|info|debug|warn|error)\s*\(/u);
    expect(backgroundSource).not.toMatch(/JSON\.stringify\([^)]*setupSecret/iu);
    expect(backgroundSource).toContain(`runtime.getURL(SETUP_TICKET_PATH)`);
    expect(backgroundSource).toContain("Promise.race([operation, timeout])");
    expect(backgroundSource).toContain("controller.abort()");
    expect(SETUP_TICKET_PATH).toBe("setup-ticket.json");
    expect(`${chromiumManifest}\n${firefoxManifest}`).not.toContain("web_accessible_resources");
    const responseSurface = backgroundSource.slice(
      backgroundSource.indexOf("async function receiveSetupPairingToken"),
      backgroundSource.indexOf("async function sendSignedHello")
    );
    expect(responseSurface).toContain("return { ok: true }");
    expect(responseSurface).toContain("return { ok: false }");
    expect(responseSurface).not.toMatch(/return\s+\{[^}]*pairingToken/isu);
    expect(responseSurface).toContain("const priorTokenSnapshot = storedTokenSnapshot()");
    expect(responseSurface).toContain("await restoreStoredTokenIfCurrent(prior, stagedPairingToken)");
    expect(responseSurface).toContain("if (tokenCommit && !durableCommitAttempted)");
    const provisioningPhase = responseSurface.indexOf('setupPhase: "provisioning"');
    const firstAuthenticationWait = responseSurface.indexOf("await waitForSetupAuthentication", provisioningPhase);
    expect(provisioningPhase).toBeGreaterThan(-1);
    expect(provisioningPhase).toBeLessThan(firstAuthenticationWait);
    expect(firstAuthenticationWait)
      .toBeLessThan(responseSurface.indexOf("tokenCommit = extensionBrowser.storage.local.set"));
    const tokenCommitStart = responseSurface.indexOf("tokenCommit = extensionBrowser.storage.local.set");
    const tokenCommitWait = responseSurface.indexOf("await tokenCommit;", tokenCommitStart);
    expect(tokenCommitStart).toBeLessThan(tokenCommitWait);
    expect(tokenCommitWait)
      .toBeLessThan(responseSurface.indexOf('setupPhase: "persisted"'));
    const persistedPhase = responseSurface.indexOf('setupPhase: "persisted"');
    expect(responseSurface.indexOf("durableCommitAttempted = true")).toBeLessThan(persistedPhase);
    expect(responseSurface).toContain("pairingToken: persistedPairingToken");
    const durableAuthenticationWait = responseSurface.indexOf("await waitForCurrentAttempt()", persistedPhase);
    expect(persistedPhase).toBeLessThan(durableAuthenticationWait);
    expect(durableAuthenticationWait).toBeLessThan(responseSurface.indexOf("return { ok: true }"));
    expect(responseSurface).toContain("await rollback().catch(() => undefined)");
    expect(responseSurface).toContain('if (result === "timeout")');
    const tokenRestoration = backgroundSource.slice(
      backgroundSource.indexOf("async function restoreStoredToken"),
      backgroundSource.indexOf("function scheduleReconnect")
    );
    expect(tokenRestoration).toContain("snapshot.value");
    expect(tokenRestoration).toContain("storage.local.remove(TOKEN_STORAGE_KEY)");
    expect(tokenRestoration).toContain("storedTokenSnapshotHasValue(current, expectedCurrentValue)");
    const mainConnect = backgroundSource.slice(
      backgroundSource.indexOf("async function connect("),
      backgroundSource.indexOf("async function loadSetupTicket")
    );
    expect(mainConnect).toContain("staged?.pairingToken ?? ordinaryOverride?.pairingToken ?? await storedToken()");
    expect(mainConnect).toContain("identity.installation_id !== expectedInstallationId");
    expect(mainConnect).toContain("stagedSetupId: staged.setupId");
    expect(mainConnect).toContain("stagedSetupPhase: staged.setupPhase");
    const authenticationWait = backgroundSource.slice(
      backgroundSource.indexOf("async function waitForSetupAuthentication"),
      backgroundSource.indexOf("async function receiveSetupPairingToken")
    );
    expect(authenticationWait).toContain("connectionGeneration !== input.generation");
    expect(authenticationWait).toContain("setupAuthenticationMatches({");
    expect(authenticationWait).toContain("currentIdentity?.installation_id");
    expect(backgroundSource).toContain("TOKEN_STORAGE_KEY in changes && !setupPairingInProgress");
  });

  it("retries when a persisted setup request never reaches the daemon", () => {
    const backgroundSource = readFileSync(new URL("../extension/src/background.ts", import.meta.url), "utf8");
    const responseSurface = backgroundSource.slice(
      backgroundSource.indexOf("async function receiveSetupPairingToken"),
      backgroundSource.indexOf("async function sendSignedHello")
    );
    expect(responseSurface).toContain("for (let attempt = 0; attempt < 3; attempt += 1)");
    expect(responseSurface).toContain('setupPhase: "persisted"');
    expect(responseSurface).toContain("the setup-bound persisted attempt remains retryable");
    expect(responseSurface.indexOf("for (let attempt = 0; attempt < 3; attempt += 1)"))
      .toBeLessThan(responseSurface.indexOf('setupPhase: "persisted"'));
  });

  it("finishes response authentication after immediate close and error events", async () => {
    const socket = new FakeSetupSocket();
    const response = deferred<string>();
    const cancelAuthentication = vi.fn();
    const exchange = setupTransport(socket, () => response.promise, cancelAuthentication);
    socket.emitOpen();
    await vi.waitFor(() => expect(socket.sent).toHaveLength(1));
    socket.emitMessage('{"safe":"response"}');
    socket.emitClose();
    socket.emitError();
    response.resolve(TOKEN);
    await expect(exchange.result).resolves.toBe(TOKEN);
    expect(socket.closeCalls).toEqual([{ code: 1000, reason: "setup complete" }]);
    expect(cancelAuthentication).not.toHaveBeenCalled();
  });

  it("rejects and cleans up a malformed response", async () => {
    const socket = new FakeSetupSocket();
    const acceptResponse = vi.fn(async () => TOKEN);
    const cancelAuthentication = vi.fn();
    const exchange = setupTransport(socket, acceptResponse, cancelAuthentication);
    socket.emitMessage("{");
    await expect(exchange.result).rejects.toThrow(/authenticate/iu);
    expect(acceptResponse).not.toHaveBeenCalled();
    expect(socket.closeCalls).toHaveLength(1);
    expect(socket.onopen).toBeNull();
    expect(socket.onmessage).toBeNull();
    expect(socket.onerror).toBeNull();
    expect(socket.onclose).toBeNull();
    expect(cancelAuthentication).toHaveBeenCalledTimes(1);
  });

  it.each(["error", "close"] as const)("rejects a transport %s before any response", async (event) => {
    const socket = new FakeSetupSocket();
    const cancelAuthentication = vi.fn();
    const exchange = setupTransport(socket, async () => TOKEN, cancelAuthentication);
    if (event === "error") socket.emitError();
    else socket.emitClose();
    await expect(exchange.result).rejects.toThrow(event === "error" ? /reached/iu : /closed/iu);
    expect(socket.closeCalls).toHaveLength(1);
    expect(cancelAuthentication).toHaveBeenCalledTimes(1);
  });

  it("flattens a socket-construction failure and cancels authentication", async () => {
    const cancelAuthentication = vi.fn();
    const exchange = startSetupPairingTransport({
      createSocket: () => {
        throw new Error("sensitive constructor detail");
      },
      createRequest: async () => {
        throw new Error("must not run");
      },
      acceptResponse: async () => TOKEN,
      cancelAuthentication,
      cancelled: () => false,
      openReadyState: 1
    });
    await expect(exchange.result).rejects.toThrow("The local setup service could not be reached.");
    await expect(exchange.result).rejects.not.toThrow(/sensitive/iu);
    expect(cancelAuthentication).toHaveBeenCalledTimes(1);
  });

  it("fails closed on a duplicate response while authentication is pending", async () => {
    const socket = new FakeSetupSocket();
    const response = deferred<string>();
    const cancelAuthentication = vi.fn();
    const exchange = setupTransport(socket, () => response.promise, cancelAuthentication);
    socket.emitMessage('{"safe":"first"}');
    socket.emitMessage('{"safe":"duplicate"}');
    await expect(exchange.result).rejects.toThrow(/authenticate/iu);
    response.resolve(TOKEN);
    await Promise.resolve();
    expect(socket.closeCalls).toHaveLength(1);
    expect(cancelAuthentication).toHaveBeenCalledTimes(1);
  });

  it("cleans up a hung response when the outer timeout cancels the exchange", async () => {
    const socket = new FakeSetupSocket();
    const cancelAuthentication = vi.fn(() => {
      throw new Error("simulated cleanup failure");
    });
    const exchange = setupTransport(
      socket,
      () => new Promise<string>(() => undefined),
      cancelAuthentication
    );
    socket.emitMessage('{"safe":"response"}');
    exchange.cancel();
    exchange.cancel();
    await expect(exchange.result).rejects.toThrow(/timed out/iu);
    expect(socket.closeCalls).toHaveLength(1);
    expect(socket.onopen).toBeNull();
    expect(socket.onmessage).toBeNull();
    expect(socket.onerror).toBeNull();
    expect(socket.onclose).toBeNull();
    expect(cancelAuthentication).toHaveBeenCalledTimes(1);
  });

  it("ignores a late successful decrypt after timeout cleanup", async () => {
    const socket = new FakeSetupSocket();
    const response = deferred<string>();
    const exchange = setupTransport(socket, () => response.promise);
    const resolved = vi.fn();
    const rejected = vi.fn();
    void exchange.result.then(resolved, rejected);
    socket.emitMessage('{"safe":"response"}');
    exchange.cancel();
    await expect(exchange.result).rejects.toThrow(/timed out/iu);
    response.resolve(TOKEN);
    await Promise.resolve();
    await Promise.resolve();
    expect(resolved).not.toHaveBeenCalled();
    expect(rejected).toHaveBeenCalledTimes(1);
    expect(socket.closeCalls).toHaveLength(1);
  });

  it("absorbs a late decrypt rejection after timeout without settling twice", async () => {
    const socket = new FakeSetupSocket();
    const response = deferred<string>();
    const exchange = setupTransport(socket, () => response.promise);
    const resolved = vi.fn();
    const rejected = vi.fn();
    void exchange.result.then(resolved, rejected);
    socket.emitMessage('{"safe":"response"}');
    exchange.cancel();
    await expect(exchange.result).rejects.toThrow(/timed out/iu);
    response.reject(new Error("late sensitive decrypt failure"));
    await Promise.resolve();
    await Promise.resolve();
    expect(resolved).not.toHaveBeenCalled();
    expect(rejected).toHaveBeenCalledTimes(1);
    expect(socket.closeCalls).toHaveLength(1);
  });

  it("proves a lost persisted acknowledgement with ordinary new-token authentication before rollback", () => {
    const backgroundSource = readFileSync(new URL("../extension/src/background.ts", import.meta.url), "utf8");
    const responseSurface = backgroundSource.slice(
      backgroundSource.indexOf("async function receiveSetupPairingToken"),
      backgroundSource.indexOf("async function sendSignedHello")
    );
    const durableAttempt = responseSurface.indexOf("durableCommitAttempted = true");
    const ordinaryNewTokenProof = responseSurface.indexOf("await connect(undefined, {", durableAttempt);
    const legacyProof = responseSurface.lastIndexOf("await connect(undefined, {");
    const guardedRestore = responseSurface.indexOf(
      "await restoreStoredTokenIfCurrent(prior, persistedPairingToken)",
      legacyProof
    );
    expect(durableAttempt).toBeLessThan(ordinaryNewTokenProof);
    expect(ordinaryNewTokenProof).toBeLessThan(legacyProof);
    expect(legacyProof).toBeLessThan(guardedRestore);
    expect(responseSurface).toContain("Without positive legacy-authentication proof, retaining the new token is safer.");
  });
});
