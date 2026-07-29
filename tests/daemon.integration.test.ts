import {
  createHash,
  createHmac,
  generateKeyPairSync,
  randomBytes,
  sign as signPayload,
  timingSafeEqual,
  webcrypto,
  type KeyObject
} from "node:crypto";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import WebSocket from "ws";
import { afterEach, describe, expect, it } from "vitest";
import {
  APPROVAL_TTL_MS,
  MAX_COMMAND_PAYLOAD_BYTES,
  MAX_IPC_MESSAGE_BYTES,
  MAX_PENDING_APPROVALS,
  MAX_PENDING_COMMANDS,
  MAX_WS_PAYLOAD_BYTES,
  type DaemonConfig
} from "../src/core/config.js";
import { BrowseWeaveDaemon } from "../src/daemon.js";
import { callBridge } from "../src/bridge/ipc-client.js";
import {
  PROTOCOL_VERSION,
  SETUP_VERSION,
  approvalDecisionSigningPayload,
  canonicalJson,
  canonicalPublicJwk,
  extensionClientProofPayload,
  extensionServerProofPayload,
  helloSigningPayload,
  ipcClientProofPayload,
  ipcServerProofPayload,
  setupPairingAadPayload,
  setupPairingClientProofPayload,
  setupPairingKeySalt,
  type BrowserIdentity,
  type IpcResponse,
  type JsonObject,
  type P256PublicJwk,
  type SetupPairingResponse,
  SESSION_CHALLENGE_PATTERN
} from "../src/core/protocol.js";

const TOKEN = "a".repeat(64);
const IPC_TOKEN = "b".repeat(64);
const FIREFOX_ORIGIN = "moz-extension://12345678-abcd-4321-abcd-1234567890ab";
const CHROMIUM_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
const FINGERPRINT_A = `sha256:${"a".repeat(64)}`;
const FINGERPRINT_B = `sha256:${"b".repeat(64)}`;
const SECRET_TEXT = "SECRET-VALUE-NEVER-AUDIT";
const UNTRUSTED_LABEL = "UNTRUSTED-PAGE-LABEL-NEVER-AUDIT";
const SETUP_SECRET = "0123456789abcdef".repeat(4);
const OTHER_SETUP_SECRET = "fedcba9876543210".repeat(4);
const SETUP_ENCRYPTION_KEY_INFO = "BrowseWeave setup encryption key v1";
const SETUP_MAX_TTL_FOR_TEST = 5 * 60_000;

interface Harness {
  root: string;
  config: DaemonConfig;
  daemon: BrowseWeaveDaemon;
}

interface SigningIdentity {
  privateKey: KeyObject;
  publicKey: P256PublicJwk;
  identity: BrowserIdentity;
}

interface ExtensionClient {
  socket: WebSocket;
  browserId: string;
  daemonInstanceId: string;
  signing: SigningIdentity;
  next(type?: string, timeoutMs?: number): Promise<JsonObject>;
}

const harnesses: Harness[] = [];
const sockets: WebSocket[] = [];
const enrolledInstallationsByRoot = new Map<string, Set<string>>();

function makeSigningIdentity(
  installationId: string,
  browserFamily: "firefox" | "chromium" = "firefox"
): SigningIdentity {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const exported = pair.publicKey.export({ format: "jwk" });
  if (!exported.x || !exported.y) throw new Error("Test key export failed");
  return {
    privateKey: pair.privateKey,
    publicKey: {
      kty: "EC",
      crv: "P-256",
      x: exported.x,
      y: exported.y,
      ext: true,
      key_ops: ["verify"]
    },
    identity: {
      installation_id: installationId,
      browser_family: browserFamily,
      browser_name: browserFamily === "firefox" ? "Test Firefox" : "Test Chromium",
      browser_version: "1.0",
      extension_version: "0.2.0"
    }
  };
}

function signature(privateKey: KeyObject, payload: string): string {
  return signPayload(
    "sha256",
    Buffer.from(payload, "utf8"),
    { key: privateKey, dsaEncoding: "ieee-p1363" }
  ).toString("base64url");
}

function nonce(): string {
  return randomBytes(32).toString("base64url");
}

function hmacProof(secret: string, payload: string): string {
  return createHmac("sha256", Buffer.from(secret, "utf8"))
    .update(payload, "utf8")
    .digest("base64url");
}

function proofMatches(candidate: unknown, expected: string): boolean {
  if (typeof candidate !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(candidate)) return false;
  return timingSafeEqual(Buffer.from(candidate, "base64url"), Buffer.from(expected, "base64url"));
}

function testConfig(root: string, overrides: Partial<DaemonConfig> = {}): DaemonConfig {
  const runtimeDir = path.join(root, "run");
  const configDir = path.join(root, "config");
  const stateDir = path.join(root, "state");
  return {
    runtimeDir,
    configDir,
    stateDir,
    tokenPath: path.join(configDir, "pairing-token"),
    ipcTokenPath: path.join(configDir, "ipc-token"),
    extensionKeyPath: path.join(configDir, "extension-public-key.json"),
    auditLogPath: path.join(stateDir, "audit.jsonl"),
    wsHost: "127.0.0.1",
    wsPort: 0,
    ipcHost: "127.0.0.1",
    ipcPort: 0,
    pairingToken: TOKEN,
    ipcToken: IPC_TOKEN,
    allowedOrigins: [],
    helloTimeoutMs: 1_000,
    commandTimeoutMs: 500,
    approvalTtlMs: APPROVAL_TTL_MS,
    maxCommandPayloadBytes: MAX_COMMAND_PAYLOAD_BYTES,
    maxWsPayloadBytes: MAX_WS_PAYLOAD_BYTES,
    maxIpcMessageBytes: MAX_IPC_MESSAGE_BYTES,
    maxPendingCommands: MAX_PENDING_COMMANDS,
    maxPendingApprovals: MAX_PENDING_APPROVALS,
    ...overrides
  };
}

async function startHarness(
  overrides: Partial<DaemonConfig> = {},
  existingRoot?: string
): Promise<Harness> {
  const root = existingRoot ?? await mkdtemp(path.join(tmpdir(), "browseweave-daemon-"));
  const config = testConfig(root, overrides);
  const daemon = new BrowseWeaveDaemon(config);
  const harness = { root, config, daemon };
  harnesses.push(harness);
  await daemon.start();
  return harness;
}

function createInbox(socket: WebSocket): (type?: string, timeoutMs?: number) => Promise<JsonObject> {
  const messages: JsonObject[] = [];
  const waiters: Array<{
    type?: string;
    resolve: (value: JsonObject) => void;
    reject: (error: Error) => void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];

  socket.on("message", (raw) => {
    const message = JSON.parse(raw.toString()) as JsonObject;
    if (message.type === "ping" && typeof message.timestamp === "number") {
      socket.send(JSON.stringify({ type: "pong", timestamp: message.timestamp }));
      return;
    }
    const index = waiters.findIndex((waiter) => waiter.type === undefined || waiter.type === message.type);
    if (index >= 0) {
      const waiter = waiters.splice(index, 1)[0];
      if (waiter) {
        clearTimeout(waiter.timer);
        waiter.resolve(message);
      }
      return;
    }
    messages.push(message);
  });

  return async (type?: string, timeoutMs = 2_000): Promise<JsonObject> => {
    const existing = messages.findIndex((message) => type === undefined || message.type === type);
    if (existing >= 0) return messages.splice(existing, 1)[0] as JsonObject;
    return await new Promise<JsonObject>((resolve, reject) => {
      const waiter: {
        type?: string;
        resolve: (value: JsonObject) => void;
        reject: (error: Error) => void;
        timer: ReturnType<typeof setTimeout>;
      } = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const at = waiters.indexOf(waiter);
          if (at >= 0) waiters.splice(at, 1);
          reject(new Error(`Timed out waiting for extension message${type ? `: ${type}` : ""}`));
        }, timeoutMs)
      };
      if (type !== undefined) waiter.type = type;
      waiters.push(waiter);
    });
  };
}

async function beginLegacyPairing(
  harness: Harness,
  browserFamily: "firefox" | "chromium",
  expiresAt = new Date(Date.now() + 60_000).toISOString()
): Promise<IpcResponse> {
  return await ipcCall(harness, "legacy_pairing_begin", {
    expires_at: expiresAt,
    browser_family: browserFamily
  });
}

function markInstallationEnrolled(harness: Harness, installationId: string): void {
  let enrolled = enrolledInstallationsByRoot.get(harness.root);
  if (enrolled === undefined) {
    enrolled = new Set<string>();
    enrolledInstallationsByRoot.set(harness.root, enrolled);
  }
  enrolled.add(installationId);
}

function installationMarkedEnrolled(harness: Harness, installationId: string): boolean {
  return enrolledInstallationsByRoot.get(harness.root)?.has(installationId) === true;
}

async function connectExtension(
  harness: Harness,
  signing: SigningIdentity,
  origin = FIREFOX_ORIGIN,
  secret = TOKEN,
  wireMessages?: string[],
  enrollUnknown = true,
  stagedSetupId?: string,
  stagedSetupPhase: "provisioning" | "persisted" = "persisted"
): Promise<ExtensionClient> {
  if (enrollUnknown && !installationMarkedEnrolled(harness, signing.identity.installation_id)) {
    const opened = await beginLegacyPairing(harness, signing.identity.browser_family);
    if (!opened.ok) throw new Error(opened.error);
  }
  const { websocketPort } = harness.daemon.addresses();
  const socket = new WebSocket(`ws://127.0.0.1:${websocketPort}`, { origin });
  sockets.push(socket);
  const next = createInbox(socket);
  await once(socket, "open");
  const clientNonce = nonce();
  const clientHello = JSON.stringify({
    type: "client_hello",
    protocol_version: PROTOCOL_VERSION,
    endpoint_role: "extension",
    client_nonce: clientNonce,
    origin,
    identity: signing.identity,
    public_key: signing.publicKey,
    ...(stagedSetupId === undefined ? {} : {
      authentication_mode: "derived-v1",
      setup_id: stagedSetupId,
      setup_phase: stagedSetupPhase
    })
  });
  wireMessages?.push(clientHello);
  socket.send(clientHello);
  const challenge = await next("challenge");
  const serverNonce = String(challenge.server_nonce);
  const daemonInstanceId = String(challenge.daemon_instance_id);
  const expectedServerProof = hmacProof(secret, extensionServerProofPayload({
    clientNonce,
    serverNonce,
    daemonInstanceId,
    origin,
    installationId: signing.identity.installation_id,
    publicKey: signing.publicKey,
    ...(stagedSetupId === undefined ? {} : { setupId: stagedSetupId, setupPhase: stagedSetupPhase })
  }));
  if (
    challenge.protocol_version !== PROTOCOL_VERSION ||
    challenge.endpoint_role !== "extension" ||
    challenge.client_nonce !== clientNonce ||
    !proofMatches(challenge.server_proof, expectedServerProof)
  ) {
    socket.terminate();
    throw new Error("Test daemon server proof failed");
  }
  const clientProof = hmacProof(secret, extensionClientProofPayload({
    clientNonce,
    serverNonce,
    daemonInstanceId,
    origin,
    installationId: signing.identity.installation_id,
    publicKey: signing.publicKey,
    serverProof: String(challenge.server_proof),
    ...(stagedSetupId === undefined ? {} : { setupId: stagedSetupId, setupPhase: stagedSetupPhase })
  }));
  const payload = helloSigningPayload({
    clientNonce,
    serverNonce,
    daemonInstanceId,
    origin,
    installationId: signing.identity.installation_id,
    publicKey: signing.publicKey,
    clientProof,
    ...(stagedSetupId === undefined ? {} : { setupId: stagedSetupId, setupPhase: stagedSetupPhase })
  });
  const hello = JSON.stringify({
    type: "hello",
    protocol_version: PROTOCOL_VERSION,
    endpoint_role: "extension",
    client_nonce: clientNonce,
    server_nonce: serverNonce,
    origin,
    daemon_instance_id: daemonInstanceId,
    identity: signing.identity,
    public_key: signing.publicKey,
    client_proof: clientProof,
    signature: signature(signing.privateKey, payload)
  });
  wireMessages?.push(hello);
  socket.send(hello);
  const ack = await next("hello_ack");
  markInstallationEnrolled(harness, signing.identity.installation_id);
  return {
    socket,
    browserId: String(ack.browser_id),
    daemonInstanceId,
    signing,
    next
  };
}

async function beginSetupPairing(
  harness: Harness,
  setupId: string,
  setupSecret: string,
  browserFamily: "firefox" | "chromium",
  expiresAt = new Date(Date.now() + 60_000).toISOString()
): Promise<IpcResponse> {
  return await ipcCall(harness, "setup_pairing_begin", {
    setup_id: setupId,
    setup_secret: setupSecret,
    expires_at: expiresAt,
    browser_family: browserFamily
  });
}

function makeSetupPairingRequest(input: {
  signing: SigningIdentity;
  setupId: string;
  setupSecret: string;
  origin?: string;
  clientNonce?: string;
}): JsonObject {
  const origin = input.origin ?? (
    input.signing.identity.browser_family === "firefox" ? FIREFOX_ORIGIN : CHROMIUM_ORIGIN
  );
  const clientNonce = input.clientNonce ?? nonce();
  const clientProof = hmacProof(input.setupSecret, setupPairingClientProofPayload({
    setupId: input.setupId,
    clientNonce,
    origin,
    installationId: input.signing.identity.installation_id,
    publicKey: input.signing.publicKey
  }));
  return {
    type: "setup_pair_request",
    protocol_version: PROTOCOL_VERSION,
    setup_version: SETUP_VERSION,
    setup_id: input.setupId,
    client_nonce: clientNonce,
    origin,
    identity: input.signing.identity,
    public_key: input.signing.publicKey,
    client_proof: clientProof
  };
}

async function sendSetupPairingRequest(
  harness: Harness,
  request: JsonObject,
  origin: string
): Promise<SetupPairingResponse> {
  const { websocketPort } = harness.daemon.addresses();
  const socket = new WebSocket(`ws://127.0.0.1:${websocketPort}`, { origin });
  sockets.push(socket);
  const next = createInbox(socket);
  await once(socket, "open");
  socket.send(JSON.stringify(request));
  return await next("setup_pair_response") as unknown as SetupPairingResponse;
}

async function expectSetupPairingRejected(
  harness: Harness,
  request: JsonObject,
  origin: string
): Promise<void> {
  const { websocketPort } = harness.daemon.addresses();
  const socket = new WebSocket(`ws://127.0.0.1:${websocketPort}`, { origin });
  sockets.push(socket);
  await once(socket, "open");
  socket.send(JSON.stringify(request));
  const [closeCode] = await once(socket, "close") as [number, Buffer];
  expect(closeCode).toBe(1008);
}

async function decryptSetupPairingToken(
  setupSecret: string,
  request: JsonObject,
  response: SetupPairingResponse,
  signing: SigningIdentity,
  origin: string
): Promise<string> {
  const ikm = await webcrypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(setupSecret),
    "HKDF",
    false,
    ["deriveKey"]
  );
  const key = await webcrypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(setupPairingKeySalt({
        setupId: response.setup_id,
        clientNonce: response.client_nonce,
        serverNonce: response.server_nonce
      })),
      info: new TextEncoder().encode(SETUP_ENCRYPTION_KEY_INFO)
    },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
  const aad = setupPairingAadPayload({
    setupId: response.setup_id,
    clientNonce: response.client_nonce,
    serverNonce: response.server_nonce,
    daemonInstanceId: response.daemon_instance_id,
    origin,
    identity: signing.identity,
    publicKey: signing.publicKey,
    expiresAt: response.expires_at
  });
  const plaintext = await webcrypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(Buffer.from(response.iv, "base64url")),
      additionalData: new TextEncoder().encode(aad),
      tagLength: 128
    },
    key,
    new Uint8Array(Buffer.from(response.encrypted_pairing_token, "base64url"))
  );
  expect(response.client_nonce).toBe(request.client_nonce);
  return new TextDecoder().decode(plaintext);
}

function expectedDerivedPairingToken(signing: SigningIdentity): string {
  const framed = (name: string, value: string): string =>
    `${name}:${Buffer.byteLength(value, "utf8")}:${value}\n`;
  const payload = "BrowseWeave installation authentication secret v1\n" +
    framed("protocol_version", String(PROTOCOL_VERSION)) +
    framed("installation_id", signing.identity.installation_id) +
    framed("public_key", canonicalPublicJwk(signing.publicKey));
  return createHmac("sha256", Buffer.from(TOKEN, "utf8")).update(payload, "utf8").digest("base64url");
}

function makeExtensionClientHello(
  signing: SigningIdentity,
  origin: string,
  clientNonce = nonce()
): JsonObject {
  return {
    type: "client_hello",
    protocol_version: PROTOCOL_VERSION,
    endpoint_role: "extension",
    client_nonce: clientNonce,
    origin,
    identity: signing.identity,
    public_key: signing.publicKey
  };
}

async function expectExtensionClientHelloRejected(
  harness: Harness,
  signing: SigningIdentity,
  origin: string
): Promise<void> {
  const { websocketPort } = harness.daemon.addresses();
  const socket = new WebSocket(`ws://127.0.0.1:${websocketPort}`, { origin });
  sockets.push(socket);
  await once(socket, "open");
  socket.send(JSON.stringify(makeExtensionClientHello(signing, origin)));
  const [closeCode] = await once(socket, "close") as [number, Buffer];
  expect(closeCode).toBe(1008);
}

async function expectStagedClientHelloRejected(
  harness: Harness,
  signing: SigningIdentity,
  origin: string,
  setupId: string,
  setupPhase?: "provisioning" | "persisted"
): Promise<void> {
  const { websocketPort } = harness.daemon.addresses();
  const socket = new WebSocket(`ws://127.0.0.1:${websocketPort}`, { origin });
  sockets.push(socket);
  await once(socket, "open");
  socket.send(JSON.stringify({
    ...makeExtensionClientHello(signing, origin),
    authentication_mode: "derived-v1",
    setup_id: setupId,
    ...(setupPhase === undefined ? {} : { setup_phase: setupPhase })
  }));
  const [closeCode] = await once(socket, "close") as [number, Buffer];
  expect(closeCode).toBe(1008);
}

function ipcCall(
  harness: Harness,
  method: string,
  params: JsonObject = {},
  secret = IPC_TOKEN,
  timeoutMs = 2_000,
  wireMessages?: string[]
): Promise<IpcResponse> {
  const endpoint = harness.daemon.addresses();
  const requestId = `req-${Math.random()}`;
  const clientNonce = nonce();
  return new Promise((resolve, reject) => {
    const socket: Socket = createConnection({ host: endpoint.ipcHost, port: endpoint.ipcPort });
    let buffer = Buffer.alloc(0);
    let phase: "challenge" | "response" = "challenge";
    let settled = false;
    const finish = (error?: Error, response?: IpcResponse): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error);
      else if (response) resolve(response);
      else reject(new Error("IPC test ended without a response"));
    };
    const timer = setTimeout(() => {
      finish(new Error("IPC test timeout"));
    }, timeoutMs);
    socket.once("connect", () => {
      const hello = JSON.stringify({
        type: "ipc_client_hello",
        protocol_version: PROTOCOL_VERSION,
        endpoint_role: "ipc",
        client_nonce: clientNonce
      });
      wireMessages?.push(hello);
      socket.write(`${hello}\n`);
    });
    socket.on("data", (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (!settled) {
        const newline = buffer.indexOf(0x0a);
        if (newline < 0) return;
        const line = buffer.subarray(0, newline).toString("utf8");
        buffer = buffer.subarray(newline + 1);
        const message = JSON.parse(line) as JsonObject;
        if (phase === "challenge") {
          const serverNonce = String(message.server_nonce);
          const daemonInstanceId = String(message.daemon_instance_id);
          const expectedServerProof = hmacProof(secret, ipcServerProofPayload({
            clientNonce,
            serverNonce,
            daemonInstanceId
          }));
          if (
            message.type !== "ipc_challenge" ||
            message.protocol_version !== PROTOCOL_VERSION ||
            message.endpoint_role !== "ipc" ||
            message.client_nonce !== clientNonce ||
            !proofMatches(message.server_proof, expectedServerProof)
          ) {
            finish(new Error("IPC server proof failed"));
            return;
          }
          const paramsSha256 = `sha256:${createHash("sha256")
            .update(canonicalJson(params), "utf8")
            .digest("hex")}`;
          const clientProof = hmacProof(secret, ipcClientProofPayload({
            clientNonce,
            serverNonce,
            daemonInstanceId,
            serverProof: String(message.server_proof),
            requestId,
            method,
            paramsSha256
          }));
          const request = JSON.stringify({
            type: "ipc_request",
            protocol_version: PROTOCOL_VERSION,
            endpoint_role: "ipc",
            id: requestId,
            method,
            params,
            client_nonce: clientNonce,
            server_nonce: serverNonce,
            daemon_instance_id: daemonInstanceId,
            client_proof: clientProof
          });
          wireMessages?.push(request);
          phase = "response";
          socket.write(`${request}\n`);
          continue;
        }
        finish(undefined, message as unknown as IpcResponse);
      }
    });
    socket.once("error", (error) => {
      finish(error);
    });
    socket.once("close", () => {
      if (!settled) finish(new Error("IPC connection closed during authentication"));
    });
  });
}

function createLineInbox(socket: Socket): (timeoutMs?: number) => Promise<string> {
  let buffer = Buffer.alloc(0);
  const lines: string[] = [];
  const waiters: Array<{
    resolve(value: string): void;
    reject(error: Error): void;
    timer: ReturnType<typeof setTimeout>;
  }> = [];
  socket.on("data", (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (true) {
      const newline = buffer.indexOf(0x0a);
      if (newline < 0) break;
      const line = buffer.subarray(0, newline).toString("utf8");
      buffer = buffer.subarray(newline + 1);
      const waiter = waiters.shift();
      if (waiter) {
        clearTimeout(waiter.timer);
        waiter.resolve(line);
      } else {
        lines.push(line);
      }
    }
  });
  socket.once("close", () => {
    for (const waiter of waiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error("Socket closed before a complete line"));
    }
  });
  return async (timeoutMs = 2_000): Promise<string> => {
    const line = lines.shift();
    if (line !== undefined) return line;
    return await new Promise<string>((resolve, reject) => {
      const waiter = {
        resolve,
        reject,
        timer: setTimeout(() => {
          const at = waiters.indexOf(waiter);
          if (at >= 0) waiters.splice(at, 1);
          reject(new Error("Timed out waiting for a socket line"));
        }, timeoutMs)
      };
      waiters.push(waiter);
    });
  };
}

async function listenTestServer(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Test server did not bind TCP");
  return address.port;
}

async function closeTestServer(server: Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

async function sendRejectedExtensionHello(harness: Harness): Promise<void> {
  const { websocketPort } = harness.daemon.addresses();
  const socket = new WebSocket(`ws://127.0.0.1:${websocketPort}`, { origin: FIREFOX_ORIGIN });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.terminate();
      reject(new Error("Rejected extension hello did not close"));
    }, 2_000);
    socket.once("open", () => socket.send("{}"));
    socket.once("close", () => {
      clearTimeout(timer);
      resolve();
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function sendRejectedIpcHello(harness: Harness): Promise<void> {
  const { ipcHost, ipcPort } = harness.daemon.addresses();
  const socket = createConnection({ host: ipcHost, port: ipcPort });
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("Rejected IPC hello did not close"));
    }, 2_000);
    socket.once("connect", () => socket.write("{}\n"));
    socket.once("close", () => {
      clearTimeout(timer);
      resolve();
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function connectExtensionAfterUnauthenticatedStorm(
  harness: Harness,
  signing: SigningIdentity
): Promise<ExtensionClient> {
  const pairing = await beginLegacyPairing(harness, signing.identity.browser_family);
  if (!pairing.ok) throw new Error(pairing.error);

  const deadline = Date.now() + 250;
  while (true) {
    try {
      return await connectExtension(
        harness,
        signing,
        FIREFOX_ORIGIN,
        TOKEN,
        undefined,
        false
      );
    } catch (error) {
      if (
        !(error instanceof Error) ||
        error.message !== "Unexpected server response: 401" ||
        Date.now() >= deadline
      ) throw error;

      // A client can observe its close before the server has removed that
      // socket from the bounded unauthenticated-admission set. Retry only this
      // transient HTTP admission response; authentication failures still fail.
      await new Promise<void>((resolve) => setTimeout(resolve, 10));
    }
  }
}

function commandFailure(
  command: JsonObject,
  fingerprint: string,
  label = UNTRUSTED_LABEL,
  category = "password"
): string {
  const commandPayload = isJsonObjectForTest(command.payload) ? command.payload : {};
  const targetTabId = typeof commandPayload.tab_id === "number" ? commandPayload.tab_id : 1;
  const targetFrameId = typeof commandPayload.frame_id === "number" ? commandPayload.frame_id : 0;
  return JSON.stringify({
    type: "result",
    id: command.id,
    ok: false,
    error: {
      code: "approval_required",
      message: "A sensitive operation requires approval.",
      category,
      approval_fingerprint: fingerprint,
      target_tab_id: targetTabId,
      target_frame_id: targetFrameId,
      details: { targets: [{ target: label }] }
    }
  });
}

function signDecision(
  extension: ExtensionClient,
  approvalRequest: JsonObject,
  decision: "approve" | "reject",
  overrides: Partial<{
    approvalId: string;
    approvalNonce: string;
    browserId: string;
    targetTabId: number;
    targetFrameId: number;
    paramsSha256: string;
    approvalFingerprint: string;
    expiresAt: string;
  }> = {},
  privateKey = extension.signing.privateKey
): string {
  const payload = approvalDecisionSigningPayload({
    daemonInstanceId: extension.daemonInstanceId,
    approvalId: overrides.approvalId ?? String(approvalRequest.approval_id),
    approvalNonce: overrides.approvalNonce ?? String(approvalRequest.approval_nonce),
    browserId: overrides.browserId ?? String(approvalRequest.browser_id),
    targetTabId: overrides.targetTabId ?? Number(approvalRequest.target_tab_id),
    targetFrameId: overrides.targetFrameId ?? Number(approvalRequest.target_frame_id),
    decision,
    action: approvalRequest.action as "click",
    paramsSha256: overrides.paramsSha256 ?? String(approvalRequest.params_sha256),
    approvalFingerprint: overrides.approvalFingerprint ?? String(approvalRequest.approval_fingerprint),
    expiresAt: overrides.expiresAt ?? String(approvalRequest.expires_at)
  });
  return signature(privateKey, payload);
}

afterEach(async () => {
  for (const socket of sockets.splice(0)) socket.terminate();
  const pending = harnesses.splice(0);
  for (const harness of pending) await harness.daemon.stop("test_cleanup");
  for (const root of new Set(pending.map((harness) => harness.root))) {
    await rm(root, { recursive: true, force: true });
    enrolledInstallationsByRoot.delete(root);
  }
});

describe("BrowseWeave daemon integration", () => {
  it("strictly validates, idempotently opens, and safely cancels setup pairing without auditing secrets", async () => {
    const harness = await startHarness();
    const setupId = "0123456789abcdef01234567";
    const otherSetupId = "1123456789abcdef01234567";
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const valid = {
      setup_id: setupId,
      setup_secret: SETUP_SECRET,
      expires_at: expiresAt,
      browser_family: "chromium"
    } as const;

    expect(await ipcCall(harness, "setup_pairing_begin", valid)).toMatchObject({
      ok: true,
      result: {
        setup_pairing_ready: true,
        setup_id: setupId,
        expires_at: expiresAt,
        browser_family: "chromium"
      }
    });
    expect(await ipcCall(harness, "setup_pairing_begin", valid)).toMatchObject({ ok: true });
    expect(await ipcCall(harness, "setup_pairing_status", { setup_id: setupId })).toEqual({
      id: expect.any(String),
      ok: true,
      result: {
        setup_pairing_status: "waiting",
        setup_id: setupId,
        expires_at: expiresAt,
        browser_family: "chromium"
      }
    });
    expect(await ipcCall(harness, "setup_pairing_status", { setup_id: otherSetupId })).toMatchObject({
      ok: true,
      result: { setup_pairing_status: "not_found", setup_id: otherSetupId }
    });
    expect(await ipcCall(harness, "setup_pairing_status", { setup_id: setupId, extra: true })).toMatchObject({
      ok: false
    });

    const invalid: JsonObject[] = [
      { ...valid, unexpected: true },
      { ...valid, setup_id: setupId.toUpperCase() },
      { ...valid, setup_secret: SETUP_SECRET.toUpperCase() },
      { ...valid, expires_at: new Date(Date.now() + SETUP_MAX_TTL_FOR_TEST + 1_000).toISOString() },
      { ...valid, expires_at: new Date(Date.now() - 1_000).toISOString() },
      { ...valid, expires_at: expiresAt.replace(/\.\d{3}Z$/u, "Z") },
      { ...valid, browser_family: "safari" }
    ];
    for (const params of invalid) {
      expect(await ipcCall(harness, "setup_pairing_begin", params)).toMatchObject({ ok: false });
    }
    expect(await beginSetupPairing(
      harness,
      otherSetupId,
      OTHER_SETUP_SECRET,
      "chromium",
      expiresAt
    )).toMatchObject({ ok: false });

    expect(await ipcCall(harness, "setup_pairing_cancel", { setup_id: otherSetupId })).toMatchObject({
      ok: true,
      result: { setup_pairing_cancelled: true, setup_id: otherSetupId }
    });
    expect(await beginSetupPairing(
      harness,
      otherSetupId,
      OTHER_SETUP_SECRET,
      "chromium",
      expiresAt
    )).toMatchObject({ ok: false });
    expect(await ipcCall(harness, "setup_pairing_cancel", { setup_id: setupId, extra: true })).toMatchObject({
      ok: false
    });
    expect(await ipcCall(harness, "setup_pairing_cancel", { setup_id: setupId })).toMatchObject({ ok: true });
    expect(await ipcCall(harness, "setup_pairing_cancel", { setup_id: setupId })).toMatchObject({ ok: true });
    expect(await beginSetupPairing(
      harness,
      otherSetupId,
      OTHER_SETUP_SECRET,
      "chromium",
      expiresAt
    )).toMatchObject({ ok: true });

    await harness.daemon.stop("setup_validation_audit_flush");
    const audit = await readFile(harness.config.auditLogPath, "utf8");
    expect(audit).not.toContain(SETUP_SECRET);
    expect(audit).not.toContain(OTHER_SETUP_SECRET);
    expect(audit).not.toContain(setupId);
    expect(audit).not.toContain(otherSetupId);
  });

  it("encrypts a per-installation secret compatibly with WebCrypto and reconnects in derived mode", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-derived-pairing-"));
    const first = await startHarness({}, root);
    const setupId = "2223456789abcdef01234567";
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const signing = makeSigningIdentity(
      "13131313-1313-4313-8313-131313131313",
      "chromium"
    );
    const originalLegacy = await connectExtension(first, signing, CHROMIUM_ORIGIN, TOKEN);
    expect(originalLegacy.browserId).toMatch(/^browser-[a-f0-9]{24}$/u);
    expect(await beginSetupPairing(first, setupId, SETUP_SECRET, "chromium", expiresAt)).toMatchObject({
      ok: true
    });
    const request = makeSetupPairingRequest({
      signing,
      setupId,
      setupSecret: SETUP_SECRET,
      origin: CHROMIUM_ORIGIN
    });
    const response = await sendSetupPairingRequest(first, request, CHROMIUM_ORIGIN);
    expect(Object.keys(response).sort()).toEqual([
      "client_nonce",
      "daemon_instance_id",
      "encrypted_pairing_token",
      "expires_at",
      "iv",
      "protocol_version",
      "server_nonce",
      "setup_id",
      "setup_version",
      "type"
    ]);
    expect(response).toMatchObject({
      type: "setup_pair_response",
      protocol_version: PROTOCOL_VERSION,
      setup_version: SETUP_VERSION,
      setup_id: setupId,
      client_nonce: request.client_nonce,
      expires_at: expiresAt
    });
    expect(Buffer.from(response.iv, "base64url")).toHaveLength(12);
    const derivedToken = await decryptSetupPairingToken(
      SETUP_SECRET,
      request,
      response,
      signing,
      CHROMIUM_ORIGIN
    );
    expect(derivedToken).toBe(expectedDerivedPairingToken(signing));
    expect(derivedToken).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(derivedToken).not.toBe(TOKEN);
    expect(derivedToken).not.toBe(SETUP_SECRET);
    const retryRequest = makeSetupPairingRequest({
      signing,
      setupId,
      setupSecret: SETUP_SECRET,
      origin: CHROMIUM_ORIGIN
    });
    expect(retryRequest.client_nonce).not.toBe(request.client_nonce);
    const retryResponse = await sendSetupPairingRequest(first, retryRequest, CHROMIUM_ORIGIN);
    await expect(decryptSetupPairingToken(
      SETUP_SECRET,
      retryRequest,
      retryResponse,
      signing,
      CHROMIUM_ORIGIN
    )).resolves.toBe(derivedToken);
    await expectSetupPairingRejected(first, request, CHROMIUM_ORIGIN);
    const pendingStatus = await ipcCall(first, "setup_pairing_status", { setup_id: setupId });
    if (!pendingStatus.ok || !isJsonObjectForTest(pendingStatus.result)) throw new Error("Pending setup receipt missing");
    expect(Object.keys(pendingStatus.result).sort()).toEqual([
      "browser_family",
      "browser_id",
      "browser_name",
      "browser_version",
      "expires_at",
      "extension_version",
      "setup_id",
      "setup_pairing_status"
    ]);
    expect(pendingStatus).toMatchObject({
      ok: true,
      result: {
        setup_pairing_status: "pending",
        setup_id: setupId,
        browser_id: expect.stringMatching(/^browser-[a-f0-9]{24}$/u),
        browser_family: "chromium",
        browser_name: signing.identity.browser_name,
        browser_version: signing.identity.browser_version,
        extension_version: signing.identity.extension_version
      }
    });
    const legacy = await connectExtension(
      first,
      signing,
      CHROMIUM_ORIGIN,
      TOKEN,
      undefined,
      false
    );
    expect(legacy.browserId).toMatch(/^browser-[a-f0-9]{24}$/u);
    const legacyRegistry = JSON.parse(await readFile(first.config.extensionKeyPath, "utf8")) as JsonObject;
    expect((legacyRegistry.installations as JsonObject)[signing.identity.installation_id]).toMatchObject({
      auth_mode: "legacy",
      public_key: signing.publicKey
    });
    await expectStagedClientHelloRejected(first, signing, CHROMIUM_ORIGIN, setupId);
    await expectStagedClientHelloRejected(first, signing, CHROMIUM_ORIGIN, setupId, "persisted");
    const provisioned = await connectExtension(
      first,
      signing,
      CHROMIUM_ORIGIN,
      derivedToken,
      undefined,
      false,
      setupId,
      "provisioning"
    );
    expect(provisioned.browserId).toBe(legacy.browserId);
    expect(await ipcCall(first, "setup_pairing_status", { setup_id: setupId })).toMatchObject({
      ok: true,
      result: { setup_pairing_status: "pending", setup_id: setupId }
    });
    const registryBeforeDurableCommit = JSON.parse(
      await readFile(first.config.extensionKeyPath, "utf8")
    ) as JsonObject;
    expect((registryBeforeDurableCommit.installations as JsonObject)[signing.identity.installation_id]).toMatchObject({
      auth_mode: "legacy",
      public_key: signing.publicKey
    });
    const connected = await connectExtension(
      first,
      signing,
      CHROMIUM_ORIGIN,
      derivedToken,
      undefined,
      false,
      setupId
    );
    expect(connected.browserId).toMatch(/^browser-[a-f0-9]{24}$/u);
    expect(connected.browserId).toBe(legacy.browserId);
    const completedStatus = await ipcCall(first, "setup_pairing_status", { setup_id: setupId });
    if (!completedStatus.ok || !isJsonObjectForTest(completedStatus.result)) {
      throw new Error("Completed setup receipt missing");
    }
    expect(Object.keys(completedStatus.result).sort()).toEqual([
      "browser_family",
      "browser_id",
      "browser_name",
      "browser_version",
      "completed_at",
      "expires_at",
      "extension_version",
      "setup_id",
      "setup_pairing_status"
    ]);
    expect(completedStatus).toMatchObject({
      ok: true,
      result: {
        setup_pairing_status: "completed",
        setup_id: setupId,
        browser_id: connected.browserId,
        browser_family: "chromium",
        extension_version: signing.identity.extension_version,
        completed_at: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/u)
      }
    });
    const completedAt = (completedStatus.result as JsonObject).completed_at;
    const reconciledAfterLostAck = await connectExtension(
      first,
      signing,
      CHROMIUM_ORIGIN,
      derivedToken,
      undefined,
      false,
      setupId,
      "persisted"
    );
    expect(reconciledAfterLostAck.browserId).toBe(connected.browserId);
    expect(await ipcCall(first, "setup_pairing_status", { setup_id: setupId })).toMatchObject({
      ok: true,
      result: {
        setup_pairing_status: "completed",
        setup_id: setupId,
        completed_at: completedAt
      }
    });
    await first.daemon.stop("derived_restart");

    const registry = JSON.parse(await readFile(first.config.extensionKeyPath, "utf8")) as JsonObject;
    expect(registry.version).toBe(2);
    expect((registry.installations as JsonObject)[signing.identity.installation_id]).toMatchObject({
      auth_mode: "derived-v1",
      public_key: signing.publicKey
    });

    const second = await startHarness({}, root);
    await expect(connectExtension(
      second,
      signing,
      CHROMIUM_ORIGIN,
      derivedToken,
      undefined,
      false
    )).resolves.toMatchObject({ browserId: connected.browserId });
    await second.daemon.stop("derived_audit_flush");
    const audit = await readFile(second.config.auditLogPath, "utf8");
    expect(audit).not.toContain(SETUP_SECRET);
    expect(audit).not.toContain(derivedToken);
    expect(audit).not.toContain(TOKEN);
    expect(audit).not.toContain(setupId);
  });

  it("keeps the legacy registry usable when durable storage fails after provisioning", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-lost-setup-response-"));
    const first = await startHarness({}, root);
    const signing = makeSigningIdentity("46464646-4646-4646-8646-464646464646", "chromium");
    const legacy = await connectExtension(first, signing, CHROMIUM_ORIGIN, TOKEN);
    const setupId = "7723456789abcdef01234567";
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    await expect(beginSetupPairing(first, setupId, SETUP_SECRET, "chromium", expiresAt))
      .resolves.toMatchObject({ ok: true });
    const request = makeSetupPairingRequest({
      signing,
      setupId,
      setupSecret: SETUP_SECRET,
      origin: CHROMIUM_ORIGIN
    });
    const response = await sendSetupPairingRequest(first, request, CHROMIUM_ORIGIN);
    const derivedToken = await decryptSetupPairingToken(
      SETUP_SECRET,
      request,
      response,
      signing,
      CHROMIUM_ORIGIN
    );
    expect(derivedToken).toBe(expectedDerivedPairingToken(signing));
    await expect(connectExtension(
      first,
      signing,
      CHROMIUM_ORIGIN,
      derivedToken,
      undefined,
      false,
      setupId,
      "provisioning"
    )).resolves.toMatchObject({ browserId: legacy.browserId });
    expect(await ipcCall(first, "setup_pairing_status", { setup_id: setupId })).toMatchObject({
      ok: true,
      result: { setup_pairing_status: "pending", browser_id: legacy.browserId }
    });
    await first.daemon.stop("lost_setup_response_restart");

    const registry = JSON.parse(await readFile(first.config.extensionKeyPath, "utf8")) as JsonObject;
    expect((registry.installations as JsonObject)[signing.identity.installation_id]).toMatchObject({
      auth_mode: "legacy",
      public_key: signing.publicKey
    });
    const second = await startHarness({}, root);
    await expect(connectExtension(second, signing, CHROMIUM_ORIGIN, TOKEN, undefined, false))
      .resolves.toMatchObject({ browserId: legacy.browserId });
    await expect(ipcCall(second, "setup_pairing_status", { setup_id: setupId })).resolves.toMatchObject({
      ok: true,
      result: { setup_pairing_status: "not_found", setup_id: setupId }
    });
  });

  it("fails setup pairing closed on wrong proof, tampering, replay, expiry, and family mismatch", async () => {
    const harness = await startHarness();
    const signing = makeSigningIdentity("14141414-1414-4414-8414-141414141414");
    const setupId = "3323456789abcdef01234567";
    const firstExpiry = new Date(Date.now() + 60_000).toISOString();
    expect(await beginSetupPairing(harness, setupId, SETUP_SECRET, "firefox", firstExpiry)).toMatchObject({
      ok: true
    });

    const wrongProof = makeSetupPairingRequest({
      signing,
      setupId,
      setupSecret: OTHER_SETUP_SECRET,
      origin: FIREFOX_ORIGIN
    });
    await expectSetupPairingRejected(harness, wrongProof, FIREFOX_ORIGIN);
    const tampered = makeSetupPairingRequest({
      signing,
      setupId,
      setupSecret: SETUP_SECRET,
      origin: FIREFOX_ORIGIN
    });
    tampered.public_key = makeSigningIdentity("15151515-1515-4515-8515-151515151515").publicKey;
    await expectSetupPairingRejected(harness, tampered, FIREFOX_ORIGIN);

    const acceptedRequest = makeSetupPairingRequest({
      signing,
      setupId,
      setupSecret: SETUP_SECRET,
      origin: FIREFOX_ORIGIN
    });
    const accepted = await sendSetupPairingRequest(harness, acceptedRequest, FIREFOX_ORIGIN);
    await expect(decryptSetupPairingToken(
      SETUP_SECRET,
      acceptedRequest,
      accepted,
      signing,
      FIREFOX_ORIGIN
    )).resolves.toBe(expectedDerivedPairingToken(signing));

    await expectSetupPairingRejected(harness, acceptedRequest, FIREFOX_ORIGIN);
    const freshRequest = makeSetupPairingRequest({
      signing,
      setupId,
      setupSecret: SETUP_SECRET,
      origin: FIREFOX_ORIGIN
    });
    await expect(sendSetupPairingRequest(harness, freshRequest, FIREFOX_ORIGIN)).resolves.toMatchObject({
      type: "setup_pair_response"
    });
    await expect(ipcCall(harness, "setup_pairing_cancel", { setup_id: setupId })).resolves.toMatchObject({ ok: true });

    const familySetupId = "4423456789abcdef01234567";
    const familyExpiry = new Date(Date.now() + 60_000).toISOString();
    expect(await beginSetupPairing(
      harness,
      familySetupId,
      SETUP_SECRET,
      "firefox",
      familyExpiry
    )).toMatchObject({ ok: true });
    const chromium = makeSigningIdentity("16161616-1616-4616-8616-161616161616", "chromium");
    await expectSetupPairingRejected(harness, makeSetupPairingRequest({
      signing: chromium,
      setupId: familySetupId,
      setupSecret: SETUP_SECRET,
      origin: CHROMIUM_ORIGIN
    }), CHROMIUM_ORIGIN);
    await ipcCall(harness, "setup_pairing_cancel", { setup_id: familySetupId });

    const expiredSetupId = "5523456789abcdef01234567";
    const expiredAt = new Date(Date.now() + 150).toISOString();
    expect(await beginSetupPairing(
      harness,
      expiredSetupId,
      SETUP_SECRET,
      "firefox",
      expiredAt
    )).toMatchObject({ ok: true });
    await new Promise((resolve) => setTimeout(resolve, 250));
    await expectSetupPairingRejected(harness, makeSetupPairingRequest({
      signing,
      setupId: expiredSetupId,
      setupSecret: SETUP_SECRET,
      origin: FIREFOX_ORIGIN
    }), FIREFOX_ORIGIN);

    await harness.daemon.stop("setup_rejection_audit_flush");
    const audit = await readFile(harness.config.auditLogPath, "utf8");
    expect(audit).not.toContain(SETUP_SECRET);
    expect(audit).not.toContain(OTHER_SETUP_SECRET);
  });

  it("rejects unknown installations without a one-use legacy window and scopes derived secrets to one identity", async () => {
    const harness = await startHarness();
    const unknown = makeSigningIdentity("17171717-1717-4717-8717-171717171717");
    await expectExtensionClientHelloRejected(harness, unknown, FIREFOX_ORIGIN);

    const derivedSigning = makeSigningIdentity("18181818-1818-4818-8818-181818181818");
    const setupId = "6623456789abcdef01234567";
    const setupExpiry = new Date(Date.now() + 60_000).toISOString();
    expect(await beginSetupPairing(
      harness,
      setupId,
      SETUP_SECRET,
      "firefox",
      setupExpiry
    )).toMatchObject({ ok: true });
    const setupRequest = makeSetupPairingRequest({
      signing: derivedSigning,
      setupId,
      setupSecret: SETUP_SECRET,
      origin: FIREFOX_ORIGIN
    });
    const setupResponse = await sendSetupPairingRequest(harness, setupRequest, FIREFOX_ORIGIN);
    const derivedToken = await decryptSetupPairingToken(
      SETUP_SECRET,
      setupRequest,
      setupResponse,
      derivedSigning,
      FIREFOX_ORIGIN
    );
    await connectExtension(
      harness,
      derivedSigning,
      FIREFOX_ORIGIN,
      derivedToken,
      undefined,
      false,
      setupId,
      "provisioning"
    );
    expect(harness.daemon.statusSnapshot().connectedBrowsers).toEqual([]);
    await expect(connectExtension(
      harness,
      derivedSigning,
      FIREFOX_ORIGIN,
      derivedToken,
      undefined,
      false,
      setupId
    )).resolves.toMatchObject({ browserId: expect.stringMatching(/^browser-[a-f0-9]{24}$/u) });

    const legacyExpiry = new Date(Date.now() + 60_000).toISOString();
    const legacyReady = await beginLegacyPairing(harness, "firefox", legacyExpiry);
    expect(legacyReady).toMatchObject({ ok: true });
    if (!legacyReady.ok || !isJsonObjectForTest(legacyReady.result)) throw new Error("Legacy setup failed");
    expect(legacyReady.result).toEqual({
      legacy_pairing_ready: true,
      expires_at: legacyExpiry,
      browser_family: "firefox"
    });
    expect(await beginLegacyPairing(harness, "firefox", legacyExpiry)).toMatchObject({ ok: true });
    expect(await ipcCall(harness, "legacy_pairing_begin", {
      expires_at: legacyExpiry,
      browser_family: "firefox",
      unexpected: true
    })).toMatchObject({ ok: false });
    expect(await beginLegacyPairing(
      harness,
      "firefox",
      new Date(Date.now() + 70_000).toISOString()
    )).toMatchObject({ ok: false });
    const familyMismatch = makeSigningIdentity(
      "19191919-1919-4919-8919-191919191919",
      "chromium"
    );
    await expectExtensionClientHelloRejected(harness, familyMismatch, CHROMIUM_ORIGIN);

    const attacker = makeSigningIdentity("20202020-2020-4020-8020-202020202020");
    const { websocketPort } = harness.daemon.addresses();
    const socket = new WebSocket(`ws://127.0.0.1:${websocketPort}`, { origin: FIREFOX_ORIGIN });
    sockets.push(socket);
    const next = createInbox(socket);
    await once(socket, "open");
    const clientNonce = nonce();
    socket.send(JSON.stringify(makeExtensionClientHello(attacker, FIREFOX_ORIGIN, clientNonce)));
    const challenge = await next("challenge");
    const clientProof = hmacProof(derivedToken, extensionClientProofPayload({
      clientNonce,
      serverNonce: String(challenge.server_nonce),
      daemonInstanceId: String(challenge.daemon_instance_id),
      origin: FIREFOX_ORIGIN,
      installationId: attacker.identity.installation_id,
      publicKey: attacker.publicKey,
      serverProof: String(challenge.server_proof)
    }));
    socket.send(JSON.stringify({
      type: "hello",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "extension",
      client_nonce: clientNonce,
      server_nonce: challenge.server_nonce,
      origin: FIREFOX_ORIGIN,
      daemon_instance_id: challenge.daemon_instance_id,
      identity: attacker.identity,
      public_key: attacker.publicKey,
      client_proof: clientProof,
      signature: signature(attacker.privateKey, helloSigningPayload({
        clientNonce,
        serverNonce: String(challenge.server_nonce),
        daemonInstanceId: String(challenge.daemon_instance_id),
        origin: FIREFOX_ORIGIN,
        installationId: attacker.identity.installation_id,
        publicKey: attacker.publicKey,
        clientProof
      }))
    }));
    const [rejectedCode] = await once(socket, "close") as [number, Buffer];
    expect(rejectedCode).toBe(1008);

    const legitimate = await connectExtension(
      harness,
      attacker,
      FIREFOX_ORIGIN,
      TOKEN,
      undefined,
      false
    );
    expect(legitimate.browserId).toMatch(/^browser-[a-f0-9]{24}$/u);
    await expectExtensionClientHelloRejected(
      harness,
      makeSigningIdentity("21212121-2121-4121-8121-212121212121"),
      FIREFOX_ORIGIN
    );

    await harness.daemon.stop("derived_scope_audit_flush");
    const registry = JSON.parse(await readFile(harness.config.extensionKeyPath, "utf8")) as JsonObject;
    const installations = registry.installations as JsonObject;
    expect(installations[derivedSigning.identity.installation_id]).toMatchObject({ auth_mode: "derived-v1" });
    expect(installations[attacker.identity.installation_id]).toMatchObject({ auth_mode: "legacy" });
    expect(Object.keys(installations)).toHaveLength(2);
    const audit = await readFile(harness.config.auditLogPath, "utf8");
    expect(audit).not.toContain(derivedToken);
    expect(audit).not.toContain(TOKEN);
    expect(audit).not.toContain(SETUP_SECRET);
  });

  it("migrates a version-1 key registry to exact version 2 and preserves legacy authentication", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-registry-migration-"));
    const config = testConfig(root);
    await mkdir(config.configDir, { recursive: true, mode: 0o700 });
    const signing = makeSigningIdentity("23232323-2323-4323-8323-232323232323");
    const browserId = `browser-${createHash("sha256")
      .update(signing.identity.installation_id, "utf8")
      .digest("hex")
      .slice(0, 24)}`;
    await writeFile(config.extensionKeyPath, `${JSON.stringify({
      version: 1,
      installations: {
        [signing.identity.installation_id]: {
          browser_id: browserId,
          public_key: signing.publicKey,
          enrolled_at: "2026-07-28T12:00:00.000Z"
        }
      }
    })}\n`, { encoding: "utf8", mode: 0o600 });

    const harness = await startHarness({}, root);
    const migrated = JSON.parse(await readFile(config.extensionKeyPath, "utf8")) as JsonObject;
    expect(migrated.version).toBe(2);
    expect(Object.keys(migrated).sort()).toEqual(["installations", "version"]);
    const entry = (migrated.installations as JsonObject)[signing.identity.installation_id] as JsonObject;
    expect(Object.keys(entry).sort()).toEqual(["auth_mode", "browser_id", "enrolled_at", "public_key"]);
    expect(entry).toMatchObject({
      auth_mode: "legacy",
      browser_id: browserId,
      public_key: signing.publicKey
    });
    await expect(connectExtension(
      harness,
      signing,
      FIREFOX_ORIGIN,
      TOKEN,
      undefined,
      false
    )).resolves.toMatchObject({ browserId });
    await harness.daemon.stop("registry_migration_audit_flush");
    const audit = await readFile(harness.config.auditLogPath, "utf8");
    expect(audit).not.toContain(TOKEN);
  });

  it("coalesces unauthenticated WebSocket and IPC storms while retaining normal audit evidence", async () => {
    const harness = await startHarness();
    for (let batch = 0; batch < 8; batch += 1) {
      await Promise.all(Array.from({ length: 4 }, async () => await sendRejectedExtensionHello(harness)));
    }
    await Promise.all(Array.from({ length: 32 }, async () => await sendRejectedIpcHello(harness)));
    await new Promise<void>((resolve) => setImmediate(resolve));
    await connectExtensionAfterUnauthenticatedStorm(
      harness,
      makeSigningIdentity("10101010-1010-4010-8010-101010101010")
    );
    await harness.daemon.stop("audit_storm_flush");

    const auditText = await readFile(harness.config.auditLogPath, "utf8");
    const records = auditText
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const extensionRaw = records.filter((record) => record.outcome === "extension_client_hello_rejected");
    const ipcRaw = records.filter((record) => record.outcome === "ipc_client_hello_rejected");
    const coalesced = records.filter((record) => record.outcome === "unauthenticated_rejections_coalesced");

    expect(extensionRaw.length).toBeGreaterThan(0);
    expect(extensionRaw.length).toBeLessThan(32);
    expect(ipcRaw.length).toBeGreaterThan(0);
    expect(ipcRaw.length).toBeLessThan(32);
    expect(
      coalesced
        .filter((record) => record.code === "extension_client_hello_rejected")
        .reduce((total, record) => total + Number(record.count), 0)
    ).toBeGreaterThan(0);
    expect(
      coalesced
        .filter((record) => record.code === "ipc_client_hello_rejected")
        .reduce((total, record) => total + Number(record.count), 0)
    ).toBeGreaterThan(0);
    expect(records).toContainEqual(expect.objectContaining({ outcome: "extension_authenticated" }));
    expect(auditText).not.toContain(TOKEN);
    expect(auditText).not.toContain(IPC_TOKEN);
    expect(auditText).not.toContain(SECRET_TEXT);
    expect(auditText).not.toContain(UNTRUSTED_LABEL);
  }, 10_000);

  it("binds private loopback TCP endpoints and authenticates every IPC request", async () => {
    const harness = await startHarness();
    const addresses = harness.daemon.addresses();
    expect(addresses.ipcHost).toBe("127.0.0.1");
    expect(addresses.ipcPort).toBeGreaterThan(0);
    if (process.platform !== "win32") {
      expect((await stat(harness.config.runtimeDir)).mode & 0o777).toBe(0o700);
      expect((await stat(harness.config.auditLogPath)).mode & 0o777).toBe(0o600);
    }

    await expect(ipcCall(harness, "status", {}, "wrong-token".repeat(4))).rejects.toThrow(/server proof/u);
    const ipcWire: string[] = [];
    const status = await ipcCall(harness, "status", {}, IPC_TOKEN, 2_000, ipcWire);
    expect(ipcWire.join("\n")).not.toContain(IPC_TOKEN);
    expect(ipcWire.join("\n")).not.toContain(TOKEN);
    expect(status).toMatchObject({
      ok: true,
      result: {
        service: "browseweave",
        protocol_version: PROTOCOL_VERSION,
        websocket_listening: true,
        connected_browsers: [],
        pending_commands: 0,
        pending_approvals: 0
      }
    });
  });

  it("does not reveal an IPC request or secret to a loopback port-squatting server", async () => {
    const captured: string[] = [];
    const fakeSockets = new Set<Socket>();
    const server = createServer((socket) => {
      fakeSockets.add(socket);
      socket.once("close", () => fakeSockets.delete(socket));
      const nextLine = createLineInbox(socket);
      void nextLine().then((line) => {
        captured.push(line);
        const hello = JSON.parse(line) as JsonObject;
        socket.write(`${JSON.stringify({
          type: "ipc_challenge",
          protocol_version: PROTOCOL_VERSION,
          endpoint_role: "ipc",
          client_nonce: hello.client_nonce,
          server_nonce: nonce(),
          daemon_instance_id: "12345678-1234-4123-8123-123456789abc",
          server_proof: nonce()
        })}\n`);
      });
    });
    const port = await listenTestServer(server);
    const previousPort = process.env.BROWSER_MCP_BRIDGE_IPC_PORT;
    const previousToken = process.env.BROWSER_MCP_BRIDGE_IPC_TOKEN;
    process.env.BROWSER_MCP_BRIDGE_IPC_PORT = String(port);
    process.env.BROWSER_MCP_BRIDGE_IPC_TOKEN = IPC_TOKEN;
    try {
      await expect(callBridge("fill_form", { password: SECRET_TEXT }, 2_000)).rejects.toThrow(
        /could not prove|authenticated protocol/u
      );
      expect(captured).toHaveLength(1);
      expect(captured[0]).not.toContain(IPC_TOKEN);
      expect(captured[0]).not.toContain(SECRET_TEXT);
      expect(captured[0]).not.toContain("fill_form");
      expect(JSON.parse(captured[0] as string)).toMatchObject({ type: "ipc_client_hello" });
    } finally {
      if (previousPort === undefined) delete process.env.BROWSER_MCP_BRIDGE_IPC_PORT;
      else process.env.BROWSER_MCP_BRIDGE_IPC_PORT = previousPort;
      if (previousToken === undefined) delete process.env.BROWSER_MCP_BRIDGE_IPC_TOKEN;
      else process.env.BROWSER_MCP_BRIDGE_IPC_TOKEN = previousToken;
      for (const socket of fakeSockets) socket.destroy();
      await closeTestServer(server);
    }
  });

  it("rejects invalid and replayed IPC authentication proofs", async () => {
    const harness = await startHarness();
    const endpoint = harness.daemon.addresses();
    const clientNonce = nonce();
    const clientHello = JSON.stringify({
      type: "ipc_client_hello",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "ipc",
      client_nonce: clientNonce
    });

    const first = createConnection({ host: endpoint.ipcHost, port: endpoint.ipcPort });
    await once(first, "connect");
    const firstLine = createLineInbox(first);
    first.write(`${clientHello}\n`);
    const challenge = JSON.parse(await firstLine()) as JsonObject;
    expect(challenge).toMatchObject({ type: "ipc_challenge", client_nonce: clientNonce });
    first.write(`${JSON.stringify({
      type: "ipc_request",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "ipc",
      id: "invalid-proof",
      method: "status",
      params: {},
      client_nonce: clientNonce,
      server_nonce: challenge.server_nonce,
      daemon_instance_id: challenge.daemon_instance_id,
      client_proof: nonce()
    })}\n`);
    await once(first, "close");

    const replay = createConnection({ host: endpoint.ipcHost, port: endpoint.ipcPort });
    await once(replay, "connect");
    replay.write(`${clientHello}\n`);
    await once(replay, "close");

    await expect(ipcCall(harness, "status")).resolves.toMatchObject({ ok: true });
  });

  it("rejects invalid and replayed extension mutual-auth handshakes", async () => {
    const harness = await startHarness();
    const signing = makeSigningIdentity("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    expect(await beginLegacyPairing(harness, "firefox")).toMatchObject({ ok: true });
    const { websocketPort } = harness.daemon.addresses();
    const clientNonce = nonce();
    const clientHello = JSON.stringify({
      type: "client_hello",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "extension",
      client_nonce: clientNonce,
      origin: FIREFOX_ORIGIN,
      identity: signing.identity,
      public_key: signing.publicKey
    });

    const first = new WebSocket(`ws://127.0.0.1:${websocketPort}`, { origin: FIREFOX_ORIGIN });
    sockets.push(first);
    const firstNext = createInbox(first);
    await once(first, "open");
    first.send(clientHello);
    const challenge = await firstNext("challenge");
    const badClientProof = nonce();
    const signed = helloSigningPayload({
      clientNonce,
      serverNonce: String(challenge.server_nonce),
      daemonInstanceId: String(challenge.daemon_instance_id),
      origin: FIREFOX_ORIGIN,
      installationId: signing.identity.installation_id,
      publicKey: signing.publicKey,
      clientProof: badClientProof
    });
    first.send(JSON.stringify({
      type: "hello",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "extension",
      client_nonce: clientNonce,
      server_nonce: challenge.server_nonce,
      origin: FIREFOX_ORIGIN,
      daemon_instance_id: challenge.daemon_instance_id,
      identity: signing.identity,
      public_key: signing.publicKey,
      client_proof: badClientProof,
      signature: signature(signing.privateKey, signed)
    }));
    const [closeCode] = await once(first, "close") as [number, Buffer];
    expect(closeCode).toBe(1008);

    const replay = new WebSocket(`ws://127.0.0.1:${websocketPort}`, { origin: FIREFOX_ORIGIN });
    sockets.push(replay);
    await once(replay, "open");
    replay.send(clientHello);
    const [replayCloseCode] = await once(replay, "close") as [number, Buffer];
    expect(replayCloseCode).toBe(1008);
    await expect(ipcCall(harness, "status")).resolves.toMatchObject({
      ok: true,
      result: { connected_browsers: [] }
    });
  });

  it("pins a challenge-proven extension key and rejects a replacement key for that installation", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-pinning-"));
    const original = makeSigningIdentity("11111111-1111-4111-8111-111111111111");
    const first = await startHarness({}, root);
    const extensionWire: string[] = [];
    const connected = await connectExtension(first, original, FIREFOX_ORIGIN, TOKEN, extensionWire);
    expect(extensionWire.join("\n")).not.toContain(TOKEN);
    expect(extensionWire.every((line) => !Object.hasOwn(JSON.parse(line) as object, "token"))).toBe(true);
    expect(connected.browserId).toMatch(/^browser-[a-f0-9]{24}$/u);
    await first.daemon.stop("restart_test");

    const registry = JSON.parse(await readFile(first.config.extensionKeyPath, "utf8")) as JsonObject;
    expect(registry.version).toBe(2);
    expect((registry.installations as JsonObject)[original.identity.installation_id]).toMatchObject({
      auth_mode: "legacy"
    });
    expect(JSON.stringify(registry)).not.toContain("private");
    if (process.platform !== "win32") {
      expect((await stat(first.config.extensionKeyPath)).mode & 0o777).toBe(0o600);
    }

    const second = await startHarness({}, root);
    await expect(connectExtension(second, original)).resolves.toMatchObject({ browserId: connected.browserId });
    const replacement = makeSigningIdentity(original.identity.installation_id);
    await expect(connectExtension(second, replacement)).rejects.toThrow(/Timed out|closed|WebSocket/iu);
  });

  it("accepts overlapping fully authenticated reconnects and keeps only the newest installation session", async () => {
    const harness = await startHarness();
    const signing = makeSigningIdentity("45454545-4545-4545-8545-454545454545");
    const initial = await connectExtension(harness, signing);
    const [left, right] = await Promise.all([
      connectExtension(harness, signing, FIREFOX_ORIGIN, TOKEN, undefined, false),
      connectExtension(harness, signing, FIREFOX_ORIGIN, TOKEN, undefined, false)
    ]);
    expect(left.browserId).toBe(initial.browserId);
    expect(right.browserId).toBe(initial.browserId);
    expect(await ipcCall(harness, "status")).toMatchObject({
      ok: true,
      result: {
        connected_browsers: [{
          browser_id: initial.browserId,
          browser_family: "firefox"
        }]
      }
    });
  });

  it("persists separately authorized extension keys and reconnects them concurrently", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-concurrent-pinning-"));
    const firefoxIdentity = makeSigningIdentity("12121212-1212-4121-8121-121212121212");
    const chromiumIdentity = makeSigningIdentity("34343434-3434-4343-8343-343434343434", "chromium");
    const first = await startHarness({}, root);

    const firefox = await connectExtension(first, firefoxIdentity, FIREFOX_ORIGIN);
    const chromium = await connectExtension(first, chromiumIdentity, CHROMIUM_ORIGIN);
    await first.daemon.stop("concurrent_registry_restart");

    const registry = JSON.parse(await readFile(first.config.extensionKeyPath, "utf8")) as JsonObject;
    expect(Object.keys(registry.installations as JsonObject)).toHaveLength(2);

    const second = await startHarness({}, root);
    const [reconnectedFirefox, reconnectedChromium] = await Promise.all([
      connectExtension(second, firefoxIdentity, FIREFOX_ORIGIN),
      connectExtension(second, chromiumIdentity, CHROMIUM_ORIGIN)
    ]);
    expect(reconnectedFirefox.browserId).toBe(firefox.browserId);
    expect(reconnectedChromium.browserId).toBe(chromium.browserId);
  });

  it("supports Firefox and Chromium simultaneously and requires browser_id for unambiguous routing", async () => {
    const harness = await startHarness();
    const firefox = await connectExtension(
      harness,
      makeSigningIdentity("22222222-2222-4222-8222-222222222222")
    );
    const chromium = await connectExtension(
      harness,
      makeSigningIdentity("33333333-3333-4333-8333-333333333333", "chromium"),
      CHROMIUM_ORIGIN
    );
    const ambiguous = await ipcCall(harness, "list_tabs");
    expect(ambiguous).toMatchObject({ ok: false });
    if (!ambiguous.ok) expect(ambiguous.error).toMatch(/browser_id/u);

    const routedPromise = ipcCall(harness, "list_tabs", { browser_id: chromium.browserId });
    const command = await chromium.next("command");
    expect(command).toMatchObject({ action: "list_tabs", approved: false, payload: {} });
    chromium.socket.send(JSON.stringify({
      type: "result",
      id: command.id,
      ok: true,
      result: { tabs: [{ id: 7, title: "Chromium tab" }], total: 1 }
    }));
    const routed = await routedPromise;
    expect(routed).toMatchObject({
      ok: true,
      result: {
        browser_id: chromium.browserId,
        tabs: [{ id: 7, browser_id: chromium.browserId }]
      }
    });
    await expect(firefox.next("command", 100)).rejects.toThrow(/Timed out/u);

    const status = await ipcCall(harness, "status");
    if (!status.ok || !isJsonObjectForTest(status.result)) throw new Error("Status failed");
    expect((status.result.connected_browsers as unknown[])).toHaveLength(2);
  });

  it("never echoes or audits remote credential values even when an extension result tries to include them", async () => {
    const harness = await startHarness();
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("45454545-4545-4454-8454-454545454545")
    );
    const credentialParams = {
      browser_id: extension.browserId,
      tab_id: 9,
      frame_id: 0,
      fields: [{ ref: "bw-1", kind: "password", value: SECRET_TEXT }],
      submit: false
    };

    const successCall = ipcCall(harness, "credential_fill", credentialParams);
    const successCommand = await extension.next("command");
    expect(successCommand).toMatchObject({
      action: "credential_fill",
      payload: { fields: [{ kind: "password", value: SECRET_TEXT }] }
    });
    extension.socket.send(JSON.stringify({
      type: "result",
      id: successCommand.id,
      ok: true,
      result: { filled: true, accidental_echo: SECRET_TEXT }
    }));
    const success = await successCall;
    expect(success).toMatchObject({
      ok: true,
      result: { credential_fill_completed: true, browser_id: extension.browserId }
    });
    expect(JSON.stringify(success)).not.toContain(SECRET_TEXT);

    const failureCall = ipcCall(harness, "credential_fill", credentialParams);
    const failureCommand = await extension.next("command");
    extension.socket.send(JSON.stringify({
      type: "result",
      id: failureCommand.id,
      ok: false,
      error: { code: "credential_apply_failed", message: `Never forward ${SECRET_TEXT}` }
    }));
    const failure = await failureCall;
    expect(failure.ok).toBe(false);
    expect(JSON.stringify(failure)).not.toContain(SECRET_TEXT);

    await harness.daemon.stop("credential_audit_flush");
    const audit = await readFile(harness.config.auditLogPath, "utf8");
    expect(audit).not.toContain(SECRET_TEXT);
  });

  async function startSessionApprovalHarness(risks = ["form_submit"]): Promise<Harness> {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-daemon-"));
    await mkdir(path.join(root, "config"), { recursive: true, mode: 0o700 });
    await writeFile(
      path.join(root, "config", "policy.json"),
      JSON.stringify({ session_approval: { enabled: true, risks } }),
      { mode: 0o600 }
    );
    return startHarness({}, root);
  }

  it("reads an allowed local file, pauses it for approval, and binds the approval to the exact bytes", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-daemon-"));
    const documents = path.join(root, "documents");
    await mkdir(documents, { recursive: true });
    await mkdir(path.join(root, "config"), { recursive: true, mode: 0o700 });
    await writeFile(
      path.join(root, "config", "policy.json"),
      JSON.stringify({
        session_approval: { enabled: true, risks: ["file_attach"] },
        file_attach: { enabled: true, allowed_directories: [documents] }
      }),
      { mode: 0o600 }
    );
    const attachment = path.join(documents, "report.txt");
    await writeFile(attachment, "quarterly numbers");

    const harness = await startHarness({}, root);
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("88888888-8888-4888-8888-888888888888")
    );
    const params = { browser_id: extension.browserId, tab_id: 3, frame_id: 0, ref: "bw-1", path: attachment };

    const call = ipcCall(harness, "attach_file", params);
    const command = await extension.next("command");
    const payload = isJsonObjectForTest(command.payload) ? command.payload : {};
    const file = isJsonObjectForTest(payload.file) ? payload.file : {};
    expect(file).toMatchObject({ name: "report.txt", mime_type: "text/plain", size: 17 });
    // The absolute path must never reach the browser; only the basename does.
    expect(JSON.stringify(payload)).not.toContain(documents);
    expect(Buffer.from(String(file.base64), "base64").toString("utf8")).toBe("quarterly numbers");

    extension.socket.send(commandFailure(command, FINGERPRINT_A, UNTRUSTED_LABEL, "file_attach"));
    const approvalRequest = await extension.next("approval_request");
    expect(await call).toMatchObject({
      ok: true,
      result: { approval_required: true, session_approval_available: true }
    });

    const begin = await ipcCall(harness, "session_approval_begin", {
      approval_id: approvalRequest.approval_id as string
    });
    const beginResult = isJsonObjectForTest(begin.result) ? begin.result : {};
    const beginFile = isJsonObjectForTest(beginResult.file) ? beginResult.file : {};
    expect(beginFile).toMatchObject({ name: "report.txt", size: 17 });
    expect(String(beginFile.sha256)).toMatch(/^[a-f0-9]{64}$/u);
    // The confirmation facts identify the file without carrying its contents.
    expect(JSON.stringify(beginResult)).not.toContain(String(file.base64));

    await ipcCall(harness, "session_approval_submit", {
      approval_id: approvalRequest.approval_id as string,
      decision: "approve",
      confirmation_phrase: String(beginResult.confirmation_phrase)
    });

    // Changing the file must not be able to ride the approval given for the
    // bytes the human actually confirmed.
    await writeFile(attachment, "different numbers");
    const tampered = ipcCall(harness, "attach_file", params);
    const tamperedCommand = await extension.next("command");
    expect(tamperedCommand.approved).toBe(false);
    extension.socket.send(commandFailure(tamperedCommand, FINGERPRINT_B, UNTRUSTED_LABEL, "file_attach"));
    await extension.next("approval_request");
    expect(await tampered).toMatchObject({ ok: true, result: { approval_required: true } });

    await writeFile(attachment, "quarterly numbers");
    const retry = ipcCall(harness, "attach_file", params);
    const liveCheck = await extension.next("command");
    expect(liveCheck).toMatchObject({ approved: false, revalidate_only: true });
    extension.socket.send(commandFailure(liveCheck, FINGERPRINT_A, UNTRUSTED_LABEL, "file_attach"));
    const approved = await extension.next("command");
    expect(approved).toMatchObject({ approved: true, approval_source: "session" });
    extension.socket.send(JSON.stringify({
      type: "result",
      id: approved.id,
      ok: true,
      result: { attached: true }
    }));
    expect(await retry).toMatchObject({ ok: true, result: { attached: true } });

    await harness.daemon.stop("attach_audit_flush");
    const audit = await readFile(harness.config.auditLogPath, "utf8");
    expect(audit).not.toContain(documents);
    expect(audit).not.toContain("report.txt");
  });

  it("refuses to read a file the owner policy does not allow", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-daemon-"));
    const documents = path.join(root, "documents");
    const elsewhere = path.join(root, "elsewhere");
    await mkdir(documents, { recursive: true });
    await mkdir(elsewhere, { recursive: true });
    await mkdir(path.join(root, "config"), { recursive: true, mode: 0o700 });
    await writeFile(
      path.join(root, "config", "policy.json"),
      JSON.stringify({ file_attach: { enabled: true, allowed_directories: [documents] } }),
      { mode: 0o600 }
    );
    await writeFile(path.join(elsewhere, "secret.txt"), "outside");

    const harness = await startHarness({}, root);
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("99999999-9999-4999-8999-999999999999")
    );
    const refused = await ipcCall(harness, "attach_file", {
      browser_id: extension.browserId,
      tab_id: 3,
      ref: "bw-1",
      path: path.join(elsewhere, "secret.txt")
    });
    expect(refused).toMatchObject({ ok: false });
    expect(String(isJsonObjectForTest(refused) ? refused.error : "")).toMatch(/outside every directory/);
  });

  it("confirms a session-approvable risk in the session and marks the executed command as session-sourced", async () => {
    const harness = await startSessionApprovalHarness();
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("55555555-5555-4555-8555-555555555555")
    );
    const params = { browser_id: extension.browserId, tab_id: 4, frame_id: 0, ref: "bw-9" };

    const firstCall = ipcCall(harness, "click", params);
    const firstCommand = await extension.next("command");
    extension.socket.send(commandFailure(firstCommand, FINGERPRINT_A, UNTRUSTED_LABEL, "form_submit"));
    const approvalRequest = await extension.next("approval_request");
    expect(await firstCall).toMatchObject({
      ok: true,
      result: { approval_required: true, session_approval_available: true }
    });

    const begin = await ipcCall(harness, "session_approval_begin", {
      approval_id: approvalRequest.approval_id as string
    });
    const challenge = isJsonObjectForTest(begin.result) ? String(begin.result.confirmation_phrase) : "";
    expect(SESSION_CHALLENGE_PATTERN.test(challenge)).toBe(true);

    // The phrase must never be reachable from a tool result or the audit log.
    expect(JSON.stringify(await firstCall)).not.toContain(challenge);

    const submitted = await ipcCall(harness, "session_approval_submit", {
      approval_id: approvalRequest.approval_id as string,
      decision: "approve",
      confirmation_phrase: challenge
    });
    expect(submitted).toMatchObject({ ok: true, result: { decision: "approve" } });

    const retry = ipcCall(harness, "click", params);
    const liveCheck = await extension.next("command");
    expect(liveCheck).toMatchObject({ approved: false, revalidate_only: true });
    extension.socket.send(commandFailure(liveCheck, FINGERPRINT_A, UNTRUSTED_LABEL, "form_submit"));
    const approvedCommand = await extension.next("command");
    expect(approvedCommand).toMatchObject({
      approved: true,
      approval_id: approvalRequest.approval_id,
      approval_source: "session"
    });
    extension.socket.send(JSON.stringify({
      type: "result",
      id: approvedCommand.id,
      ok: true,
      result: { clicked: true }
    }));
    expect(await retry).toMatchObject({ ok: true, result: { clicked: true } });

    await harness.daemon.stop("session_approval_audit_flush");
    const audit = await readFile(harness.config.auditLogPath, "utf8");
    expect(audit).not.toContain(challenge);
    expect(audit).toContain("session_approved");
  });

  it("destroys the approval after one wrong confirmation phrase", async () => {
    const harness = await startSessionApprovalHarness(["message"]);
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("66666666-6666-4666-8666-666666666666")
    );
    const params = { browser_id: extension.browserId, tab_id: 5, frame_id: 0, ref: "bw-2" };

    const call = ipcCall(harness, "click", params);
    const command = await extension.next("command");
    extension.socket.send(commandFailure(command, FINGERPRINT_A, UNTRUSTED_LABEL, "message"));
    const approvalRequest = await extension.next("approval_request");
    await call;

    const begin = await ipcCall(harness, "session_approval_begin", {
      approval_id: approvalRequest.approval_id as string
    });
    const challenge = isJsonObjectForTest(begin.result) ? String(begin.result.confirmation_phrase) : "";

    const wrong = await ipcCall(harness, "session_approval_submit", {
      approval_id: approvalRequest.approval_id as string,
      decision: "approve",
      confirmation_phrase: "amber cedar flint onyx"
    });
    expect(wrong).toMatchObject({ ok: false });

    // The correct phrase must not rescue an approval already spent on a guess.
    const retryWithTruth = await ipcCall(harness, "session_approval_submit", {
      approval_id: approvalRequest.approval_id as string,
      decision: "approve",
      confirmation_phrase: challenge
    });
    expect(retryWithTruth).toMatchObject({ ok: false });
    expect(await ipcCall(harness, "status")).toMatchObject({ ok: true, result: { pending_approvals: 0 } });
  });

  it("never offers session confirmation for a risk outside the opted-in tier", async () => {
    const harness = await startSessionApprovalHarness(["form_submit"]);
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("77777777-7777-4777-8777-777777777777")
    );
    const params = { browser_id: extension.browserId, tab_id: 6, frame_id: 0, ref: "bw-4" };

    const categories = ["password", "payment", "delete", "message"];
    for (const [index, category] of categories.entries()) {
      const call = ipcCall(harness, "click", { ...params, ref: `bw-${index + 20}` });
      const command = await extension.next("command");
      extension.socket.send(commandFailure(command, FINGERPRINT_A, UNTRUSTED_LABEL, category));
      const approvalRequest = await extension.next("approval_request");
      expect(await call).toMatchObject({
        ok: true,
        result: { approval_required: true, session_approval_available: false }
      });
      const begin = await ipcCall(harness, "session_approval_begin", {
        approval_id: approvalRequest.approval_id as string
      });
      expect(begin).toMatchObject({ ok: false });
    }
  });

  it("accepts only an extension-signed approval and consumes it once after a fresh live fingerprint", async () => {
    const harness = await startHarness();
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("44444444-4444-4444-8444-444444444444")
    );
    const params = { browser_id: extension.browserId, tab_id: 7, frame_id: 0, ref: "bw-3", text: SECRET_TEXT };

    const firstCall = ipcCall(harness, "click", params);
    const firstCommand = await extension.next("command");
    extension.socket.send(commandFailure(firstCommand, FINGERPRINT_A));
    const approvalRequest = await extension.next("approval_request");
    expect(approvalRequest).toMatchObject({ target_tab_id: 7, target_frame_id: 0 });
    const firstResult = await firstCall;
    expect(firstResult).toMatchObject({
      ok: true,
      result: {
        approval_required: true,
        approval_ui: "browser_extension",
        browser_id: extension.browserId
      }
    });

    const directConfirm = await ipcCall(harness, "confirm_pending", {
      approval_id: approvalRequest.approval_id as string,
      user_confirmed: true
    });
    expect(directConfirm).toMatchObject({ ok: false });

    const approvalMessage = {
      type: "approval_decision",
      approval_id: approvalRequest.approval_id,
      decision: "approve",
      signature: signDecision(extension, approvalRequest, "approve")
    };
    extension.socket.send(JSON.stringify(approvalMessage));
    expect(await extension.next("approval_resolved")).toMatchObject({ outcome: "approved" });

    extension.socket.send(JSON.stringify(approvalMessage));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const afterReplay = await ipcCall(harness, "status");
    expect(afterReplay).toMatchObject({ ok: true, result: { pending_approvals: 1 } });

    const retry = ipcCall(harness, "click", params);
    const liveCheck = await extension.next("command");
    expect(liveCheck).toMatchObject({ approved: false, revalidate_only: true });
    extension.socket.send(commandFailure(liveCheck, FINGERPRINT_A));
    const approvedCommand = await extension.next("command");
    expect(approvedCommand).toMatchObject({
      approved: true,
      approval_id: approvalRequest.approval_id,
      approval_fingerprint: FINGERPRINT_A,
      payload: { tab_id: 7, frame_id: 0, ref: "bw-3", text: SECRET_TEXT }
    });
    extension.socket.send(JSON.stringify({
      type: "result",
      id: approvedCommand.id,
      ok: true,
      result: { clicked: true }
    }));
    expect(await extension.next("approval_resolved")).toMatchObject({
      approval_id: approvalRequest.approval_id,
      outcome: "consumed"
    });
    expect(await retry).toMatchObject({ ok: true, result: { clicked: true, browser_id: extension.browserId } });

    const third = ipcCall(harness, "click", params);
    const thirdCommand = await extension.next("command");
    expect(thirdCommand.approved).toBe(false);
    extension.socket.send(commandFailure(thirdCommand, FINGERPRINT_A));
    const secondApproval = await extension.next("approval_request");
    expect(secondApproval.approval_id).not.toBe(approvalRequest.approval_id);
    expect(await third).toMatchObject({ ok: true, result: { approval_required: true } });

    const audit = await readFile(harness.config.auditLogPath, "utf8");
    expect(audit).not.toContain(SECRET_TEXT);
    expect(audit).not.toContain(UNTRUSTED_LABEL);
    expect(audit).not.toContain(String(approvalRequest.approval_id));
  });

  it("rejects a forged approval signature without creating a usable grant", async () => {
    const harness = await startHarness();
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("55555555-5555-4555-8555-555555555555")
    );
    const call = ipcCall(harness, "click", { browser_id: extension.browserId, tab_id: 1, ref: "bw-1" });
    const command = await extension.next("command");
    extension.socket.send(commandFailure(command, FINGERPRINT_A));
    const approval = await extension.next("approval_request");
    await call;

    const attacker = makeSigningIdentity("66666666-6666-4666-8666-666666666666");
    extension.socket.send(JSON.stringify({
      type: "approval_decision",
      approval_id: approval.approval_id,
      decision: "approve",
      signature: signDecision(extension, approval, "approve", {}, attacker.privateKey)
    }));
    const [closeCode] = await once(extension.socket, "close") as [number, Buffer];
    expect(closeCode).toBe(1008);
    const status = await ipcCall(harness, "status");
    expect(status).toMatchObject({
      ok: true,
      result: { connected_browsers: [], pending_approvals: 0 }
    });
  });

  it("does not consume an approval when the fresh target fingerprint changes", async () => {
    const harness = await startHarness();
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("77777777-7777-4777-8777-777777777777")
    );
    const params = { browser_id: extension.browserId, tab_id: 4, ref: "bw-8" };
    const first = ipcCall(harness, "click", params);
    const command = await extension.next("command");
    extension.socket.send(commandFailure(command, FINGERPRINT_A));
    const approval = await extension.next("approval_request");
    await first;
    extension.socket.send(JSON.stringify({
      type: "approval_decision",
      approval_id: approval.approval_id,
      decision: "approve",
      signature: signDecision(extension, approval, "approve")
    }));
    await extension.next("approval_resolved");

    const retry = ipcCall(harness, "click", params);
    const liveCheck = await extension.next("command");
    expect(liveCheck).toMatchObject({ approved: false, revalidate_only: true });
    extension.socket.send(commandFailure(liveCheck, FINGERPRINT_B));
    const replacementApproval = await extension.next("approval_request");
    expect(replacementApproval.approval_fingerprint).toBe(FINGERPRINT_B);
    expect(replacementApproval.approval_id).not.toBe(approval.approval_id);
    expect(await retry).toMatchObject({ ok: true, result: { approval_required: true } });
    await expect(extension.next("command", 100)).rejects.toThrow(/Timed out/u);
  });

  it("never executes during approval revalidation when the live risk disappears", async () => {
    const harness = await startHarness();
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("99999999-9999-4999-8999-999999999999")
    );
    const params = { browser_id: extension.browserId, tab_id: 6, ref: "bw-4" };
    const first = ipcCall(harness, "click", params);
    const firstCommand = await extension.next("command");
    expect(firstCommand).toMatchObject({ approved: false, revalidate_only: false });
    extension.socket.send(commandFailure(firstCommand, FINGERPRINT_A));
    const approval = await extension.next("approval_request");
    await first;
    extension.socket.send(JSON.stringify({
      type: "approval_decision",
      approval_id: approval.approval_id,
      decision: "approve",
      signature: signDecision(extension, approval, "approve")
    }));
    await extension.next("approval_resolved");

    const retry = ipcCall(harness, "click", params);
    const liveCheck = await extension.next("command");
    expect(liveCheck).toMatchObject({ approved: false, revalidate_only: true });
    extension.socket.send(JSON.stringify({
      type: "result",
      id: liveCheck.id,
      ok: false,
      error: {
        code: "approval_no_longer_required",
        message: "The live target no longer has the approved risk context."
      }
    }));
    expect(await extension.next("approval_resolved")).toMatchObject({
      approval_id: approval.approval_id,
      outcome: "cancelled"
    });
    const result = await retry;
    expect(result).toMatchObject({ ok: false });
    if (!result.ok) expect(result.error).toMatch(/approval_no_longer_required/u);
    await expect(extension.next("command", 100)).rejects.toThrow(/Timed out/u);
    expect(await ipcCall(harness, "status")).toMatchObject({
      ok: true,
      result: { pending_approvals: 0 }
    });
  });

  it("binds approval decisions to every signed field", async () => {
    const harness = await startHarness();
    const extension = await connectExtension(
      harness,
      makeSigningIdentity("88888888-8888-4888-8888-888888888888")
    );
    const call = ipcCall(harness, "click", { browser_id: extension.browserId, tab_id: 2, ref: "bw-9" });
    const command = await extension.next("command");
    extension.socket.send(commandFailure(command, FINGERPRINT_A));
    const approval = await extension.next("approval_request");
    await call;

    extension.socket.send(JSON.stringify({
      type: "approval_decision",
      approval_id: approval.approval_id,
      decision: "approve",
      signature: signDecision(extension, approval, "approve", { paramsSha256: FINGERPRINT_B })
    }));
    const [closeCode] = await once(extension.socket, "close") as [number, Buffer];
    expect(closeCode).toBe(1008);
  });
});

function isJsonObjectForTest(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
