import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  ExtensionHandshake,
  hmacSha256Base64Url
} from "../extension/src/security/handshake";
import {
  PROTOCOL_VERSION,
  extensionClientProofPayload,
  extensionServerProofPayload,
  type BrowserIdentity,
  type P256PublicJwk
} from "../src/core/protocol";

const PAIRING_SECRET = "pairing-secret-with-utf8-ç-0123456789";
const ORIGIN = "moz-extension://12345678-abcd-4321-abcd-1234567890ab";
const CLIENT_NONCE = "A".repeat(43);
const SERVER_NONCE = "B".repeat(43);
const DAEMON_ID = "00000000-1111-4222-8333-444444444444";
const PUBLIC_KEY: P256PublicJwk = {
  kty: "EC",
  crv: "P-256",
  x: "C".repeat(43),
  y: "D".repeat(43),
  ext: true,
  key_ops: ["verify"]
};
const IDENTITY: BrowserIdentity = {
  installation_id: "12345678-abcd-4def-8abc-1234567890ab",
  browser_family: "firefox",
  browser_name: "Test Firefox",
  browser_version: "1.0",
  extension_version: "0.1.0"
};

function handshake(): ExtensionHandshake {
  return new ExtensionHandshake({ origin: ORIGIN, identity: IDENTITY, publicKey: PUBLIC_KEY }, CLIENT_NONCE);
}

async function validChallenge(
  setupId?: string,
  setupPhase: "provisioning" | "persisted" = "provisioning"
): Promise<Record<string, unknown>> {
  const serverProof = await hmacSha256Base64Url(PAIRING_SECRET, extensionServerProofPayload({
    clientNonce: CLIENT_NONCE,
    serverNonce: SERVER_NONCE,
    daemonInstanceId: DAEMON_ID,
    origin: ORIGIN,
    installationId: IDENTITY.installation_id,
    publicKey: PUBLIC_KEY,
    ...(setupId === undefined ? {} : { setupId, setupPhase })
  }));
  return {
    type: "challenge",
    protocol_version: PROTOCOL_VERSION,
    endpoint_role: "extension",
    client_nonce: CLIENT_NONCE,
    server_nonce: SERVER_NONCE,
    daemon_instance_id: DAEMON_ID,
    server_proof: serverProof
  };
}

describe("BrowseWeave extension mutual authentication", () => {
  it("sends no pairing secret and proves both sides over the exact transcript", async () => {
    const state = handshake();
    const clientHello = state.createClientHello();
    expect(clientHello).toMatchObject({
      type: "client_hello",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "extension",
      client_nonce: CLIENT_NONCE
    });
    expect(JSON.stringify(clientHello)).not.toContain(PAIRING_SECRET);
    expect(clientHello).not.toHaveProperty("token");

    const challenge = await validChallenge();
    await state.verifyChallenge(challenge, PAIRING_SECRET);
    const hello = state.createHello("E".repeat(86));
    expect(hello).not.toHaveProperty("token");
    const expectedClientProof = await hmacSha256Base64Url(PAIRING_SECRET, extensionClientProofPayload({
      clientNonce: CLIENT_NONCE,
      serverNonce: SERVER_NONCE,
      daemonInstanceId: DAEMON_ID,
      origin: ORIGIN,
      installationId: IDENTITY.installation_id,
      publicKey: PUBLIC_KEY,
      serverProof: String(challenge.server_proof)
    }));
    expect(hello.client_proof).toBe(expectedClientProof);
    expect(state.acceptHelloAck({
      type: "hello_ack",
      protocol_version: PROTOCOL_VERSION,
      browser_id: "browser-0123456789abcdef01234567"
    })).toBe("browser-0123456789abcdef01234567");
    expect(state.phase).toBe("authenticated");
  });

  it("uses UTF-8 token bytes and unpadded 32-byte HMAC-SHA256 proofs", async () => {
    const payload = "BrowseWeave transcript";
    const proof = await hmacSha256Base64Url(PAIRING_SECRET, payload);
    const nodeProof = createHmac("sha256", Buffer.from(PAIRING_SECRET, "utf8"))
      .update(payload, "utf8")
      .digest("base64url");
    expect(proof).toBe(nodeProof);
    expect(proof).toHaveLength(43);
    expect(proof).not.toContain("=");
  });

  it("marks and cryptographically binds only the staged setup reconnect", async () => {
    const setupId = "0123456789abcdef01234567";
    const staged = new ExtensionHandshake({
      origin: ORIGIN,
      identity: IDENTITY,
      publicKey: PUBLIC_KEY,
      stagedSetupId: setupId,
      stagedSetupPhase: "provisioning"
    }, CLIENT_NONCE);
    expect(staged.createClientHello()).toEqual(expect.objectContaining({
      authentication_mode: "derived-v1",
      setup_id: setupId,
      setup_phase: "provisioning"
    }));
    await staged.verifyChallenge(await validChallenge(setupId), PAIRING_SECRET);
    expect(staged.helloSigningPayload()).toContain(`setup_id:${setupId.length}:${setupId}`);
    expect(staged.helloSigningPayload()).toContain("setup_phase:12:provisioning");
    const mismatched = new ExtensionHandshake({
      origin: ORIGIN,
      identity: IDENTITY,
      publicKey: PUBLIC_KEY,
      stagedSetupId: setupId,
      stagedSetupPhase: "provisioning"
    }, CLIENT_NONCE);
    mismatched.createClientHello();
    await expect(mismatched.verifyChallenge(
      await validChallenge("1123456789abcdef01234567"),
      PAIRING_SECRET
    )).rejects.toThrow(/prove possession/iu);
    const phaseMismatched = new ExtensionHandshake({
      origin: ORIGIN,
      identity: IDENTITY,
      publicKey: PUBLIC_KEY,
      stagedSetupId: setupId,
      stagedSetupPhase: "provisioning"
    }, CLIENT_NONCE);
    phaseMismatched.createClientHello();
    await expect(phaseMismatched.verifyChallenge(
      await validChallenge(setupId, "persisted"),
      PAIRING_SECRET
    )).rejects.toThrow(/prove possession/iu);
    expect(handshake().createClientHello()).not.toHaveProperty("authentication_mode");
    expect(() => new ExtensionHandshake({
      origin: ORIGIN,
      identity: IDENTITY,
      publicKey: PUBLIC_KEY,
      stagedSetupId: setupId.toUpperCase(),
      stagedSetupPhase: "provisioning"
    }, CLIENT_NONCE)).toThrow(/setup ID/iu);
    expect(() => new ExtensionHandshake({
      origin: ORIGIN,
      identity: IDENTITY,
      publicKey: PUBLIC_KEY,
      stagedSetupId: setupId
    }, CLIENT_NONCE)).toThrow(/supplied together/iu);
  });

  it("rejects an invalid server proof before creating a client proof", async () => {
    const state = handshake();
    state.createClientHello();
    const challenge = { ...await validChallenge(), server_proof: "Z".repeat(43) };
    await expect(state.verifyChallenge(challenge, PAIRING_SECRET)).rejects.toThrow(/prove possession/);
    expect(state.phase).toBe("failed");
    expect(() => state.createHello("E".repeat(86))).toThrow(/invalid or out of order/);
  });

  it("rejects nonce mismatch, duplicate challenge replay, and early acknowledgement", async () => {
    const mismatch = handshake();
    mismatch.createClientHello();
    await expect(mismatch.verifyChallenge({
      ...await validChallenge(),
      client_nonce: "F".repeat(43)
    }, PAIRING_SECRET)).rejects.toThrow(/does not match/);

    const replay = handshake();
    replay.createClientHello();
    const challenge = await validChallenge();
    await replay.verifyChallenge(challenge, PAIRING_SECRET);
    await expect(replay.verifyChallenge(challenge, PAIRING_SECRET)).rejects.toThrow(/replayed/);

    const earlyAck = handshake();
    earlyAck.createClientHello();
    expect(() => earlyAck.acceptHelloAck({
      type: "hello_ack",
      protocol_version: PROTOCOL_VERSION,
      browser_id: "browser-0123456789abcdef01234567"
    })).toThrow(/out-of-order/);
  });
});
