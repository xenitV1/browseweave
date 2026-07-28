import { createServer } from "node:net";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DEFAULT_IPC_PORT, DEFAULT_WS_PORT } from "../src/config.js";
import { PROTOCOL_VERSION } from "../src/protocol.js";
import {
  authorizeServiceMutation,
  isBrowseWeaveServiceIdentity,
  isExactBrowseWeaveHealth,
  isProvenStoppedSystemdService,
  probeLoopbackPort,
  runManagedServiceInstallOperation,
  waitForExactBridgeHealth
} from "../src/service-install-guard.js";

const openServers: Array<ReturnType<typeof createServer>> = [];

afterEach(async () => {
  await Promise.all(openServers.splice(0).map(async (server) => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }));
});

function healthyStatus(): Record<string, unknown> {
  return {
    service: "browseweave",
    protocol_version: PROTOCOL_VERSION,
    websocket_listening: true,
    connected_browsers: [],
    pending_commands: 0,
    pending_approvals: 0,
    uptime_seconds: 1
  };
}

describe("managed service install guard", () => {
  it("requires the exact authenticated service identity and exact healthy listener state", () => {
    expect(isBrowseWeaveServiceIdentity(healthyStatus())).toBe(true);
    expect(isExactBrowseWeaveHealth(healthyStatus())).toBe(true);
    expect(isBrowseWeaveServiceIdentity({ ...healthyStatus(), service: "lookalike" })).toBe(false);
    expect(isBrowseWeaveServiceIdentity({ ...healthyStatus(), protocol_version: PROTOCOL_VERSION + 1 })).toBe(false);
    expect(isExactBrowseWeaveHealth({ ...healthyStatus(), websocket_listening: false })).toBe(false);
  });

  it("accepts only explicit non-active systemd states as stopped proof", () => {
    expect(isProvenStoppedSystemdService(3, "inactive\n")).toBe(true);
    expect(isProvenStoppedSystemdService(3, "failed\n")).toBe(true);
    expect(isProvenStoppedSystemdService(4, "unknown\n")).toBe(true);
    expect(isProvenStoppedSystemdService(0, "active\n")).toBe(false);
    expect(isProvenStoppedSystemdService(1, "")).toBe(false);
    expect(isProvenStoppedSystemdService(1, "permission denied\n")).toBe(false);
  });

  it("does not probe ports after an existing daemon authenticates", async () => {
    const probePort = vi.fn(async () => true);
    await expect(authorizeServiceMutation({
      authenticateStatus: async () => healthyStatus(),
      probePort
    })).resolves.toBe("authenticated");
    expect(probePort).not.toHaveBeenCalled();
  });

  it("permits a first install only when both default ports are proven available", async () => {
    const probed: number[] = [];
    await expect(authorizeServiceMutation({
      authenticateStatus: async () => { throw new Error("not running"); },
      probePort: async (port) => {
        probed.push(port);
        return false;
      }
    })).resolves.toBe("ports_available");
    expect(probed.sort((left, right) => left - right)).toEqual([DEFAULT_WS_PORT, DEFAULT_IPC_PORT].sort((left, right) => left - right));
  });

  it("refuses mutation when an unauthenticated process owns either default port", async () => {
    await expect(authorizeServiceMutation({
      authenticateStatus: async () => ({ service: "browseweave", protocol_version: 999 }),
      probePort: async (port) => port === DEFAULT_IPC_PORT
    })).rejects.toThrow(/32111.*already in use.*No service files or tasks were changed/iu);
  });

  it("probes an occupied loopback port without sending any bytes", async () => {
    const received: Buffer[] = [];
    const server = createServer((socket) => socket.on("data", (chunk) => received.push(chunk)));
    openServers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Test server did not expose a TCP port.");

    await expect(probeLoopbackPort(address.port)).resolves.toBe(true);
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(Buffer.concat(received)).toHaveLength(0);
  });

  it("retries bounded health checks and accepts only the exact status contract", async () => {
    let clock = 0;
    const statuses: unknown[] = [
      new Error("starting"),
      { ...healthyStatus(), websocket_listening: false },
      healthyStatus()
    ];
    const status = vi.fn(async () => {
      const next = statuses.shift();
      if (next instanceof Error) throw next;
      return next;
    });
    await expect(waitForExactBridgeHealth({
      status,
      timeoutMs: 1_000,
      retryMs: 100,
      now: () => clock,
      sleep: async (milliseconds) => { clock += milliseconds; }
    })).resolves.toMatchObject({
      service: "browseweave",
      protocol_version: PROTOCOL_VERSION,
      websocket_listening: true
    });
    expect(status).toHaveBeenCalledTimes(3);
  });

  it("reports a deterministic failure when health never reaches the exact contract", async () => {
    let clock = 0;
    await expect(waitForExactBridgeHealth({
      status: async () => ({ ...healthyStatus(), service: "foreign" }),
      timeoutMs: 200,
      retryMs: 100,
      now: () => clock,
      sleep: async (milliseconds) => { clock += milliseconds; }
    })).rejects.toThrow(/within 1 seconds.*identity, protocol, or WebSocket/iu);
  });

  it("preserves the root start failure and aggregates every reported cleanup failure", async () => {
    const root = new Error("start failed");
    const firstCleanup = new Error("task delete failed");
    const secondCleanup = new Error("definition delete failed");
    const cleanup = vi.fn(async () => [firstCleanup, secondCleanup]);
    await expect(runManagedServiceInstallOperation({
      installAndStart: async () => { throw root; },
      verifyHealth: async () => undefined,
      cleanupNewResources: cleanup
    })).rejects.toMatchObject({
      name: "AggregateError",
      errors: [root, firstCleanup, secondCleanup]
    });
    expect(cleanup).toHaveBeenCalledOnce();
  });

  it("does not run rollback after install and exact health both succeed", async () => {
    const cleanup = vi.fn(async () => []);
    await expect(runManagedServiceInstallOperation({
      installAndStart: async () => undefined,
      verifyHealth: async () => undefined,
      cleanupNewResources: cleanup
    })).resolves.toBeUndefined();
    expect(cleanup).not.toHaveBeenCalled();
  });

  it("rolls back a successful start when the bounded health verification fails", async () => {
    const healthError = new Error("health failed");
    const cleanup = vi.fn(async () => []);
    await expect(runManagedServiceInstallOperation({
      installAndStart: async () => undefined,
      verifyHealth: async () => { throw healthError; },
      cleanupNewResources: cleanup
    })).rejects.toBe(healthError);
    expect(cleanup).toHaveBeenCalledOnce();
  });
});
