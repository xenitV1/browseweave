import { describe, expect, it, vi } from "vitest";
import { createServicePlan } from "../src/service-plan.js";
import { ensureExactOwnedServiceReady } from "../src/native-service.js";
import { PROTOCOL_VERSION } from "../src/protocol.js";

function plan() {
  return createServicePlan({
    platform: "linux",
    home: "/home/ada",
    nodePath: "/opt/browseweave/node",
    daemonPath: "/opt/browseweave/daemon.js"
  });
}

function healthy() {
  return { service: "browseweave", protocol_version: PROTOCOL_VERSION, websocket_listening: true };
}

describe("native host exact-owned service start", () => {
  it("does not start when the exact authenticated service is already healthy", async () => {
    const current = plan();
    const start = vi.fn(async () => undefined);
    const probePort = vi.fn(async () => true);
    await ensureExactOwnedServiceReady({
      plan: current,
      definitionContents: current.definitionContent!,
      status: async () => healthy(),
      start,
      probePort
    });
    expect(start).not.toHaveBeenCalled();
    expect(probePort).not.toHaveBeenCalled();
  });

  it("starts only the fixed command after exact ownership and free-port proof", async () => {
    const current = plan();
    let statusCalls = 0;
    const start = vi.fn(async () => undefined);
    const probePort = vi.fn(async () => false);
    await ensureExactOwnedServiceReady({
      plan: current,
      definitionContents: current.definitionContent!,
      status: async () => {
        statusCalls += 1;
        if (statusCalls < 3) throw new Error("stopped");
        return healthy();
      },
      start,
      probePort
    });
    expect(start).toHaveBeenCalledOnce();
    expect(start).toHaveBeenCalledWith({
      command: "systemctl",
      args: ["--user", "start", "browseweave-daemon.service"]
    });
    expect(probePort).toHaveBeenCalledTimes(2);
  });

  it("refuses modified, older-owned, or missing definitions before any command", async () => {
    const current = plan();
    const start = vi.fn(async () => undefined);
    const status = vi.fn(async () => healthy());
    for (const contents of [
      current.definitionContent!.replace("RestartSec=2", "RestartSec=3"),
      "",
      "# foreign\n"
    ]) {
      await expect(ensureExactOwnedServiceReady({
        plan: current,
        definitionContents: contents,
        status,
        start
      })).rejects.toThrow(/repaired/iu);
    }
    expect(status).not.toHaveBeenCalled();
    expect(start).not.toHaveBeenCalled();
  });

  it("does not start when either unauthenticated loopback port is occupied", async () => {
    const current = plan();
    const start = vi.fn(async () => undefined);
    await expect(ensureExactOwnedServiceReady({
      plan: current,
      definitionContents: current.definitionContent!,
      status: async () => { throw new Error("not authenticated"); },
      start,
      probePort: async (port) => port === 32110
    })).rejects.toThrow(/already in use/iu);
    expect(start).not.toHaveBeenCalled();
  });

  it("requires an exact current Windows task in addition to the exact definition", async () => {
    const current = createServicePlan({
      platform: "win32",
      home: "C:\\Users\\Ada",
      nodePath: "C:\\BrowseWeave\\node.exe",
      daemonPath: "C:\\BrowseWeave\\daemon.js",
      userId: "S-1-5-21-100-200-300-1001"
    });
    const start = vi.fn(async () => undefined);
    await expect(ensureExactOwnedServiceReady({
      plan: current,
      definitionContents: current.definitionContent!,
      windowsTaskXml: "<Task></Task>",
      status: async () => healthy(),
      start
    })).rejects.toThrow(/Windows task.*repaired/iu);
    expect(start).not.toHaveBeenCalled();
  });
});
