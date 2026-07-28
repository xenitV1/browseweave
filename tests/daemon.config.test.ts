import { mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getIpcToken, getPairingToken, getRuntimePaths } from "../src/config.js";
import {
  SafeAuditLogger,
  canonicalJson,
  isAllowedExtensionOrigin,
  parseIpcRequest
} from "../src/daemon.js";
import { PROTOCOL_VERSION } from "../src/protocol.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map(async (directory) => {
      await rm(directory, { recursive: true, force: true });
    })
  );
});

describe("daemon configuration and pure protocol helpers", () => {
  it("bounds the audit queue and records one safe dropped-event summary", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-audit-queue-"));
    temporaryDirectories.push(root);
    const auditPath = path.join(root, "audit.jsonl");
    const audit = new SafeAuditLogger(auditPath, {
      maxQueueEntries: 4,
      maxFileBytes: 64 * 1024
    });
    await audit.start();

    for (let index = 0; index < 100; index += 1) {
      audit.record({ event: "connection", outcome: "normal_security_event" });
    }
    await audit.close();

    const records = (await readFile(auditPath, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(records.filter((record) => record.outcome === "normal_security_event")).toHaveLength(5);
    expect(records.filter((record) => record.outcome === "audit_events_dropped")).toEqual([
      expect.objectContaining({ event: "connection", count: 95 })
    ]);
  });

  it("caps the active audit file and retains only one bounded rotation", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-audit-rotation-"));
    temporaryDirectories.push(root);
    const auditPath = path.join(root, "audit.jsonl");
    const audit = new SafeAuditLogger(auditPath, {
      maxQueueEntries: 128,
      maxFileBytes: 512
    });
    await audit.start();

    for (let index = 0; index < 40; index += 1) {
      audit.record({ event: "connection", outcome: "normal_security_event", count: index + 1 });
    }
    await audit.close();

    const active = await stat(auditPath);
    const rotated = await stat(`${auditPath}.1`);
    expect(active.size).toBeGreaterThan(0);
    expect(rotated.size).toBeGreaterThan(0);
    expect(active.size).toBeLessThanOrEqual(512);
    expect(rotated.size).toBeLessThanOrEqual(512);
    const retained = `${await readFile(`${auditPath}.1`, "utf8")}${await readFile(auditPath, "utf8")}`;
    expect(retained).toContain('"outcome":"normal_security_event"');
  });

  it("refuses an unsafe rotated-audit symlink without modifying its target", async () => {
    if (process.platform === "win32") return;
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-audit-symlink-"));
    temporaryDirectories.push(root);
    const auditPath = path.join(root, "audit.jsonl");
    const targetPath = path.join(root, "must-not-change.txt");
    await writeFile(targetPath, "sentinel", "utf8");
    await symlink(targetPath, `${auditPath}.1`);
    const audit = new SafeAuditLogger(auditPath, {
      maxQueueEntries: 128,
      maxFileBytes: 512
    });
    await audit.start();

    for (let index = 0; index < 40; index += 1) {
      audit.record({ event: "connection", outcome: "normal_security_event", count: index + 1 });
    }
    await audit.close();

    expect(audit.lastError).toMatch(/rotated audit log is not a safe user-owned file/u);
    expect(await readFile(targetPath, "utf8")).toBe("sentinel");
    expect((await stat(auditPath)).size).toBeLessThanOrEqual(512);
  });

  it("uses XDG locations on Linux with a private generated token", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-config-"));
    temporaryDirectories.push(root);
    const env = {
      HOME: path.join(root, "home"),
      XDG_RUNTIME_DIR: path.join(root, "run"),
      XDG_CONFIG_HOME: path.join(root, "config"),
      XDG_STATE_HOME: path.join(root, "state")
    };

    const paths = getRuntimePaths(env, "linux");
    expect(paths.runtimeDir).toBe(path.join(root, "run", "browseweave"));
    expect(paths.tokenPath).toBe(
      path.join(root, "config", "browseweave", "pairing-token")
    );
    expect(paths.ipcTokenPath).toBe(
      path.join(root, "config", "browseweave", "ipc-token")
    );
    expect(paths.auditLogPath).toBe(
      path.join(root, "state", "browseweave", "audit.jsonl")
    );

    const first = await getPairingToken(paths, env);
    const second = await getPairingToken(paths, env);
    const ipcFirst = await getIpcToken(paths, env);
    const ipcSecond = await getIpcToken(paths, env);
    expect(first).toMatch(/^[a-f0-9]{64}$/u);
    expect(second).toBe(first);
    expect(ipcFirst).toMatch(/^[a-f0-9]{64}$/u);
    expect(ipcSecond).toBe(ipcFirst);
    expect(ipcFirst).not.toBe(first);
    expect((await readFile(paths.tokenPath, "utf8")).trim()).toBe(first);
    expect((await stat(paths.tokenPath)).mode & 0o777).toBe(0o600);
    expect((await stat(paths.ipcTokenPath)).mode & 0o777).toBe(0o600);
    expect((await stat(paths.configDir)).mode & 0o777).toBe(0o700);
  });

  it("uses native per-user paths on macOS and Windows", () => {
    const mac = getRuntimePaths({ HOME: "/Users/Ada" }, "darwin");
    expect(mac.configDir).toBe("/Users/Ada/Library/Application Support/BrowseWeave");
    expect(mac.stateDir).toBe("/Users/Ada/Library/Logs/BrowseWeave");

    const windows = getRuntimePaths(
      { USERPROFILE: "C:\\Users\\Ada", LOCALAPPDATA: "C:\\Users\\Ada\\AppData\\Local" },
      "win32"
    );
    expect(windows.configDir).toBe("C:\\Users\\Ada\\AppData\\Local\\BrowseWeave\\Config");
    expect(windows.auditLogPath).toBe("C:\\Users\\Ada\\AppData\\Local\\BrowseWeave\\State\\audit.jsonl");
  });

  it("accepts only Firefox or Chromium extension origins and can pin an exact origin", () => {
    const firefoxOrigin = "moz-extension://12345678-abcd-4321-abcd-1234567890ab";
    const chromiumOrigin = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";
    expect(isAllowedExtensionOrigin(firefoxOrigin)).toBe(true);
    expect(isAllowedExtensionOrigin(chromiumOrigin)).toBe(true);
    expect(isAllowedExtensionOrigin(firefoxOrigin, [firefoxOrigin])).toBe(true);
    expect(
      isAllowedExtensionOrigin(firefoxOrigin, ["moz-extension://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"])
    ).toBe(false);
    expect(isAllowedExtensionOrigin("https://example.com")).toBe(false);
    expect(isAllowedExtensionOrigin("moz-extension://uuid/path")).toBe(false);
  });

  it("validates bounded NDJSON envelopes and canonicalizes params independent of key order", () => {
    const envelope = (id: string, method: string, params: Record<string, unknown>) => ({
      type: "ipc_request",
      protocol_version: PROTOCOL_VERSION,
      endpoint_role: "ipc",
      id,
      method,
      params,
      client_nonce: Buffer.alloc(32, 1).toString("base64url"),
      server_nonce: Buffer.alloc(32, 2).toString("base64url"),
      daemon_instance_id: "12345678-1234-4234-8234-1234567890ab",
      client_proof: Buffer.alloc(32, 3).toString("base64url")
    });
    const request = parseIpcRequest(
      JSON.stringify(envelope("req-1", "click", { z: 1, a: { y: 2, x: 3 } })),
      1024
    );
    expect(request.method).toBe("click");
    expect(canonicalJson(request.params)).toBe(canonicalJson({ a: { x: 3, y: 2 }, z: 1 }));
    expect(() => parseIpcRequest("not-json", 1024)).toThrow(/JSON/u);
    expect(() =>
      parseIpcRequest(
        JSON.stringify(envelope("req-2", "type", { text: "x".repeat(200) })),
        50
      )
    ).toThrow(/size|limit/u);
    expect(() => parseIpcRequest(
      JSON.stringify({ ...envelope("req-3", "click", {}), token: "a".repeat(64) }),
      1024
    )).toThrow(/unsupported field/u);
  });
});
