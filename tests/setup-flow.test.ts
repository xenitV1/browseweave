import { request } from "node:http";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  SETUP_ID_PATTERN,
  SETUP_SECRET_PATTERN,
  createSetupTicket,
  prepareManagedExtension,
  prepareSetupBeforeBrowserConsent,
  removeManagedExtensionCopy,
  shouldReuseConnectedBrowser,
  setupPageHtml,
  startSetupPageServer
} from "../src/setup/flow.js";

function get(url: string): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
  return new Promise((resolve, reject) => {
    const call = request(url, { method: "GET" }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk: Buffer) => chunks.push(chunk));
      response.once("end", () => resolve({
        status: response.statusCode ?? 0,
        headers: response.headers,
        body: Buffer.concat(chunks).toString("utf8")
      }));
    });
    call.once("error", reject);
    call.end();
  });
}

describe("one-click local setup page", () => {
  it("never reuses a live connection after its legacy extension copy was removed", () => {
    expect(shouldReuseConnectedBrowser({ newProfile: false, legacyCopyRemoved: false })).toBe(true);
    expect(shouldReuseConnectedBrowser({ newProfile: true, legacyCopyRemoved: false })).toBe(false);
    expect(shouldReuseConnectedBrowser({ newProfile: false, legacyCopyRemoved: true })).toBe(false);
  });

  it("configures MCP clients before installing the service or asking for browser consent", async () => {
    const phases: string[] = [];
    await prepareSetupBeforeBrowserConsent({
      configureClients: async () => { phases.push("mcp"); },
      installService: async () => { phases.push("service"); }
    });
    expect(phases).toEqual(["mcp", "service"]);
  });
  it("keeps the short-lived secret out of the URL and serves only the exact loopback path", async () => {
    const setup = await startSetupPageServer({ browser: "chrome", extensionPath: "/tmp/BrowseWeave extension" });
    try {
      expect(setup.setupId).toMatch(SETUP_ID_PATTERN);
      expect(setup.setupSecret).toMatch(SETUP_SECRET_PATTERN);
      expect(setup.url).not.toContain(setup.setupSecret);
      const page = await get(setup.url);
      expect(page.status).toBe(200);
      expect(page.headers["cache-control"]).toContain("no-store");
      expect(page.headers["content-security-policy"]).toContain("default-src 'none'");
      expect(page.headers["referrer-policy"]).toBe("no-referrer");
      expect(page.body).toContain(`data-setup-id="${setup.setupId}"`);
      expect(page.body).not.toContain(setup.setupSecret);
      expect(page.body).not.toContain("data-setup-secret");
      expect(page.body).toContain('id="browseweave-connect"');
      expect(page.body).not.toContain("<script");

      const wrong = await get(new URL("/", setup.url).toString());
      expect(wrong.status).toBe(404);
      expect(wrong.body).not.toContain(setup.setupSecret);
    } finally {
      await setup.close();
    }
    await expect(get(setup.url)).rejects.toThrow();
  });

  it("escapes the user-visible extension path without changing the fixed setup DOM contract", () => {
    const html = setupPageHtml({
      browser: "zen",
      extensionPath: "/tmp/<Browse & Weave>/manifest.json",
      setupId: "a".repeat(24),
      expiresAt: new Date(Date.now() + 60_000).toISOString()
    });
    expect(html).toContain("/tmp/&lt;Browse &amp; Weave&gt;/manifest.json");
    expect(html).not.toContain("/tmp/<Browse & Weave>");
    expect(html).toContain("Connect this browser");
    expect(html).toContain('id="browseweave-auto-refresh"');
  });

  it("rejects malformed or overlong-lived setup material", async () => {
    expect(() => setupPageHtml({
      browser: "chrome",
      extensionPath: "/tmp/extension",
      setupId: "not-an-id",
      expiresAt: new Date(Date.now() + 60_000).toISOString()
    })).toThrow(/session ID/iu);
    await expect(startSetupPageServer({
      browser: "chrome",
      extensionPath: "/tmp/extension",
      ttlMs: 5 * 60_000 + 1
    })).rejects.toThrow(/lifetime/iu);
  });

  it("does not let unrelated loopback requests consume the valid setup-page budget", async () => {
    const setup = await startSetupPageServer({ browser: "chrome", extensionPath: "/tmp/extension" });
    try {
      const wrongUrl = new URL("/unrelated", setup.url).toString();
      for (let attempt = 0; attempt < 125; attempt += 1) {
        expect((await get(wrongUrl)).status).toBe(404);
      }
      const page = await get(setup.url);
      expect(page.status).toBe(200);
      expect(page.body).toContain(`data-setup-id="${setup.setupId}"`);
    } finally {
      await setup.close();
    }
  });

  it("creates an owner-only non-web setup ticket and removes only its exact contents", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "browseweave-setup-ticket-"));
    try {
      const ticket = await createSetupTicket({
        extensionPath: directory,
        setupId: "a".repeat(24),
        setupSecret: "b".repeat(64),
        expiresAt: new Date(Date.now() + 60_000).toISOString()
      });
      expect(path.basename(ticket.path)).toBe("setup-ticket.json");
      if (process.platform !== "win32") {
        expect((await stat(ticket.path)).mode & 0o777).toBe(0o600);
      }
      expect(JSON.parse(await readFile(ticket.path, "utf8"))).toEqual({
        version: 1,
        setup_id: "a".repeat(24),
        setup_secret: "b".repeat(64),
        expires_at: expect.any(String)
      });
      await expect(createSetupTicket({
        extensionPath: directory,
        setupId: "c".repeat(24),
        setupSecret: "d".repeat(64),
        expiresAt: new Date(Date.now() + 60_000).toISOString()
      })).rejects.toThrow(/already exists/iu);
      await writeFile(ticket.path, "tampered\n", "utf8");
      await expect(ticket.remove()).rejects.toThrow(/changed/iu);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("removes an unchanged setup ticket exactly once", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "browseweave-setup-ticket-cleanup-"));
    try {
      const ticket = await createSetupTicket({
        extensionPath: directory,
        setupId: "e".repeat(24),
        setupSecret: "f".repeat(64),
        expiresAt: new Date(Date.now() + 60_000).toISOString()
      });
      await ticket.remove();
      await ticket.remove();
      await expect(stat(ticket.path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("recovers only an exact expired owner-only setup ticket after an interrupted setup", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "browseweave-setup-ticket-recovery-"));
    const ticketPath = path.join(directory, "setup-ticket.json");
    try {
      const expired = {
        version: 1,
        setup_id: "1".repeat(24),
        setup_secret: "2".repeat(64),
        expires_at: new Date(Date.now() - 1_000).toISOString()
      };
      await writeFile(ticketPath, `${JSON.stringify(expired)}\n`, { encoding: "utf8", mode: 0o600 });
      const replacement = await createSetupTicket({
        extensionPath: directory,
        setupId: "3".repeat(24),
        setupSecret: "4".repeat(64),
        expiresAt: new Date(Date.now() + 60_000).toISOString()
      });
      expect(JSON.parse(await readFile(ticketPath, "utf8"))).toMatchObject({
        setup_id: "3".repeat(24),
        setup_secret: "4".repeat(64)
      });
      await replacement.remove();

      await writeFile(ticketPath, `${JSON.stringify(expired, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
      await expect(createSetupTicket({
        extensionPath: directory,
        setupId: "5".repeat(24),
        setupSecret: "6".repeat(64),
        expiresAt: new Date(Date.now() + 60_000).toISOString()
      })).rejects.toThrow(/already exists/iu);
      expect(await readFile(ticketPath, "utf8")).toContain("\n  \"version\"");
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("removes only a copy it created, so relocating cannot leave two enabled copies", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-relocate-"));
    const source = path.join(root, "source");
    const oldParent = path.join(root, "old");
    const foreignParent = path.join(root, "foreign");
    await mkdir(source);
    await writeFile(path.join(source, "manifest.json"), '{"name":"BrowseWeave"}\n', "utf8");
    try {
      await prepareManagedExtension({ sourcePath: source, stableParent: oldParent, target: "chromium-mv3", version: "0.1.0" });
      expect(await removeManagedExtensionCopy(oldParent, "chromium-mv3")).toBe(true);
      await expect(stat(path.join(oldParent, "chromium-mv3"))).rejects.toThrow();
      // Removing again is harmless once the copy is gone.
      expect(await removeManagedExtensionCopy(oldParent, "chromium-mv3")).toBe(false);

      // A directory BrowseWeave did not create is never deleted, even if it
      // sits exactly where a managed copy would.
      await mkdir(path.join(foreignParent, "chromium-mv3"), { recursive: true });
      await writeFile(path.join(foreignParent, "chromium-mv3", "manifest.json"), "{}\n", "utf8");
      expect(await removeManagedExtensionCopy(foreignParent, "chromium-mv3")).toBe(false);
      expect(await readFile(path.join(foreignParent, "chromium-mv3", "manifest.json"), "utf8")).toBe("{}\n");

      expect(await removeManagedExtensionCopy("relative/path", "chromium-mv3")).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("installs the unpacked extension at a stable managed path and refuses modified files", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-managed-extension-"));
    const source = path.join(root, "source");
    const stableParent = path.join(root, "stable");
    await mkdir(source);
    await writeFile(path.join(source, "manifest.json"), '{"name":"BrowseWeave"}\n', "utf8");
    await writeFile(path.join(source, "background.js"), 'console.log("safe fixture");\n', "utf8");
    try {
      const first = await prepareManagedExtension({
        sourcePath: source,
        stableParent,
        target: "chromium-mv3",
        version: "0.1.0"
      });
      expect(first).toBe(path.join(stableParent, "chromium-mv3"));
      expect(await readFile(path.join(first, "manifest.json"), "utf8")).toContain("BrowseWeave");
      expect(await prepareManagedExtension({
        sourcePath: source,
        stableParent,
        target: "chromium-mv3",
        version: "0.1.0"
      })).toBe(first);
      await writeFile(path.join(first, "background.js"), "tampered\n", "utf8");
      await expect(prepareManagedExtension({
        sourcePath: source,
        stableParent,
        target: "chromium-mv3",
        version: "0.1.0"
      })).rejects.toThrow(/modified/iu);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
