import { createServer, type Server } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants, chmod, cp, lstat, mkdir, mkdtemp, open, readFile, readdir, rename, rm, unlink, type FileHandle } from "node:fs/promises";
import path from "node:path";

export const SETUP_SESSION_TTL_MS = 5 * 60_000;
export const SETUP_ID_PATTERN = /^[a-f0-9]{24}$/u;
export const SETUP_SECRET_PATTERN = /^[a-f0-9]{64}$/u;

export type SetupBrowserTarget = "chrome" | "zen";

export interface SetupPageServer {
  readonly setupId: string;
  readonly setupSecret: string;
  readonly url: string;
  readonly expiresAt: string;
  close(): Promise<void>;
}

export interface SetupTicket {
  readonly path: string;
  remove(): Promise<void>;
}

const MANAGED_EXTENSION_MARKER = ".browseweave-managed.json";

interface ManagedExtensionMarker {
  managed_by: "BrowseWeave";
  target: "chromium-mv3" | "firefox-mv2";
  version: string;
  content_sha256: string;
}

interface SetupPageInput {
  browser: SetupBrowserTarget;
  extensionPath: string;
  setupId: string;
  expiresAt: string;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&#39;");
}

export async function extensionTreeDigest(directory: string): Promise<string> {
  const hash = createHash("sha256");
  const visit = async (current: string, prefix = ""): Promise<void> => {
    const entries = (await readdir(current, { withFileTypes: true }))
      .sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      if (prefix === "" && (entry.name === MANAGED_EXTENSION_MARKER || entry.name === "setup-ticket.json")) continue;
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const absolute = path.join(current, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`The extension contains an unsafe symbolic link: ${relative}`);
      if (entry.isDirectory()) {
        hash.update(`directory:${Buffer.byteLength(relative, "utf8")}:${relative}\n`, "utf8");
        await visit(absolute, relative);
        continue;
      }
      if (!entry.isFile()) throw new Error(`The extension contains an unsupported filesystem entry: ${relative}`);
      const bytes = await readFile(absolute);
      hash.update(`file:${Buffer.byteLength(relative, "utf8")}:${relative}:${bytes.byteLength}\n`, "utf8");
      hash.update(bytes);
    }
  };
  await visit(directory);
  return hash.digest("hex");
}

async function assertNoSetupTicket(directory: string): Promise<void> {
  try {
    await lstat(path.join(directory, "setup-ticket.json"));
    throw new Error("The packaged extension unexpectedly contains a setup ticket.");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

function parseManagedExtensionMarker(contents: string): ManagedExtensionMarker {
  let value: unknown;
  try {
    value = JSON.parse(contents) as unknown;
  } catch {
    throw new Error("The managed extension marker is invalid.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The managed extension marker is invalid.");
  }
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(",") !== "content_sha256,managed_by,target,version" ||
    record.managed_by !== "BrowseWeave" ||
    (record.target !== "chromium-mv3" && record.target !== "firefox-mv2") ||
    typeof record.version !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(record.version) ||
    typeof record.content_sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(record.content_sha256)
  ) throw new Error("The managed extension marker is invalid.");
  return record as unknown as ManagedExtensionMarker;
}

async function removeExpiredSetupTicket(ticketPath: string): Promise<boolean> {
  let info;
  try {
    info = await lstat(ticketPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
  if (
    !info.isFile() || info.isSymbolicLink() ||
    (typeof process.getuid === "function" && info.uid !== process.getuid()) ||
    (process.platform !== "win32" && (info.mode & 0o077) !== 0) ||
    info.size < 1 || info.size > 1_024
  ) return false;

  const handle = await open(ticketPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  let contents: string;
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== info.dev || opened.ino !== info.ino || opened.size !== info.size) return false;
    contents = await handle.readFile("utf8");
  } finally {
    await handle.close();
  }

  let value: unknown;
  try {
    value = JSON.parse(contents) as unknown;
  } catch {
    return false;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).join(",") !== "version,setup_id,setup_secret,expires_at" ||
    record.version !== 1 ||
    typeof record.setup_id !== "string" || !SETUP_ID_PATTERN.test(record.setup_id) ||
    typeof record.setup_secret !== "string" || !SETUP_SECRET_PATTERN.test(record.setup_secret) ||
    typeof record.expires_at !== "string"
  ) return false;
  const expiry = Date.parse(record.expires_at);
  if (
    !Number.isFinite(expiry) || new Date(expiry).toISOString() !== record.expires_at ||
    expiry > Date.now() ||
    contents !== `${JSON.stringify({
      version: 1,
      setup_id: record.setup_id,
      setup_secret: record.setup_secret,
      expires_at: record.expires_at
    })}\n`
  ) return false;

  const current = await lstat(ticketPath);
  if (
    !current.isFile() || current.isSymbolicLink() || current.dev !== info.dev ||
    current.ino !== info.ino || current.size !== info.size ||
    await readFile(ticketPath, "utf8") !== contents
  ) return false;
  await unlink(ticketPath);
  return true;
}

async function verifyManagedExtension(directory: string): Promise<ManagedExtensionMarker> {
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("The managed extension path is unsafe.");
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error("The managed extension path is not owned by the current user.");
  }
  const markerPath = path.join(directory, MANAGED_EXTENSION_MARKER);
  const markerInfo = await lstat(markerPath);
  if (!markerInfo.isFile() || markerInfo.isSymbolicLink()) throw new Error("The managed extension marker is unsafe.");
  const marker = parseManagedExtensionMarker(await readFile(markerPath, "utf8"));
  if (await extensionTreeDigest(directory) !== marker.content_sha256) {
    throw new Error("The managed extension files were modified and were not overwritten.");
  }
  return marker;
}

export async function prepareManagedExtension(input: {
  sourcePath: string;
  stableParent: string;
  target: ManagedExtensionMarker["target"];
  version: string;
}): Promise<string> {
  if (
    !path.isAbsolute(input.sourcePath) || !path.isAbsolute(input.stableParent) ||
    /[\0\r\n]/u.test(input.sourcePath) || /[\0\r\n]/u.test(input.stableParent) ||
    !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(input.version)
  ) throw new Error("The managed extension installation input is invalid.");
  const sourceInfo = await lstat(input.sourcePath);
  if (!sourceInfo.isDirectory() || sourceInfo.isSymbolicLink()) throw new Error("The extension source path is unsafe.");
  await assertNoSetupTicket(input.sourcePath);
  await mkdir(input.stableParent, { recursive: true, mode: 0o700 });
  const parentInfo = await lstat(input.stableParent);
  if (!parentInfo.isDirectory() || parentInfo.isSymbolicLink()) throw new Error("The extension installation directory is unsafe.");
  if (typeof process.getuid === "function" && parentInfo.uid !== process.getuid()) {
    throw new Error("The extension installation directory is not owned by the current user.");
  }
  if (process.platform !== "win32") await chmod(input.stableParent, 0o700);

  const destination = path.join(input.stableParent, input.target);
  let existing: ManagedExtensionMarker | undefined;
  try {
    existing = await verifyManagedExtension(destination);
    if (existing.target !== input.target) throw new Error("The managed extension target does not match.");
  } catch (error) {
    try {
      await lstat(destination);
      throw error;
    } catch (presenceError) {
      if ((presenceError as NodeJS.ErrnoException).code !== "ENOENT") throw presenceError;
    }
  }

  const sourceDigest = await extensionTreeDigest(input.sourcePath);
  if (
    existing?.version === input.version &&
    existing.content_sha256 === sourceDigest
  ) return destination;
  if (existing?.version === input.version) {
    throw new Error("The same BrowseWeave extension version has different files and was not replaced.");
  }

  const stagingRoot = await mkdtemp(path.join(input.stableParent, `.${input.target}.install-`));
  const staging = path.join(stagingRoot, input.target);
  let backup: string | undefined;
  try {
    await cp(input.sourcePath, staging, { recursive: true, force: false, errorOnExist: true });
    await assertNoSetupTicket(staging);
    const copiedDigest = await extensionTreeDigest(staging);
    if (copiedDigest !== sourceDigest) throw new Error("The managed extension copy failed its integrity check.");
    const marker: ManagedExtensionMarker = {
      managed_by: "BrowseWeave",
      target: input.target,
      version: input.version,
      content_sha256: copiedDigest
    };
    const markerHandle = await open(
      path.join(staging, MANAGED_EXTENSION_MARKER),
      fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
      0o600
    );
    try {
      await markerHandle.writeFile(`${JSON.stringify(marker)}\n`, "utf8");
      await markerHandle.sync();
    } finally {
      await markerHandle.close();
    }
    if (existing) {
      backup = path.join(input.stableParent, `.${input.target}.backup-${randomBytes(8).toString("hex")}`);
      await rename(destination, backup);
    }
    try {
      await rename(staging, destination);
    } catch (error) {
      if (backup) await rename(backup, destination).catch(() => undefined);
      throw error;
    }
    let installed: ManagedExtensionMarker;
    try {
      installed = await verifyManagedExtension(destination);
      if (installed.version !== input.version || installed.target !== input.target) {
        throw new Error("The installed extension did not match the requested release.");
      }
    } catch (installError) {
      const rollbackErrors: unknown[] = [];
      try {
        await rm(destination, { recursive: true, force: true });
      } catch (error) {
        rollbackErrors.push(error);
      }
      if (backup) {
        try {
          await rename(backup, destination);
          backup = undefined;
        } catch (error) {
          rollbackErrors.push(error);
        }
      }
      if (rollbackErrors.length > 0) {
        throw new AggregateError(
          [installError, ...rollbackErrors],
          "The managed extension verification failed and rollback was incomplete."
        );
      }
      throw installError;
    }
    if (backup) {
      await rm(backup, { recursive: true, force: true });
      backup = undefined;
    }
    return destination;
  } finally {
    await rm(stagingRoot, { recursive: true, force: true });
    if (backup) {
      try {
        await lstat(destination);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") await rename(backup, destination).catch(() => undefined);
      }
    }
  }
}

function assertSetupPageInput(input: SetupPageInput): void {
  if (!SETUP_ID_PATTERN.test(input.setupId)) throw new Error("The setup session ID is invalid.");
  if (input.browser !== "chrome" && input.browser !== "zen") throw new Error("The setup browser is invalid.");
  if (!input.extensionPath || /[\0\r\n]/u.test(input.extensionPath)) {
    throw new Error("The extension path is invalid.");
  }
  const expiresAt = Date.parse(input.expiresAt);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) throw new Error("The setup expiry is invalid.");
}

/** The normal web page contains only a non-secret session ID. */
export function setupPageHtml(input: SetupPageInput): string {
  assertSetupPageInput(input);
  const browserLabel = input.browser === "chrome" ? "Google Chrome" : "Zen";
  const loadStep = input.browser === "chrome"
    ? "In the Extensions tab, enable Developer mode, choose Load unpacked, and select this folder:"
    : "In about:debugging, choose Load Temporary Add-on and select manifest.json inside this folder:";
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta id="browseweave-auto-refresh" http-equiv="refresh" content="5">
    <meta name="referrer" content="no-referrer">
    <title>Connect BrowseWeave</title>
    <style>
      :root { color-scheme: light; font-family: system-ui, sans-serif; background: #f4f8fc; color: #132238; }
      * { box-sizing: border-box; }
      body { margin: 0; }
      main { width: min(680px, calc(100% - 2rem)); margin: 6vh auto; background: white; border: 1px solid #c9d7e7; border-radius: 18px; padding: clamp(1.2rem, 4vw, 2.4rem); box-shadow: 0 18px 55px rgb(20 48 80 / 12%); }
      h1 { margin: 0 0 .75rem; font-size: clamp(1.7rem, 5vw, 2.5rem); }
      p { line-height: 1.55; }
      .step { border-left: 4px solid #18bfe5; padding: .2rem 0 .2rem 1rem; margin: 1.2rem 0; }
      code { display: block; margin-top: .6rem; padding: .75rem; border-radius: 8px; background: #edf4fa; overflow-wrap: anywhere; user-select: all; }
      button { width: 100%; margin-top: 1rem; border: 0; border-radius: 10px; padding: .9rem 1rem; background: #123d59; color: white; font: inherit; font-weight: 700; cursor: pointer; }
      button:disabled { cursor: wait; opacity: .62; }
      #browseweave-setup-status { min-height: 1.5rem; font-weight: 650; }
      .boundary { color: #536779; font-size: .92rem; }
    </style>
  </head>
  <body>
    <main id="browseweave-setup" data-setup-id="${input.setupId}">
      <h1>Connect BrowseWeave</h1>
      <p>This page connects ${browserLabel} to the BrowseWeave service running only on this computer.</p>
      <div class="step">
        <strong>1. Add the extension</strong>
        <p>${loadStep}</p>
        <code>${escapeHtml(input.extensionPath)}</code>
        <p>This page refreshes automatically until the extension is present.</p>
      </div>
      <div class="step">
        <strong>2. Confirm the connection</strong>
        <p>After BrowseWeave appears in ${browserLabel}, choose the button below once.</p>
        <button id="browseweave-connect" type="button">Connect this browser</button>
        <p id="browseweave-setup-status" role="status" aria-live="polite">Waiting for the BrowseWeave extension.</p>
      </div>
      <p class="boundary">The connection request expires at ${escapeHtml(input.expiresAt)}. No pairing key is copied, displayed, placed in browser history, or sent to an AI.</p>
    </main>
  </body>
</html>`;
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  });
}

export async function createSetupTicket(input: {
  extensionPath: string;
  setupId: string;
  setupSecret: string;
  expiresAt: string;
}): Promise<SetupTicket> {
  if (!path.isAbsolute(input.extensionPath) || /[\0\r\n]/u.test(input.extensionPath)) {
    throw new Error("The setup-ticket extension directory is invalid.");
  }
  if (!SETUP_ID_PATTERN.test(input.setupId) || !SETUP_SECRET_PATTERN.test(input.setupSecret)) {
    throw new Error("The setup-ticket capability is invalid.");
  }
  const expiry = Date.parse(input.expiresAt);
  if (!Number.isFinite(expiry) || expiry <= Date.now() || expiry > Date.now() + SETUP_SESSION_TTL_MS + 5_000) {
    throw new Error("The setup-ticket expiry is invalid.");
  }
  const directoryInfo = await lstat(input.extensionPath);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw new Error("The extension build is not a safe directory for a setup ticket.");
  }
  if (typeof process.getuid === "function" && directoryInfo.uid !== process.getuid()) {
    throw new Error("The extension build is not owned by the current user.");
  }
  const ticketPath = path.join(input.extensionPath, "setup-ticket.json");
  const contents = `${JSON.stringify({
    version: 1,
    setup_id: input.setupId,
    setup_secret: input.setupSecret,
    expires_at: input.expiresAt
  })}\n`;
  let handle: FileHandle | undefined;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      handle = await open(
        ticketPath,
        fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY | fsConstants.O_NOFOLLOW,
        0o600
      );
      break;
    } catch (error) {
      if (
        (error as NodeJS.ErrnoException).code !== "EEXIST" || attempt !== 0 ||
        !await removeExpiredSetupTicket(ticketPath)
      ) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") {
          throw new Error("A setup ticket already exists. Finish or cancel the other BrowseWeave setup first.");
        }
        throw error;
      }
    }
  }
  if (!handle) throw new Error("BrowseWeave could not create the short-lived setup ticket.");
  try {
    await handle.writeFile(contents, "utf8");
    await handle.sync();
  } catch (writeError) {
    let cleanupError: unknown;
    try {
      const opened = await handle.stat();
      await handle.close();
      handle = undefined;
      const current = await lstat(ticketPath);
      if (
        !current.isFile() || current.isSymbolicLink() ||
        current.dev !== opened.dev || current.ino !== opened.ino
      ) throw new Error("The incomplete setup ticket path changed and was not removed.");
      await unlink(ticketPath);
    } catch (error) {
      cleanupError = error;
    }
    if (cleanupError) {
      throw new AggregateError([writeError, cleanupError], "Setup-ticket creation and cleanup both failed.");
    }
    throw writeError;
  } finally {
    await handle?.close();
  }
  if (process.platform !== "win32") await chmod(ticketPath, 0o600);
  let removed = false;
  return {
    path: ticketPath,
    async remove() {
      if (removed) return;
      const info = await lstat(ticketPath);
      if (
        !info.isFile() || info.isSymbolicLink() ||
        (typeof process.getuid === "function" && info.uid !== process.getuid()) ||
        (process.platform !== "win32" && (info.mode & 0o077) !== 0) ||
        await readFile(ticketPath, "utf8") !== contents
      ) throw new Error("The setup ticket changed and was not removed.");
      await unlink(ticketPath);
      removed = true;
    }
  };
}

export async function startSetupPageServer(input: {
  browser: SetupBrowserTarget;
  extensionPath: string;
  ttlMs?: number;
}): Promise<SetupPageServer> {
  const ttlMs = input.ttlMs ?? SETUP_SESSION_TTL_MS;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 30_000 || ttlMs > SETUP_SESSION_TTL_MS) {
    throw new Error("The setup lifetime must be between 30 seconds and 5 minutes.");
  }
  const setupId = randomBytes(12).toString("hex");
  const setupSecret = randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + ttlMs).toISOString();
  let expectedHost = "";
  const expectedPath = `/setup/${setupId}`;
  const html = setupPageHtml({
    browser: input.browser,
    extensionPath: input.extensionPath,
    setupId,
    expiresAt
  });
  let acceptedRequests = 0;
  const server = createServer((request, response) => {
    const host = request.headers.host;
    if (
      request.method !== "GET" ||
      host !== expectedHost || request.url !== expectedPath
    ) {
      response.writeHead(404, {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff"
      });
      response.end("Not found");
      return;
    }
    acceptedRequests += 1;
    if (acceptedRequests > 120) {
      response.writeHead(404, {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff"
      });
      response.end("Not found");
      return;
    }
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store, no-cache, must-revalidate",
      pragma: "no-cache",
      expires: "0",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; connect-src 'none'; img-src 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "cross-origin-resource-policy": "same-origin"
    });
    response.end(html);
  });
  server.requestTimeout = 5_000;
  server.headersTimeout = 3_000;
  server.keepAliveTimeout = 1_000;
  server.maxHeadersCount = 32;
  server.maxConnections = 8;
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    await closeServer(server);
    throw new Error("The local setup page did not receive a loopback port.");
  }
  expectedHost = `127.0.0.1:${address.port}`;
  let closed = false;
  return {
    setupId,
    setupSecret,
    expiresAt,
    url: `http://${expectedHost}${expectedPath}`,
    async close() {
      if (closed) return;
      closed = true;
      await closeServer(server);
    }
  };
}
