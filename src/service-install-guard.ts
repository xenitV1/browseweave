import { createConnection } from "node:net";
import {
  DEFAULT_IPC_HOST,
  DEFAULT_IPC_PORT,
  DEFAULT_WS_PORT
} from "./config.js";
import { PROTOCOL_VERSION, isJsonObject, type JsonObject } from "./protocol.js";

const DEFAULT_PROBE_TIMEOUT_MS = 1_000;
const DEFAULT_HEALTH_TIMEOUT_MS = 12_000;
const DEFAULT_HEALTH_RETRY_MS = 250;

export interface ServiceMutationAuthorizationInput {
  authenticateStatus: () => Promise<unknown>;
  probePort?: (port: number) => Promise<boolean>;
}

export interface BridgeHealthPollInput {
  status: () => Promise<unknown>;
  timeoutMs?: number;
  retryMs?: number;
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
}

export interface ManagedServiceInstallOperationInput {
  installAndStart: () => Promise<void>;
  verifyHealth: () => Promise<void>;
  cleanupNewResources: () => Promise<readonly unknown[]>;
}

export interface ExactBridgeHealth extends JsonObject {
  service: "browseweave";
  protocol_version: typeof PROTOCOL_VERSION;
  websocket_listening: true;
}

/**
 * Connect without writing any bytes. A successful connection means another
 * process owns the loopback port; a refused connection means it is available.
 */
export async function probeLoopbackPort(
  port: number,
  timeoutMs = DEFAULT_PROBE_TIMEOUT_MS
): Promise<boolean> {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("The loopback port probe received an invalid port.");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000) {
    throw new Error("The loopback port probe timeout is invalid.");
  }

  return await new Promise<boolean>((resolve, reject) => {
    const socket = createConnection({ host: DEFAULT_IPC_HOST, port });
    let settled = false;
    const finish = (error: Error | undefined, occupied: boolean): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(occupied);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(undefined, true));
    socket.once("timeout", () => finish(
      new Error(`BrowseWeave could not safely determine who owns loopback port ${port}.`),
      false
    ));
    socket.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "ECONNREFUSED") {
        finish(undefined, false);
        return;
      }
      finish(new Error(`BrowseWeave could not safely probe loopback port ${port}: ${error.message}`), false);
    });
  });
}

export function isBrowseWeaveServiceIdentity(value: unknown): boolean {
  return isJsonObject(value)
    && value.service === "browseweave"
    && value.protocol_version === PROTOCOL_VERSION;
}

export function isExactBrowseWeaveHealth(value: unknown): value is ExactBridgeHealth {
  return isBrowseWeaveServiceIdentity(value)
    && isJsonObject(value)
    && value.websocket_listening === true;
}

export function isProvenStoppedSystemdService(exitCode: number, stdout: string): boolean {
  if (!Number.isInteger(exitCode) || exitCode === 0) return false;
  return new Set(["inactive", "failed", "unknown"]).has(stdout.trim());
}

/**
 * Authorize mutations only when the current daemon authenticates, or when both
 * default ports are demonstrably unused. The IPC client sends only its public
 * hello until the server proves knowledge of the local IPC secret.
 */
export async function authorizeServiceMutation(
  input: ServiceMutationAuthorizationInput
): Promise<"authenticated" | "ports_available"> {
  try {
    if (isBrowseWeaveServiceIdentity(await input.authenticateStatus())) return "authenticated";
  } catch {
    // Authentication failure is handled by a no-write ownership probe below.
  }

  const probe = input.probePort ?? ((port: number) => probeLoopbackPort(port));
  const [websocketOccupied, ipcOccupied] = await Promise.all([
    probe(DEFAULT_WS_PORT),
    probe(DEFAULT_IPC_PORT)
  ]);
  const occupied = [
    websocketOccupied ? DEFAULT_WS_PORT : undefined,
    ipcOccupied ? DEFAULT_IPC_PORT : undefined
  ].filter((port): port is number => port !== undefined);
  if (occupied.length > 0) {
    throw new Error(
      `BrowseWeave did not authenticate, and loopback port${occupied.length === 1 ? "" : "s"} ` +
      `${occupied.join(", ")} ${occupied.length === 1 ? "is" : "are"} already in use. ` +
      "No service files or tasks were changed. Close the blocking program or restore the matching BrowseWeave configuration, then retry."
    );
  }
  return "ports_available";
}

export async function waitForExactBridgeHealth(input: BridgeHealthPollInput): Promise<ExactBridgeHealth> {
  const timeoutMs = input.timeoutMs ?? DEFAULT_HEALTH_TIMEOUT_MS;
  const retryMs = input.retryMs ?? DEFAULT_HEALTH_RETRY_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new Error("The BrowseWeave health-check timeout is invalid.");
  }
  if (!Number.isInteger(retryMs) || retryMs < 1 || retryMs > timeoutMs) {
    throw new Error("The BrowseWeave health-check retry interval is invalid.");
  }
  const now = input.now ?? Date.now;
  const sleep = input.sleep ?? (async (milliseconds: number) => {
    await new Promise<void>((resolve) => globalThis.setTimeout(resolve, milliseconds));
  });
  const deadline = now() + timeoutMs;
  let lastFailure = "the daemon did not return a valid status";

  do {
    try {
      const status = await input.status();
      if (isExactBrowseWeaveHealth(status)) return status;
      lastFailure = "the status identity, protocol, or WebSocket listener did not match";
    } catch (error) {
      lastFailure = error instanceof Error ? error.message : String(error);
    }
    if (now() >= deadline) break;
    await sleep(Math.min(retryMs, Math.max(1, deadline - now())));
  } while (now() < deadline);

  throw new Error(
    `BrowseWeave service did not become healthy within ${Math.ceil(timeoutMs / 1_000)} seconds: ` +
    lastFailure.replace(/[\r\n]+/gu, " ").slice(0, 300)
  );
}

/** Preserve the install/start failure as the first error while reporting every cleanup failure. */
export async function runManagedServiceInstallOperation(
  input: ManagedServiceInstallOperationInput
): Promise<void> {
  try {
    await input.installAndStart();
    await input.verifyHealth();
  } catch (operationError) {
    let cleanupErrors: readonly unknown[];
    try {
      cleanupErrors = await input.cleanupNewResources();
    } catch (cleanupError) {
      cleanupErrors = [cleanupError];
    }
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [operationError, ...cleanupErrors],
        "BrowseWeave service installation failed, and one or more newly-created managed resources could not be cleaned up safely."
      );
    }
    throw operationError;
  }
}
