/**
 * Storage for the two deliberately separate credential channels: the trusted
 * five-minute local handoff and the opt-in one-use remote-origin permission.
 * Credential values never enter this module; only bindings and metadata do.
 */
import {
  MAX_CREDENTIAL_HANDOFFS,
  MAX_REMOTE_CREDENTIAL_PERMISSIONS,
  MAX_REMOTE_CREDENTIAL_PERMISSION_MS,
  LocalCredentialHandoffLedger,
  RemoteCredentialPermissionLedger,
  credentialGrantTargetMatches,
  isLocalCredentialHandoff,
  isRemoteCredentialPermission,
  normalizeHttpsOrigin,
  type LocalCredentialHandoff,
  type RemoteCredentialPermission
} from "../security/credentials";
import { BridgeError, activeTab, extensionBrowser, sessionStorageArea } from "./environment";

const LOCAL_CREDENTIAL_HANDOFFS_SESSION_KEY = "browseweave_local_credential_handoffs_v1";
const REMOTE_CREDENTIAL_PERMISSIONS_STORAGE_KEY = "browseweave_remote_credential_permissions_v1";

let localCredentialHandoffsLoaded = false;
let localCredentialHandoffsLock: Promise<void> = Promise.resolve();
let localCredentialHandoffs = new LocalCredentialHandoffLedger();
let remoteCredentialPermissionsLoaded = false;
let remoteCredentialPermissionsLock: Promise<void> = Promise.resolve();
let remoteCredentialPermissions = new RemoteCredentialPermissionLedger();

export function credentialStateError(code: string, message: string, cause?: unknown): BridgeError {
  return new BridgeError(
    code,
    message,
    undefined,
    cause === undefined ? undefined : { cause: cause instanceof Error ? cause.message : String(cause) }
  );
}

export function randomCredentialId(prefix: "credential" | "remote-credential"): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return `${prefix}-${[...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

async function withLocalCredentialHandoffsLock<T>(operation: () => Promise<T>): Promise<T> {
  const previous = localCredentialHandoffsLock;
  let release: (() => void) | undefined;
  localCredentialHandoffsLock = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release?.();
  }
}

async function persistLocalCredentialHandoffsUnlocked(): Promise<void> {
  const area = sessionStorageArea();
  if (!area) throw credentialStateError("credential_handoff_storage_unavailable", "Trusted credential-handoff session storage is unavailable.");
  try {
    await area.set({
      [LOCAL_CREDENTIAL_HANDOFFS_SESSION_KEY]: {
        version: 1,
        handoffs: localCredentialHandoffs.snapshot()
      }
    });
  } catch (error) {
    throw credentialStateError(
      "credential_handoff_storage_unavailable",
      "BrowseWeave could not persist the local credential handoff.",
      error
    );
  }
}

async function ensureLocalCredentialHandoffsLoadedUnlocked(): Promise<void> {
  if (localCredentialHandoffsLoaded) return;
  const area = sessionStorageArea();
  if (!area) throw credentialStateError("credential_handoff_storage_unavailable", "Trusted credential-handoff session storage is unavailable.");
  let stored: Record<string, unknown>;
  try {
    stored = await area.get(LOCAL_CREDENTIAL_HANDOFFS_SESSION_KEY);
  } catch (error) {
    throw credentialStateError("credential_handoff_storage_unavailable", "BrowseWeave could not read local credential handoffs.", error);
  }
  const value = stored[LOCAL_CREDENTIAL_HANDOFFS_SESSION_KEY];
  if (value === undefined) {
    localCredentialHandoffsLoaded = true;
    return;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw credentialStateError("credential_handoff_state_invalid", "The local credential-handoff ledger failed integrity checks.");
  }
  const record = value as Record<string, unknown>;
  const rawHandoffs = record.handoffs;
  if (
    record.version !== 1 || !Array.isArray(rawHandoffs) || rawHandoffs.length > MAX_CREDENTIAL_HANDOFFS ||
    rawHandoffs.some((handoff) => !isLocalCredentialHandoff(handoff))
  ) {
    throw credentialStateError("credential_handoff_state_invalid", "The local credential-handoff ledger failed integrity checks.");
  }
  try {
    localCredentialHandoffs = new LocalCredentialHandoffLedger(rawHandoffs as LocalCredentialHandoff[]);
  } catch (error) {
    throw credentialStateError("credential_handoff_state_invalid", "The local credential-handoff ledger failed integrity checks.", error);
  }
  localCredentialHandoffsLoaded = true;
  if (localCredentialHandoffs.prune()) await persistLocalCredentialHandoffsUnlocked();
}

export function notifyCredentialState(): void {
  void extensionBrowser.runtime.sendMessage({ kind: "bridge:credentials" }).catch(() => undefined);
}

export async function storeLocalCredentialHandoff(handoff: LocalCredentialHandoff): Promise<void> {
  await withLocalCredentialHandoffsLock(async () => {
    await ensureLocalCredentialHandoffsLoadedUnlocked();
    localCredentialHandoffs.revokeTab(handoff.tab_id);
    localCredentialHandoffs.add(handoff);
    await persistLocalCredentialHandoffsUnlocked();
  });
  notifyCredentialState();
}

export async function listLocalCredentialHandoffs(): Promise<LocalCredentialHandoff[]> {
  return withLocalCredentialHandoffsLock(async () => {
    await ensureLocalCredentialHandoffsLoadedUnlocked();
    if (localCredentialHandoffs.prune()) await persistLocalCredentialHandoffsUnlocked();
    return localCredentialHandoffs.snapshot();
  });
}

export async function consumeLocalCredentialHandoff(handoffId: string): Promise<LocalCredentialHandoff> {
  return withLocalCredentialHandoffsLock(async () => {
    await ensureLocalCredentialHandoffsLoadedUnlocked();
    const handoff = localCredentialHandoffs.consume(handoffId);
    if (!handoff) throw new BridgeError("credential_handoff_missing", "This local credential handoff is missing, expired, or already used.");
    await persistLocalCredentialHandoffsUnlocked();
    notifyCredentialState();
    return handoff;
  });
}

export async function revokeLocalCredentialHandoff(handoffId: string): Promise<void> {
  await withLocalCredentialHandoffsLock(async () => {
    await ensureLocalCredentialHandoffsLoadedUnlocked();
    if (!localCredentialHandoffs.revoke(handoffId)) return;
    await persistLocalCredentialHandoffsUnlocked();
  });
  notifyCredentialState();
}

export async function revokeCredentialHandoffsForTab(removedTabId: number): Promise<void> {
  await withLocalCredentialHandoffsLock(async () => {
    await ensureLocalCredentialHandoffsLoadedUnlocked();
    if (localCredentialHandoffs.revokeTab(removedTabId) === 0) return;
    await persistLocalCredentialHandoffsUnlocked();
  });
  notifyCredentialState();
}

async function withRemoteCredentialPermissionsLock<T>(operation: () => Promise<T>): Promise<T> {
  const previous = remoteCredentialPermissionsLock;
  let release: (() => void) | undefined;
  remoteCredentialPermissionsLock = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release?.();
  }
}

async function persistRemoteCredentialPermissionsUnlocked(): Promise<void> {
  try {
    await extensionBrowser.storage.local.set({
      [REMOTE_CREDENTIAL_PERMISSIONS_STORAGE_KEY]: {
        version: 1,
        permissions: remoteCredentialPermissions.snapshot()
      }
    });
  } catch (error) {
    throw credentialStateError(
      "remote_credential_permission_storage_unavailable",
      "BrowseWeave could not persist the one-use remote credential permission.",
      error
    );
  }
}

async function ensureRemoteCredentialPermissionsLoadedUnlocked(): Promise<void> {
  if (remoteCredentialPermissionsLoaded) return;
  let stored: Record<string, unknown>;
  try {
    stored = await extensionBrowser.storage.local.get(REMOTE_CREDENTIAL_PERMISSIONS_STORAGE_KEY);
  } catch (error) {
    throw credentialStateError(
      "remote_credential_permission_storage_unavailable",
      "BrowseWeave could not read remote credential permissions.",
      error
    );
  }
  const value = stored[REMOTE_CREDENTIAL_PERMISSIONS_STORAGE_KEY];
  if (value === undefined) {
    remoteCredentialPermissionsLoaded = true;
    return;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw credentialStateError("remote_credential_permission_state_invalid", "The remote credential-permission ledger failed integrity checks.");
  }
  const record = value as Record<string, unknown>;
  const rawPermissions = record.permissions;
  if (
    record.version !== 1 || !Array.isArray(rawPermissions) || rawPermissions.length > MAX_REMOTE_CREDENTIAL_PERMISSIONS ||
    rawPermissions.some((permission) => !isRemoteCredentialPermission(permission))
  ) {
    throw credentialStateError("remote_credential_permission_state_invalid", "The remote credential-permission ledger failed integrity checks.");
  }
  try {
    remoteCredentialPermissions = new RemoteCredentialPermissionLedger(rawPermissions as RemoteCredentialPermission[]);
  } catch (error) {
    throw credentialStateError("remote_credential_permission_state_invalid", "The remote credential-permission ledger failed integrity checks.", error);
  }
  remoteCredentialPermissionsLoaded = true;
  if (remoteCredentialPermissions.prune()) await persistRemoteCredentialPermissionsUnlocked();
}

export async function listRemoteCredentialPermissions(): Promise<RemoteCredentialPermission[]> {
  return withRemoteCredentialPermissionsLock(async () => {
    await ensureRemoteCredentialPermissionsLoadedUnlocked();
    if (remoteCredentialPermissions.prune()) await persistRemoteCredentialPermissionsUnlocked();
    return remoteCredentialPermissions.snapshot();
  });
}

export async function createRemoteCredentialPermission(
  expectedOrigin: string,
  expectedTabId: number,
  durationMs: number
): Promise<RemoteCredentialPermission> {
  const exactOrigin = normalizeHttpsOrigin(expectedOrigin);
  if (!Number.isSafeInteger(durationMs) || durationMs < 60_000 || durationMs > MAX_REMOTE_CREDENTIAL_PERMISSION_MS) {
    throw new Error("Remote credential permission duration must be between 1 minute and 24 hours.");
  }
  const createdAt = Date.now();
  const permission: RemoteCredentialPermission = {
    permission_id: randomCredentialId("remote-credential"),
    origin: exactOrigin,
    created_at: new Date(createdAt).toISOString(),
    expires_at: new Date(createdAt + durationMs).toISOString(),
    one_use: true
  };
  await withRemoteCredentialPermissionsLock(async () => {
    await ensureRemoteCredentialPermissionsLoadedUnlocked();
    const currentTab = await activeTab();
    if (!credentialGrantTargetMatches({
      expectedOrigin: exactOrigin,
      expectedTabId,
      currentUrl: currentTab.url,
      currentTabId: currentTab.id
    })) {
      throw new BridgeError(
        "remote_credential_target_changed",
        "The active tab or HTTPS origin changed after the permission prompt. Review the current site and confirm again."
      );
    }
    const previousPermissions = remoteCredentialPermissions.snapshot();
    remoteCredentialPermissions.add(permission, createdAt);
    try {
      await persistRemoteCredentialPermissionsUnlocked();
    } catch (error) {
      remoteCredentialPermissions = new RemoteCredentialPermissionLedger(previousPermissions);
      throw error;
    }
  });
  notifyCredentialState();
  return permission;
}

export async function revokeRemoteCredentialPermission(permissionId: string): Promise<void> {
  await withRemoteCredentialPermissionsLock(async () => {
    await ensureRemoteCredentialPermissionsLoadedUnlocked();
    if (!remoteCredentialPermissions.revoke(permissionId)) return;
    await persistRemoteCredentialPermissionsUnlocked();
  });
  notifyCredentialState();
}

export async function consumeRemoteCredentialPermission(origin: string): Promise<RemoteCredentialPermission> {
  return withRemoteCredentialPermissionsLock(async () => {
    await ensureRemoteCredentialPermissionsLoadedUnlocked();
    const permission = remoteCredentialPermissions.consumeOrigin(origin);
    if (!permission) {
      throw new BridgeError(
        "remote_credential_permission_required",
        `Remote credential filling is disabled for ${origin}. The user must grant one-use access from the BrowseWeave popup on that exact HTTPS origin.`
      );
    }
    await persistRemoteCredentialPermissionsUnlocked();
    notifyCredentialState();
    return permission;
  });
}
