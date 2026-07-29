/**
 * Ownership ledger for tabs BrowseWeave itself opened. Cleanup and single-tab
 * close intersect requests with this ledger, so a tab the user already had open
 * can never be closed by BrowseWeave.
 */
import {
  MAX_MANAGED_TABS,
  canCreateManagedTab,
  isManagedTabOwned,
  managedTabsAfterClose,
  normalizeManagedTabIds,
  selectManagedTabsForCleanup
} from "../shared/pure";
import { BridgeError, extensionBrowser, sessionStorageArea } from "./environment";

const MANAGED_TABS_SESSION_KEY = "browseweave_managed_tabs_v1";

const managedTabIds = new Set<number>();
let managedTabsLoaded = false;
let managedTabsLock: Promise<void> = Promise.resolve();

function managedTabsStateError(message: string, cause?: unknown): BridgeError {
  return new BridgeError(
    "managed_tab_state_unavailable",
    message,
    undefined,
    cause === undefined ? undefined : { cause: cause instanceof Error ? cause.message : String(cause) }
  );
}

async function withManagedTabsLock<T>(operation: () => Promise<T>): Promise<T> {
  const previous = managedTabsLock;
  let release: (() => void) | undefined;
  managedTabsLock = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release?.();
  }
}

export async function ensureManagedTabsLoadedUnlocked(): Promise<void> {
  if (managedTabsLoaded) return;
  const area = sessionStorageArea();
  if (!area) {
    throw managedTabsStateError(
      "This browser cannot safely persist BrowseWeave tab ownership across extension-worker restarts. No managed tab was opened."
    );
  }
  let stored: Record<string, unknown>;
  try {
    stored = await area.get(MANAGED_TABS_SESSION_KEY);
  } catch (error) {
    throw managedTabsStateError("BrowseWeave could not read its managed-tab ownership ledger.", error);
  }
  const value = stored[MANAGED_TABS_SESSION_KEY];
  if (value === undefined) {
    managedTabsLoaded = true;
    return;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw managedTabsStateError("The managed-tab ownership ledger is invalid. No tab action was taken.");
  }
  const record = value as Record<string, unknown>;
  const rawIds = record.tab_ids;
  const normalized = normalizeManagedTabIds(rawIds);
  if (
    record.version !== 1 || !Array.isArray(rawIds) || rawIds.length !== normalized.length ||
    normalized.length > MAX_MANAGED_TABS
  ) {
    throw managedTabsStateError("The managed-tab ownership ledger failed integrity checks. No tab action was taken.");
  }
  for (const id of normalized) managedTabIds.add(id);
  managedTabsLoaded = true;
}

async function persistManagedTabsUnlocked(): Promise<void> {
  const area = sessionStorageArea();
  if (!area) throw managedTabsStateError("Managed-tab session storage is unavailable.");
  try {
    await area.set({
      [MANAGED_TABS_SESSION_KEY]: {
        version: 1,
        tab_ids: normalizeManagedTabIds([...managedTabIds])
      }
    });
  } catch (error) {
    throw managedTabsStateError("BrowseWeave could not save its managed-tab ownership ledger.", error);
  }
}

export function notifyManagedTabState(): void {
  void extensionBrowser.runtime.sendMessage({
    kind: "bridge:managed-tabs",
    managed_tab_count: managedTabIds.size,
    managed_tab_limit: MAX_MANAGED_TABS
  }).catch(() => undefined);
}

export async function reconcileManagedTabsUnlocked(): Promise<void> {
  let changed = false;
  for (const id of [...managedTabIds]) {
    try {
      await extensionBrowser.tabs.get(id);
    } catch {
      managedTabIds.delete(id);
      changed = true;
    }
  }
  if (changed) {
    await persistManagedTabsUnlocked();
    notifyManagedTabState();
  }
}

export async function managedTabsSummary(): Promise<{ managed_tab_count: number; managed_tab_limit: number }> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    return { managed_tab_count: managedTabIds.size, managed_tab_limit: MAX_MANAGED_TABS };
  });
}

export async function untrackManagedTab(id: number): Promise<void> {
  await withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    const remaining = managedTabsAfterClose([...managedTabIds], id);
    if (remaining.length === managedTabIds.size) return;
    managedTabIds.clear();
    for (const tabIdValue of remaining) managedTabIds.add(tabIdValue);
    await persistManagedTabsUnlocked();
    notifyManagedTabState();
  });
}

export async function isManagedTab(id: number): Promise<boolean> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    return isManagedTabOwned([...managedTabIds], id);
  });
}

export async function createManagedTab(
  url: string,
  active: boolean,
  beforeCreate: () => Promise<void>
): Promise<browser.tabs.Tab> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    if (!canCreateManagedTab([...managedTabIds])) {
      throw new BridgeError(
        "managed_tab_limit",
        `This browser profile already has ${MAX_MANAGED_TABS} open tabs created by BrowseWeave. Close one or run browser_cleanup_tabs before opening another.`,
        undefined,
        { managed_tab_count: managedTabIds.size, managed_tab_limit: MAX_MANAGED_TABS }
      );
    }
    await beforeCreate();
    const created = await extensionBrowser.tabs.create({ url, active });
    if (typeof created.id !== "number" || !Number.isSafeInteger(created.id) || created.id <= 0) {
      throw new BridgeError("tab_not_found", "The new browser tab did not receive a valid ID and could not be managed safely.");
    }
    managedTabIds.add(created.id);
    try {
      await persistManagedTabsUnlocked();
    } catch (storageError) {
      let rolledBack = false;
      try {
        await extensionBrowser.tabs.remove(created.id);
        rolledBack = true;
      } catch {
        // Keep the ID in memory when even rollback fails; this worker will still enforce the cap.
      }
      if (rolledBack) managedTabIds.delete(created.id);
      notifyManagedTabState();
      throw storageError;
    }
    notifyManagedTabState();
    return created;
  });
}

export async function cleanupManagedTabs(requested: unknown): Promise<Record<string, unknown>> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    if (requested !== undefined) {
      const normalized = normalizeManagedTabIds(requested);
      if (!Array.isArray(requested) || requested.length > MAX_MANAGED_TABS || requested.length !== normalized.length) {
        throw new BridgeError("invalid_tab_ids", `tab_ids must contain at most ${MAX_MANAGED_TABS} unique positive integer tab IDs.`);
      }
    }
    const selected = selectManagedTabsForCleanup([...managedTabIds], requested);
    const closed: number[] = [];
    for (const id of selected) {
      try {
        await extensionBrowser.tabs.remove(id);
        managedTabIds.delete(id);
        closed.push(id);
      } catch {
        try {
          await extensionBrowser.tabs.get(id);
        } catch {
          managedTabIds.delete(id);
        }
      }
    }
    await persistManagedTabsUnlocked();
    notifyManagedTabState();
    const remaining = normalizeManagedTabIds([...managedTabIds]);
    return {
      closed_tab_ids: closed,
      remaining_tab_ids: remaining,
      managed_tab_count: remaining.length
    };
  });
}

/** Current ledger size without forcing a load; callers use it for status only. */
export function managedTabCount(): number {
  return managedTabIds.size;
}
