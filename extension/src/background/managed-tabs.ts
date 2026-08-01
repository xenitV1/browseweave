/**
 * Ownership ledger for tabs BrowseWeave itself opened. Cleanup and single-tab
 * close intersect requests with this ledger, so a tab the user already had open
 * can never be closed by BrowseWeave.
 *
 * Each entry also records which agent opened the tab. One browser profile can
 * serve several MCP client sessions at once, and without an owner they share a
 * single pool: each one lists, drives, and closes the others' tabs, and the
 * cleanup that ends one session destroys work in progress in another. The owner
 * scopes those operations. It is an isolation boundary between cooperating
 * agents, not a security one — a local process holding the IPC token could
 * claim any identity, but it already had full authority.
 */
import {
  MAX_MANAGED_TABS,
  MAX_MANAGED_TABS_TOTAL,
  agentOwnsManagedTab,
  canCreateManagedTabForAgent,
  isAgentId,
  managedTabOwner,
  normalizeManagedTabLedger,
  normalizeManagedTabIds,
  selectManagedTabsForAgentCleanup,
  type ManagedTabEntry
} from "../shared/pure";
import { BridgeError, extensionBrowser, sessionStorageArea } from "./environment";

const MANAGED_TABS_SESSION_KEY = "browseweave_managed_tabs_v1";

/** tab ID -> owning agent, or null for a tab recorded before ownership existed. */
const managedTabs = new Map<number, string | null>();
let managedTabsLoaded = false;
let managedTabsLock: Promise<void> = Promise.resolve();

/** Whether a managed tab is this agent's, another agent's, or not managed. */
export type ManagedTabAccess = "unmanaged" | "owned" | "foreign";

function ledgerEntries(): ManagedTabEntry[] {
  return normalizeManagedTabLedger([...managedTabs].map(([id, owner]) => ({ id, owner })));
}

function ownedCount(entries: readonly ManagedTabEntry[], agent: unknown): number {
  if (!isAgentId(agent)) return 0;
  return entries.filter((entry) => entry.owner === agent).length;
}

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
  if (record.version === 1) {
    // Written before ownership existed. Those tabs belong to no agent, so no
    // agent may drive them; a cleanup can still collect them.
    const rawIds = record.tab_ids;
    const normalized = normalizeManagedTabIds(rawIds);
    if (
      !Array.isArray(rawIds) || rawIds.length !== normalized.length ||
      normalized.length > MAX_MANAGED_TABS_TOTAL
    ) {
      throw managedTabsStateError("The managed-tab ownership ledger failed integrity checks. No tab action was taken.");
    }
    for (const id of normalized) managedTabs.set(id, null);
    managedTabsLoaded = true;
    return;
  }
  const rawTabs = record.tabs;
  const entries = normalizeManagedTabLedger(rawTabs);
  if (
    record.version !== 2 || !Array.isArray(rawTabs) || rawTabs.length !== entries.length ||
    entries.length > MAX_MANAGED_TABS_TOTAL
  ) {
    throw managedTabsStateError("The managed-tab ownership ledger failed integrity checks. No tab action was taken.");
  }
  for (const entry of entries) managedTabs.set(entry.id, entry.owner);
  managedTabsLoaded = true;
}

async function persistManagedTabsUnlocked(): Promise<void> {
  const area = sessionStorageArea();
  if (!area) throw managedTabsStateError("Managed-tab session storage is unavailable.");
  try {
    await area.set({
      [MANAGED_TABS_SESSION_KEY]: {
        version: 2,
        tabs: ledgerEntries()
      }
    });
  } catch (error) {
    throw managedTabsStateError("BrowseWeave could not save its managed-tab ownership ledger.", error);
  }
}

export function notifyManagedTabState(): void {
  void extensionBrowser.runtime.sendMessage({
    kind: "bridge:managed-tabs",
    managed_tab_count: managedTabs.size,
    managed_tab_limit: MAX_MANAGED_TABS_TOTAL
  }).catch(() => undefined);
}

export async function reconcileManagedTabsUnlocked(): Promise<void> {
  let changed = false;
  for (const id of [...managedTabs.keys()]) {
    try {
      await extensionBrowser.tabs.get(id);
    } catch {
      managedTabs.delete(id);
      changed = true;
    }
  }
  if (changed) {
    await persistManagedTabsUnlocked();
    notifyManagedTabState();
  }
}

export async function managedTabsSummary(agent: unknown): Promise<{
  managed_tab_count: number;
  managed_tab_limit: number;
  managed_tab_total: number;
  managed_tab_total_limit: number;
}> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    const entries = ledgerEntries();
    return {
      managed_tab_count: ownedCount(entries, agent),
      managed_tab_limit: MAX_MANAGED_TABS,
      managed_tab_total: entries.length,
      managed_tab_total_limit: MAX_MANAGED_TABS_TOTAL
    };
  });
}

export async function untrackManagedTab(id: number): Promise<void> {
  await withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    if (!managedTabs.delete(id)) return;
    await persistManagedTabsUnlocked();
    notifyManagedTabState();
  });
}

export async function isManagedTab(id: number): Promise<boolean> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    return managedTabOwner(ledgerEntries(), id) !== undefined;
  });
}

/**
 * Classifies a tab for one agent. A tab BrowseWeave never opened stays
 * "unmanaged" and remains usable by every agent exactly as before: only tabs
 * BrowseWeave owns are scoped.
 */
export async function managedTabAccess(id: number, agent: unknown): Promise<ManagedTabAccess> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    const entries = ledgerEntries();
    if (managedTabOwner(entries, id) === undefined) return "unmanaged";
    return agentOwnsManagedTab(entries, id, agent) ? "owned" : "foreign";
  });
}

export async function createManagedTab(
  url: string,
  active: boolean,
  agent: unknown,
  beforeCreate: () => Promise<void>
): Promise<browser.tabs.Tab> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    return createManagedTabUnlocked(url, active, agent, beforeCreate);
  });
}

function isBlankTabUrl(url: string | undefined): boolean {
  return url === undefined || url === "" || url === "about:blank";
}

/**
 * Returns a managed tab that is still sitting on about:blank, creating one only
 * when none exists.
 *
 * Opening a tab at a real site needs a live document to bind the decision to,
 * so the destination is navigated into a blank tab BrowseWeave owns. A retry of
 * the same request — the approval channel always retries — must land on that
 * same tab instead of leaking another one into the managed budget, which is why
 * adoption comes before creation. During an approval-only recheck nothing may
 * be created at all, so the absence of an adoptable tab is an error there.
 *
 * Only this agent's own blank tab is adoptable. Adopting another agent's would
 * navigate that agent's tab away and bind this agent's approval to it.
 */
export async function blankManagedTabForNavigation(
  active: boolean,
  adoptOnly: boolean,
  agent: unknown
): Promise<browser.tabs.Tab> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    const entries = ledgerEntries();
    for (const entry of entries) {
      if (!agentOwnsManagedTab(entries, entry.id, agent)) continue;
      try {
        const candidate = await extensionBrowser.tabs.get(entry.id);
        if (isBlankTabUrl(candidate.url)) return candidate;
      } catch {
        // Reconciliation already dropped tabs that no longer exist.
      }
    }
    if (adoptOnly) {
      throw new BridgeError(
        "approval_context_changed",
        "The blank BrowseWeave tab this open request was bound to is gone. Nothing was executed."
      );
    }
    return createManagedTabUnlocked("about:blank", active, agent, async () => undefined);
  });
}

async function createManagedTabUnlocked(
  url: string,
  active: boolean,
  agent: unknown,
  beforeCreate: () => Promise<void>
): Promise<browser.tabs.Tab> {
  const entries = ledgerEntries();
  if (!canCreateManagedTabForAgent(entries, agent)) {
    const atTotal = entries.length >= MAX_MANAGED_TABS_TOTAL;
    throw new BridgeError(
      "managed_tab_limit",
      atTotal
        ? `Every connected agent together already has ${MAX_MANAGED_TABS_TOTAL} open tabs created by BrowseWeave in this browser profile. Close one or run browser_cleanup_tabs before opening another.`
        : `This agent already has ${MAX_MANAGED_TABS} open tabs created by BrowseWeave. Close one or run browser_cleanup_tabs before opening another.`,
      undefined,
      {
        managed_tab_count: ownedCount(entries, agent),
        managed_tab_limit: MAX_MANAGED_TABS,
        managed_tab_total: entries.length,
        managed_tab_total_limit: MAX_MANAGED_TABS_TOTAL
      }
    );
  }
  await beforeCreate();
  const created = await extensionBrowser.tabs.create({ url, active });
  if (typeof created.id !== "number" || !Number.isSafeInteger(created.id) || created.id <= 0) {
    throw new BridgeError("tab_not_found", "The new browser tab did not receive a valid ID and could not be managed safely.");
  }
  managedTabs.set(created.id, isAgentId(agent) ? agent : null);
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
    if (rolledBack) managedTabs.delete(created.id);
    notifyManagedTabState();
    throw storageError;
  }
  notifyManagedTabState();
  return created;
}

/** Managed tab IDs for read-only reporting; never a close authorization. */
export async function managedTabIdList(): Promise<number[]> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    return normalizeManagedTabIds([...managedTabs.keys()]);
  });
}

/** Managed tabs with their owners, so a listing can say which are the caller's. */
export async function managedTabLedger(): Promise<ManagedTabEntry[]> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    return ledgerEntries();
  });
}

export async function cleanupManagedTabs(requested: unknown, agent: unknown): Promise<Record<string, unknown>> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    if (requested !== undefined) {
      const normalized = normalizeManagedTabIds(requested);
      if (
        !Array.isArray(requested) || requested.length > MAX_MANAGED_TABS_TOTAL ||
        requested.length !== normalized.length
      ) {
        throw new BridgeError(
          "invalid_tab_ids",
          `tab_ids must contain at most ${MAX_MANAGED_TABS_TOTAL} unique positive integer tab IDs.`
        );
      }
    }
    const closed = await closeSelectedUnlocked(selectManagedTabsForAgentCleanup(ledgerEntries(), agent, requested));
    const entries = ledgerEntries();
    return {
      closed_tab_ids: closed,
      // Only this agent's remaining tabs: another agent's are not this caller's
      // to track, and reporting them invites acting on them.
      remaining_tab_ids: entries.filter((entry) => isAgentId(agent) && entry.owner === agent).map((entry) => entry.id),
      managed_tab_count: ownedCount(entries, agent),
      managed_tab_total: entries.length
    };
  });
}

async function closeSelectedUnlocked(selected: readonly number[]): Promise<number[]> {
  const closed: number[] = [];
  for (const id of selected) {
    try {
      await extensionBrowser.tabs.remove(id);
      managedTabs.delete(id);
      closed.push(id);
    } catch {
      try {
        await extensionBrowser.tabs.get(id);
      } catch {
        managedTabs.delete(id);
      }
    }
  }
  await persistManagedTabsUnlocked();
  notifyManagedTabState();
  return closed;
}

/**
 * Closes every managed tab regardless of owner.
 *
 * This is the human's own button in the extension popup, not an agent command.
 * The person owns the browser, so agent scoping does not apply to them: a
 * cleanup they ask for that left another agent's tabs open would not be the
 * cleanup they asked for.
 */
export async function cleanupEveryManagedTab(): Promise<Record<string, unknown>> {
  return withManagedTabsLock(async () => {
    await ensureManagedTabsLoadedUnlocked();
    await reconcileManagedTabsUnlocked();
    const closed = await closeSelectedUnlocked(ledgerEntries().map((entry) => entry.id));
    return {
      closed_tab_ids: closed,
      remaining_tab_ids: normalizeManagedTabIds([...managedTabs.keys()]),
      managed_tab_count: managedTabs.size
    };
  });
}

/** Current ledger size without forcing a load; callers use it for status only. */
export function managedTabCount(): number {
  return managedTabs.size;
}
