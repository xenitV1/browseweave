/**
 * Shared browser-API surface and error type for the privileged background
 * runtime. This module owns no product state so every other background file
 * can depend on it without creating a cycle.
 */

export type ExtensionActionApi = {
  setBadgeBackgroundColor(details: { color: string }): Promise<void>;
  setBadgeText(details: { text: string }): Promise<void>;
  setTitle(details: { title: string }): Promise<void>;
};

export type CrossBrowserApi = typeof browser & {
  action?: ExtensionActionApi;
  browserAction?: ExtensionActionApi;
  scripting?: {
    executeScript(details: {
      target: { tabId: number; allFrames?: boolean; frameIds?: number[] };
      files: string[];
    }): Promise<unknown>;
  };
  runtime: typeof browser.runtime & {
    getBrowserInfo?: () => Promise<{ name: string; vendor: string; version: string; buildID: string }>;
  };
  storage: typeof browser.storage & {
    session?: typeof browser.storage.local;
  };
};

const extensionGlobals = globalThis as typeof globalThis & {
  browser?: typeof browser;
  chrome?: typeof browser;
};
export const extensionBrowser: CrossBrowserApi = (() => {
  const candidate = (extensionGlobals.browser ?? extensionGlobals.chrome) as CrossBrowserApi | undefined;
  if (!candidate) throw new Error("BrowseWeave could not find the WebExtensions API.");
  return candidate;
})();

export const extensionAction = extensionBrowser.action ?? extensionBrowser.browserAction;

export class BridgeError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly category?: string,
    readonly details?: Record<string, unknown>,
    readonly approvalFingerprint?: string,
    readonly targetTabId?: number,
    readonly targetFrameId?: number,
    readonly localTargetBinding?: string
  ) {
    super(message);
  }
}

export function sessionStorageArea(): CrossBrowserApi["storage"]["local"] | undefined {
  return extensionBrowser.storage.session;
}

export async function activeTab(): Promise<browser.tabs.Tab> {
  const tabs = await extensionBrowser.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab || typeof tab.id !== "number") throw new BridgeError("tab_not_found", "No active browser tab was found.");
  return tab;
}

export async function targetTab(payload: Record<string, unknown>): Promise<browser.tabs.Tab> {
  if (typeof payload.tab_id === "number" && Number.isInteger(payload.tab_id)) {
    try {
      return await extensionBrowser.tabs.get(payload.tab_id);
    } catch {
      throw new BridgeError("tab_not_found", "The requested browser tab was not found.", undefined, { tab_id: payload.tab_id });
    }
  }
  return activeTab();
}

export function tabId(tab: browser.tabs.Tab): number {
  if (typeof tab.id !== "number") throw new BridgeError("tab_not_found", "The browser tab has no ID.");
  return tab.id;
}

export function windowId(tab: browser.tabs.Tab): number {
  if (typeof tab.windowId !== "number") throw new BridgeError("window_not_found", "The browser window for this tab was not found.");
  return tab.windowId;
}
