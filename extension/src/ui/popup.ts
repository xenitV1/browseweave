import { maskUntrustedApprovalDescription, normalizeText } from "../shared/pure";

interface BrowserIdentityView {
  installation_id?: string;
  browser_family?: string;
  browser_name?: string;
  browser_version?: string;
  extension_version?: string;
}

interface HumanInterventionView {
  tab_id?: number;
  origin?: string;
  kind?: string;
  message?: string;
  pause_origin?: boolean;
  detected_at?: string;
}

interface CredentialHandoffView {
  handoff_id: string;
  origin: string;
  fields: Array<{ ref: string; kind: "username" | "password"; label?: string }>;
  submit: boolean;
  expires_at: string;
}

interface RemoteCredentialPermissionView {
  permission_id: string;
  origin: string;
  expires_at: string;
}

interface UiStatus {
  phase?: string;
  connected?: boolean;
  last_error?: string;
  has_token?: boolean;
  active_tab_access?: string;
  identity?: BrowserIdentityView | null;
  human_interventions?: HumanInterventionView[];
  managed_tab_count?: number;
  managed_tab_limit?: number;
  managed_tabs_error?: string | null;
  active_tab_id?: number | null;
  active_origin?: string | null;
  credential_handoffs?: CredentialHandoffView[];
  remote_credential_permissions?: RemoteCredentialPermissionView[];
  credential_state_error?: string | null;
}

const statusDot = document.querySelector<HTMLElement>("#status-dot");
const statusLabel = document.querySelector<HTMLElement>("#status-label");
const statusDetail = document.querySelector<HTMLElement>("#status-detail");
const accessLabel = document.querySelector<HTMLElement>("#access-label");
const browserLabel = document.querySelector<HTMLElement>("#browser-label");
const installationLabel = document.querySelector<HTMLElement>("#installation-label");
const reconnectButton = document.querySelector<HTMLButtonElement>("#reconnect");
const optionsButton = document.querySelector<HTMLButtonElement>("#open-options");
const actionResult = document.querySelector<HTMLElement>("#action-result");
const humanCard = document.querySelector<HTMLElement>("#human-card");
const humanMessage = document.querySelector<HTMLElement>("#human-message");
const humanOrigin = document.querySelector<HTMLElement>("#human-origin");
const resumeHumanButton = document.querySelector<HTMLButtonElement>("#resume-human");
const managedTabCount = document.querySelector<HTMLElement>("#managed-tab-count");
const managedTabDetail = document.querySelector<HTMLElement>("#managed-tab-detail");
const cleanupManagedTabsButton = document.querySelector<HTMLButtonElement>("#cleanup-managed-tabs");
const credentialCard = document.querySelector<HTMLElement>("#credential-card");
const credentialOrigin = document.querySelector<HTMLElement>("#credential-origin");
const credentialFields = document.querySelector<HTMLElement>("#credential-fields");
const credentialSubmitNote = document.querySelector<HTMLElement>("#credential-submit-note");
const completeCredentialButton = document.querySelector<HTMLButtonElement>("#complete-credential");
const cancelCredentialButton = document.querySelector<HTMLButtonElement>("#cancel-credential");
const credentialResult = document.querySelector<HTMLElement>("#credential-result");
const remoteOrigin = document.querySelector<HTMLElement>("#remote-origin");
const remotePermissionState = document.querySelector<HTMLElement>("#remote-permission-state");
const remotePermissionDuration = document.querySelector<HTMLSelectElement>("#remote-permission-duration");
const grantRemoteCredentialButton = document.querySelector<HTMLButtonElement>("#grant-remote-credential");
const revokeRemoteCredentialButton = document.querySelector<HTMLButtonElement>("#revoke-remote-credential");
const remotePermissionResult = document.querySelector<HTMLElement>("#remote-permission-result");

let activeCredentialHandoff: CredentialHandoffView | undefined;
let renderedCredentialHandoffId = "";
let activeRemotePermission: RemoteCredentialPermissionView | undefined;
let currentActiveOrigin = "";
let currentActiveTabId: number | null = null;

function readableLabel(value: unknown, fallback: string): string {
  const normalized = normalizeText(value, 80).replace(/_/gu, " ");
  if (!normalized) return fallback;
  return normalized.replace(/\b\p{L}/gu, (character) => character.toLocaleUpperCase());
}

function shortInstallationId(value: unknown): string {
  if (typeof value !== "string" || value.length < 13) return "Unavailable";
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function showActionResult(message: string, kind: "success" | "error" | "" = ""): void {
  if (!actionResult) return;
  actionResult.textContent = message;
  actionResult.className = `result ${kind}`.trim();
}

function showCredentialResult(message: string, kind: "success" | "error" | "" = ""): void {
  if (!credentialResult) return;
  credentialResult.textContent = message;
  credentialResult.className = `result ${kind}`.trim();
}

function showRemotePermissionResult(message: string, kind: "success" | "error" | "" = ""): void {
  if (!remotePermissionResult) return;
  remotePermissionResult.textContent = message;
  remotePermissionResult.className = `result ${kind}`.trim();
}

function renderHumanIntervention(interventions: HumanInterventionView[]): void {
  const intervention = interventions[0];
  if (!humanCard || !humanMessage || !humanOrigin) return;
  humanCard.hidden = !intervention;
  if (!intervention) {
    humanMessage.textContent = "";
    humanOrigin.textContent = "";
    return;
  }
  humanMessage.textContent = maskUntrustedApprovalDescription(
    intervention.message || "This page requires direct user action in the browser."
  );
  const origin = normalizeText(intervention.origin, 180);
  const kind = readableLabel(intervention.kind, "Human verification");
  humanOrigin.textContent = origin ? `${kind} · ${origin}` : kind;
}

function clearCredentialInputs(): void {
  for (const input of credentialFields?.querySelectorAll<HTMLInputElement>("input") ?? []) input.value = "";
}

function renderCredentialHandoff(handoffs: CredentialHandoffView[]): void {
  const handoff = handoffs
    .filter((item) => typeof item?.handoff_id === "string" && Number.isFinite(Date.parse(item.expires_at)))
    .sort((left, right) => Date.parse(left.expires_at) - Date.parse(right.expires_at))[0];
  activeCredentialHandoff = handoff;
  if (!credentialCard || !credentialOrigin || !credentialFields || !credentialSubmitNote) return;
  credentialCard.hidden = !handoff;
  if (!handoff) {
    clearCredentialInputs();
    credentialFields.replaceChildren();
    renderedCredentialHandoffId = "";
    credentialOrigin.textContent = "";
    credentialSubmitNote.hidden = true;
    return;
  }
  credentialOrigin.textContent = `Bound HTTPS origin · ${normalizeText(handoff.origin, 180)}`;
  credentialSubmitNote.hidden = handoff.submit !== true;
  if (renderedCredentialHandoffId === handoff.handoff_id) return;
  clearCredentialInputs();
  credentialFields.replaceChildren();
  renderedCredentialHandoffId = handoff.handoff_id;
  for (const field of handoff.fields) {
    if (field.kind !== "username" && field.kind !== "password") continue;
    const label = document.createElement("label");
    label.textContent = field.kind === "username" ? "Username, email, or phone" : "Password";
    const input = document.createElement("input");
    input.type = field.kind === "password" ? "password" : "text";
    input.autocomplete = "off";
    input.maxLength = field.kind === "password" ? 1024 : 320;
    input.required = true;
    input.spellcheck = false;
    input.dataset.credentialKind = field.kind;
    input.setAttribute("autocapitalize", "none");
    label.append(input);
    credentialFields.append(label);
  }
}

function renderRemoteCredentialPermission(
  activeOrigin: string,
  permissions: RemoteCredentialPermissionView[],
  error: string
): void {
  currentActiveOrigin = /^https:\/\//u.test(activeOrigin) ? activeOrigin : "";
  activeRemotePermission = permissions.find((permission) => permission.origin === currentActiveOrigin);
  if (remoteOrigin) {
    remoteOrigin.textContent = error
      ? normalizeText(error, 220)
      : currentActiveOrigin || "Open this popup on an HTTPS sign-in page.";
  }
  if (remotePermissionState) {
    remotePermissionState.textContent = activeRemotePermission
      ? `Until ${new Date(activeRemotePermission.expires_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
      : "Off";
  }
  if (grantRemoteCredentialButton) {
    grantRemoteCredentialButton.disabled = !currentActiveOrigin || currentActiveTabId === null ||
      Boolean(activeRemotePermission) || Boolean(error);
  }
  if (revokeRemoteCredentialButton) revokeRemoteCredentialButton.hidden = !activeRemotePermission;
}

function render(status: UiStatus): void {
  if (!statusDot || !statusLabel || !statusDetail || !accessLabel) return;
  statusDot.className = "status-dot";

  if (status.connected) {
    statusDot.classList.add("connected");
    statusLabel.textContent = "Local bridge connected";
    statusDetail.textContent = status.human_interventions?.length
      ? "Automated actions are paused while you complete a browser step."
      : "This browser profile is ready for approved local control.";
  } else if (status.phase === "needs_token" || !status.has_token) {
    statusDot.classList.add("error");
    statusLabel.textContent = "Connection setup required";
    statusDetail.textContent = "Open Settings and choose Connect BrowseWeave. No key needs to be copied.";
  } else if (status.phase === "connecting" || status.phase === "authenticating") {
    statusDot.classList.add("connecting");
    statusLabel.textContent = "Connecting to the local bridge";
    statusDetail.textContent = "The signed browser identity is being verified.";
  } else {
    statusDot.classList.add("error");
    statusLabel.textContent = "Local bridge disconnected";
    statusDetail.textContent = normalizeText(status.last_error, 260) || "Check that the BrowseWeave bridge service is running.";
  }

  accessLabel.textContent = status.active_tab_access === "normal_web"
    ? "Current web page available"
    : status.active_tab_access === "restricted"
      ? "Restricted browser page"
      : "Active page unknown";
  const identity = status.identity;
  if (browserLabel) {
    browserLabel.textContent = identity?.browser_name
      ? `${normalizeText(identity.browser_name, 50)} ${normalizeText(identity.browser_version, 30)}`.trim()
      : "Unavailable";
  }
  if (installationLabel) installationLabel.textContent = shortInstallationId(identity?.installation_id);
  const managedCount = typeof status.managed_tab_count === "number" && Number.isInteger(status.managed_tab_count)
    ? Math.max(0, status.managed_tab_count)
    : 0;
  const managedLimit = typeof status.managed_tab_limit === "number" && Number.isInteger(status.managed_tab_limit)
    ? Math.max(1, status.managed_tab_limit)
    : 10;
  if (managedTabCount) managedTabCount.textContent = `${managedCount} / ${managedLimit}`;
  if (managedTabDetail) {
    managedTabDetail.textContent = status.managed_tabs_error
      ? normalizeText(status.managed_tabs_error, 240)
      : managedCount === 0
        ? "No open tab is currently owned by BrowseWeave. Your existing tabs are never included."
        : `${managedCount} open tab${managedCount === 1 ? " is" : "s are"} owned by BrowseWeave in this browser session.`;
  }
  if (cleanupManagedTabsButton) cleanupManagedTabsButton.disabled = managedCount === 0 || Boolean(status.managed_tabs_error);
  renderHumanIntervention(Array.isArray(status.human_interventions) ? status.human_interventions : []);
  renderCredentialHandoff(Array.isArray(status.credential_handoffs) ? status.credential_handoffs : []);
  currentActiveTabId = typeof status.active_tab_id === "number" && Number.isSafeInteger(status.active_tab_id) && status.active_tab_id > 0
    ? status.active_tab_id
    : null;
  renderRemoteCredentialPermission(
    typeof status.active_origin === "string" ? status.active_origin : "",
    Array.isArray(status.remote_credential_permissions) ? status.remote_credential_permissions : [],
    typeof status.credential_state_error === "string" ? status.credential_state_error : ""
  );
}

async function refresh(): Promise<void> {
  try {
    const status = await browser.runtime.sendMessage({ kind: "ui:get-status" }) as UiStatus;
    render(status || {});
  } catch (error) {
    render({ phase: "error", last_error: error instanceof Error ? error.message : "The extension background did not respond." });
  }
}

reconnectButton?.addEventListener("click", async () => {
  reconnectButton.disabled = true;
  try {
    await browser.runtime.sendMessage({ kind: "ui:reconnect" });
    await new Promise((resolve) => globalThis.setTimeout(resolve, 350));
    await refresh();
  } finally {
    reconnectButton.disabled = false;
  }
});

resumeHumanButton?.addEventListener("click", async () => {
  resumeHumanButton.disabled = true;
  showActionResult("");
  try {
    await browser.runtime.sendMessage({ kind: "ui:resume-human" });
    showActionResult("The page is clear. BrowseWeave can continue.", "success");
    await refresh();
  } catch (error) {
    showActionResult(error instanceof Error ? error.message : "The browser step is still waiting for you.", "error");
  } finally {
    resumeHumanButton.disabled = false;
  }
});

cleanupManagedTabsButton?.addEventListener("click", async () => {
  const count = Number.parseInt(managedTabCount?.textContent || "0", 10);
  if (count < 1) return;
  if (!globalThis.confirm(`Close ${count} tab${count === 1 ? "" : "s"} created by BrowseWeave? Your other tabs will stay open.`)) return;
  cleanupManagedTabsButton.disabled = true;
  showActionResult("");
  try {
    const result = await browser.runtime.sendMessage({ kind: "ui:cleanup-managed-tabs" }) as {
      closed_tab_ids?: number[];
      managed_tab_count?: number;
    };
    const closed = Array.isArray(result?.closed_tab_ids) ? result.closed_tab_ids.length : 0;
    showActionResult(`${closed} managed tab${closed === 1 ? "" : "s"} closed.`, "success");
    await refresh();
  } catch (error) {
    showActionResult(error instanceof Error ? error.message : "Managed tabs could not be closed.", "error");
    cleanupManagedTabsButton.disabled = false;
  }
});

completeCredentialButton?.addEventListener("click", async () => {
  const handoff = activeCredentialHandoff;
  if (!handoff || !credentialFields) return;
  const inputs = [...credentialFields.querySelectorAll<HTMLInputElement>("input[data-credential-kind]")];
  const fields = inputs.map((input) => ({
    kind: input.dataset.credentialKind,
    value: input.value
  }));
  if (fields.length !== handoff.fields.length || fields.some((field) => !field.value)) {
    showCredentialResult("Enter every requested value before continuing.", "error");
    return;
  }
  completeCredentialButton.disabled = true;
  if (cancelCredentialButton) cancelCredentialButton.disabled = true;
  showCredentialResult("");
  try {
    const response = browser.runtime.sendMessage({
      kind: "ui:complete-credential-handoff",
      handoff_id: handoff.handoff_id,
      fields
    }) as Promise<{ submitted?: boolean }>;
    // WebExtensions clones the message at send time. Remove live DOM values
    // immediately instead of retaining them while the background is working.
    clearCredentialInputs();
    credentialFields.replaceChildren();
    renderedCredentialHandoffId = "";
    for (const field of fields) field.value = "";
    const result = await response;
    showCredentialResult(result?.submitted ? "Credentials filled and sign-in submitted." : "Credentials filled once.", "success");
    await refresh();
  } catch (error) {
    showCredentialResult(error instanceof Error ? error.message : "The credential handoff could not be completed.", "error");
    await refresh();
  } finally {
    clearCredentialInputs();
    for (const field of fields) field.value = "";
    completeCredentialButton.disabled = false;
    if (cancelCredentialButton) cancelCredentialButton.disabled = false;
  }
});

cancelCredentialButton?.addEventListener("click", async () => {
  const handoff = activeCredentialHandoff;
  if (!handoff) return;
  clearCredentialInputs();
  cancelCredentialButton.disabled = true;
  try {
    await browser.runtime.sendMessage({ kind: "ui:cancel-credential-handoff", handoff_id: handoff.handoff_id });
    renderedCredentialHandoffId = "";
    showCredentialResult("Credential handoff cancelled.", "success");
    await refresh();
  } catch (error) {
    showCredentialResult(error instanceof Error ? error.message : "The credential handoff could not be cancelled.", "error");
  } finally {
    cancelCredentialButton.disabled = false;
  }
});

grantRemoteCredentialButton?.addEventListener("click", async () => {
  if (!currentActiveOrigin || currentActiveTabId === null) return;
  const expectedOrigin = currentActiveOrigin;
  const expectedTabId = currentActiveTabId;
  const confirmed = globalThis.confirm(
    `Allow the connected AI to send a username and password to ${expectedOrigin} once? ` +
    "Your AI provider and tool transport may see those values."
  );
  if (!confirmed) return;
  grantRemoteCredentialButton.disabled = true;
  showRemotePermissionResult("");
  try {
    await browser.runtime.sendMessage({
      kind: "ui:create-remote-credential-permission",
      duration_ms: Number(remotePermissionDuration?.value || 900_000),
      expected_origin: expectedOrigin,
      expected_tab_id: expectedTabId
    });
    showRemotePermissionResult("One-use remote sign-in permission granted for this exact origin.", "success");
    await refresh();
  } catch (error) {
    showRemotePermissionResult(error instanceof Error ? error.message : "Permission could not be granted.", "error");
    grantRemoteCredentialButton.disabled = false;
  }
});

revokeRemoteCredentialButton?.addEventListener("click", async () => {
  const permission = activeRemotePermission;
  if (!permission) return;
  revokeRemoteCredentialButton.disabled = true;
  try {
    await browser.runtime.sendMessage({
      kind: "ui:revoke-remote-credential-permission",
      permission_id: permission.permission_id
    });
    showRemotePermissionResult("Remote sign-in permission revoked.", "success");
    await refresh();
  } catch (error) {
    showRemotePermissionResult(error instanceof Error ? error.message : "Permission could not be revoked.", "error");
  } finally {
    revokeRemoteCredentialButton.disabled = false;
  }
});

optionsButton?.addEventListener("click", () => {
  void browser.runtime.openOptionsPage();
  globalThis.close();
});

browser.runtime.onMessage.addListener((message: unknown) => {
  if (message && typeof message === "object") {
    const kind = (message as Record<string, unknown>).kind;
    if (
      kind === "bridge:state" || kind === "bridge:human-state" ||
      kind === "bridge:managed-tabs" || kind === "bridge:credentials"
    ) void refresh();
  }
  return undefined;
});

void refresh();
