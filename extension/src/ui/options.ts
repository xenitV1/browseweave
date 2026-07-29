import { normalizeText } from "../shared/pure";

interface BrowserIdentityView {
  installation_id?: string;
  browser_name?: string;
  browser_version?: string;
}

interface UiStatus {
  phase?: string;
  connected?: boolean;
  last_error?: string;
  has_token?: boolean;
  identity?: BrowserIdentityView | null;
  remote_credential_permissions?: Array<{ permission_id: string; origin: string; expires_at: string }>;
  credential_state_error?: string | null;
  session_approval_enabled?: boolean;
}

const connectButton = document.querySelector<HTMLButtonElement>("#connect-native");
const removeButton = document.querySelector<HTMLButtonElement>("#remove-token");
const result = document.querySelector<HTMLElement>("#connect-result");
const statusLabel = document.querySelector<HTMLElement>("#status-label");
const statusDetail = document.querySelector<HTMLElement>("#status-detail");
const browserLabel = document.querySelector<HTMLElement>("#browser-label");
const installationLabel = document.querySelector<HTMLElement>("#installation-label");
const remotePermissionsEmpty = document.querySelector<HTMLElement>("#remote-permissions-empty");
const remotePermissionsList = document.querySelector<HTMLElement>("#remote-permissions-list");
const permissionResult = document.querySelector<HTMLElement>("#permission-result");
const sessionApprovalToggle = document.querySelector<HTMLInputElement>("#session-approval-toggle");
const sessionApprovalResult = document.querySelector<HTMLElement>("#session-approval-result");

function showResult(message: string, kind: "success" | "error" | "" = ""): void {
  if (!result) return;
  result.textContent = message;
  result.className = `result ${kind}`.trim();
}

function showSessionApprovalResult(message: string, kind: "success" | "error" | "" = ""): void {
  if (!sessionApprovalResult) return;
  sessionApprovalResult.textContent = message;
  sessionApprovalResult.className = `result ${kind}`.trim();
}

function showPermissionResult(message: string, kind: "success" | "error" | "" = ""): void {
  if (!permissionResult) return;
  permissionResult.textContent = message;
  permissionResult.className = `result ${kind}`.trim();
}

function renderRemotePermissions(status: UiStatus): void {
  const permissions = Array.isArray(status.remote_credential_permissions)
    ? status.remote_credential_permissions
      .filter((permission) => (
        typeof permission.permission_id === "string" && typeof permission.origin === "string" &&
        Number.isFinite(Date.parse(permission.expires_at))
      ))
      .sort((left, right) => Date.parse(left.expires_at) - Date.parse(right.expires_at))
    : [];
  remotePermissionsList?.replaceChildren();
  if (remotePermissionsEmpty) {
    remotePermissionsEmpty.hidden = permissions.length > 0 || Boolean(status.credential_state_error);
    if (status.credential_state_error) remotePermissionsEmpty.textContent = normalizeText(status.credential_state_error, 240);
  }
  if (!remotePermissionsList) return;
  for (const permission of permissions) {
    const item = document.createElement("article");
    item.className = "permission-item";
    const origin = document.createElement("strong");
    origin.textContent = normalizeText(permission.origin, 200);
    const expiry = document.createElement("small");
    expiry.textContent = `One use · expires ${new Date(permission.expires_at).toLocaleString()}`;
    const revoke = document.createElement("button");
    revoke.type = "button";
    revoke.className = "danger";
    revoke.textContent = "Revoke";
    revoke.addEventListener("click", async () => {
      revoke.disabled = true;
      showPermissionResult("");
      try {
        await browser.runtime.sendMessage({
          kind: "ui:revoke-remote-credential-permission",
          permission_id: permission.permission_id
        });
        showPermissionResult("Remote sign-in permission revoked.", "success");
        await refreshStatus();
      } catch (error) {
        showPermissionResult(error instanceof Error ? error.message : "Permission could not be revoked.", "error");
        revoke.disabled = false;
      }
    });
    item.append(origin, expiry, revoke);
    remotePermissionsList.append(item);
  }
}

function renderStatus(status: UiStatus): void {
  if (!statusLabel || !statusDetail) return;
  if (status.connected) {
    statusLabel.textContent = "Connection ready";
    statusDetail.textContent = "Approved local AI clients can control permitted pages in this browser profile.";
    if (connectButton) connectButton.textContent = "Reconnect BrowseWeave";
  } else if (!status.has_token || status.phase === "needs_token") {
    statusLabel.textContent = "Ready to connect";
    statusDetail.textContent = "Choose Connect BrowseWeave. No pairing key needs to be copied or displayed.";
    if (connectButton) connectButton.textContent = "Connect BrowseWeave";
  } else if (status.phase === "connecting" || status.phase === "authenticating") {
    statusLabel.textContent = "Connecting";
    statusDetail.textContent = "The local service and signed browser identity are being verified.";
    if (connectButton) connectButton.textContent = "Connecting…";
  } else {
    statusLabel.textContent = "Connection unavailable";
    statusDetail.textContent = normalizeText(status.last_error, 320) || "Check that the local BrowseWeave bridge is running.";
    if (connectButton) connectButton.textContent = "Repair connection";
  }
  if (removeButton) removeButton.hidden = !status.has_token;
  const identity = status.identity;
  if (browserLabel) {
    browserLabel.textContent = identity?.browser_name
      ? `${normalizeText(identity.browser_name, 80)} ${normalizeText(identity.browser_version, 40)}`.trim()
      : "Unavailable";
  }
  if (installationLabel) installationLabel.textContent = normalizeText(identity?.installation_id, 80) || "Unavailable";
  if (sessionApprovalToggle) sessionApprovalToggle.checked = status.session_approval_enabled === true;
  renderRemotePermissions(status);
}

sessionApprovalToggle?.addEventListener("change", () => {
  const enabled = sessionApprovalToggle.checked;
  void browser.runtime.sendMessage({ kind: "ui:set-session-approval", enabled })
    .then(() => {
      showSessionApprovalResult(
        enabled
          ? "Session-confirmed approvals are on for form submissions, message or publish actions, and off-site navigation."
          : "Session-confirmed approvals are off. Every sensitive action now waits for approval on this page.",
        "success"
      );
      return refreshStatus();
    })
    .catch((error: unknown) => {
      sessionApprovalToggle.checked = !enabled;
      showSessionApprovalResult(error instanceof Error ? error.message : "The setting could not be changed.", "error");
    });
});

async function refreshStatus(): Promise<void> {
  try {
    const status = await browser.runtime.sendMessage({ kind: "ui:get-status" }) as UiStatus;
    renderStatus(status || {});
  } catch (error) {
    renderStatus({ phase: "error", last_error: error instanceof Error ? error.message : "The extension did not respond." });
  }
}

connectButton?.addEventListener("click", async (event) => {
  if (!event.isTrusted) return;
  connectButton.disabled = true;
  connectButton.textContent = "Opening local helper…";
  showResult("");
  try {
    const response = await browser.runtime.sendMessage({ kind: "ui:native-setup" }) as unknown;
    if (!response || typeof response !== "object" || Array.isArray(response)) {
      throw new Error("The extension returned an invalid setup result.");
    }
    const setup = response as Record<string, unknown>;
    if (setup.ok !== true) {
      throw new Error(typeof setup.message === "string"
        ? normalizeText(setup.message, 320)
        : "BrowseWeave could not complete the local connection.");
    }
    showResult("Connected. The pairing key stayed hidden and this browser is ready for approved local AI clients.", "success");
    await refreshStatus();
  } catch (error) {
    showResult(error instanceof Error ? error.message : "BrowseWeave could not complete the local connection.", "error");
    await refreshStatus();
  } finally {
    connectButton.disabled = false;
  }
});

removeButton?.addEventListener("click", async () => {
  const confirmed = globalThis.confirm("Remove this pairing? Local AI clients cannot reconnect until you connect BrowseWeave again.");
  if (!confirmed) return;
  removeButton.disabled = true;
  try {
    await browser.runtime.sendMessage({ kind: "ui:remove-pairing" });
    showResult("Pairing removed. The browser installation identity remains local to this profile.", "success");
    await refreshStatus();
  } catch (error) {
    showResult(error instanceof Error ? error.message : "The pairing could not be removed.", "error");
  } finally {
    removeButton.disabled = false;
  }
});

browser.runtime.onMessage.addListener((message: unknown) => {
  if (message && typeof message === "object") {
    const kind = (message as Record<string, unknown>).kind;
    if (kind === "bridge:state" || kind === "bridge:credentials" || kind === "bridge:session-approval") void refreshStatus();
  }
  return undefined;
});

void refreshStatus();
