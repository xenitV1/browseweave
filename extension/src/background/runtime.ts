import {
  BRIDGE_URL,
  MAX_MANAGED_TABS,
  TOKEN_STORAGE_KEY,
  approvalGuardDecision,
  approvalFingerprint,
  captureImageDimensions,
  classifyRisk,
  diffSnapshots,
  externalNavigationRisk,
  maskUntrustedApprovalDescription,
  mutationIntervalMs,
  normalizeNavigationUrl,
  normalizePagination,
  normalizeScreenshotOptions,
  normalizeSnapshotOptions,
  normalizeText,
  normalizeViewportState,
  normalizeWaitOptions,
  redactUrl,
  sameViewportState,
  type ViewportState
} from "../shared/pure";
import {
  BASE64URL_PATTERN,
  BROWSER_ACTIONS,
  PROTOCOL_VERSION,
  SHA256_PATTERN,
  approvalDecisionSigningPayload,
  isApprovalFingerprint,
  isBrowserAction,
  isJsonObject,
  isJsonValue,
  type ApprovalDecision,
  type ApprovalSource,
  type BrowserAction,
  type BrowserIdentity,
  type ExtensionApprovalRequest,
  type JsonObject,
  type P256PublicJwk
} from "../../../src/core/protocol";
import {
  ApprovalGrantLedger,
  MAX_LOCAL_APPROVAL_GRANTS,
  hashCommandParams,
  isLocalApprovalGrant,
  type LocalApprovalGrant
} from "../security/approval-grants";
import { ExtensionHandshake } from "../security/handshake";
import {
  SETUP_PAIRING_TIMEOUT_MS,
  SETUP_TICKET_PATH,
  SetupPairingHandshake,
  parseSetupTicketText,
  setupAuthenticationMatches,
  setupSenderMatches,
  startSetupPairingTransport,
  storedTokenSnapshotHasValue,
  storedTokenSnapshotsEqual,
  type StoredTokenSnapshot
} from "../setup/setup-pairing";
import {
  NATIVE_SETUP_HOST_NAME,
  nativeSetupBeginRequest,
  nativeSetupCancelRequest,
  nativeSetupErrorMessage,
  parseNativeSetupBeginResponse,
  withNativeSetupTimeout,
  type NativeSetupErrorCode,
  type NativeSetupTicket
} from "../setup/native-setup";
import {
  DEFAULT_REMOTE_CREDENTIAL_PERMISSION_MS,
  LOCAL_CREDENTIAL_HANDOFF_TTL_MS,
  credentialGrantTargetMatches,
  normalizeHttpsOrigin,
  scrubCredentialValues,
  validateCredentialCommandPayload,
  type CredentialCommandSpec,
  type CredentialFieldSpec,
  type CredentialFieldView,
  type LocalCredentialHandoff,
  type RemoteCredentialField,
  type RemoteCredentialPermission
} from "../security/credentials";
import {
  BridgeError,
  activeTab,
  extensionAction,
  extensionBrowser,
  sessionStorageArea,
  tabId,
  targetTab,
  windowId,
  type CrossBrowserApi
} from "./environment";
import {
  cleanupManagedTabs,
  createManagedTab,
  isManagedTab,
  managedTabsSummary,
  managedTabCount,
  untrackManagedTab
} from "./managed-tabs";
import {
  consumeLocalCredentialHandoff,
  consumeRemoteCredentialPermission,
  createRemoteCredentialPermission,
  listLocalCredentialHandoffs,
  listRemoteCredentialPermissions,
  randomCredentialId,
  revokeCredentialHandoffsForTab,
  revokeLocalCredentialHandoff,
  revokeRemoteCredentialPermission,
  storeLocalCredentialHandoff
} from "./credential-store";
import { browserIdentity, deviceSigningKey, installationId, signPayload } from "./device-identity";

type ConnectionPhase ="needs_token" | "disconnected" | "connecting" | "authenticating" | "connected" | "error";

interface ConnectionState {
  phase: ConnectionPhase;
  lastError: string;
  connectedAt: string | null;
  reconnectAttempt: number;
}

interface PublicApproval {
  approval_id: string;
  action: BrowserAction;
  risk: string;
  description: string;
  expires_at: string;
  approval_fingerprint: string;
  target_tab_id: number;
  target_frame_id: number;
  target_origin: string;
  target_site: string;
  target_title: string;
  destination_origin: string;
}

interface TrustedApprovalTarget {
  tab_id: number;
  frame_id: number;
  origin: string;
  site: string;
  title: string;
  binding_fingerprint: string;
  destination_origin: string;
}

interface LocalApprovalContext {
  action: BrowserAction;
  target_tab_id: number;
  target_frame_id: number;
  destination_origin: string;
  source_binding_fingerprint: string;
  expires_at: number;
}

interface PendingApproval extends ExtensionApprovalRequest {
  daemon_instance_id: string;
  received_at: string;
  safe_description: string;
  trusted_target: TrustedApprovalTarget;
}

interface HumanInterventionState {
  tab_id: number;
  origin: string;
  kind: "captcha" | "challenge" | "webauthn" | "http_403" | "http_429";
  message: string;
  pause_origin: boolean;
  detected_at: string;
}

interface CommandMessage {
  type: "command";
  id: string;
  action: string;
  payload: Record<string, unknown>;
  approved: boolean;
  approval_id?: string;
  approval_fingerprint?: string;
  approval_source?: ApprovalSource;
  revalidate_only?: boolean;
}

interface ExtensionErrorPayload {
  code: string;
  message: string;
  category?: string;
  approval_fingerprint?: string;
  target_tab_id?: number;
  target_frame_id?: number;
  details?: Record<string, unknown>;
}

interface ContentReply {
  ok: boolean;
  result?: unknown;
  error?: ExtensionErrorPayload;
}

const COMMAND_ACTIONS = new Set([
  ...BROWSER_ACTIONS
]);

const CONTENT_ACTIONS = new Set(["snapshot", "click", "click_at", "type", "fill_form", "hover", "press", "scroll", "wait"]);
const MAX_INCOMING_MESSAGE_BYTES = 2 * 1024 * 1024;
const DEFAULT_SNAPSHOT_CHARS = 12_000;
const MAX_SNAPSHOT_CACHE_ENTRIES = 6;
const SNAPSHOT_FRAME_CONCURRENCY = 6;
const MAX_SCREENSHOT_DATA_URL_CHARS = 12 * 1024 * 1024;
const MAX_SCREENSHOT_CACHE_ENTRIES = 8;
const SCREENSHOT_TTL_MS = 120_000;
const AUTHENTICATION_TIMEOUT_MS = 10_000;
/** Upper bound on any computed pacing interval, independent of its source. */
const MAX_MUTATION_INTERVAL_MS = 5_000;
/** How long a tab keeps the conservative pacing after a detected challenge. */
const MUTATION_STRESS_WINDOW_MS = 60_000;
const SESSION_APPROVAL_STORAGE_KEY = "browseweave_session_approval_v1";
/** Comfortably longer than the daemon's approval TTL, so a replay always lands inside it. */
const SESSION_APPROVAL_REPLAY_WINDOW_MS = 15 * 60_000;
const SESSION_STATE_STORAGE_KEY = "browseweave_session_state_v2";
const LOCAL_APPROVAL_GRANTS_SESSION_KEY = "browseweave_local_approval_grants_v2";

interface SnapshotCacheEntry {
  tabId: number;
  signature: string;
  snapshot: Record<string, unknown>;
}

const snapshotCache = new Map<string, SnapshotCacheEntry>();

interface ScreenshotCacheEntry {
  tabId: number;
  imageWidth: number;
  imageHeight: number;
  viewport: ViewportState;
  expiresAt: number;
}

const screenshotCache = new Map<string, ScreenshotCacheEntry>();
const pendingApprovals = new Map<string, PendingApproval>();
const localApprovalContexts = new Map<string, LocalApprovalContext>();
const humanInterventions = new Map<number, HumanInterventionState>();
const pausedOrigins = new Map<string, HumanInterventionState["kind"]>();
const mutationQueues = new Map<number, Promise<void>>();
const lastMutationFinishedAt = new Map<number, number>();
const mutationStressUntil = new Map<number, number>();
/** Session-approved IDs already executed, so a replay cannot run twice. */
const consumedSessionApprovals = new Map<string, number>();

const MUTATING_ACTIONS = new Set<BrowserAction>([
  "hover", "click_at", "click", "type", "fill_form", "credential_fill", "press", "scroll",
  "navigate", "back", "forward", "reload", "close_tab", "cleanup_tabs", "activate_tab", "new_tab"
]);
const DOM_GUARDED_ACTIONS = new Set<BrowserAction>([
  "hover", "click_at", "click", "type", "fill_form", "credential_fill", "press", "scroll",
  "navigate", "back", "forward", "reload"
]);
const PAGE_GUARDED_READ_ACTIONS = new Set<BrowserAction>(["snapshot", "screenshot", "credential_handoff_prepare"]);
const APPROVAL_CONTEXT_ACTIONS = new Set<BrowserAction>([
  "click_at", "click", "type", "fill_form", "press", "navigate"
]);

let socket: WebSocket | null = null;
let authenticated = false;
let reconnectTimer: ReturnType<typeof globalThis.setTimeout> | undefined;
let authenticationTimer: ReturnType<typeof globalThis.setTimeout> | undefined;
let connectionGeneration = 0;
let daemonInstanceId = "";
let browserId = "";
let currentIdentity: BrowserIdentity | null = null;
let connectionHandshake: ExtensionHandshake | null = null;
let sessionStateLoaded = false;
let sessionWriteQueue: Promise<void> = Promise.resolve();
let localApprovalGrantsLoaded = false;
let localApprovalGrantsLock: Promise<void> = Promise.resolve();
let localApprovalGrants = new ApprovalGrantLedger();
let setupPairingInProgress = false;
let nativeSetupLaunchInProgress = false;
let state: ConnectionState = {
  phase: "disconnected",
  lastError: "",
  connectedAt: null,
  reconnectAttempt: 0
};

function validSnapshotCacheEntry(value: unknown): value is SnapshotCacheEntry {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return typeof record.tabId === "number" && Number.isInteger(record.tabId) &&
    typeof record.signature === "string" && record.signature.length <= 2_000 &&
    !!record.snapshot && typeof record.snapshot === "object" && !Array.isArray(record.snapshot);
}

function validScreenshotCacheEntry(value: unknown): value is ScreenshotCacheEntry {
  if (!value || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  if (
    typeof record.tabId !== "number" || !Number.isInteger(record.tabId) ||
    typeof record.imageWidth !== "number" || !Number.isFinite(record.imageWidth) || record.imageWidth <= 0 ||
    typeof record.imageHeight !== "number" || !Number.isFinite(record.imageHeight) || record.imageHeight <= 0 ||
    typeof record.expiresAt !== "number" || !Number.isFinite(record.expiresAt)
  ) return false;
  try {
    normalizeViewportState(record.viewport);
    return true;
  } catch {
    return false;
  }
}

async function ensureSessionStateLoaded(): Promise<void> {
  if (sessionStateLoaded) return;
  sessionStateLoaded = true;
  const area = sessionStorageArea();
  if (!area) return;
  try {
    const stored = await area.get(SESSION_STATE_STORAGE_KEY);
    const value = stored[SESSION_STATE_STORAGE_KEY];
    if (!value || typeof value !== "object" || Array.isArray(value)) return;
    const record = value as Record<string, unknown>;
    if (Array.isArray(record.snapshots)) {
      for (const item of record.snapshots.slice(-MAX_SNAPSHOT_CACHE_ENTRIES)) {
        if (!Array.isArray(item) || typeof item[0] !== "string" || !validSnapshotCacheEntry(item[1])) continue;
        snapshotCache.set(item[0], item[1]);
      }
    }
    if (Array.isArray(record.screenshots)) {
      for (const item of record.screenshots.slice(-MAX_SCREENSHOT_CACHE_ENTRIES)) {
        if (!Array.isArray(item) || typeof item[0] !== "string" || !validScreenshotCacheEntry(item[1])) continue;
        if (item[1].expiresAt > Date.now()) screenshotCache.set(item[0], item[1]);
      }
    }
    if (Array.isArray(record.human_interventions)) {
      for (const item of record.human_interventions.slice(-20)) {
        if (!item || typeof item !== "object" || Array.isArray(item)) continue;
        const entry = item as Record<string, unknown>;
        if (
          typeof entry.tab_id !== "number" || !Number.isInteger(entry.tab_id) ||
          typeof entry.origin !== "string" || !/^https?:\/\//u.test(entry.origin) ||
          !["captcha", "challenge", "webauthn", "http_403", "http_429"].includes(String(entry.kind)) ||
          typeof entry.message !== "string" || typeof entry.pause_origin !== "boolean" ||
          typeof entry.detected_at !== "string"
        ) continue;
        const intervention = entry as unknown as HumanInterventionState;
        humanInterventions.set(intervention.tab_id, intervention);
        if (intervention.pause_origin) pausedOrigins.set(intervention.origin, intervention.kind);
      }
    }
  } catch {
    // Session storage is an optimization; never weaken the bridge if it is unavailable.
  }
}

function persistSessionState(): Promise<void> {
  const area = sessionStorageArea();
  if (!area) return Promise.resolve();
  const sessionValue = {
    snapshots: [...snapshotCache.entries()],
    screenshots: [...screenshotCache.entries()],
    approvals: [...pendingApprovals.values()],
    human_interventions: [...humanInterventions.values()]
  };
  sessionWriteQueue = sessionWriteQueue
    .catch(() => undefined)
    .then(async () => {
      await area.set({ [SESSION_STATE_STORAGE_KEY]: sessionValue });
    })
    .catch(() => undefined);
  return sessionWriteQueue;
}

function approvalGrantStorageError(message: string, cause?: unknown): BridgeError {
  return new BridgeError(
    "approval_grant_storage_unavailable",
    message,
    undefined,
    cause === undefined ? undefined : { cause: cause instanceof Error ? cause.message : String(cause) }
  );
}

async function withLocalApprovalGrantsLock<T>(operation: () => Promise<T>): Promise<T> {
  const previous = localApprovalGrantsLock;
  let release: (() => void) | undefined;
  localApprovalGrantsLock = new Promise<void>((resolve) => {
    release = resolve;
  });
  await previous.catch(() => undefined);
  try {
    return await operation();
  } finally {
    release?.();
  }
}

async function persistLocalApprovalGrantsUnlocked(): Promise<void> {
  const area = sessionStorageArea();
  if (!area) throw approvalGrantStorageError("Trusted session storage for local approvals is unavailable.");
  try {
    await area.set({
      [LOCAL_APPROVAL_GRANTS_SESSION_KEY]: {
        version: 2,
        grants: localApprovalGrants.snapshot()
      }
    });
  } catch (error) {
    throw approvalGrantStorageError("BrowseWeave could not persist the local one-time approval grant.", error);
  }
}

async function ensureLocalApprovalGrantsLoadedUnlocked(): Promise<void> {
  if (localApprovalGrantsLoaded) return;
  const area = sessionStorageArea();
  if (!area) throw approvalGrantStorageError("Trusted session storage for local approvals is unavailable.");
  let stored: Record<string, unknown>;
  try {
    stored = await area.get(LOCAL_APPROVAL_GRANTS_SESSION_KEY);
  } catch (error) {
    throw approvalGrantStorageError("BrowseWeave could not read its local approval grants.", error);
  }
  const value = stored[LOCAL_APPROVAL_GRANTS_SESSION_KEY];
  if (value === undefined) {
    localApprovalGrantsLoaded = true;
    return;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw approvalGrantStorageError("The local approval-grant ledger failed integrity checks.");
  }
  const record = value as Record<string, unknown>;
  const rawGrants = record.grants;
  if (
    record.version !== 2 || !Array.isArray(rawGrants) || rawGrants.length > MAX_LOCAL_APPROVAL_GRANTS ||
    rawGrants.some((grant) => !isLocalApprovalGrant(grant))
  ) {
    throw approvalGrantStorageError("The local approval-grant ledger failed integrity checks.");
  }
  try {
    localApprovalGrants = new ApprovalGrantLedger(rawGrants as LocalApprovalGrant[]);
  } catch (error) {
    throw approvalGrantStorageError("The local approval-grant ledger failed integrity checks.", error);
  }
  localApprovalGrantsLoaded = true;
  if (localApprovalGrants.prune()) await persistLocalApprovalGrantsUnlocked();
}

async function saveLocalApprovalGrant(approval: PendingApproval): Promise<void> {
  await withLocalApprovalGrantsLock(async () => {
    await ensureLocalApprovalGrantsLoadedUnlocked();
    const grant: LocalApprovalGrant = {
      approval_id: approval.approval_id,
      daemon_instance_id: approval.daemon_instance_id,
      browser_id: approval.browser_id,
      target_tab_id: approval.target_tab_id,
      target_frame_id: approval.target_frame_id,
      action: approval.action,
      params_sha256: approval.params_sha256,
      approval_fingerprint: approval.approval_fingerprint,
      expires_at: approval.expires_at,
      decision: "approve"
    };
    localApprovalGrants.add(grant);
    try {
      await persistLocalApprovalGrantsUnlocked();
    } catch (error) {
      localApprovalGrants.revoke(grant.approval_id);
      throw error;
    }
  });
}

async function revokeLocalApprovalGrant(approvalId: string): Promise<void> {
  await withLocalApprovalGrantsLock(async () => {
    await ensureLocalApprovalGrantsLoadedUnlocked();
    if (!localApprovalGrants.revoke(approvalId)) return;
    await persistLocalApprovalGrantsUnlocked();
  });
}

async function revokeLocalApprovalGrantsForDaemon(disconnectedDaemonInstanceId: string): Promise<void> {
  if (!disconnectedDaemonInstanceId) return;
  await withLocalApprovalGrantsLock(async () => {
    await ensureLocalApprovalGrantsLoadedUnlocked();
    if (localApprovalGrants.revokeForDaemon(disconnectedDaemonInstanceId) === 0) return;
    await persistLocalApprovalGrantsUnlocked();
  });
}

async function revokeLocalApprovalGrantsForTarget(targetTabId: number, targetFrameId?: number): Promise<void> {
  await withLocalApprovalGrantsLock(async () => {
    await ensureLocalApprovalGrantsLoadedUnlocked();
    if (localApprovalGrants.revokeForTarget(targetTabId, targetFrameId) === 0) return;
    await persistLocalApprovalGrantsUnlocked();
  });
}

/**
 * The browser owner's opt-in for session-confirmed approvals. It lives in
 * extension storage and is writable only from the trusted settings page, so the
 * daemon alone can never enable this weaker authority. Absent means off.
 */
async function sessionApprovalEnabled(): Promise<boolean> {
  try {
    const stored = await extensionBrowser.storage.local.get(SESSION_APPROVAL_STORAGE_KEY);
    return stored[SESSION_APPROVAL_STORAGE_KEY] === true;
  } catch {
    return false;
  }
}

/**
 * Second gate for a session-confirmed command, independent of the content
 * script's live risk check. Fails closed on a disabled toggle or a replayed ID.
 */
async function consumeSessionApproval(approvalId: string): Promise<void> {
  if (!await sessionApprovalEnabled()) {
    throw new BridgeError(
      "session_approval_disabled",
      "Session-confirmed approval is turned off in BrowseWeave settings. Approve this action in the extension instead."
    );
  }
  const now = Date.now();
  for (const [id, expiresAt] of consumedSessionApprovals) {
    if (expiresAt <= now) consumedSessionApprovals.delete(id);
  }
  if (consumedSessionApprovals.has(approvalId)) {
    throw new BridgeError(
      "session_approval_replayed",
      "That session confirmation was already used. Request the action again."
    );
  }
  consumedSessionApprovals.set(approvalId, now + SESSION_APPROVAL_REPLAY_WINDOW_MS);
}

async function consumeLocalApprovalGrant(
  approvalId: string,
  action: BrowserAction,
  payload: JsonObject,
  approvalFingerprintValue: string,
  targetTabIdValue: number,
  targetFrameIdValue: number
): Promise<void> {
  const paramsSha256 = await hashCommandParams(payload);
  await withLocalApprovalGrantsLock(async () => {
    await ensureLocalApprovalGrantsLoadedUnlocked();
    const result = localApprovalGrants.consume({
      approvalId,
      daemonInstanceId,
      browserId,
      targetTabId: targetTabIdValue,
      targetFrameId: targetFrameIdValue,
      action,
      paramsSha256,
      approvalFingerprint: approvalFingerprintValue
    });
    if (result.mutated) await persistLocalApprovalGrantsUnlocked();
    if (result.ok) return;
    const messages: Record<typeof result.code, string> = {
      approval_grant_missing: "No extension-owned human approval grant exists for this command, or it was already consumed.",
      approval_grant_expired: "The extension-owned human approval grant expired before execution.",
      approval_grant_mismatch: "The approved command does not match the one-time grant created by the BrowseWeave popup."
    };
    throw new BridgeError(result.code, messages[result.code]);
  });
}

interface CredentialBindingReply {
  origin: string;
  document_epoch: string;
  binding_fingerprint: string;
  fields: CredentialFieldView[];
  submit: boolean;
}

function parseCredentialBindingReply(
  value: unknown,
  expectedFields: CredentialFieldSpec[],
  expectedSubmit: boolean
): CredentialBindingReply {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new BridgeError("invalid_credential_binding", "The page returned an invalid credential binding.");
  }
  const record = value as Record<string, unknown>;
  let exactOrigin: string;
  try {
    exactOrigin = normalizeHttpsOrigin(record.origin);
  } catch (error) {
    throw new BridgeError("credential_https_required", error instanceof Error ? error.message : "Credentials require HTTPS.");
  }
  if (
    exactOrigin !== record.origin || typeof record.document_epoch !== "string" ||
    record.document_epoch.length < 8 || record.document_epoch.length > 128 ||
    typeof record.binding_fingerprint !== "string" || !isApprovalFingerprint(record.binding_fingerprint) ||
    record.submit !== expectedSubmit || !Array.isArray(record.fields) || record.fields.length !== expectedFields.length
  ) {
    throw new BridgeError("invalid_credential_binding", "The page returned an invalid credential binding.");
  }
  const fields: CredentialFieldView[] = record.fields.map((rawField, index) => {
    const expected = expectedFields[index];
    if (!expected || !rawField || typeof rawField !== "object" || Array.isArray(rawField)) {
      throw new BridgeError("invalid_credential_binding", "The page credential fields do not match the request.");
    }
    const field = rawField as Record<string, unknown>;
    if (field.ref !== expected.ref || field.kind !== expected.kind || typeof field.label !== "string" || field.label.length > 120) {
      throw new BridgeError("invalid_credential_binding", "The page credential fields do not match the request.");
    }
    return { ref: expected.ref, kind: expected.kind, label: normalizeText(field.label, 120) };
  });
  return {
    origin: exactOrigin,
    document_epoch: record.document_epoch,
    binding_fingerprint: record.binding_fingerprint,
    fields,
    submit: expectedSubmit
  };
}

function publicState(): Record<string, unknown> {
  return {
    phase: state.phase,
    connected: state.phase === "connected" && authenticated,
    last_error: state.lastError,
    connected_at: state.connectedAt,
    reconnect_attempt: state.reconnectAttempt,
    endpoint: "127.0.0.1:32110",
    protocol_version: PROTOCOL_VERSION,
    browser_id: browserId || null,
    identity: currentIdentity,
    pending_approvals: pendingApprovals.size,
    managed_tab_count: managedTabCount(),
    managed_tab_limit: MAX_MANAGED_TABS,
    requires_human: humanInterventions.size > 0,
    human_interventions: [...humanInterventions.values()]
  };
}

async function updateBadge(): Promise<void> {
  if (!extensionAction) return;
  const badge = pendingApprovals.size > 0
    ? { text: pendingApprovals.size > 99 ? "99+" : String(pendingApprovals.size), color: "#b54708" }
    : humanInterventions.size > 0
      ? { text: "H!", color: "#b42318" }
    : state.phase === "connected"
    ? { text: "ON", color: "#248a55" }
    : state.phase === "connecting" || state.phase === "authenticating"
      ? { text: "…", color: "#a56b12" }
      : state.phase === "needs_token"
        ? { text: "KEY", color: "#805ad5" }
        : { text: "!", color: "#b83246" };
  await extensionAction.setBadgeBackgroundColor({ color: badge.color }).catch(() => undefined);
  await extensionAction.setBadgeText({ text: badge.text }).catch(() => undefined);
  await extensionAction.setTitle({
    title: pendingApprovals.size > 0
      ? `${pendingApprovals.size} BrowseWeave approval${pendingApprovals.size === 1 ? "" : "s"} waiting`
      : humanInterventions.size > 0
        ? "BrowseWeave is paused for direct user action"
      : state.phase === "connected" ? "BrowseWeave is connected" : "BrowseWeave is waiting for the local bridge"
  }).catch(() => undefined);
}

function setState(patch: Partial<ConnectionState>): void {
  state = { ...state, ...patch };
  void updateBadge();
  void extensionBrowser.runtime.sendMessage({ kind: "bridge:state", state: publicState() }).catch(() => undefined);
}

function notifyApprovalState(): void {
  void updateBadge();
  void persistSessionState();
  void extensionBrowser.runtime.sendMessage({ kind: "bridge:approvals", pending: pendingApprovals.size }).catch(() => undefined);
}

function notifyHumanState(): void {
  void updateBadge();
  void persistSessionState();
  void extensionBrowser.runtime.sendMessage({ kind: "bridge:human-state", state: publicState() }).catch(() => undefined);
}

function clearReconnectTimer(): void {
  if (reconnectTimer !== undefined) {
    clearTimeout(reconnectTimer);
    reconnectTimer = undefined;
  }
}

function clearConnectionTimers(): void {
  clearReconnectTimer();
  if (authenticationTimer !== undefined) {
    globalThis.clearTimeout(authenticationTimer);
    authenticationTimer = undefined;
  }
}

async function storedToken(): Promise<string> {
  const stored = await extensionBrowser.storage.local.get(TOKEN_STORAGE_KEY);
  const value = stored[TOKEN_STORAGE_KEY];
  return typeof value === "string" ? value.trim() : "";
}

async function storedTokenSnapshot(): Promise<StoredTokenSnapshot> {
  const stored = await extensionBrowser.storage.local.get(TOKEN_STORAGE_KEY);
  return Object.prototype.hasOwnProperty.call(stored, TOKEN_STORAGE_KEY)
    ? { present: true, value: stored[TOKEN_STORAGE_KEY] }
    : { present: false };
}

async function restoreStoredToken(snapshot: StoredTokenSnapshot): Promise<void> {
  if (snapshot.present) {
    await extensionBrowser.storage.local.set({ [TOKEN_STORAGE_KEY]: snapshot.value });
  } else {
    await extensionBrowser.storage.local.remove(TOKEN_STORAGE_KEY);
  }
}

async function restoreStoredTokenIfCurrent(
  snapshot: StoredTokenSnapshot,
  expectedCurrentValue: string
): Promise<boolean> {
  const current = await storedTokenSnapshot();
  if (!storedTokenSnapshotHasValue(current, expectedCurrentValue)) return false;
  await restoreStoredToken(snapshot);
  return true;
}

function scheduleReconnect(generation: number): void {
  if (generation !== connectionGeneration) return;
  clearReconnectTimer();
  const nextAttempt = state.reconnectAttempt + 1;
  const delay = Math.min(30_000, 750 * (2 ** Math.min(nextAttempt - 1, 6))) + Math.floor(Math.random() * 250);
  setState({ reconnectAttempt: nextAttempt, phase: "disconnected" });
  reconnectTimer = globalThis.setTimeout(() => {
    reconnectTimer = undefined;
    void connect();
  }, delay);
}

function clearPendingApprovals(): void {
  const changed = pendingApprovals.size > 0;
  pendingApprovals.clear();
  localApprovalContexts.clear();
  if (changed) notifyApprovalState();
}

function closeCurrentSocket(): void {
  const disconnectedDaemonInstanceId = daemonInstanceId;
  authenticated = false;
  daemonInstanceId = "";
  browserId = "";
  currentIdentity = null;
  connectionHandshake = null;
  if (disconnectedDaemonInstanceId) {
    void revokeLocalApprovalGrantsForDaemon(disconnectedDaemonInstanceId).catch(() => undefined);
  }
  clearConnectionTimers();
  if (socket) {
    const oldSocket = socket;
    socket = null;
    oldSocket.onopen = null;
    oldSocket.onmessage = null;
    oldSocket.onerror = null;
    oldSocket.onclose = null;
    try {
      oldSocket.close(1000, "reconnect");
    } catch {
      // The socket may already be closing.
    }
  }
}

async function connect(staged?: {
  pairingToken: string;
  installationId: string;
  setupId: string;
  setupPhase: "provisioning" | "persisted";
}, ordinaryOverride?: { pairingToken: string; installationId: string }): Promise<void> {
  const generation = ++connectionGeneration;
  await ensureSessionStateLoaded();
  closeCurrentSocket();
  clearPendingApprovals();

  const token = staged?.pairingToken ?? ordinaryOverride?.pairingToken ?? await storedToken();
  if (generation !== connectionGeneration) return;
  if (token.length < 16) {
    setState({ phase: "needs_token", lastError: "A pairing key has not been configured.", connectedAt: null });
    return;
  }

  setState({ phase: "connecting", lastError: "", connectedAt: null });
  let identity: BrowserIdentity;
  let publicKey: P256PublicJwk;
  try {
    [identity, { publicKey }] = await Promise.all([browserIdentity(), deviceSigningKey()]);
  } catch (error) {
    if (generation === connectionGeneration) {
      setState({
        phase: "error",
        lastError: error instanceof Error ? error.message : "BrowseWeave could not prepare its browser identity."
      });
    }
    return;
  }
  if (generation !== connectionGeneration) return;
  const expectedInstallationId = staged?.installationId ?? ordinaryOverride?.installationId;
  if (expectedInstallationId !== undefined && identity.installation_id !== expectedInstallationId) {
    setState({
      phase: "error",
      lastError: "The browser installation identity changed during local setup.",
      connectedAt: null
    });
    return;
  }
  const nextHandshake = new ExtensionHandshake({
    origin: extensionBrowser.runtime.getURL("").replace(/\/$/u, ""),
    identity,
    publicKey,
    ...(staged ? { stagedSetupId: staged.setupId, stagedSetupPhase: staged.setupPhase } : {})
  });
  const nextSocket = new WebSocket(BRIDGE_URL);
  socket = nextSocket;
  connectionHandshake = nextHandshake;
  currentIdentity = identity;

  nextSocket.onopen = () => {
    if (
      generation !== connectionGeneration || socket !== nextSocket ||
      connectionHandshake !== nextHandshake
    ) return;
    setState({ phase: "authenticating", lastError: "" });
    authenticationTimer = globalThis.setTimeout(() => {
      if (generation === connectionGeneration && socket === nextSocket && !authenticated) {
        nextSocket.close(1008, "authentication timeout");
      }
    }, AUTHENTICATION_TIMEOUT_MS);
    try {
      nextSocket.send(JSON.stringify(nextHandshake.createClientHello()));
    } catch {
      nextSocket.close(1008, "client hello failed");
    }
  };

  nextSocket.onmessage = (event) => {
    if (generation !== connectionGeneration || socket !== nextSocket) return;
    void handleSocketMessage(event.data, nextSocket, generation, token, nextHandshake);
  };

  nextSocket.onerror = () => {
    if (generation !== connectionGeneration || socket !== nextSocket) return;
    setState({ phase: "error", lastError: "BrowseWeave could not reach the local bridge." });
  };

  nextSocket.onclose = (event) => {
    if (generation !== connectionGeneration || socket !== nextSocket) return;
    const disconnectedDaemonInstanceId = daemonInstanceId;
    socket = null;
    authenticated = false;
    daemonInstanceId = "";
    browserId = "";
    currentIdentity = null;
    connectionHandshake = null;
    if (disconnectedDaemonInstanceId) {
      void revokeLocalApprovalGrantsForDaemon(disconnectedDaemonInstanceId).catch(() => undefined);
    }
    clearConnectionTimers();
    clearPendingApprovals();
    const reason = event.code === 1008
      ? "The pairing key or browser identity was rejected."
      : "The local bridge connection closed.";
    setState({ phase: event.code === 1008 ? "error" : "disconnected", lastError: reason, connectedAt: null });
    scheduleReconnect(generation);
  };
}

async function loadSetupTicket(
  setupId: string,
  signal: AbortSignal
): Promise<{ setupSecret: string; expiresAt: number }> {
  const ticketUrl = extensionBrowser.runtime.getURL(SETUP_TICKET_PATH);
  const response = await globalThis.fetch(ticketUrl, {
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
    signal
  });
  if (!response.ok || response.redirected || response.url !== ticketUrl) {
    throw new Error("The local setup ticket is unavailable.");
  }
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && (!/^\d{1,4}$/u.test(contentLength) || Number(contentLength) > 512)) {
    throw new Error("The local setup ticket is invalid.");
  }
  const ticket = parseSetupTicketText(await response.text(), setupId);
  return { setupSecret: ticket.setup_secret, expiresAt: Date.parse(ticket.expires_at) };
}

async function waitForSetupAuthentication(input: {
  generation: number;
  installationId: string;
  deadline: number;
  cancelled: () => boolean;
}): Promise<void> {
  while (!input.cancelled() && Date.now() < input.deadline) {
    if (connectionGeneration !== input.generation) {
      throw new Error("The main browser connection changed during local setup.");
    }
    if (setupAuthenticationMatches({
      expectedGeneration: input.generation,
      currentGeneration: connectionGeneration,
      expectedInstallationId: input.installationId,
      currentInstallationId: currentIdentity?.installation_id,
      authenticated,
      phase: state.phase,
      socketOpen: socket?.readyState === WebSocket.OPEN
    })) return;
    if (state.phase === "error" || state.phase === "needs_token" || state.phase === "disconnected") {
      throw new Error("The main browser connection could not authenticate after local setup.");
    }
    await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 25));
  }
  throw new Error("The main browser connection did not authenticate before local setup expired.");
}

async function receiveSetupPairingToken(
  setupId: string,
  suppliedTicket?: Pick<NativeSetupTicket, "setupSecret" | "expiresAt">
): Promise<{ ok: boolean }> {
  if (setupPairingInProgress) return { ok: false };
  setupPairingInProgress = true;
  let setupSecret = "";
  let cancelled = false;
  let cancelSetupSocket: (() => void) | undefined;
  const controller = new AbortController();
  const deadline = Date.now() + SETUP_PAIRING_TIMEOUT_MS;
  let timeoutHandle: ReturnType<typeof globalThis.setTimeout> | undefined;
  const priorTokenSnapshot = storedTokenSnapshot();
  let stagedPairingToken = "";
  let mainConnectionDisturbed = false;
  let tokenCommit: Promise<void> | undefined;
  let durableCommitAttempted = false;
  let rollbackOperation: Promise<void> | undefined;
  const rollback = (): Promise<void> => {
    rollbackOperation ??= (async () => {
      const prior = await priorTokenSnapshot;
      if (tokenCommit && !durableCommitAttempted) {
        await tokenCommit.catch(() => undefined);
        await restoreStoredTokenIfCurrent(prior, stagedPairingToken);
      }
      if (mainConnectionDisturbed) await connect();
    })();
    return rollbackOperation;
  };
  try {
    const operation = (async (): Promise<{ ok: boolean }> => {
      await priorTokenSnapshot;
      if (cancelled || Date.now() >= deadline) throw new Error("The local setup attempt expired.");
      const ticket = suppliedTicket ?? await loadSetupTicket(setupId, controller.signal);
      if (cancelled || Date.now() >= deadline) throw new Error("The local setup attempt expired.");
      setupSecret = ticket.setupSecret;
      const [identity, { publicKey }] = await Promise.all([browserIdentity(), deviceSigningKey()]);
      if (cancelled || Date.now() >= deadline || Date.now() >= ticket.expiresAt) {
        throw new Error("The local setup attempt expired.");
      }
      const handshake = new SetupPairingHandshake({
        setupId,
        setupSecret,
        origin: extensionBrowser.runtime.getURL("").replace(/\/$/u, ""),
        identity,
        publicKey
      }, { timeoutMs: Math.max(1, deadline - Date.now()) });
      const setupTransport = startSetupPairingTransport({
        createSocket: () => new WebSocket(BRIDGE_URL),
        createRequest: () => handshake.createRequest(),
        acceptResponse: (response) => handshake.acceptResponse(response),
        cancelAuthentication: () => handshake.cancel(),
        cancelled: () => cancelled,
        openReadyState: WebSocket.OPEN
      });
      cancelSetupSocket = setupTransport.cancel;
      const pairingToken = await setupTransport.result;
      cancelSetupSocket = undefined;
      setupSecret = "";
      stagedPairingToken = pairingToken;
      if (cancelled || Date.now() >= deadline) throw new Error("The local setup attempt expired.");
      mainConnectionDisturbed = true;
      await connect({
        pairingToken,
        installationId: identity.installation_id,
        setupId,
        setupPhase: "provisioning"
      });
      let setupConnectionGeneration = connectionGeneration;
      await waitForSetupAuthentication({
        generation: setupConnectionGeneration,
        installationId: identity.installation_id,
        deadline: Math.min(deadline, ticket.expiresAt),
        cancelled: () => cancelled
      });
      if (cancelled || Date.now() >= deadline) throw new Error("The local setup attempt expired.");
      const preCommitSnapshot = await priorTokenSnapshot;
      if (!storedTokenSnapshotsEqual(await storedTokenSnapshot(), preCommitSnapshot)) {
        throw new Error("The local pairing changed during setup.");
      }
      tokenCommit = extensionBrowser.storage.local.set({ [TOKEN_STORAGE_KEY]: pairingToken });
      await tokenCommit;
      const persistedPairingToken = await storedToken();
      if (cancelled || persistedPairingToken !== pairingToken) {
        throw new Error("The local setup attempt expired.");
      }
      durableCommitAttempted = true;
      const authenticationDeadline = Math.min(deadline, ticket.expiresAt);
      const waitForCurrentAttempt = async (): Promise<void> => {
        setupConnectionGeneration = connectionGeneration;
        await waitForSetupAuthentication({
          generation: setupConnectionGeneration,
          installationId: identity.installation_id,
          deadline: authenticationDeadline,
          cancelled: () => cancelled
        });
      };
      let newTokenAuthenticated = false;
      for (let attempt = 0; attempt < 3; attempt += 1) {
        if (cancelled || Date.now() >= authenticationDeadline) break;
        try {
          await connect({
            pairingToken: persistedPairingToken,
            installationId: identity.installation_id,
            setupId,
            setupPhase: "persisted"
          });
          await waitForCurrentAttempt();
          return { ok: true };
        } catch {
          // A lost hello acknowledgement is indistinguishable from a lost commit request.
        }
        if (cancelled || Date.now() >= authenticationDeadline) break;
        try {
          await connect(undefined, {
            pairingToken: persistedPairingToken,
            installationId: identity.installation_id
          });
          await waitForCurrentAttempt();
          newTokenAuthenticated = true;
        } catch {
          // If the daemon did not commit, the setup-bound persisted attempt remains retryable.
        }
      }
      const prior = await priorTokenSnapshot;
      const priorPairingToken = prior.present && typeof prior.value === "string"
        ? prior.value.trim()
        : "";
      if (
        !newTokenAuthenticated && !cancelled &&
        Date.now() < authenticationDeadline && priorPairingToken.length >= 16
      ) {
        try {
          await connect(undefined, {
            pairingToken: priorPairingToken,
            installationId: identity.installation_id
          });
          await waitForCurrentAttempt();
          await restoreStoredTokenIfCurrent(prior, persistedPairingToken);
        } catch {
          // Without positive legacy-authentication proof, retaining the new token is safer.
        }
      }
      throw new Error("The durable local setup commit could not be reconciled.");
    })().catch(async () => {
      await rollback().catch(() => undefined);
      return { ok: false };
    });

    const timeout = new Promise<"timeout">((resolve) => {
      timeoutHandle = globalThis.setTimeout(() => {
        cancelled = true;
        controller.abort();
        cancelSetupSocket?.();
        resolve("timeout");
      }, SETUP_PAIRING_TIMEOUT_MS);
    });
    const result = await Promise.race([operation, timeout]);
    if (result === "timeout") {
      await rollback().catch(() => undefined);
      return { ok: false };
    }
    return result;
  } finally {
    cancelled = true;
    controller.abort();
    cancelSetupSocket?.();
    if (timeoutHandle !== undefined) globalThis.clearTimeout(timeoutHandle);
    setupSecret = "";
    setupPairingInProgress = false;
  }
}

interface NativeSetupUiResult {
  ok: boolean;
  error_code?: NativeSetupErrorCode;
  message?: string;
}

function nativeSetupFailure(errorCode: NativeSetupErrorCode): NativeSetupUiResult {
  return {
    ok: false,
    error_code: errorCode,
    message: nativeSetupErrorMessage(errorCode)
  };
}

async function cancelNativeSetup(setupId: string): Promise<void> {
  try {
    await withNativeSetupTimeout(
      extensionBrowser.runtime.sendNativeMessage(
        NATIVE_SETUP_HOST_NAME,
        nativeSetupCancelRequest(setupId)
      ),
      5_000
    );
  } catch {
    // Setup sessions expire quickly. Cancellation is best-effort cleanup only.
  }
}

async function startNativeSetup(): Promise<NativeSetupUiResult> {
  if (nativeSetupLaunchInProgress || setupPairingInProgress) {
    return {
      ok: false,
      error_code: "operation_failed",
      message: "A BrowseWeave connection attempt is already in progress."
    };
  }
  nativeSetupLaunchInProgress = true;
  let setupId = "";
  let ticket: NativeSetupTicket | undefined;
  try {
    const identity = await browserIdentity();
    let response: unknown;
    try {
      response = await withNativeSetupTimeout(
        extensionBrowser.runtime.sendNativeMessage(
          NATIVE_SETUP_HOST_NAME,
          nativeSetupBeginRequest(identity.browser_family)
        )
      );
    } catch {
      return nativeSetupFailure("helper_unavailable");
    }
    const parsed = parseNativeSetupBeginResponse(response, identity.browser_family);
    response = undefined;
    if ("errorCode" in parsed) return nativeSetupFailure(parsed.errorCode);
    ticket = parsed;
    setupId = ticket.setupId;
    const paired = await receiveSetupPairingToken(setupId, {
      setupSecret: ticket.setupSecret,
      expiresAt: ticket.expiresAt
    });
    return paired.ok ? { ok: true } : nativeSetupFailure("operation_failed");
  } catch {
    return nativeSetupFailure("internal_error");
  } finally {
    ticket = undefined;
    if (setupId) await cancelNativeSetup(setupId);
    nativeSetupLaunchInProgress = false;
  }
}

async function sendSignedHello(
  handshake: ExtensionHandshake,
  currentSocket: WebSocket,
  generation: number
): Promise<void> {
  const signature = await signPayload(handshake.helloSigningPayload());
  if (
    generation !== connectionGeneration || socket !== currentSocket ||
    connectionHandshake !== handshake || currentSocket.readyState !== WebSocket.OPEN
  ) return;
  const hello = handshake.createHello(signature);
  daemonInstanceId = handshake.daemonInstanceId();
  currentSocket.send(JSON.stringify(hello));
}

function publicApproval(approval: PendingApproval): PublicApproval {
  return {
    approval_id: approval.approval_id,
    action: approval.action,
    risk: normalizeText(approval.risk, 80) || "sensitive_action",
    description: approval.safe_description,
    expires_at: approval.expires_at,
    approval_fingerprint: approval.approval_fingerprint,
    target_tab_id: approval.target_tab_id,
    target_frame_id: approval.target_frame_id,
    target_origin: approval.trusted_target.origin,
    target_site: approval.trusted_target.site,
    target_title: approval.trusted_target.title,
    destination_origin: approval.trusted_target.destination_origin
  };
}

function pruneApprovals(now = Date.now()): void {
  let changed = false;
  for (const [approvalId, approval] of pendingApprovals) {
    if (Date.parse(approval.expires_at) <= now) {
      pendingApprovals.delete(approvalId);
      changed = true;
    }
  }
  if (changed) notifyApprovalState();
}

async function invalidateApprovalTarget(tabIdValue: number, frameIdValue?: number): Promise<void> {
  let changed = false;
  for (const [approvalId, approval] of pendingApprovals) {
    if (approval.target_tab_id !== tabIdValue) continue;
    if (frameIdValue !== undefined && approval.target_frame_id !== frameIdValue) continue;
    pendingApprovals.delete(approvalId);
    changed = true;
  }
  for (const [fingerprint, context] of localApprovalContexts) {
    if (context.target_tab_id !== tabIdValue) continue;
    if (frameIdValue !== undefined && context.target_frame_id !== frameIdValue) continue;
    localApprovalContexts.delete(fingerprint);
  }
  await revokeLocalApprovalGrantsForTarget(tabIdValue, frameIdValue).catch(() => undefined);
  if (changed) notifyApprovalState();
}

type ParsedApprovalRequest = Omit<PendingApproval, "trusted_target">;

function parseApprovalRequest(record: Record<string, unknown>): ParsedApprovalRequest | null {
  if (
    record.type !== "approval_request" ||
    typeof record.approval_id !== "string" || !/^[A-Za-z0-9_-]{1,256}$/u.test(record.approval_id) ||
    typeof record.approval_nonce !== "string" || record.approval_nonce.length < 16 ||
      record.approval_nonce.length > 512 || !BASE64URL_PATTERN.test(record.approval_nonce) ||
    typeof record.browser_id !== "string" || record.browser_id !== browserId ||
    typeof record.target_tab_id !== "number" || !Number.isSafeInteger(record.target_tab_id) || record.target_tab_id <= 0 ||
    typeof record.target_frame_id !== "number" || !Number.isSafeInteger(record.target_frame_id) || record.target_frame_id < 0 ||
    !isBrowserAction(record.action) ||
    typeof record.risk !== "string" || record.risk.length > 160 ||
    typeof record.description !== "string" || record.description.length > 4_000 ||
    typeof record.params_sha256 !== "string" || !SHA256_PATTERN.test(record.params_sha256) ||
    !isApprovalFingerprint(record.approval_fingerprint) ||
    typeof record.expires_at !== "string"
  ) return null;
  const expiresAt = Date.parse(record.expires_at);
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now() || expiresAt > Date.now() + 30 * 60_000) return null;
  const safeDescription = maskUntrustedApprovalDescription(record.description);
  return {
    type: "approval_request",
    approval_id: record.approval_id,
    approval_nonce: record.approval_nonce,
    browser_id: record.browser_id,
    target_tab_id: record.target_tab_id,
    target_frame_id: record.target_frame_id,
    action: record.action,
    risk: normalizeText(record.risk, 160),
    description: safeDescription,
    params_sha256: record.params_sha256,
    approval_fingerprint: record.approval_fingerprint,
    expires_at: record.expires_at,
    daemon_instance_id: daemonInstanceId,
    received_at: new Date().toISOString(),
    safe_description: safeDescription
  };
}

async function trustedApprovalTarget(approval: ParsedApprovalRequest): Promise<TrustedApprovalTarget> {
  let tab: browser.tabs.Tab;
  try {
    tab = await extensionBrowser.tabs.get(approval.target_tab_id);
  } catch {
    throw new Error("The approval target tab no longer exists.");
  }
  if (tabId(tab) !== approval.target_tab_id) throw new Error("The approval target tab changed.");
  const rawProbe = await sendContentCommand(tab, approval.target_frame_id, "approval_target_probe", {
    approval_fingerprint: approval.approval_fingerprint,
    require_risk_binding: approval.action !== "navigate"
  }, false);
  if (!rawProbe || typeof rawProbe !== "object" || Array.isArray(rawProbe)) {
    throw new Error("The approval target document could not be verified.");
  }
  const probe = rawProbe as Record<string, unknown>;
  if (
    typeof probe.origin !== "string" || !/^https?:\/\//u.test(probe.origin) ||
    typeof probe.document_epoch !== "string" || probe.document_epoch.length < 8 || probe.document_epoch.length > 128 ||
    typeof probe.binding_fingerprint !== "string" || !isApprovalFingerprint(probe.binding_fingerprint)
  ) throw new Error("The approval target document returned an invalid binding.");
  const parsedOrigin = new URL(probe.origin);
  if (parsedOrigin.origin !== probe.origin) throw new Error("The approval target origin is invalid.");
  const probedDestination = probe.destination_origin === "" ? "" : exactWebOrigin(probe.destination_origin);
  if (probe.destination_origin !== "" && !probedDestination) {
    throw new Error("The approval destination origin is invalid.");
  }
  const localContext = localApprovalContexts.get(approval.approval_fingerprint);
  const localContextMatches = Boolean(
    localContext && localContext.expires_at > Date.now() && localContext.action === approval.action &&
    localContext.target_tab_id === approval.target_tab_id && localContext.target_frame_id === approval.target_frame_id
  );
  if (
    approval.action === "navigate" && (
      !localContextMatches || !localContext?.source_binding_fingerprint ||
      localContext.source_binding_fingerprint !== probe.binding_fingerprint
    )
  ) throw new Error("The navigation source document changed before approval.");
  const destinationOrigin = probedDestination || (
    localContextMatches && localContext
      ? localContext.destination_origin
      : ""
  );
  return {
    tab_id: approval.target_tab_id,
    frame_id: approval.target_frame_id,
    origin: parsedOrigin.origin,
    site: `${parsedOrigin.protocol}//${parsedOrigin.host}`,
    title: normalizeText(tab.title || "Untitled tab", 120),
    binding_fingerprint: probe.binding_fingerprint,
    destination_origin: destinationOrigin
  };
}

async function receiveApprovalRequest(record: Record<string, unknown>, currentSocket: WebSocket): Promise<void> {
  const approval = parseApprovalRequest(record);
  if (!approval || pendingApprovals.size >= 100 || pendingApprovals.has(approval?.approval_id || "")) {
    currentSocket.close(1008, "invalid approval request");
    return;
  }
  let trustedTarget: TrustedApprovalTarget;
  try {
    trustedTarget = await trustedApprovalTarget(approval);
  } catch {
    currentSocket.close(1008, "invalid approval target");
    return;
  }
  const localContext = localApprovalContexts.get(approval.approval_fingerprint);
  if (
    localContext && localContext.expires_at > Date.now() && localContext.action === approval.action &&
    localContext.target_tab_id === approval.target_tab_id && localContext.target_frame_id === approval.target_frame_id
  ) {
    if (!trustedTarget.destination_origin) trustedTarget.destination_origin = localContext.destination_origin;
  }
  if (approval.risk === "external_navigation" && !trustedTarget.destination_origin) {
    currentSocket.close(1008, "missing trusted approval destination");
    return;
  }
  if (!authenticated || socket !== currentSocket || currentSocket.readyState !== WebSocket.OPEN) return;
  pendingApprovals.set(approval.approval_id, { ...approval, trusted_target: trustedTarget });
  notifyApprovalState();
}

function receiveApprovalResolution(record: Record<string, unknown>, currentSocket: WebSocket): void {
  const outcomes = new Set(["approved", "rejected", "consumed", "cancelled", "expired"]);
  if (
    typeof record.approval_id !== "string" || !/^[A-Za-z0-9_-]{1,256}$/u.test(record.approval_id) ||
    typeof record.outcome !== "string" || !outcomes.has(record.outcome)
  ) {
    currentSocket.close(1008, "invalid approval resolution");
    return;
  }
  if (pendingApprovals.delete(record.approval_id)) notifyApprovalState();
  if (record.outcome !== "approved") {
    void revokeLocalApprovalGrant(record.approval_id).catch(() => undefined);
  }
}

async function handleSocketMessage(
  rawData: unknown,
  currentSocket: WebSocket,
  generation: number,
  pairingSecret: string,
  handshake: ExtensionHandshake
): Promise<void> {
  if (typeof rawData !== "string" || rawData.length > MAX_INCOMING_MESSAGE_BYTES) {
    currentSocket.close(1009, "invalid message");
    return;
  }
  let message: unknown;
  try {
    message = JSON.parse(rawData);
  } catch {
    currentSocket.close(1007, "invalid json");
    return;
  }
  if (!message || typeof message !== "object") {
    currentSocket.close(1007, "invalid message");
    return;
  }
  const record = message as Record<string, unknown>;
  if (record.type === "challenge") {
    try {
      if (authenticated || connectionHandshake !== handshake) {
        throw new Error("The daemon challenge is out of order.");
      }
      await handshake.verifyChallenge(record, pairingSecret);
      await sendSignedHello(handshake, currentSocket, generation);
    } catch (error) {
      setState({
        phase: "error",
        lastError: error instanceof Error ? error.message : "BrowseWeave could not authenticate the local service."
      });
      currentSocket.close(1008, "mutual authentication failed");
    }
    return;
  }
  if (record.type === "hello_ack") {
    let acceptedBrowserId: string;
    try {
      if (authenticated || !daemonInstanceId || connectionHandshake !== handshake) {
        throw new Error("The daemon acknowledgement is out of order.");
      }
      acceptedBrowserId = handshake.acceptHelloAck(record);
    } catch {
      setState({ phase: "error", lastError: "The local bridge protocol or browser identity is incompatible." });
      currentSocket.close(1002, "protocol mismatch");
      return;
    }
    if (authenticationTimer !== undefined) {
      globalThis.clearTimeout(authenticationTimer);
      authenticationTimer = undefined;
    }
    browserId = acceptedBrowserId;
    authenticated = true;
    setState({ phase: "connected", lastError: "", connectedAt: new Date().toISOString(), reconnectAttempt: 0 });
    return;
  }
  if (record.type === "ping") {
    if (!authenticated || typeof record.timestamp !== "number" || !Number.isFinite(record.timestamp)) {
      currentSocket.close(1008, "invalid ping");
      return;
    }
    currentSocket.send(JSON.stringify({ type: "pong", timestamp: record.timestamp }));
    return;
  }
  if (record.type === "approval_request") {
    if (!authenticated) {
      currentSocket.close(1008, "not authenticated");
      return;
    }
    await receiveApprovalRequest(record, currentSocket);
    return;
  }
  if (record.type === "approval_resolved") {
    if (!authenticated) {
      currentSocket.close(1008, "not authenticated");
      return;
    }
    receiveApprovalResolution(record, currentSocket);
    return;
  }
  if (record.type !== "command") {
    currentSocket.close(1002, "unexpected message");
    return;
  }
  if (!authenticated) {
    currentSocket.close(1008, "not authenticated");
    return;
  }
  await handleCommand(record as unknown as CommandMessage, currentSocket, generation);
}

async function decideApproval(approvalId: string, decision: ApprovalDecision): Promise<{ ok: true }> {
  pruneApprovals();
  const approval = pendingApprovals.get(approvalId);
  if (!approval) throw new Error("This approval is no longer pending.");
  if (
    !authenticated || !socket || socket.readyState !== WebSocket.OPEN ||
    !daemonInstanceId || approval.daemon_instance_id !== daemonInstanceId ||
    !browserId || approval.browser_id !== browserId
  ) throw new Error("The local bridge connection changed. Request a new approval.");

  const sameTrustedTarget = (candidate: TrustedApprovalTarget): boolean => (
    candidate.tab_id === approval.trusted_target.tab_id &&
    candidate.frame_id === approval.trusted_target.frame_id &&
    candidate.origin === approval.trusted_target.origin &&
    candidate.binding_fingerprint === approval.trusted_target.binding_fingerprint &&
    candidate.destination_origin === approval.trusted_target.destination_origin
  );
  if (decision === "approve" && !sameTrustedTarget(await trustedApprovalTarget(approval))) {
    throw new Error("The target tab, origin, or document changed. Review the page and request a new approval.");
  }

  const decisionPayload = approvalDecisionSigningPayload({
    daemonInstanceId,
    approvalId: approval.approval_id,
    approvalNonce: approval.approval_nonce,
    browserId: approval.browser_id,
    targetTabId: approval.target_tab_id,
    targetFrameId: approval.target_frame_id,
    decision,
    action: approval.action,
    paramsSha256: approval.params_sha256,
    approvalFingerprint: approval.approval_fingerprint,
    expiresAt: approval.expires_at
  });
  const signature = await signPayload(decisionPayload);
  const currentSocket = socket;
  if (decision === "approve" && !sameTrustedTarget(await trustedApprovalTarget(approval))) {
    throw new Error("The target changed while the approval was being signed. Request a new approval.");
  }
  if (
    pendingApprovals.get(approvalId) !== approval || socket !== currentSocket ||
    currentSocket.readyState !== WebSocket.OPEN || Date.parse(approval.expires_at) <= Date.now()
  ) throw new Error("This approval expired before the decision could be sent.");
  let localGrantSaved = false;
  if (decision === "approve") {
    await saveLocalApprovalGrant(approval);
    localGrantSaved = true;
  }
  try {
    if (
      pendingApprovals.get(approvalId) !== approval || socket !== currentSocket ||
      currentSocket.readyState !== WebSocket.OPEN || !authenticated ||
      daemonInstanceId !== approval.daemon_instance_id || browserId !== approval.browser_id ||
      Date.parse(approval.expires_at) <= Date.now()
    ) throw new Error("The connection changed before the approval decision could be sent.");
    currentSocket.send(JSON.stringify({
      type: "approval_decision",
      approval_id: approval.approval_id,
      decision,
      signature
    }));
  } catch (error) {
    if (localGrantSaved) await revokeLocalApprovalGrant(approval.approval_id).catch(() => undefined);
    throw error;
  }
  pendingApprovals.delete(approvalId);
  notifyApprovalState();
  return { ok: true };
}

function serializeError(error: unknown): ExtensionErrorPayload {
  if (error instanceof BridgeError) {
    const payload: ExtensionErrorPayload = { code: error.code, message: error.message };
    if (error.category) payload.category = error.category;
    if (error.approvalFingerprint) payload.approval_fingerprint = error.approvalFingerprint;
    if (error.targetTabId !== undefined) payload.target_tab_id = error.targetTabId;
    if (error.targetFrameId !== undefined) payload.target_frame_id = error.targetFrameId;
    if (error.details) payload.details = error.details;
    return payload;
  }
  return {
    code: "extension_error",
    message: error instanceof Error ? error.message : "The browser extension could not complete the action."
  };
}

function exactWebOrigin(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) return "";
  try {
    const parsed = new URL(value);
    return (parsed.protocol === "https:" || parsed.protocol === "http:") && parsed.origin === value
      ? parsed.origin
      : "";
  } catch {
    return "";
  }
}

function rememberLocalApprovalContext(action: BrowserAction, error: unknown): void {
  if (
    !(error instanceof BridgeError) || error.code !== "approval_required" ||
    !error.approvalFingerprint || error.targetTabId === undefined || error.targetFrameId === undefined
  ) return;
  const now = Date.now();
  for (const [fingerprint, context] of localApprovalContexts) {
    if (context.expires_at <= now) localApprovalContexts.delete(fingerprint);
  }
  localApprovalContexts.set(error.approvalFingerprint, {
    action,
    target_tab_id: error.targetTabId,
    target_frame_id: error.targetFrameId,
    destination_origin: exactWebOrigin(error.details?.destination_origin),
    source_binding_fingerprint: isApprovalFingerprint(error.localTargetBinding) ? error.localTargetBinding : "",
    expires_at: now + 30 * 60_000
  });
}

async function handleCommand(command: CommandMessage, currentSocket: WebSocket, generation: number): Promise<void> {
  if (
    typeof command.id !== "string" || command.id.length < 1 || command.id.length > 128 ||
    typeof command.action !== "string" ||
    !isJsonObject(command.payload) || !isJsonValue(command.payload) ||
    typeof command.approved !== "boolean" ||
    typeof command.revalidate_only !== "boolean" ||
    (command.approved === true && (
      command.revalidate_only ||
      typeof command.approval_id !== "string" || !/^[A-Za-z0-9_-]{1,256}$/u.test(command.approval_id) ||
      !isApprovalFingerprint(command.approval_fingerprint)
    )) ||
    (command.approved !== true && (
      command.approval_id !== undefined || command.approval_fingerprint !== undefined
    ))
  ) {
    if (command.action === "credential_fill") scrubCredentialValues(command.payload);
    currentSocket.close(1007, "invalid command");
    return;
  }
  let response: Record<string, unknown>;
  try {
    if (!isBrowserAction(command.action) || !COMMAND_ACTIONS.has(command.action)) {
      throw new BridgeError("unsupported_action", `Unsupported browser action: ${command.action}`);
    }
    const suppliedFingerprint = isApprovalFingerprint(command.approval_fingerprint) ? command.approval_fingerprint : "";
    const approvalSource: ApprovalSource = command.approval_source === "session" ? "session" : "extension_signed";
    let executionPayload = command.payload;
    if (command.approved) {
      if (!APPROVAL_CONTEXT_ACTIONS.has(command.action)) {
        throw new BridgeError("approval_context_changed", "This action cannot consume a page-bound approval grant.");
      }
      const target = await targetTab(command.payload);
      const targetTabId = tabId(target);
      const targetFrameId = command.action === "click_at" || command.action === "navigate"
        ? 0
        : frameIdFrom(command.payload);
      if (approvalSource === "session") {
        // No extension-signed grant exists for this authority, so the owner's
        // opt-in and replay ledger stand in its place. The content script
        // independently rejects any risk class that is not session-approvable.
        await consumeSessionApproval(command.approval_id as string);
      } else {
        await consumeLocalApprovalGrant(
          command.approval_id as string,
          command.action,
          command.payload as JsonObject,
          suppliedFingerprint,
          targetTabId,
          targetFrameId
        );
      }
      // Lock an omitted active-tab target to the exact tab whose grant was
      // consumed. A later focus change cannot redirect the approved action.
      executionPayload = { ...command.payload, tab_id: targetTabId };
    }
    const result = await executeCommandWithGuards(
      command.action,
      executionPayload,
      command.approved,
      suppliedFingerprint,
      command.revalidate_only,
      approvalSource
    );
    response = { type: "result", id: command.id, ok: true, result: result ?? null };
  } catch (error) {
    if (isBrowserAction(command.action)) rememberLocalApprovalContext(command.action, error);
    response = { type: "result", id: command.id, ok: false, error: serializeError(error) };
  }
  if (command.action === "credential_fill") scrubCredentialValues(command.payload);
  if (generation === connectionGeneration && socket === currentSocket && currentSocket.readyState === WebSocket.OPEN) {
    currentSocket.send(JSON.stringify(response));
  }
}

async function injectContentScript(tab: browser.tabs.Tab): Promise<void> {
  try {
    if (extensionBrowser.runtime.getManifest().manifest_version === 3 && extensionBrowser.scripting?.executeScript) {
      await extensionBrowser.scripting.executeScript({
        target: { tabId: tabId(tab), allFrames: true },
        files: ["content.js"]
      });
    } else {
      await extensionBrowser.tabs.executeScript(tabId(tab), {
        file: "content.js",
        allFrames: true,
        matchAboutBlank: true,
        runAt: "document_idle"
      });
    }
  } catch (error) {
    throw new BridgeError(
      "page_not_controllable",
      "This page cannot be controlled by a browser extension. Open or reload a normal HTTP or HTTPS page.",
      undefined,
      { cause: error instanceof Error ? error.message : String(error) }
    );
  }
}

async function sendContentCommand(
  tab: browser.tabs.Tab,
  frameId: number,
  action: string,
  payload: Record<string, unknown>,
  approved: boolean,
  suppliedFingerprint = "",
  revalidateOnly = false,
  retry = true,
  approvalSource: ApprovalSource = "extension_signed"
): Promise<unknown> {
  try {
    const reply = await extensionBrowser.tabs.sendMessage(tabId(tab), {
      kind: "bridge:content-command",
      action,
      payload,
      approved,
      approval_fingerprint: suppliedFingerprint,
      approval_source: approvalSource,
      revalidate_only: revalidateOnly,
      approval_context: { tab_id: tabId(tab), frame_id: frameId }
    }, { frameId }) as ContentReply;
    if (!reply || typeof reply.ok !== "boolean") {
      throw new BridgeError("invalid_content_response", "The page controller returned an invalid response.");
    }
    if (!reply.ok) {
      const error = reply.error || { code: "page_action_failed", message: "The page action could not be completed." };
      throw new BridgeError(
        error.code,
        error.message,
        error.category,
        error.details,
        error.approval_fingerprint,
        error.code === "approval_required" ? tabId(tab) : undefined,
        error.code === "approval_required" ? frameId : undefined
      );
    }
    return reply.result ?? null;
  } catch (error) {
    if (error instanceof BridgeError && error.code !== "invalid_content_response") throw error;
    if (retry) {
      await injectContentScript(tab);
      return sendContentCommand(
        tab, frameId, action, payload, approved, suppliedFingerprint, revalidateOnly, false, approvalSource
      );
    }
    if (error instanceof BridgeError) throw error;
    throw new BridgeError(
      "page_not_controllable",
      "This page cannot be accessed. Browser-internal, extension, store, and some protected pages cannot be controlled.",
      undefined,
      { cause: error instanceof Error ? error.message : String(error) }
    );
  }
}

function frameIdFrom(payload: Record<string, unknown>): number {
  return typeof payload.frame_id === "number" && Number.isInteger(payload.frame_id) && payload.frame_id >= 0
    ? payload.frame_id
    : 0;
}

interface HumanProbeResult {
  requires_human: boolean;
  kind?: HumanInterventionState["kind"];
  message?: string;
  pause_origin?: boolean;
}

function tabOrigin(tab: browser.tabs.Tab): string {
  try {
    const url = new URL(tab.url || "");
    return url.protocol === "http:" || url.protocol === "https:" ? url.origin : "";
  } catch {
    return "";
  }
}

function humanRequiredError(intervention: HumanInterventionState): BridgeError {
  return new BridgeError(
    "requires_human",
    intervention.message,
    "human_verification",
    {
      tab_id: intervention.tab_id,
      origin: intervention.origin,
      kind: intervention.kind,
      paused_origin: intervention.pause_origin,
      next_step: "Complete or review this step directly in the browser, then use Check again in the BrowseWeave popup."
    }
  );
}

function rememberHumanIntervention(tab: browser.tabs.Tab, probe: HumanProbeResult): HumanInterventionState {
  const origin = tabOrigin(tab);
  const intervention: HumanInterventionState = {
    tab_id: tabId(tab),
    origin,
    kind: probe.kind ?? "challenge",
    message: normalizeText(probe.message, 320) || "This page requires direct user action in the browser.",
    pause_origin: probe.pause_origin === true,
    detected_at: new Date().toISOString()
  };
  humanInterventions.set(intervention.tab_id, intervention);
  // A detected challenge, 403, or 429 is the site asking for less traffic, so
  // the tab keeps the conservative pacing even after the human resumes it.
  mutationStressUntil.set(intervention.tab_id, Date.now() + MUTATION_STRESS_WINDOW_MS);
  if (intervention.pause_origin && origin) pausedOrigins.set(origin, intervention.kind);
  notifyHumanState();
  return intervention;
}

function tabIsStressed(tabIdValue: number): boolean {
  const until = mutationStressUntil.get(tabIdValue);
  if (until === undefined) return false;
  if (until > Date.now()) return true;
  mutationStressUntil.delete(tabIdValue);
  return false;
}

async function safetyProbe(tab: browser.tabs.Tab): Promise<HumanProbeResult> {
  const raw = await sendContentCommand(tab, 0, "safety_probe", {}, false);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { requires_human: false };
  const record = raw as Record<string, unknown>;
  if (record.requires_human !== true) return { requires_human: false };
  const kind = ["captcha", "challenge", "webauthn", "http_403", "http_429"].includes(String(record.kind))
    ? record.kind as HumanInterventionState["kind"]
    : "challenge";
  return {
    requires_human: true,
    kind,
    message: typeof record.message === "string" ? record.message : "This page requires direct user action in the browser.",
    pause_origin: record.pause_origin === true || kind === "http_403" || kind === "http_429"
  };
}

async function guardHumanIntervention(tab: browser.tabs.Tab): Promise<void> {
  const existing = humanInterventions.get(tabId(tab));
  if (existing) throw humanRequiredError(existing);
  const origin = tabOrigin(tab);
  const pausedKind = origin ? pausedOrigins.get(origin) : undefined;
  if (pausedKind) {
    const paused: HumanInterventionState = {
      tab_id: tabId(tab),
      origin,
      kind: pausedKind,
      message: "Automated actions for this origin remain paused after a visible 403 or 429 response.",
      pause_origin: true,
      detected_at: new Date().toISOString()
    };
    humanInterventions.set(paused.tab_id, paused);
    notifyHumanState();
    throw humanRequiredError(paused);
  }
  const probe = await safetyProbe(tab);
  if (probe.requires_human) throw humanRequiredError(rememberHumanIntervention(tab, probe));
}

async function runSerializedMutation<T>(
  tabIdValue: number,
  intervalMs: number,
  operation: () => Promise<T>
): Promise<T> {
  const previous = mutationQueues.get(tabIdValue) ?? Promise.resolve();
  let tail: Promise<void>;
  const result = previous.catch(() => undefined).then(async () => {
    const elapsed = Date.now() - (lastMutationFinishedAt.get(tabIdValue) ?? 0);
    const remaining = Math.min(MAX_MUTATION_INTERVAL_MS, Math.max(0, intervalMs)) - elapsed;
    if (remaining > 0) await new Promise((resolve) => globalThis.setTimeout(resolve, remaining));
    try {
      return await operation();
    } finally {
      lastMutationFinishedAt.set(tabIdValue, Date.now());
    }
  });
  tail = result.then(() => undefined, () => undefined);
  mutationQueues.set(tabIdValue, tail);
  try {
    return await result;
  } finally {
    if (mutationQueues.get(tabIdValue) === tail) mutationQueues.delete(tabIdValue);
  }
}

async function executeCommandWithGuards(
  action: BrowserAction,
  payload: Record<string, unknown>,
  approved: boolean,
  suppliedFingerprint: string,
  revalidateOnly: boolean,
  approvalSource: ApprovalSource = "extension_signed"
): Promise<unknown> {
  if ((approved || revalidateOnly) && !APPROVAL_CONTEXT_ACTIONS.has(action)) {
    throw new BridgeError(
      revalidateOnly ? "approval_no_longer_required" : "approval_context_changed",
      revalidateOnly
        ? "This action has no live approval context to revalidate. Nothing was executed."
        : "The approved risk context does not match this action. Nothing was executed."
    );
  }
  if (!MUTATING_ACTIONS.has(action)) {
    if (PAGE_GUARDED_READ_ACTIONS.has(action)) {
      const tab = await targetTab(payload);
      if (tabOrigin(tab)) await guardHumanIntervention(tab);
      return executeCommand(action, { ...payload, tab_id: tabId(tab) }, approved, suppliedFingerprint, revalidateOnly, approvalSource);
    }
    return executeCommand(action, payload, approved, suppliedFingerprint, revalidateOnly, approvalSource);
  }

  if (action === "cleanup_tabs") {
    return executeCommand(action, payload, approved, suppliedFingerprint, revalidateOnly, approvalSource);
  }

  let tab: browser.tabs.Tab | undefined;
  try {
    tab = await targetTab(payload);
  } catch (error) {
    if (action !== "new_tab") throw error;
  }
  const queueId = tab ? tabId(tab) : -1;
  const lockedPayload = tab && action !== "new_tab" ? { ...payload, tab_id: tabId(tab) } : payload;
  const interval = mutationIntervalMs({ action, key: payload.key, stressed: tabIsStressed(queueId) });
  return runSerializedMutation(queueId, interval, async () => {
    if (tab && DOM_GUARDED_ACTIONS.has(action) && tabOrigin(tab)) await guardHumanIntervention(tab);
    // There is intentionally no automatic retry here. The caller receives the first result.
    return executeCommand(action, lockedPayload, approved, suppliedFingerprint, revalidateOnly, approvalSource);
  });
}

async function resumeHumanIntervention(): Promise<{ ok: true }> {
  const tab = await activeTab();
  const intervention = humanInterventions.get(tabId(tab));
  if (!intervention) {
    const waiting = humanInterventions.values().next().value as HumanInterventionState | undefined;
    if (waiting) throw new Error(`Switch to paused tab ${waiting.tab_id}, complete the browser step, then check again.`);
    return { ok: true };
  }
  const probe = await safetyProbe(tab);
  if (probe.requires_human) throw humanRequiredError(rememberHumanIntervention(tab, probe));
  humanInterventions.delete(tabId(tab));
  if (intervention.origin) pausedOrigins.delete(intervention.origin);
  notifyHumanState();
  return { ok: true };
}

async function readTopViewport(tab: browser.tabs.Tab): Promise<ViewportState> {
  try {
    return normalizeViewportState(await sendContentCommand(tab, 0, "viewport", {}, false));
  } catch (error) {
    if (error instanceof BridgeError) throw error;
    throw new BridgeError("viewport_unavailable", "The visible page area could not be read safely.");
  }
}

function randomScreenshotId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return `shot-${[...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function pruneScreenshots(now = Date.now()): void {
  for (const [id, entry] of screenshotCache) {
    if (entry.expiresAt <= now) screenshotCache.delete(id);
  }
  while (screenshotCache.size > MAX_SCREENSHOT_CACHE_ENTRIES) {
    const oldest = screenshotCache.keys().next().value;
    if (typeof oldest !== "string") break;
    screenshotCache.delete(oldest);
  }
}

async function rememberScreenshot(entry: ScreenshotCacheEntry): Promise<string> {
  await ensureSessionStateLoaded();
  pruneScreenshots();
  let id = randomScreenshotId();
  while (screenshotCache.has(id)) id = randomScreenshotId();
  screenshotCache.set(id, entry);
  pruneScreenshots();
  await persistSessionState();
  return id;
}

function staleScreenshot(message = "The screenshot is unknown, expired, or the page changed. Take a new screenshot."): BridgeError {
  return new BridgeError("stale_screenshot", message);
}

async function securedClickAtPayload(
  tab: browser.tabs.Tab,
  payload: Record<string, unknown>
): Promise<Record<string, unknown>> {
  if (payload.frame_id !== undefined && payload.frame_id !== 0) {
    throw new BridgeError("invalid_frame", "Visual coordinate clicks can only use a top-frame screenshot.");
  }
  await ensureSessionStateLoaded();
  pruneScreenshots();
  const screenshotId = typeof payload.screenshot_id === "string" ? payload.screenshot_id : "";
  const capture = screenshotCache.get(screenshotId);
  if (!capture || capture.expiresAt <= Date.now() || capture.tabId !== tabId(tab)) throw staleScreenshot();
  if (
    payload.screenshot_width !== capture.imageWidth ||
    payload.screenshot_height !== capture.imageHeight
  ) {
    throw staleScreenshot("The screenshot dimensions do not match the capture. Take a new screenshot and use its exact dimensions.");
  }
  let liveViewport: ViewportState;
  try {
    liveViewport = await readTopViewport(tab);
  } catch {
    throw staleScreenshot("The current page view could not be verified. Take a new screenshot.");
  }
  if (!sameViewportState(capture.viewport, liveViewport)) {
    throw staleScreenshot("The page size, document, or scroll position changed after capture. Take a new screenshot.");
  }
  return {
    ...payload,
    frame_id: 0,
    screenshot_id: screenshotId,
    screenshot_width: capture.imageWidth,
    screenshot_height: capture.imageHeight,
    __capture_viewport: capture.viewport,
    __screenshot_expires_at: capture.expiresAt
  };
}

async function createSnapshotId(snapshot: Record<string, unknown>): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(snapshot));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return `s-${[...digest].slice(0, 12).map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

async function rememberSnapshot(id: string, entry: SnapshotCacheEntry): Promise<void> {
  snapshotCache.delete(id);
  snapshotCache.set(id, entry);
  while (snapshotCache.size > MAX_SNAPSHOT_CACHE_ENTRIES) {
    const oldest = snapshotCache.keys().next().value;
    if (typeof oldest !== "string") break;
    snapshotCache.delete(oldest);
  }
  await persistSessionState();
}

/** Runs `worker` over `items` with a bounded number in flight, preserving order. */
async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  worker: (item: T) => Promise<R>
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  const runnerCount = Math.min(Math.max(1, limit), Math.max(1, items.length));
  await Promise.all(Array.from({ length: runnerCount }, async () => {
    for (let index = cursor++; index < items.length; index = cursor++) {
      const item = items[index];
      if (item !== undefined) results[index] = await worker(item);
    }
  }));
  return results;
}

async function snapshot(payload: Record<string, unknown>, approved: boolean): Promise<Record<string, unknown>> {
  await ensureSessionStateLoaded();
  const tab = await targetTab(payload);
  const id = tabId(tab);
  const options = normalizeSnapshotOptions(payload.mode, payload.max_elements, payload.query);
  const maxChars = typeof payload.max_chars === "number" && Number.isFinite(payload.max_chars)
    ? Math.min(30_000, Math.max(2_000, Math.trunc(payload.max_chars)))
    : DEFAULT_SNAPSHOT_CHARS;
  const signature = JSON.stringify({
    mode: options.mode,
    max_elements: options.maxElements,
    query: options.query,
    max_chars: maxChars
  });
  let frames = await extensionBrowser.webNavigation.getAllFrames({ tabId: id }).catch(() => null);
  if (!frames?.length) {
    await injectContentScript(tab);
    frames = await extensionBrowser.webNavigation.getAllFrames({ tabId: id }).catch(() => null);
  }
  const frameList = frames?.length ? frames : [{ frameId: 0, parentFrameId: -1, url: tab.url || "" }];
  const outputFrames: Array<Record<string, unknown>> = [];
  const incompleteFrames: Array<Record<string, unknown>> = [];

  // Reading frames concurrently keeps the cost of an ordinary page with many
  // third-party iframes at the slowest frame rather than their sum. Ordering is
  // preserved because later truncation drops the deepest frames first.
  const frameReads = await mapWithConcurrency(frameList, SNAPSHOT_FRAME_CONCURRENCY, async (frame) => {
    try {
      const frameSnapshot = await sendContentCommand(tab, frame.frameId, "snapshot", {
        mode: options.mode,
        max_elements: options.maxElements,
        query: options.query
      }, approved);
      return { frame, snapshot: frameSnapshot as Record<string, unknown> };
    } catch (error) {
      return { frame, error };
    }
  });
  for (const read of frameReads) {
    if ("snapshot" in read) {
      outputFrames.push({
        frame_id: read.frame.frameId,
        parent_frame_id: read.frame.parentFrameId,
        ...read.snapshot
      });
      continue;
    }
    incompleteFrames.push({
      frame_id: read.frame.frameId,
      url: redactUrl(read.frame.url),
      reason: read.error instanceof Error ? read.error.message : "The frame could not be read."
    });
  }

  const result: Record<string, unknown> = {
    tab_id: id,
    frames: outputFrames,
    incomplete_frames: incompleteFrames,
    truncated: false
  };
  const contentBudget = Math.max(1_500, maxChars - 160);
  while (JSON.stringify(result).length > contentBudget) {
    const candidates = outputFrames
      .filter((frame) => Array.isArray(frame.elements) && (frame.elements as unknown[]).length > 0)
      .sort((left, right) => (right.elements as unknown[]).length - (left.elements as unknown[]).length);
    const largest = candidates[0];
    if (!largest) break;
    const elements = largest.elements as unknown[];
    const nextLength = Math.min(elements.length - 1, Math.floor(elements.length * 0.7));
    largest.elements = elements.slice(0, Math.max(0, nextLength));
    largest.truncated = true;
    result.truncated = true;
  }

  let omittedFrames = 0;
  while (JSON.stringify(result).length > contentBudget && outputFrames.length > 1) {
    outputFrames.pop();
    omittedFrames += 1;
    result.truncated = true;
  }
  if (omittedFrames) result.omitted_frames = omittedFrames;

  if (JSON.stringify(result).length > contentBudget && incompleteFrames.length > 3) {
    result.omitted_incomplete_frames = incompleteFrames.length - 3;
    incompleteFrames.splice(3);
    result.truncated = true;
  }

  if (JSON.stringify(result).length > contentBudget) {
    for (const frame of outputFrames) {
      const page = frame.page;
      if (page && typeof page === "object" && !Array.isArray(page)) {
        const pageRecord = page as Record<string, unknown>;
        pageRecord.headings = Array.isArray(pageRecord.headings) ? pageRecord.headings.slice(0, 3) : [];
        pageRecord.landmarks = Array.isArray(pageRecord.landmarks) ? pageRecord.landmarks.slice(0, 5) : [];
        delete pageRecord.description;
        delete pageRecord.canonical;
      }
      if (typeof frame.url === "string") frame.url = frame.url.slice(0, 512);
      if (typeof frame.title === "string") frame.title = frame.title.slice(0, 160);
    }
    result.truncated = true;
  }

  if (JSON.stringify(result).length > contentBudget) {
    result.frames = [];
    result.incomplete_frames = [];
    result.omitted_frames = frameList.length;
    result.truncated = true;
  }

  const snapshotId = await createSnapshotId(result);
  const sinceId = typeof payload.since_snapshot_id === "string" && /^s-[a-f0-9]{24}$/.test(payload.since_snapshot_id)
    ? payload.since_snapshot_id
    : "";
  const previous = sinceId ? snapshotCache.get(sinceId) : undefined;
  await rememberSnapshot(snapshotId, { tabId: id, signature, snapshot: result });

  if (sinceId === snapshotId) {
    return { tab_id: id, snapshot_id: snapshotId, unchanged: true };
  }

  const fullResult: Record<string, unknown> = { ...result, snapshot_id: snapshotId, unchanged: false };
  if (previous && previous.tabId === id && previous.signature === signature) {
    const deltaResult: Record<string, unknown> = {
      tab_id: id,
      snapshot_id: snapshotId,
      since_snapshot_id: sinceId,
      unchanged: false,
      delta: diffSnapshots(previous.snapshot, result),
      truncated: result.truncated === true
    };
    if (JSON.stringify(deltaResult).length <= maxChars) return deltaResult;
    fullResult.delta_too_large = true;
  } else if (sinceId) {
    fullResult.delta_unavailable = true;
  }
  return fullResult;
}

async function guardNavigationRisk(
  action: "navigate" | "new_tab",
  url: string,
  approved: boolean,
  suppliedFingerprint: string,
  revalidateOnly: boolean,
  context: Record<string, unknown>,
  targetTabIdValue?: number,
  targetFrameIdValue = 0,
  sourceBindingFingerprint = ""
): Promise<void> {
  const navigationRisk = externalNavigationRisk(
    context.current_url,
    url,
    action === "new_tab" ? "new_tab" : "existing_tab"
  );
  const risk = navigationRisk || classifyRisk({ action, url });
  if (!risk) {
    const decision = approvalGuardDecision({ hasRisk: false, approved, revalidateOnly, suppliedFingerprint });
    if (decision === "allow") return;
    throw new BridgeError(
      decision,
      decision === "approval_no_longer_required"
        ? "The navigation no longer requires approval. The previous approval context was invalidated without navigating."
        : "The navigation no longer matches the approved risk context. Nothing was executed."
    );
  }
  if (action === "new_tab" || targetTabIdValue === undefined) {
    throw new BridgeError(
      "approval_target_unavailable",
      "A new external tab has no live document to bind an approval to. Open a blank managed tab first, then navigate that exact tab."
    );
  }
  // Full normalized URLs stay inside the SHA-256 material so two masked query
  // secrets can never share an approval. Only redacted URLs are returned.
  const fingerprint = await approvalFingerprint({ version: 1, action, url, risk, context });
  const decision = approvalGuardDecision({
    hasRisk: true,
    approved,
    revalidateOnly,
    currentFingerprint: fingerprint,
    suppliedFingerprint
  });
  if (decision === "allow") return;
  throw new BridgeError(
    "approval_required",
    revalidateOnly
      ? "The live navigation risk was revalidated without navigating."
      : approved
        ? "The navigation target changed after approval. A new user approval is required."
        : `User approval is required before navigating to this possible ${risk.reason.toLowerCase()} target.`,
    risk.category,
    {
      action,
      url: redactUrl(url),
      ...(navigationRisk ? { destination_origin: navigationRisk.destinationOrigin } : {})
    },
    fingerprint,
    targetTabIdValue,
    targetFrameIdValue,
    sourceBindingFingerprint
  );
}

async function readApprovalDocumentBinding(tab: browser.tabs.Tab, frameIdValue: number): Promise<string> {
  const raw = await sendContentCommand(tab, frameIdValue, "approval_target_probe", {
    approval_fingerprint: "",
    require_risk_binding: false
  }, false);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new BridgeError("approval_context_changed", "The live navigation document could not be bound safely.");
  }
  const binding = (raw as Record<string, unknown>).binding_fingerprint;
  if (typeof binding !== "string" || !isApprovalFingerprint(binding)) {
    throw new BridgeError("approval_context_changed", "The live navigation document returned an invalid binding.");
  }
  return binding;
}

async function prepareLocalCredentialHandoff(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  let command: CredentialCommandSpec<CredentialFieldSpec>;
  try {
    command = validateCredentialCommandPayload(payload, false);
  } catch (error) {
    throw new BridgeError("invalid_credential_request", error instanceof Error ? error.message : "The credential request is invalid.");
  }
  const tab = await targetTab({ tab_id: command.tabId });
  const rawBinding = await sendContentCommand(tab, command.frameId, "credential_prepare", {
    tab_id: command.tabId,
    frame_id: command.frameId,
    fields: command.fields,
    submit: command.submit
  }, false);
  const binding = parseCredentialBindingReply(rawBinding, command.fields, command.submit);
  const createdAt = Date.now();
  const handoff: LocalCredentialHandoff = {
    handoff_id: randomCredentialId("credential"),
    tab_id: command.tabId,
    frame_id: command.frameId,
    origin: binding.origin,
    document_epoch: binding.document_epoch,
    binding_fingerprint: binding.binding_fingerprint,
    fields: binding.fields,
    submit: binding.submit,
    created_at: new Date(createdAt).toISOString(),
    expires_at: new Date(createdAt + LOCAL_CREDENTIAL_HANDOFF_TTL_MS).toISOString()
  };
  await storeLocalCredentialHandoff(handoff);
  return {
    requires_human: true,
    credential_handoff_id: handoff.handoff_id,
    origin: handoff.origin,
    field_kinds: handoff.fields.map((field) => field.kind),
    submit: handoff.submit,
    expires_at: handoff.expires_at,
    next_step: "Open the BrowseWeave extension popup in this browser and complete the trusted local credential handoff."
  };
}

async function fillRemoteCredentials(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  let command: CredentialCommandSpec<RemoteCredentialField>;
  try {
    command = validateCredentialCommandPayload(payload, true);
  } catch (error) {
    throw new BridgeError("invalid_credential_request", error instanceof Error ? error.message : "The credential request is invalid.");
  }
  const tab = await targetTab({ tab_id: command.tabId });
  const fieldSpecs = command.fields.map(({ ref, kind }) => ({ ref, kind }));
  let applyPayload: Record<string, unknown> | undefined;
  try {
    const rawBinding = await sendContentCommand(tab, command.frameId, "credential_prepare", {
      tab_id: command.tabId,
      frame_id: command.frameId,
      fields: fieldSpecs,
      submit: command.submit
    }, false);
    const binding = parseCredentialBindingReply(rawBinding, fieldSpecs, command.submit);
    await consumeRemoteCredentialPermission(binding.origin);
    applyPayload = {
      tab_id: command.tabId,
      frame_id: command.frameId,
      fields: command.fields,
      submit: command.submit,
      origin: binding.origin,
      document_epoch: binding.document_epoch,
      binding_fingerprint: binding.binding_fingerprint
    };
    await sendContentCommand(tab, command.frameId, "credential_apply", applyPayload, false);
    return {
      filled_fields: command.fields.length,
      field_kinds: command.fields.map((field) => field.kind),
      submitted: command.submit,
      permission_consumed: true
    };
  } finally {
    scrubCredentialValues(applyPayload);
    scrubCredentialValues({ fields: command.fields });
  }
}

function localCredentialValues(
  handoff: LocalCredentialHandoff,
  rawFields: unknown
): RemoteCredentialField[] {
  if (!Array.isArray(rawFields) || rawFields.length !== handoff.fields.length) {
    throw new Error("Provide every field requested by this credential handoff.");
  }
  const byKind = new Map<string, string>();
  for (const rawField of rawFields) {
    if (!rawField || typeof rawField !== "object" || Array.isArray(rawField)) {
      throw new Error("A local credential field is invalid.");
    }
    const field = rawField as Record<string, unknown>;
    if (
      Object.keys(field).some((key) => key !== "kind" && key !== "value") ||
      (field.kind !== "username" && field.kind !== "password") ||
      typeof field.value !== "string" || byKind.has(field.kind)
    ) throw new Error("A local credential field is invalid.");
    byKind.set(field.kind, field.value);
  }
  const withRefs = handoff.fields.map((field) => ({
    ref: field.ref,
    kind: field.kind,
    value: byKind.get(field.kind) ?? ""
  }));
  return validateCredentialCommandPayload({
    tab_id: handoff.tab_id,
    frame_id: handoff.frame_id,
    fields: withRefs,
    submit: handoff.submit
  }, true).fields;
}

async function completeLocalCredentialHandoff(handoffId: string, rawFields: unknown): Promise<Record<string, unknown>> {
  const preview = (await listLocalCredentialHandoffs()).find((handoff) => handoff.handoff_id === handoffId);
  if (!preview) throw new BridgeError("credential_handoff_missing", "This local credential handoff is missing, expired, or already used.");
  const fields = localCredentialValues(preview, rawFields);
  let applyPayload: Record<string, unknown> | undefined;
  try {
    // A credential handoff fills and may submit a login form, so it keeps the
    // conservative interval rather than the continuing-interaction one.
    const interval = mutationIntervalMs({
      action: "credential_fill",
      stressed: tabIsStressed(preview.tab_id)
    });
    return await runSerializedMutation(preview.tab_id, interval, async () => {
      const tab = await targetTab({ tab_id: preview.tab_id });
      if (tabOrigin(tab)) await guardHumanIntervention(tab);

      // The one-use handoff is consumed only after every fallible preflight,
      // then immediately applied while this tab's mutation queue is held.
      const handoff = await consumeLocalCredentialHandoff(handoffId);
      if (
        handoff.binding_fingerprint !== preview.binding_fingerprint || handoff.document_epoch !== preview.document_epoch ||
        handoff.origin !== preview.origin
      ) throw new BridgeError("credential_handoff_changed", "The local credential handoff changed before it could be consumed.");
      applyPayload = {
        tab_id: handoff.tab_id,
        frame_id: handoff.frame_id,
        fields,
        submit: handoff.submit,
        origin: handoff.origin,
        document_epoch: handoff.document_epoch,
        binding_fingerprint: handoff.binding_fingerprint
      };
      await sendContentCommand(tab, handoff.frame_id, "credential_apply", applyPayload, false);
      return {
        ok: true,
        filled_fields: fields.length,
        field_kinds: fields.map((field) => field.kind),
        submitted: handoff.submit
      };
    });
  } finally {
    scrubCredentialValues(applyPayload);
    scrubCredentialValues({ fields });
    scrubCredentialValues({ fields: rawFields });
  }
}

async function waitForTabCondition(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  const tab = await targetTab(payload);
  const id = tabId(tab);
  const condition = typeof payload.condition === "string" ? payload.condition : "";
  const options = normalizeWaitOptions(payload.timeout_ms ?? payload.timeout, payload.quiet_ms);
  const expectedUrl = typeof payload.value === "string"
    ? payload.value
    : typeof payload.url_contains === "string" ? payload.url_contains : "";
  if (condition === "url_contains" && !expectedUrl) {
    throw new BridgeError("invalid_wait", "value is required for the url_contains condition.");
  }
  const started = performance.now();
  while (true) {
    let current: browser.tabs.Tab;
    try {
      current = await extensionBrowser.tabs.get(id);
    } catch {
      throw new BridgeError("tab_not_found", "The browser tab being waited on was closed.");
    }
    const matched = condition === "load_complete"
      ? current.status === "complete"
      : condition === "url_contains"
        ? (current.url || "").includes(expectedUrl)
        : false;
    if (matched) {
      return { tab_id: id, condition, matched: true, elapsed_ms: Math.round(performance.now() - started) };
    }
    if (condition !== "load_complete" && condition !== "url_contains") {
      throw new BridgeError("invalid_wait", "Unsupported browser wait condition.");
    }
    const elapsed = performance.now() - started;
    if (elapsed >= options.timeoutMs) throw new BridgeError("wait_timeout", `The wait condition was not met within ${options.timeoutMs} ms.`);
    await new Promise((resolve) => setTimeout(resolve, Math.min(100, options.timeoutMs - elapsed)));
  }
}

async function executeCommand(
  action: BrowserAction,
  payload: Record<string, unknown>,
  approved: boolean,
  suppliedFingerprint: string,
  revalidateOnly: boolean,
  approvalSource: ApprovalSource = "extension_signed"
): Promise<unknown> {
  if (action === "list_tabs") {
    const tabs = await extensionBrowser.tabs.query({});
    const pagination = normalizePagination(payload.limit, payload.offset);
    const page = tabs.slice(pagination.offset, pagination.offset + pagination.limit);
    return {
      tabs: page.map((tab) => ({
        id: tab.id,
        window_id: tab.windowId,
        index: tab.index,
        active: tab.active,
        pinned: tab.pinned,
        audible: tab.audible || false,
        discarded: tab.discarded || false,
        status: tab.status || "unknown",
        title: normalizeText(tab.title || "", 300),
        url: redactUrl(tab.url || "")
      })),
      total: tabs.length,
      offset: pagination.offset,
      limit: pagination.limit,
      has_more: pagination.offset + page.length < tabs.length,
      next_offset: pagination.offset + page.length < tabs.length ? pagination.offset + page.length : null
    };
  }
  if (action === "snapshot") return snapshot(payload, approved);
  if (action === "credential_handoff_prepare") return prepareLocalCredentialHandoff(payload);
  if (action === "credential_fill") return fillRemoteCredentials(payload);
  if (action === "wait" && ["load_complete", "url_contains"].includes(String(payload.condition))) {
    return waitForTabCondition(payload);
  }
  if (action === "click_at") {
    const tab = await targetTab(payload);
    const securedPayload = await securedClickAtPayload(tab, payload);
    return sendContentCommand(
      tab, 0, action, securedPayload, approved, suppliedFingerprint, revalidateOnly, true, approvalSource
    );
  }
  if (CONTENT_ACTIONS.has(action)) {
    const tab = await targetTab(payload);
    return sendContentCommand(
      tab, frameIdFrom(payload), action, payload, approved, suppliedFingerprint, revalidateOnly, true, approvalSource
    );
  }
  if (action === "screenshot") {
    const tab = await targetTab(payload);
    if (!tab.active) {
      throw new BridgeError("tab_not_active", "Activate the tab before taking a screenshot.", undefined, { tab_id: tab.id });
    }
    const options = normalizeScreenshotOptions(payload.format, payload.quality);
    const capture = async (quality: number | null): Promise<string> => extensionBrowser.tabs.captureVisibleTab(
      windowId(tab),
      quality === null ? { format: options.format } : { format: options.format, quality }
    );
    let actualQuality = options.quality;
    let stableCapture: { dataUrl: string; viewport: ViewportState } | undefined;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const current = await extensionBrowser.tabs.get(tabId(tab));
      if (!current.active) {
        throw new BridgeError("tab_not_active", "The tab must remain active while the screenshot is captured.", undefined, { tab_id: tab.id });
      }
      const before = await readTopViewport(tab);
      const dataUrl = await capture(actualQuality);
      const after = await readTopViewport(tab);
      const stillActive = await extensionBrowser.tabs.get(tabId(tab));
      const unchanged = stillActive.active && sameViewportState(before, after);
      if (unchanged && dataUrl.length <= MAX_SCREENSHOT_DATA_URL_CHARS) {
        stableCapture = { dataUrl, viewport: after };
        break;
      }
      if (unchanged && options.format === "png") {
        throw new BridgeError("screenshot_too_large", "The PNG screenshot exceeds the safe transfer limit. Use JPEG.");
      }
      if (attempt === 0) {
        if (options.format === "jpeg") actualQuality = 55;
        continue;
      }
      if (!unchanged) {
        throw new BridgeError("screenshot_changed", "The page size or scroll position changed during capture. Stabilize the page and retry.");
      }
      throw new BridgeError("screenshot_too_large", "The JPEG screenshot exceeds the safe transfer limit even at reduced quality.");
    }
    if (!stableCapture) {
      throw new BridgeError("screenshot_changed", "The page changed during capture. Stabilize it and retry.");
    }
    let dimensions: { width: number; height: number };
    try {
      dimensions = captureImageDimensions(stableCapture.dataUrl);
    } catch {
      throw new BridgeError("screenshot_dimensions_unavailable", "The screenshot dimensions could not be verified. Retry before a visual click.");
    }
    const expiresAt = Date.now() + SCREENSHOT_TTL_MS;
    const screenshotId = await rememberScreenshot({
      tabId: tabId(tab),
      imageWidth: dimensions.width,
      imageHeight: dimensions.height,
      viewport: stableCapture.viewport,
      expiresAt
    });
    return {
      tab_id: tabId(tab),
      screenshot_id: screenshotId,
      expires_at: new Date(expiresAt).toISOString(),
      image_width: dimensions.width,
      image_height: dimensions.height,
      data_url: stableCapture.dataUrl,
      format: options.format,
      quality: actualQuality,
      ...stableCapture.viewport
    };
  }
  if (action === "navigate") {
    const tab = await targetTab(payload);
    const url = normalizeNavigationUrl(payload.url);
    const currentUrl = tab.url || "";
    const sourceBindingFingerprint = await readApprovalDocumentBinding(tab, 0);
    await guardNavigationRisk("navigate", url, approved, suppliedFingerprint, revalidateOnly, {
      tab_id: tabId(tab),
      current_url: currentUrl,
      source_binding_fingerprint: sourceBindingFingerprint
    }, tabId(tab), 0, sourceBindingFingerprint);
    const liveTab = await extensionBrowser.tabs.get(tabId(tab));
    if ((liveTab.url || "") !== currentUrl) {
      throw new BridgeError(
        "approval_context_changed",
        "The browser tab changed while navigation safety was being verified. Nothing was executed."
      );
    }
    const updated = await extensionBrowser.tabs.update(tabId(tab), { url });
    return { tab_id: updated.id, url: redactUrl(updated.url || url) };
  }
  if (action === "back") {
    const tab = await targetTab(payload);
    await extensionBrowser.tabs.goBack(tabId(tab));
    return { tab_id: tabId(tab), navigated: "back" };
  }
  if (action === "forward") {
    const tab = await targetTab(payload);
    await extensionBrowser.tabs.goForward(tabId(tab));
    return { tab_id: tabId(tab), navigated: "forward" };
  }
  if (action === "reload") {
    const tab = await targetTab(payload);
    await extensionBrowser.tabs.reload(tabId(tab), { bypassCache: payload.bypass_cache === true });
    return { tab_id: tabId(tab), reloaded: true };
  }
  if (action === "close_tab") {
    const tab = await targetTab(payload);
    const id = tabId(tab);
    const wasManaged = await isManagedTab(id);
    if (!wasManaged) {
      throw new BridgeError(
        "tab_not_managed",
        "BrowseWeave can close only tabs it created. Close this existing tab manually in the browser."
      );
    }
    await extensionBrowser.tabs.remove(id);
    await untrackManagedTab(id);
    return { tab_id: id, closed: true };
  }
  if (action === "cleanup_tabs") return cleanupManagedTabs(payload.tab_ids);
  if (action === "activate_tab") {
    const tab = await targetTab(payload);
    const updated = await extensionBrowser.tabs.update(tabId(tab), { active: true });
    if (payload.focus_window !== false) await extensionBrowser.windows.update(windowId(tab), { focused: true });
    return { tab_id: updated.id, active: true, window_id: updated.windowId };
  }
  if (action === "new_tab") {
    const url = payload.url === undefined ? "about:blank" : normalizeNavigationUrl(payload.url);
    const active = payload.active !== false;
    const created = await createManagedTab(url, active, () => guardNavigationRisk(
      "new_tab",
      url,
      approved,
      suppliedFingerprint,
      revalidateOnly,
      { active }
    ));
    return {
      tab_id: created.id,
      window_id: created.windowId,
      active: created.active,
      url: redactUrl(created.url || url),
      managed_tab_count: managedTabCount(),
      managed_tab_limit: MAX_MANAGED_TABS
    };
  }
  throw new BridgeError("unsupported_action", `Unsupported browser action: ${action}`);
}

async function uiStatus(): Promise<Record<string, unknown>> {
  const token = await storedToken();
  const identity = currentIdentity ?? await browserIdentity().catch(() => null);
  let managedSummary: { managed_tab_count: number; managed_tab_limit: number } = {
    managed_tab_count: managedTabCount(),
    managed_tab_limit: MAX_MANAGED_TABS
  };
  let managedTabsError = "";
  try {
    managedSummary = await managedTabsSummary();
  } catch (error) {
    managedTabsError = error instanceof Error ? error.message : "Managed-tab ownership is unavailable.";
  }
  let activeAccess: "normal_web" | "restricted" | "unknown" = "unknown";
  let activeOrigin = "";
  let activeTabId: number | null = null;
  try {
    const tab = await activeTab();
    activeTabId = tabId(tab);
    activeAccess = /^https?:/i.test(tab.url || "") ? "normal_web" : "restricted";
    if ((tab.url || "").startsWith("https:")) activeOrigin = normalizeHttpsOrigin(tab.url || "");
  } catch {
    // Leave it unknown.
  }
  let credentialHandoffs: LocalCredentialHandoff[] = [];
  let remoteCredentialPermissionViews: RemoteCredentialPermission[] = [];
  let credentialStateErrorMessage = "";
  try {
    [credentialHandoffs, remoteCredentialPermissionViews] = await Promise.all([
      listLocalCredentialHandoffs(),
      listRemoteCredentialPermissions()
    ]);
  } catch (error) {
    credentialStateErrorMessage = error instanceof Error ? error.message : "Credential state is unavailable.";
  }
  pruneApprovals();
  return {
    ...publicState(),
    ...managedSummary,
    managed_tabs_error: managedTabsError || null,
    identity,
    has_token: token.length >= 16,
    active_tab_access: activeAccess,
    active_tab_id: activeTabId,
    active_origin: activeOrigin || null,
    credential_handoffs: credentialHandoffs,
    remote_credential_permissions: remoteCredentialPermissionViews,
    credential_state_error: credentialStateErrorMessage || null,
    session_approval_enabled: await sessionApprovalEnabled(),
    approvals: [...pendingApprovals.values()]
      .sort((left, right) => Date.parse(left.expires_at) - Date.parse(right.expires_at))
      .map(publicApproval)
  };
}

function trustedSender(sender: browser.runtime.MessageSender, allowedPages: readonly string[]): boolean {
  if (sender.id !== extensionBrowser.runtime.id || typeof sender.url !== "string") return false;
  return allowedPages.some((page) => sender.url === extensionBrowser.runtime.getURL(page));
}

extensionBrowser.runtime.onMessage.addListener((message: unknown, sender) => {
  if (!message || typeof message !== "object") return undefined;
  const record = message as Record<string, unknown>;
  const fromPopup = trustedSender(sender, ["popup.html"]);
  const fromOptions = trustedSender(sender, ["options.html"]);
  if (record.kind === "setup:pair") {
    const setupId = typeof record.setup_id === "string" ? record.setup_id : "";
    if (!setupSenderMatches({
      extensionId: extensionBrowser.runtime.id,
      ...(sender.id === undefined ? {} : { senderId: sender.id }),
      ...(sender.url === undefined ? {} : { senderUrl: sender.url }),
      ...(sender.frameId === undefined ? {} : { frameId: sender.frameId }),
      setupId
    })) {
      return Promise.resolve({ ok: false });
    }
    return receiveSetupPairingToken(setupId);
  }
  if (record.kind === "ui:get-status" && (fromPopup || fromOptions)) return uiStatus();
  if (record.kind === "ui:native-setup") {
    if (!fromOptions) return Promise.reject(new Error("Local setup can be started only from BrowseWeave Settings."));
    return startNativeSetup();
  }
  if (record.kind === "ui:remove-pairing") {
    if (!fromOptions) return Promise.reject(new Error("Pairing can be removed only from BrowseWeave Settings."));
    if (setupPairingInProgress || nativeSetupLaunchInProgress) {
      return Promise.reject(new Error("Wait for the current connection attempt to finish before removing the pairing."));
    }
    return extensionBrowser.storage.local.remove(TOKEN_STORAGE_KEY).then(() => {
      void connect();
      return { ok: true };
    });
  }
  if (record.kind === "ui:reconnect") {
    if (!fromPopup && !fromOptions) return Promise.reject(new Error("Untrusted extension message sender."));
    void connect();
    return Promise.resolve({ ok: true });
  }
  if (record.kind === "ui:decide-approval") {
    if (!fromPopup) return Promise.reject(new Error("Approval decisions are accepted only from the BrowseWeave popup."));
    if (
      typeof record.approval_id !== "string" || !/^[A-Za-z0-9_-]{1,256}$/u.test(record.approval_id) ||
      (record.decision !== "approve" && record.decision !== "reject")
    ) return Promise.reject(new Error("The approval decision is invalid."));
    return decideApproval(record.approval_id, record.decision);
  }
  if (record.kind === "ui:resume-human") {
    if (!fromPopup) return Promise.reject(new Error("Human handoff can be resumed only from the BrowseWeave popup."));
    return resumeHumanIntervention();
  }
  if (record.kind === "ui:cleanup-managed-tabs") {
    if (!fromPopup) return Promise.reject(new Error("Managed tabs can be closed from the BrowseWeave popup only."));
    return cleanupManagedTabs(undefined);
  }
  if (record.kind === "ui:complete-credential-handoff") {
    if (!fromPopup) return Promise.reject(new Error("Local credentials are accepted only from the trusted BrowseWeave popup."));
    if (typeof record.handoff_id !== "string" || !/^credential-[a-f0-9]{32}$/u.test(record.handoff_id)) {
      scrubCredentialValues({ fields: record.fields });
      return Promise.reject(new Error("The credential handoff ID is invalid."));
    }
    return completeLocalCredentialHandoff(record.handoff_id, record.fields)
      .finally(() => scrubCredentialValues({ fields: record.fields }));
  }
  if (record.kind === "ui:cancel-credential-handoff") {
    if (!fromPopup) return Promise.reject(new Error("Credential handoffs can be cancelled only from the BrowseWeave popup."));
    if (typeof record.handoff_id !== "string" || !/^credential-[a-f0-9]{32}$/u.test(record.handoff_id)) {
      return Promise.reject(new Error("The credential handoff ID is invalid."));
    }
    return revokeLocalCredentialHandoff(record.handoff_id).then(() => ({ ok: true }));
  }
  if (record.kind === "ui:create-remote-credential-permission") {
    if (!fromPopup) return Promise.reject(new Error("Remote credential permission can be granted only from the BrowseWeave popup."));
    const durationMs = record.duration_ms === undefined ? DEFAULT_REMOTE_CREDENTIAL_PERMISSION_MS : record.duration_ms;
    if (
      typeof durationMs !== "number" ||
      ![15 * 60 * 1000, 60 * 60 * 1000, 24 * 60 * 60 * 1000].includes(durationMs)
    ) {
      return Promise.reject(new Error("Choose a 15-minute, 1-hour, or 24-hour permission window."));
    }
    if (!credentialGrantTargetMatches({
      expectedOrigin: record.expected_origin,
      expectedTabId: record.expected_tab_id,
      currentUrl: record.expected_origin,
      currentTabId: record.expected_tab_id
    })) return Promise.reject(new Error("The trusted permission target is invalid. Reopen the popup and confirm again."));
    return createRemoteCredentialPermission(record.expected_origin as string, record.expected_tab_id as number, durationMs);
  }
  if (record.kind === "ui:revoke-remote-credential-permission") {
    if (!fromPopup && !fromOptions) return Promise.reject(new Error("Untrusted extension message sender."));
    if (typeof record.permission_id !== "string" || !/^remote-credential-[a-f0-9]{32}$/u.test(record.permission_id)) {
      return Promise.reject(new Error("The remote credential permission ID is invalid."));
    }
    return revokeRemoteCredentialPermission(record.permission_id).then(() => ({ ok: true }));
  }
  if (record.kind === "ui:set-session-approval") {
    // Settings-page only. If any other surface could flip this, the weaker
    // session authority would no longer require the browser owner's consent.
    if (!fromOptions) return Promise.reject(new Error("Session-confirmed approval can be changed only from BrowseWeave Settings."));
    if (typeof record.enabled !== "boolean") return Promise.reject(new Error("The session-approval setting must be true or false."));
    const enabled = record.enabled;
    return extensionBrowser.storage.local.set({ [SESSION_APPROVAL_STORAGE_KEY]: enabled }).then(() => {
      if (!enabled) consumedSessionApprovals.clear();
      void extensionBrowser.runtime.sendMessage({ kind: "bridge:session-approval", enabled }).catch(() => undefined);
      return { ok: true, enabled };
    });
  }
  return undefined;
});

extensionBrowser.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && TOKEN_STORAGE_KEY in changes && !setupPairingInProgress) void connect();
});

function onApprovalTargetNavigation(details: { tabId: number; frameId: number }): void {
  const frameIdValue = details.frameId === 0 ? undefined : details.frameId;
  void invalidateApprovalTarget(details.tabId, frameIdValue);
  if (details.frameId === 0) void revokeCredentialHandoffsForTab(details.tabId).catch(() => undefined);
}

extensionBrowser.webNavigation.onCommitted.addListener(onApprovalTargetNavigation);
extensionBrowser.webNavigation.onHistoryStateUpdated.addListener(onApprovalTargetNavigation);
extensionBrowser.webNavigation.onReferenceFragmentUpdated.addListener(onApprovalTargetNavigation);

extensionBrowser.tabs.onUpdated.addListener((updatedTabId, changeInfo) => {
  if (typeof changeInfo.url !== "string") return;
  void invalidateApprovalTarget(updatedTabId);
  void revokeCredentialHandoffsForTab(updatedTabId).catch(() => undefined);
});

extensionBrowser.tabs.onRemoved.addListener((removedTabId) => {
  const intervention = humanInterventions.get(removedTabId);
  if (intervention) {
    humanInterventions.delete(removedTabId);
    if (intervention.origin) pausedOrigins.delete(intervention.origin);
    notifyHumanState();
  }
  mutationQueues.delete(removedTabId);
  lastMutationFinishedAt.delete(removedTabId);
  mutationStressUntil.delete(removedTabId);
  void untrackManagedTab(removedTabId).catch(() => undefined);
  void revokeCredentialHandoffsForTab(removedTabId).catch(() => undefined);
  void invalidateApprovalTarget(removedTabId);
});

extensionBrowser.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    void storedToken().then((token) => {
      if (token.length < 16) void extensionBrowser.runtime.openOptionsPage();
    });
  }
});

async function initializeBackground(): Promise<void> {
  try {
    const localStorage = extensionBrowser.storage.local as typeof extensionBrowser.storage.local & {
      setAccessLevel?: (options: { accessLevel: "TRUSTED_CONTEXTS" }) => Promise<void>;
    };
    if (typeof localStorage.setAccessLevel === "function") {
      await localStorage.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => undefined);
    }
    const sessionStorage = sessionStorageArea() as (CrossBrowserApi["storage"]["local"] & {
      setAccessLevel?: (options: { accessLevel: "TRUSTED_CONTEXTS" }) => Promise<void>;
    }) | undefined;
    if (typeof sessionStorage?.setAccessLevel === "function") {
      await sessionStorage.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => undefined);
    }
    await ensureSessionStateLoaded();
    pruneScreenshots();
    await persistSessionState();
    await Promise.all([installationId(), deviceSigningKey()]);
    await connect();
  } catch (error) {
    setState({
      phase: "error",
      lastError: error instanceof Error ? error.message : "BrowseWeave background initialization failed.",
      connectedAt: null
    });
  }
}

void initializeBackground();
