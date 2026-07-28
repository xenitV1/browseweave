/**
 * Shared JSON contracts for BrowseWeave's loopback WebSocket and TCP IPC.
 * Keep this file free of browser-only and Node-only imports.
 */

export const PROTOCOL_VERSION = 3 as const;
export const SETUP_VERSION = 1 as const;
export const APPROVAL_FINGERPRINT_PATTERN = /^sha256:[a-f0-9]{64}$/u;
export const SHA256_PATTERN = /^sha256:[a-f0-9]{64}$/u;
export const INSTALLATION_ID_PATTERN = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/u;
export const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/u;
export const SETUP_ID_PATTERN = /^[a-f0-9]{24}$/u;

export const BROWSER_ACTIONS = [
  "list_tabs",
  "snapshot",
  "screenshot",
  "wait",
  "hover",
  "click_at",
  "click",
  "type",
  "fill_form",
  "credential_handoff_prepare",
  "credential_fill",
  "press",
  "scroll",
  "navigate",
  "back",
  "forward",
  "reload",
  "close_tab",
  "cleanup_tabs",
  "activate_tab",
  "new_tab"
] as const;

export type BrowserAction = (typeof BROWSER_ACTIONS)[number];
export type BrowserFamily = "firefox" | "chromium";
export type ApprovalDecision = "approve" | "reject";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface P256PublicJwk extends JsonObject {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  ext: true;
  key_ops: ["verify"];
}

export interface BrowserIdentity extends JsonObject {
  installation_id: string;
  browser_family: BrowserFamily;
  browser_name: string;
  browser_version: string;
  extension_version: string;
}

export type SetupAuthenticationPhase = "provisioning" | "persisted";

export interface ExtensionClientHello {
  type: "client_hello";
  protocol_version: typeof PROTOCOL_VERSION;
  endpoint_role: "extension";
  client_nonce: string;
  origin: string;
  identity: BrowserIdentity;
  public_key: P256PublicJwk;
  /** Present only for the first authenticated reconnect after local setup. */
  authentication_mode?: "derived-v1";
  /** Binds a staged derived secret to the exact short-lived local setup session. */
  setup_id?: string;
  /** Distinguishes pre-storage proof from the durable post-storage commit. */
  setup_phase?: SetupAuthenticationPhase;
}

export interface ServerChallenge {
  type: "challenge";
  protocol_version: typeof PROTOCOL_VERSION;
  endpoint_role: "extension";
  client_nonce: string;
  server_nonce: string;
  daemon_instance_id: string;
  server_proof: string;
}

export interface ExtensionHello {
  type: "hello";
  protocol_version: typeof PROTOCOL_VERSION;
  endpoint_role: "extension";
  client_nonce: string;
  server_nonce: string;
  origin: string;
  daemon_instance_id: string;
  identity: BrowserIdentity;
  public_key: P256PublicJwk;
  client_proof: string;
  signature: string;
}

export interface ExtensionHelloAck {
  type: "hello_ack";
  protocol_version: typeof PROTOCOL_VERSION;
  browser_id: string;
}

/**
 * Initial local setup is a separate, short-lived exchange. The setup secret is
 * deliberately absent from both wire messages and is used only as key
 * material by the two loopback endpoints.
 */
export interface SetupPairingRequest {
  type: "setup_pair_request";
  protocol_version: typeof PROTOCOL_VERSION;
  setup_version: typeof SETUP_VERSION;
  setup_id: string;
  client_nonce: string;
  origin: string;
  identity: BrowserIdentity;
  public_key: P256PublicJwk;
  client_proof: string;
}

export interface SetupPairingResponse {
  type: "setup_pair_response";
  protocol_version: typeof PROTOCOL_VERSION;
  setup_version: typeof SETUP_VERSION;
  setup_id: string;
  client_nonce: string;
  server_nonce: string;
  daemon_instance_id: string;
  expires_at: string;
  iv: string;
  encrypted_pairing_token: string;
}

export interface SetupPairingWaitingStatus extends JsonObject {
  setup_pairing_status: "waiting";
  setup_id: string;
  expires_at: string;
  browser_family: BrowserFamily;
}

export interface SetupPairingPendingStatus extends JsonObject {
  setup_pairing_status: "pending";
  setup_id: string;
  expires_at: string;
  browser_id: string;
  browser_family: BrowserFamily;
  browser_name: string;
  browser_version: string;
  extension_version: string;
}

export interface SetupPairingCompletedStatus extends JsonObject {
  setup_pairing_status: "completed";
  setup_id: string;
  expires_at: string;
  browser_id: string;
  browser_family: BrowserFamily;
  browser_name: string;
  browser_version: string;
  extension_version: string;
  completed_at: string;
}

export interface SetupPairingNotFoundStatus extends JsonObject {
  setup_pairing_status: "not_found";
  setup_id: string;
}

export type SetupPairingStatus =
  | SetupPairingWaitingStatus
  | SetupPairingPendingStatus
  | SetupPairingCompletedStatus
  | SetupPairingNotFoundStatus;

export interface ServerPing {
  type: "ping";
  timestamp: number;
}

export interface ExtensionPong {
  type: "pong";
  timestamp: number;
}

interface ExtensionCommandBase {
  type: "command";
  /** Internal daemon-generated ID. IPC callers cannot choose this value. */
  id: string;
  action: BrowserAction;
  payload: JsonObject;
  /** Re-evaluate live approval context without executing the requested action. */
  revalidate_only: boolean;
}

export interface ExtensionUnapprovedCommand extends ExtensionCommandBase {
  approved: false;
  approval_fingerprint?: never;
}

export interface ExtensionApprovedCommand extends ExtensionCommandBase {
  /** True only after a matching one-time extension-signed decision is consumed. */
  approved: true;
  /** Must match a still-live extension-owned grant created by the popup decision. */
  approval_id: string;
  approval_fingerprint: string;
}

export type ExtensionCommand = ExtensionUnapprovedCommand | ExtensionApprovedCommand;

export interface ExtensionApprovalRequest {
  type: "approval_request";
  approval_id: string;
  approval_nonce: string;
  browser_id: string;
  /** Exact live browser tab resolved by the extension before it requested approval. */
  target_tab_id: number;
  /** Exact live frame resolved by the extension; zero is the top-level document. */
  target_frame_id: number;
  action: BrowserAction;
  risk: string;
  description: string;
  params_sha256: string;
  approval_fingerprint: string;
  expires_at: string;
}

export interface ExtensionApprovalResolved {
  type: "approval_resolved";
  approval_id: string;
  outcome: "approved" | "rejected" | "consumed" | "cancelled" | "expired";
}

export interface ExtensionApprovalDecision {
  type: "approval_decision";
  approval_id: string;
  decision: ApprovalDecision;
  signature: string;
}

export interface ExtensionError {
  code: string;
  message: string;
  category?: string;
  approval_fingerprint?: string;
  target_tab_id?: number;
  target_frame_id?: number;
  details?: JsonObject;
}

export interface ExtensionSuccessResult {
  type: "result";
  id: string;
  ok: true;
  result: JsonValue;
}

export interface ExtensionFailureResult {
  type: "result";
  id: string;
  ok: false;
  error: ExtensionError;
}

export type ExtensionResult = ExtensionSuccessResult | ExtensionFailureResult;
export type ExtensionInboundMessage =
  | ExtensionClientHello
  | SetupPairingRequest
  | ExtensionHello
  | ExtensionResult
  | ExtensionApprovalDecision
  | ExtensionPong;
export type ExtensionOutboundMessage =
  | ServerChallenge
  | SetupPairingResponse
  | ExtensionHelloAck
  | ServerPing
  | ExtensionCommand
  | ExtensionApprovalRequest
  | ExtensionApprovalResolved;

export interface IpcClientHello {
  type: "ipc_client_hello";
  protocol_version: typeof PROTOCOL_VERSION;
  endpoint_role: "ipc";
  client_nonce: string;
}

export interface IpcServerChallenge {
  type: "ipc_challenge";
  protocol_version: typeof PROTOCOL_VERSION;
  endpoint_role: "ipc";
  client_nonce: string;
  server_nonce: string;
  daemon_instance_id: string;
  server_proof: string;
}

export interface IpcRequest {
  type: "ipc_request";
  protocol_version: typeof PROTOCOL_VERSION;
  endpoint_role: "ipc";
  id: string;
  method: string;
  params: JsonObject;
  client_nonce: string;
  server_nonce: string;
  daemon_instance_id: string;
  client_proof: string;
}

export interface IpcSuccessResponse {
  id: string;
  ok: true;
  result: JsonValue;
}

export interface IpcFailureResponse {
  id: string;
  ok: false;
  error: string;
}

export type IpcResponse = IpcSuccessResponse | IpcFailureResponse;

export interface ApprovalRequiredResult extends JsonObject {
  approval_required: true;
  approval_id: string;
  approval_ui: "browser_extension";
  browser_id: string;
  target_tab_id: number;
  target_frame_id: number;
  risk: string;
  description: string;
  action: BrowserAction;
  expires_at: string;
  message: string;
}

export interface ConnectedBrowserSummary extends JsonObject {
  browser_id: string;
  browser_family: BrowserFamily;
  browser_name: string;
  browser_version: string;
  extension_version: string;
  connected_at: string;
}

export interface BridgeStatus extends JsonObject {
  service: "browseweave";
  protocol_version: typeof PROTOCOL_VERSION;
  websocket_listening: boolean;
  connected_browsers: ConnectedBrowserSummary[];
  pending_commands: number;
  pending_approvals: number;
  uptime_seconds: number;
}

const ACTION_SET: ReadonlySet<string> = new Set(BROWSER_ACTIONS);

export function isBrowserAction(value: unknown): value is BrowserAction {
  return typeof value === "string" && ACTION_SET.has(value);
}

export function isApprovalFingerprint(value: unknown): value is string {
  return typeof value === "string" && APPROVAL_FINGERPRINT_PATTERN.test(value);
}

export function isInstallationId(value: unknown): value is string {
  return typeof value === "string" && INSTALLATION_ID_PATTERN.test(value);
}

export function isJsonObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function isJsonValue(value: unknown): value is JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) return true;
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (isJsonObject(value)) return Object.values(value).every(isJsonValue);
  return false;
}

export function isP256PublicJwk(value: unknown): value is P256PublicJwk {
  if (!isJsonObject(value)) return false;
  return value.kty === "EC" &&
    value.crv === "P-256" &&
    value.ext === true &&
    Array.isArray(value.key_ops) &&
    value.key_ops.length === 1 &&
    value.key_ops[0] === "verify" &&
    typeof value.x === "string" && value.x.length === 43 && BASE64URL_PATTERN.test(value.x) &&
    typeof value.y === "string" && value.y.length === 43 && BASE64URL_PATTERN.test(value.y);
}

function framedField(name: string, value: string): string {
  return `${name}:${new TextEncoder().encode(value).byteLength}:${value}\n`;
}

function stagedAuthenticationFields(
  setupId: string | undefined,
  setupPhase: SetupAuthenticationPhase | undefined
): string {
  return setupId === undefined || setupPhase === undefined
    ? ""
    : framedField("authentication_mode", "derived-v1") +
      framedField("setup_id", setupId) +
      framedField("setup_phase", setupPhase);
}

export function canonicalJson(value: JsonValue): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isJsonObject(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] ?? null)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function canonicalPublicJwk(jwk: P256PublicJwk): string {
  return `${jwk.kty}.${jwk.crv}.${jwk.x}.${jwk.y}`;
}

export function setupPairingClientProofPayload(input: {
  setupId: string;
  clientNonce: string;
  origin: string;
  installationId: string;
  publicKey: P256PublicJwk;
}): string {
  return "BrowseWeave setup client proof v1\n" +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("setup_version", String(SETUP_VERSION)) +
    framedField("setup_id", input.setupId) +
    framedField("client_nonce", input.clientNonce) +
    framedField("origin", input.origin) +
    framedField("installation_id", input.installationId) +
    framedField("public_key", canonicalPublicJwk(input.publicKey));
}

export function setupPairingKeySalt(input: {
  setupId: string;
  clientNonce: string;
  serverNonce: string;
}): string {
  return "BrowseWeave setup key salt v1\n" +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("setup_version", String(SETUP_VERSION)) +
    framedField("setup_id", input.setupId) +
    framedField("client_nonce", input.clientNonce) +
    framedField("server_nonce", input.serverNonce);
}

export function setupPairingAadPayload(input: {
  setupId: string;
  clientNonce: string;
  serverNonce: string;
  daemonInstanceId: string;
  origin: string;
  identity: BrowserIdentity;
  publicKey: P256PublicJwk;
  expiresAt: string;
}): string {
  return "BrowseWeave setup encrypted pairing token v1\n" +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("setup_version", String(SETUP_VERSION)) +
    framedField("setup_id", input.setupId) +
    framedField("client_nonce", input.clientNonce) +
    framedField("server_nonce", input.serverNonce) +
    framedField("daemon_instance_id", input.daemonInstanceId) +
    framedField("origin", input.origin) +
    framedField("identity", canonicalJson(input.identity)) +
    framedField("public_key", canonicalPublicJwk(input.publicKey)) +
    framedField("expires_at", input.expiresAt);
}

export function helloSigningPayload(input: {
  clientNonce: string;
  serverNonce: string;
  daemonInstanceId: string;
  origin: string;
  installationId: string;
  publicKey: P256PublicJwk;
  clientProof: string;
  setupId?: string;
  setupPhase?: SetupAuthenticationPhase;
}): string {
  return "BrowseWeave hello signature v1\n" +
    framedField("endpoint_role", "extension") +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("client_nonce", input.clientNonce) +
    framedField("server_nonce", input.serverNonce) +
    framedField("daemon_instance_id", input.daemonInstanceId) +
    framedField("origin", input.origin) +
    framedField("installation_id", input.installationId) +
    framedField("public_key", canonicalPublicJwk(input.publicKey)) +
    stagedAuthenticationFields(input.setupId, input.setupPhase) +
    framedField("client_proof", input.clientProof);
}

export function extensionServerProofPayload(input: {
  clientNonce: string;
  serverNonce: string;
  daemonInstanceId: string;
  origin: string;
  installationId: string;
  publicKey: P256PublicJwk;
  setupId?: string;
  setupPhase?: SetupAuthenticationPhase;
}): string {
  return "BrowseWeave extension server proof v1\n" +
    framedField("endpoint_role", "extension") +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("client_nonce", input.clientNonce) +
    framedField("server_nonce", input.serverNonce) +
    framedField("daemon_instance_id", input.daemonInstanceId) +
    framedField("origin", input.origin) +
    framedField("installation_id", input.installationId) +
    framedField("public_key", canonicalPublicJwk(input.publicKey)) +
    stagedAuthenticationFields(input.setupId, input.setupPhase);
}

export function extensionClientProofPayload(input: {
  clientNonce: string;
  serverNonce: string;
  daemonInstanceId: string;
  origin: string;
  installationId: string;
  publicKey: P256PublicJwk;
  serverProof: string;
  setupId?: string;
  setupPhase?: SetupAuthenticationPhase;
}): string {
  return "BrowseWeave extension client proof v1\n" +
    framedField("endpoint_role", "extension") +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("client_nonce", input.clientNonce) +
    framedField("server_nonce", input.serverNonce) +
    framedField("daemon_instance_id", input.daemonInstanceId) +
    framedField("origin", input.origin) +
    framedField("installation_id", input.installationId) +
    framedField("public_key", canonicalPublicJwk(input.publicKey)) +
    stagedAuthenticationFields(input.setupId, input.setupPhase) +
    framedField("server_proof", input.serverProof);
}

export function ipcServerProofPayload(input: {
  clientNonce: string;
  serverNonce: string;
  daemonInstanceId: string;
}): string {
  return "BrowseWeave IPC server proof v1\n" +
    framedField("endpoint_role", "ipc") +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("client_nonce", input.clientNonce) +
    framedField("server_nonce", input.serverNonce) +
    framedField("daemon_instance_id", input.daemonInstanceId);
}

export function ipcClientProofPayload(input: {
  clientNonce: string;
  serverNonce: string;
  daemonInstanceId: string;
  serverProof: string;
  requestId: string;
  method: string;
  paramsSha256: string;
}): string {
  return "BrowseWeave IPC client proof v1\n" +
    framedField("endpoint_role", "ipc") +
    framedField("protocol_version", String(PROTOCOL_VERSION)) +
    framedField("client_nonce", input.clientNonce) +
    framedField("server_nonce", input.serverNonce) +
    framedField("daemon_instance_id", input.daemonInstanceId) +
    framedField("server_proof", input.serverProof) +
    framedField("request_id", input.requestId) +
    framedField("method", input.method) +
    framedField("params_sha256", input.paramsSha256);
}

export function approvalDecisionSigningPayload(input: {
  daemonInstanceId: string;
  approvalId: string;
  approvalNonce: string;
  browserId: string;
  targetTabId: number;
  targetFrameId: number;
  decision: ApprovalDecision;
  action: BrowserAction;
  paramsSha256: string;
  approvalFingerprint: string;
  expiresAt: string;
}): string {
  return "BrowseWeave approval decision signature v2\n" +
    framedField("daemon_instance_id", input.daemonInstanceId) +
    framedField("approval_id", input.approvalId) +
    framedField("approval_nonce", input.approvalNonce) +
    framedField("browser_id", input.browserId) +
    framedField("target_tab_id", String(input.targetTabId)) +
    framedField("target_frame_id", String(input.targetFrameId)) +
    framedField("decision", input.decision) +
    framedField("action", input.action) +
    framedField("params_sha256", input.paramsSha256) +
    framedField("approval_fingerprint", input.approvalFingerprint) +
    framedField("expires_at", input.expiresAt);
}
