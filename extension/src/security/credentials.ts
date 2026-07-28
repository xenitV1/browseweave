import { isStableRef, normalizeText } from "../shared/pure";

export const LOCAL_CREDENTIAL_HANDOFF_TTL_MS = 5 * 60 * 1000;
export const MAX_REMOTE_CREDENTIAL_PERMISSION_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_REMOTE_CREDENTIAL_PERMISSION_MS = 15 * 60 * 1000;
export const MAX_CREDENTIAL_HANDOFFS = 10;
export const MAX_REMOTE_CREDENTIAL_PERMISSIONS = 20;

export type CredentialKind = "username" | "password";

export interface CredentialFieldSpec {
  ref: string;
  kind: CredentialKind;
}

export interface RemoteCredentialField extends CredentialFieldSpec {
  value: string;
}

export interface CredentialCommandSpec<TField extends CredentialFieldSpec> {
  tabId: number;
  frameId: number;
  fields: TField[];
  submit: boolean;
}

export interface CredentialFieldView extends CredentialFieldSpec {
  label: string;
}

export interface LocalCredentialHandoff {
  handoff_id: string;
  tab_id: number;
  frame_id: number;
  origin: string;
  document_epoch: string;
  binding_fingerprint: string;
  fields: CredentialFieldView[];
  submit: boolean;
  created_at: string;
  expires_at: string;
}

export interface RemoteCredentialPermission {
  permission_id: string;
  origin: string;
  created_at: string;
  expires_at: string;
  one_use: true;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(record).every((key) => allowedSet.has(key));
}

function positiveTabId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function frameId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function credentialKind(value: unknown): value is CredentialKind {
  return value === "username" || value === "password";
}

export function normalizeHttpsOrigin(value: unknown): string {
  if (typeof value !== "string" || value.length > 2048) throw new Error("A valid HTTPS origin is required.");
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("A valid HTTPS origin is required.");
  }
  if (
    parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.origin === "null" ||
    parsed.hostname.includes("*")
  ) {
    throw new Error("Credential access is allowed only for an exact HTTPS origin.");
  }
  return parsed.origin;
}

/**
 * Binds a trusted permission prompt to the exact tab and HTTPS origin that the
 * user saw. Both values must still match when the background persists it.
 */
export function credentialGrantTargetMatches(input: {
  expectedOrigin: unknown;
  expectedTabId: unknown;
  currentUrl: unknown;
  currentTabId: unknown;
}): boolean {
  if (
    typeof input.expectedTabId !== "number" || !positiveTabId(input.expectedTabId) ||
    typeof input.currentTabId !== "number" || !positiveTabId(input.currentTabId) ||
    input.expectedTabId !== input.currentTabId || typeof input.expectedOrigin !== "string"
  ) return false;
  try {
    const expectedOrigin = normalizeHttpsOrigin(input.expectedOrigin);
    return expectedOrigin === input.expectedOrigin && normalizeHttpsOrigin(input.currentUrl) === expectedOrigin;
  } catch {
    return false;
  }
}

export function validateCredentialCommandPayload(
  value: unknown,
  includeValues: false
): CredentialCommandSpec<CredentialFieldSpec>;
export function validateCredentialCommandPayload(
  value: unknown,
  includeValues: true
): CredentialCommandSpec<RemoteCredentialField>;
export function validateCredentialCommandPayload(
  value: unknown,
  includeValues: boolean
): CredentialCommandSpec<CredentialFieldSpec | RemoteCredentialField> {
  if (!isPlainRecord(value) || !exactKeys(value, ["tab_id", "frame_id", "fields", "submit"])) {
    throw new Error("The credential request contains unsupported fields.");
  }
  if (!positiveTabId(value.tab_id)) throw new Error("A valid tab_id is required for credential access.");
  const normalizedFrameId = value.frame_id === undefined ? 0 : value.frame_id;
  if (!frameId(normalizedFrameId)) throw new Error("frame_id must be a non-negative integer.");
  if (value.submit !== undefined && typeof value.submit !== "boolean") {
    throw new Error("submit must be true or false.");
  }
  if (!Array.isArray(value.fields) || value.fields.length < 1 || value.fields.length > 2) {
    throw new Error("A credential request must contain one or two fields.");
  }
  const refs = new Set<string>();
  const kinds = new Set<CredentialKind>();
  const fields = value.fields.map((rawField) => {
    if (!isPlainRecord(rawField) || !exactKeys(rawField, includeValues ? ["ref", "kind", "value"] : ["ref", "kind"])) {
      throw new Error("A credential field contains unsupported data.");
    }
    if (!isStableRef(rawField.ref) || !credentialKind(rawField.kind)) {
      throw new Error("Every credential field requires a valid ref and username/password kind.");
    }
    if (refs.has(rawField.ref) || kinds.has(rawField.kind)) {
      throw new Error("Credential field refs and kinds must be unique.");
    }
    refs.add(rawField.ref);
    kinds.add(rawField.kind);
    if (!includeValues) return { ref: rawField.ref, kind: rawField.kind };
    if (typeof rawField.value !== "string" || rawField.value.length < 1) {
      throw new Error("Every remote credential field requires a non-empty value.");
    }
    const maximum = rawField.kind === "username" ? 320 : 1024;
    if (rawField.value.length > maximum) {
      throw new Error(`The ${rawField.kind} value exceeds its safe length limit.`);
    }
    return { ref: rawField.ref, kind: rawField.kind, value: rawField.value };
  });
  return {
    tabId: value.tab_id,
    frameId: normalizedFrameId,
    fields,
    submit: value.submit === true
  };
}

/** Best-effort reference clearing after the one permitted use. */
export function scrubCredentialValues(payload: unknown): void {
  if (!isPlainRecord(payload) || !Array.isArray(payload.fields)) return;
  for (const rawField of payload.fields) {
    if (!isPlainRecord(rawField) || !("value" in rawField)) continue;
    rawField.value = "";
    delete rawField.value;
  }
}

function boundedId(value: unknown, prefix: string): value is string {
  return typeof value === "string" && value.length <= 128 && value.startsWith(prefix) && /^[A-Za-z0-9_-]+$/u.test(value);
}

function isoTimestamp(value: unknown): value is string {
  return typeof value === "string" && Number.isFinite(Date.parse(value));
}

export function isLocalCredentialHandoff(value: unknown): value is LocalCredentialHandoff {
  if (!isPlainRecord(value)) return false;
  if (
    !boundedId(value.handoff_id, "credential-") || !positiveTabId(value.tab_id) || !frameId(value.frame_id) ||
    typeof value.origin !== "string" || !isoTimestamp(value.created_at) || !isoTimestamp(value.expires_at) ||
    typeof value.document_epoch !== "string" || value.document_epoch.length < 8 || value.document_epoch.length > 128 ||
    typeof value.binding_fingerprint !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(value.binding_fingerprint) ||
    typeof value.submit !== "boolean" || !Array.isArray(value.fields) || value.fields.length < 1 || value.fields.length > 2
  ) return false;
  try {
    if (
      normalizeHttpsOrigin(value.origin) !== value.origin ||
      Date.parse(value.expires_at) <= Date.parse(value.created_at) ||
      Date.parse(value.expires_at) - Date.parse(value.created_at) > LOCAL_CREDENTIAL_HANDOFF_TTL_MS
    ) return false;
  } catch {
    return false;
  }
  const refs = new Set<string>();
  const kinds = new Set<CredentialKind>();
  for (const rawField of value.fields) {
    if (!isPlainRecord(rawField) || !isStableRef(rawField.ref) || !credentialKind(rawField.kind)) return false;
    if (refs.has(rawField.ref) || kinds.has(rawField.kind)) return false;
    if (typeof rawField.label !== "string" || rawField.label.length > 120) return false;
    refs.add(rawField.ref);
    kinds.add(rawField.kind);
  }
  return true;
}

export function isRemoteCredentialPermission(value: unknown): value is RemoteCredentialPermission {
  if (!isPlainRecord(value)) return false;
  if (
    !boundedId(value.permission_id, "remote-credential-") || !isoTimestamp(value.created_at) ||
    !isoTimestamp(value.expires_at) || value.one_use !== true
  ) return false;
  try {
    return normalizeHttpsOrigin(value.origin) === value.origin &&
      Date.parse(value.expires_at) > Date.parse(value.created_at) &&
      Date.parse(value.expires_at) - Date.parse(value.created_at) <= MAX_REMOTE_CREDENTIAL_PERMISSION_MS;
  } catch {
    return false;
  }
}

export class LocalCredentialHandoffLedger {
  #handoffs = new Map<string, LocalCredentialHandoff>();

  constructor(initial: readonly LocalCredentialHandoff[] = []) {
    if (initial.length > MAX_CREDENTIAL_HANDOFFS || initial.some((item) => !isLocalCredentialHandoff(item))) {
      throw new Error("The local credential-handoff ledger is invalid.");
    }
    for (const handoff of initial) {
      if (this.#handoffs.has(handoff.handoff_id)) throw new Error("The local credential-handoff ledger has duplicate IDs.");
      this.#handoffs.set(handoff.handoff_id, structuredClone(handoff));
    }
  }

  snapshot(): LocalCredentialHandoff[] {
    return [...this.#handoffs.values()].map((handoff) => structuredClone(handoff));
  }

  prune(now = Date.now()): boolean {
    let changed = false;
    for (const [id, handoff] of this.#handoffs) {
      if (Date.parse(handoff.expires_at) <= now) {
        this.#handoffs.delete(id);
        changed = true;
      }
    }
    return changed;
  }

  add(handoff: LocalCredentialHandoff, now = Date.now()): void {
    if (!isLocalCredentialHandoff(handoff) || Date.parse(handoff.expires_at) <= now) {
      throw new Error("The local credential handoff is invalid or expired.");
    }
    this.prune(now);
    if (this.#handoffs.has(handoff.handoff_id)) throw new Error("A credential handoff already uses this ID.");
    if (this.#handoffs.size >= MAX_CREDENTIAL_HANDOFFS) throw new Error("Too many local credential handoffs are pending.");
    this.#handoffs.set(handoff.handoff_id, structuredClone(handoff));
  }

  consume(handoffId: string, now = Date.now()): LocalCredentialHandoff | null {
    const handoff = this.#handoffs.get(handoffId);
    if (!handoff) return null;
    this.#handoffs.delete(handoffId);
    if (Date.parse(handoff.expires_at) <= now) return null;
    return structuredClone(handoff);
  }

  revoke(handoffId: string): boolean {
    return this.#handoffs.delete(handoffId);
  }

  revokeTab(tabId: number): number {
    let revoked = 0;
    for (const [id, handoff] of this.#handoffs) {
      if (handoff.tab_id !== tabId) continue;
      this.#handoffs.delete(id);
      revoked += 1;
    }
    return revoked;
  }
}

export class RemoteCredentialPermissionLedger {
  #permissions = new Map<string, RemoteCredentialPermission>();

  constructor(initial: readonly RemoteCredentialPermission[] = []) {
    if (initial.length > MAX_REMOTE_CREDENTIAL_PERMISSIONS || initial.some((item) => !isRemoteCredentialPermission(item))) {
      throw new Error("The remote credential-permission ledger is invalid.");
    }
    const origins = new Set<string>();
    for (const permission of initial) {
      if (this.#permissions.has(permission.permission_id) || origins.has(permission.origin)) {
        throw new Error("The remote credential-permission ledger contains duplicates.");
      }
      origins.add(permission.origin);
      this.#permissions.set(permission.permission_id, { ...permission });
    }
  }

  snapshot(): RemoteCredentialPermission[] {
    return [...this.#permissions.values()].map((permission) => ({ ...permission }));
  }

  prune(now = Date.now()): boolean {
    let changed = false;
    for (const [id, permission] of this.#permissions) {
      if (Date.parse(permission.expires_at) <= now) {
        this.#permissions.delete(id);
        changed = true;
      }
    }
    return changed;
  }

  add(permission: RemoteCredentialPermission, now = Date.now()): void {
    if (!isRemoteCredentialPermission(permission) || Date.parse(permission.expires_at) <= now) {
      throw new Error("The remote credential permission is invalid or expired.");
    }
    this.prune(now);
    if (this.#permissions.has(permission.permission_id)) throw new Error("A remote credential permission already uses this ID.");
    for (const [id, existing] of this.#permissions) {
      if (existing.origin === permission.origin) this.#permissions.delete(id);
    }
    if (this.#permissions.size >= MAX_REMOTE_CREDENTIAL_PERMISSIONS) {
      throw new Error("Too many remote credential permissions are pending.");
    }
    this.#permissions.set(permission.permission_id, { ...permission });
  }

  consumeOrigin(origin: string, now = Date.now()): RemoteCredentialPermission | null {
    this.prune(now);
    const permission = [...this.#permissions.values()].find((item) => item.origin === origin);
    if (!permission) return null;
    this.#permissions.delete(permission.permission_id);
    return { ...permission };
  }

  revoke(permissionId: string): boolean {
    return this.#permissions.delete(permissionId);
  }
}

export function safeCredentialLabel(value: unknown, kind: CredentialKind): string {
  return normalizeText(value, 120) || (kind === "username" ? "Username or email" : "Password");
}
