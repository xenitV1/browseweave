import {
  SHA256_PATTERN,
  canonicalJson,
  isApprovalFingerprint,
  isBrowserAction,
  type BrowserAction,
  type JsonObject
} from "../../src/protocol";

export const MAX_LOCAL_APPROVAL_GRANTS = 100 as const;

export interface LocalApprovalGrant {
  approval_id: string;
  daemon_instance_id: string;
  browser_id: string;
  target_tab_id: number;
  target_frame_id: number;
  action: BrowserAction;
  params_sha256: string;
  approval_fingerprint: string;
  expires_at: string;
  decision: "approve";
}

export interface LocalApprovalClaim {
  approvalId: string;
  daemonInstanceId: string;
  browserId: string;
  targetTabId: number;
  targetFrameId: number;
  action: BrowserAction;
  paramsSha256: string;
  approvalFingerprint: string;
}

export type GrantConsumption =
  | { ok: true; grant: LocalApprovalGrant; mutated: true }
  | {
      ok: false;
      code: "approval_grant_missing" | "approval_grant_expired" | "approval_grant_mismatch";
      mutated: boolean;
    };

function validBoundedId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,256}$/u.test(value);
}

export function isLocalApprovalGrant(value: unknown): value is LocalApprovalGrant {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return validBoundedId(record.approval_id) &&
    validBoundedId(record.daemon_instance_id) &&
    validBoundedId(record.browser_id) &&
    typeof record.target_tab_id === "number" && Number.isSafeInteger(record.target_tab_id) && record.target_tab_id > 0 &&
    typeof record.target_frame_id === "number" && Number.isSafeInteger(record.target_frame_id) && record.target_frame_id >= 0 &&
    isBrowserAction(record.action) &&
    typeof record.params_sha256 === "string" && SHA256_PATTERN.test(record.params_sha256) &&
    isApprovalFingerprint(record.approval_fingerprint) &&
    typeof record.expires_at === "string" && Number.isFinite(Date.parse(record.expires_at)) &&
    record.decision === "approve";
}

export async function hashCommandParams(payload: JsonObject): Promise<string> {
  const encoded = new TextEncoder().encode(canonicalJson(payload));
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", encoded));
  return `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

/** One-time, extension-owned approval grants. Claiming a known ID always consumes it. */
export class ApprovalGrantLedger {
  #grants = new Map<string, LocalApprovalGrant>();

  constructor(initial: readonly LocalApprovalGrant[] = []) {
    if (initial.length > MAX_LOCAL_APPROVAL_GRANTS || initial.some((grant) => !isLocalApprovalGrant(grant))) {
      throw new Error("The local approval-grant ledger is invalid.");
    }
    for (const grant of initial) {
      if (this.#grants.has(grant.approval_id)) throw new Error("The local approval-grant ledger contains duplicate IDs.");
      this.#grants.set(grant.approval_id, { ...grant });
    }
  }

  get size(): number {
    return this.#grants.size;
  }

  snapshot(): LocalApprovalGrant[] {
    return [...this.#grants.values()].map((grant) => ({ ...grant }));
  }

  prune(now = Date.now()): boolean {
    let mutated = false;
    for (const [approvalId, grant] of this.#grants) {
      if (Date.parse(grant.expires_at) <= now) {
        this.#grants.delete(approvalId);
        mutated = true;
      }
    }
    return mutated;
  }

  add(grant: LocalApprovalGrant, now = Date.now()): void {
    if (!isLocalApprovalGrant(grant) || Date.parse(grant.expires_at) <= now) {
      throw new Error("The local approval grant is invalid or expired.");
    }
    this.prune(now);
    const existing = this.#grants.get(grant.approval_id);
    if (existing) throw new Error("A local approval grant already uses this ID.");
    if (this.#grants.size >= MAX_LOCAL_APPROVAL_GRANTS) {
      throw new Error("Too many local approval grants are pending.");
    }
    this.#grants.set(grant.approval_id, { ...grant });
  }

  revoke(approvalId: string): boolean {
    return this.#grants.delete(approvalId);
  }

  revokeForDaemon(daemonInstanceId: string): number {
    let revoked = 0;
    for (const [approvalId, grant] of this.#grants) {
      if (grant.daemon_instance_id !== daemonInstanceId) continue;
      this.#grants.delete(approvalId);
      revoked += 1;
    }
    return revoked;
  }

  revokeForTarget(targetTabId: number, targetFrameId?: number): number {
    let revoked = 0;
    for (const [approvalId, grant] of this.#grants) {
      if (grant.target_tab_id !== targetTabId) continue;
      if (targetFrameId !== undefined && grant.target_frame_id !== targetFrameId) continue;
      this.#grants.delete(approvalId);
      revoked += 1;
    }
    return revoked;
  }

  consume(claim: LocalApprovalClaim, now = Date.now()): GrantConsumption {
    const grant = this.#grants.get(claim.approvalId);
    if (!grant) return { ok: false, code: "approval_grant_missing", mutated: false };
    this.#grants.delete(claim.approvalId);
    if (Date.parse(grant.expires_at) <= now) {
      return { ok: false, code: "approval_grant_expired", mutated: true };
    }
    const matches = grant.decision === "approve" &&
      grant.daemon_instance_id === claim.daemonInstanceId &&
      grant.browser_id === claim.browserId &&
      grant.target_tab_id === claim.targetTabId &&
      grant.target_frame_id === claim.targetFrameId &&
      grant.action === claim.action &&
      grant.params_sha256 === claim.paramsSha256 &&
      grant.approval_fingerprint === claim.approvalFingerprint;
    if (!matches) return { ok: false, code: "approval_grant_mismatch", mutated: true };
    return { ok: true, grant, mutated: true };
  }
}
