import { describe, expect, it } from "vitest";
import {
  ApprovalGrantLedger,
  hashCommandParams,
  type LocalApprovalClaim,
  type LocalApprovalGrant
} from "../extension/src/approval-grants";

const NOW = Date.parse("2030-01-01T00:00:00.000Z");
const PARAMS_HASH = `sha256:${"a".repeat(64)}`;
const FINGERPRINT = `sha256:${"b".repeat(64)}`;

function grant(overrides: Partial<LocalApprovalGrant> = {}): LocalApprovalGrant {
  return {
    approval_id: "approval-1",
    daemon_instance_id: "daemon-1",
    browser_id: "browser-1",
    target_tab_id: 17,
    target_frame_id: 0,
    action: "click",
    params_sha256: PARAMS_HASH,
    approval_fingerprint: FINGERPRINT,
    expires_at: "2030-01-01T00:01:00.000Z",
    decision: "approve",
    ...overrides
  };
}

function claim(overrides: Partial<LocalApprovalClaim> = {}): LocalApprovalClaim {
  return {
    approvalId: "approval-1",
    daemonInstanceId: "daemon-1",
    browserId: "browser-1",
    targetTabId: 17,
    targetFrameId: 0,
    action: "click",
    paramsSha256: PARAMS_HASH,
    approvalFingerprint: FINGERPRINT,
    ...overrides
  };
}

describe("extension-owned one-time approval grants", () => {
  it("rejects a fake approved command when the popup created no local grant", () => {
    const ledger = new ApprovalGrantLedger();
    expect(ledger.consume(claim(), NOW)).toEqual({
      ok: false,
      code: "approval_grant_missing",
      mutated: false
    });
  });

  it("consumes a matching grant before execution and rejects replay", () => {
    const ledger = new ApprovalGrantLedger([grant()]);
    expect(ledger.consume(claim(), NOW)).toMatchObject({ ok: true, mutated: true });
    expect(ledger.size).toBe(0);
    expect(ledger.consume(claim(), NOW)).toEqual({
      ok: false,
      code: "approval_grant_missing",
      mutated: false
    });
  });

  it("rejects duplicate approval IDs instead of overwriting a local grant", () => {
    const ledger = new ApprovalGrantLedger([grant()]);
    expect(() => ledger.add(grant(), NOW)).toThrow(/already uses this ID/);
    expect(ledger.size).toBe(1);
  });

  it("revokes a cancelled grant and every grant bound to a disconnected daemon", () => {
    const ledger = new ApprovalGrantLedger([
      grant(),
      grant({ approval_id: "approval-2" }),
      grant({ approval_id: "approval-3", daemon_instance_id: "daemon-2" })
    ]);
    expect(ledger.revoke("approval-1")).toBe(true);
    expect(ledger.revokeForDaemon("daemon-1")).toBe(1);
    expect(ledger.snapshot()).toMatchObject([{ approval_id: "approval-3", daemon_instance_id: "daemon-2" }]);
  });

  it("revokes grants when their exact tab or frame navigates", () => {
    const ledger = new ApprovalGrantLedger([
      grant(),
      grant({ approval_id: "approval-2", target_frame_id: 2 }),
      grant({ approval_id: "approval-3", target_tab_id: 18 })
    ]);
    expect(ledger.revokeForTarget(17, 2)).toBe(1);
    expect(ledger.snapshot().map((item) => item.approval_id)).toEqual(["approval-1", "approval-3"]);
    expect(ledger.revokeForTarget(17)).toBe(1);
    expect(ledger.snapshot()).toMatchObject([{ approval_id: "approval-3", target_tab_id: 18 }]);
  });

  it.each([
    { action: "navigate" as const },
    { paramsSha256: `sha256:${"c".repeat(64)}` },
    { approvalFingerprint: `sha256:${"d".repeat(64)}` },
    { daemonInstanceId: "daemon-2" },
    { browserId: "browser-2" },
    { targetTabId: 18 },
    { targetFrameId: 2 }
  ])("consumes and rejects a mismatched claim: %o", (mismatch) => {
    const ledger = new ApprovalGrantLedger([grant()]);
    expect(ledger.consume(claim(mismatch), NOW)).toEqual({
      ok: false,
      code: "approval_grant_mismatch",
      mutated: true
    });
    expect(ledger.size).toBe(0);
  });

  it("hashes command parameters with the protocol canonical JSON ordering", async () => {
    await expect(hashCommandParams({ z: 1, nested: { b: true, a: "x" }, a: 2 }))
      .resolves.toBe(await hashCommandParams({ a: 2, nested: { a: "x", b: true }, z: 1 }));
  });
});
