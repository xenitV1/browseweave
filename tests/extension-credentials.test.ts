import { describe, expect, it } from "vitest";
import {
  LOCAL_CREDENTIAL_HANDOFF_TTL_MS,
  MAX_REMOTE_CREDENTIAL_PERMISSION_MS,
  LocalCredentialHandoffLedger,
  RemoteCredentialPermissionLedger,
  credentialGrantTargetMatches,
  isLocalCredentialHandoff,
  isRemoteCredentialPermission,
  normalizeHttpsOrigin,
  scrubCredentialValues,
  validateCredentialCommandPayload,
  type LocalCredentialHandoff,
  type RemoteCredentialPermission
} from "../extension/src/credentials";

const NOW = Date.parse("2030-01-01T00:00:00.000Z");
const SECRET_SENTINEL = "BW_SECRET_SENTINEL_DO_NOT_LEAK";

function handoff(overrides: Partial<LocalCredentialHandoff> = {}): LocalCredentialHandoff {
  return {
    handoff_id: "credential-11111111111111111111111111111111",
    tab_id: 17,
    frame_id: 0,
    origin: "https://login.example.com",
    document_epoch: "document-epoch-1",
    binding_fingerprint: `sha256:${"a".repeat(64)}`,
    fields: [
      { ref: "bw-1", kind: "username", label: "Email" },
      { ref: "bw-2", kind: "password", label: "Password" }
    ],
    submit: true,
    created_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + LOCAL_CREDENTIAL_HANDOFF_TTL_MS).toISOString(),
    ...overrides
  };
}

function permission(overrides: Partial<RemoteCredentialPermission> = {}): RemoteCredentialPermission {
  return {
    permission_id: "remote-credential-11111111111111111111111111111111",
    origin: "https://login.example.com",
    created_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 15 * 60_000).toISOString(),
    one_use: true,
    ...overrides
  };
}

describe("BrowseWeave credential boundary", () => {
  it("accepts only one or two unique username/password refs with exact payload keys", () => {
    expect(validateCredentialCommandPayload({
      tab_id: 17,
      fields: [{ ref: "bw-1", kind: "username" }, { ref: "bw-2", kind: "password" }],
      submit: true
    }, false)).toEqual({
      tabId: 17,
      frameId: 0,
      fields: [{ ref: "bw-1", kind: "username" }, { ref: "bw-2", kind: "password" }],
      submit: true
    });

    expect(() => validateCredentialCommandPayload({
      tab_id: 17,
      fields: [{ ref: "bw-1", kind: "password" }, { ref: "bw-1", kind: "username" }]
    }, false)).toThrow(/unique/);
    expect(() => validateCredentialCommandPayload({
      tab_id: 17,
      fields: [{ ref: "bw-1", kind: "password" }, { ref: "bw-2", kind: "password" }]
    }, false)).toThrow(/unique/);
    expect(() => validateCredentialCommandPayload({
      tab_id: 17,
      fields: [{ ref: "bw-1", kind: "otp" }]
    }, false)).toThrow(/username\/password/);
    expect(() => validateCredentialCommandPayload({
      tab_id: 17,
      fields: [{ ref: "bw-1", kind: "card" }]
    }, false)).toThrow(/username\/password/);
    expect(() => validateCredentialCommandPayload({
      tab_id: 17,
      fields: [{ ref: "bw-1", kind: "username" }],
      wildcard_origin: "*"
    }, false)).toThrow(/unsupported fields/);
  });

  it("enforces remote value presence and length without returning or retaining the sentinel", () => {
    const payload = {
      tab_id: 17,
      frame_id: 3,
      fields: [
        { ref: "bw-1", kind: "username", value: "person@example.com" },
        { ref: "bw-2", kind: "password", value: SECRET_SENTINEL }
      ],
      submit: false
    };
    const parsed = validateCredentialCommandPayload(payload, true);
    expect(parsed.fields).toHaveLength(2);
    scrubCredentialValues(payload);
    scrubCredentialValues({ fields: parsed.fields });
    expect(JSON.stringify(payload)).not.toContain(SECRET_SENTINEL);
    expect(JSON.stringify(parsed)).not.toContain(SECRET_SENTINEL);

    expect(() => validateCredentialCommandPayload({
      tab_id: 17,
      fields: [{ ref: "bw-1", kind: "username", value: "x".repeat(321) }]
    }, true)).toThrow(/safe length limit/);
    expect(() => validateCredentialCommandPayload({
      tab_id: 17,
      fields: [{ ref: "bw-1", kind: "password", value: "x".repeat(1025) }]
    }, true)).toThrow(/safe length limit/);
  });

  it("normalizes only exact HTTPS origins and rejects insecure or wildcard targets", () => {
    expect(normalizeHttpsOrigin("https://login.example.com/path?x=1")).toBe("https://login.example.com");
    expect(normalizeHttpsOrigin("https://login.example.com:8443/path")).toBe("https://login.example.com:8443");
    expect(() => normalizeHttpsOrigin("http://login.example.com")).toThrow(/HTTPS/);
    expect(() => normalizeHttpsOrigin("https://*.example.com")).toThrow(/exact HTTPS origin/);
    expect(() => normalizeHttpsOrigin("https://user:pass@example.com")).toThrow(/exact HTTPS origin/);
  });

  it("binds the trusted remote prompt to the exact visible tab and origin", () => {
    expect(credentialGrantTargetMatches({
      expectedOrigin: "https://login.example.com",
      expectedTabId: 17,
      currentUrl: "https://login.example.com/sign-in",
      currentTabId: 17
    })).toBe(true);
    expect(credentialGrantTargetMatches({
      expectedOrigin: "https://login.example.com",
      expectedTabId: 17,
      currentUrl: "https://evil.example/sign-in",
      currentTabId: 17
    })).toBe(false);
    expect(credentialGrantTargetMatches({
      expectedOrigin: "https://login.example.com",
      expectedTabId: 17,
      currentUrl: "https://login.example.com/sign-in",
      currentTabId: 18
    })).toBe(false);
    expect(credentialGrantTargetMatches({
      expectedOrigin: "https://login.example.com/path",
      expectedTabId: 17,
      currentUrl: "https://login.example.com/path",
      currentTabId: 17
    })).toBe(false);
  });

  it("validates five-minute local handoffs and consumes exactly once under a race", async () => {
    expect(isLocalCredentialHandoff(handoff())).toBe(true);
    expect(isLocalCredentialHandoff(handoff({
      expires_at: new Date(NOW + LOCAL_CREDENTIAL_HANDOFF_TTL_MS + 1).toISOString()
    }))).toBe(false);

    const ledger = new LocalCredentialHandoffLedger([handoff()]);
    const [first, second] = await Promise.all([
      Promise.resolve().then(() => ledger.consume(handoff().handoff_id, NOW + 1)),
      Promise.resolve().then(() => ledger.consume(handoff().handoff_id, NOW + 1))
    ]);
    expect([first, second].filter(Boolean)).toHaveLength(1);
    expect(ledger.consume(handoff().handoff_id, NOW + 1)).toBeNull();
  });

  it("revokes local handoffs by tab and never persists credential values", () => {
    const second = handoff({
      handoff_id: "credential-22222222222222222222222222222222",
      tab_id: 18
    });
    const ledger = new LocalCredentialHandoffLedger([handoff(), second]);
    expect(ledger.revokeTab(17)).toBe(1);
    expect(ledger.snapshot()).toEqual([second]);
    expect(JSON.stringify(ledger.snapshot())).not.toContain(SECRET_SENTINEL);
  });

  it("keeps remote filling off by default and consumes an exact-origin grant once", async () => {
    const ledger = new RemoteCredentialPermissionLedger();
    expect(ledger.consumeOrigin("https://login.example.com", NOW)).toBeNull();
    ledger.add(permission(), NOW);

    const [first, second] = await Promise.all([
      Promise.resolve().then(() => ledger.consumeOrigin("https://login.example.com", NOW + 1)),
      Promise.resolve().then(() => ledger.consumeOrigin("https://login.example.com", NOW + 1))
    ]);
    expect([first, second].filter(Boolean)).toHaveLength(1);
    expect(ledger.consumeOrigin("https://login.example.com", NOW + 1)).toBeNull();
  });

  it("rejects cross-origin, expired, over-24-hour, and duplicate-ID permissions", () => {
    expect(isRemoteCredentialPermission(permission())).toBe(true);
    expect(isRemoteCredentialPermission(permission({
      expires_at: new Date(NOW + MAX_REMOTE_CREDENTIAL_PERMISSION_MS + 1).toISOString()
    }))).toBe(false);
    expect(isRemoteCredentialPermission(permission({ origin: "http://login.example.com" }))).toBe(false);

    const ledger = new RemoteCredentialPermissionLedger([permission()]);
    expect(ledger.consumeOrigin("https://sub.login.example.com", NOW + 1)).toBeNull();
    expect(ledger.snapshot()).toHaveLength(1);
    expect(() => ledger.add(permission(), NOW + 1)).toThrow(/already uses this ID/);
    expect(ledger.snapshot()).toHaveLength(1);
  });

  it("replaces only an earlier permission for the same exact origin and supports revocation", () => {
    const ledger = new RemoteCredentialPermissionLedger([permission()]);
    const replacement = permission({
      permission_id: "remote-credential-22222222222222222222222222222222",
      expires_at: new Date(NOW + 60 * 60_000).toISOString()
    });
    ledger.add(replacement, NOW + 1);
    expect(ledger.snapshot()).toEqual([replacement]);
    expect(ledger.revoke(replacement.permission_id)).toBe(true);
    expect(ledger.snapshot()).toEqual([]);
  });
});
