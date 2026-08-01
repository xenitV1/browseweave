import { describe, expect, it } from "vitest";
import { isComposedDescendant, queryAllOpenElements } from "../extension/src/shared/dom-utils";
import {
  BRIDGE_URL,
  MAX_MANAGED_TABS,
  approvalGuardDecision,
  approvalFingerprint,
  boundedScroll,
  captureImageDimensions,
  canCreateManagedTab,
  classifyRisk,
  compactSelectOptions,
  MAX_MANAGED_TABS_TOTAL,
  agentOwnsManagedTab,
  canCreateManagedTabForAgent,
  compactSubframeUrl,
  isAgentId,
  managedTabOwner,
  normalizeManagedTabLedger,
  selectManagedTabsForAgentCleanup,
  diffSnapshots,
  externalNavigationRisk,
  fillBatchKeystrokeIntervalMs,
  isStableRef,
  isApprovalFingerprint,
  isMeaningfulPlainText,
  isManagedTabOwned,
  managedTabsAfterClose,
  mapVisualCoordinates,
  maskUntrustedApprovalDescription,
  maskSensitiveValue,
  normalizeManagedTabIds,
  normalizeNavigationUrl,
  keystrokeIntervalMs,
  mutationIntervalMs,
  MUTATION_INTERVAL_COMMITTING_MS,
  MUTATION_INTERVAL_CONTINUING_MS,
  MUTATION_INTERVAL_STRESSED_MS,
  normalizePagination,
  normalizeScreenshotOptions,
  formatSnapshotCursor,
  parseSnapshotCursor,
  MAX_SNAPSHOT_OFFSET,
  normalizeSnapshotOptions,
  normalizeText,
  normalizeViewportState,
  normalizeWaitOptions,
  pointerApproachPoints,
  redactUrl,
  sameViewportState,
  scrollStepDeltas,
  TYPING_MAX_INTERVAL_MS,
  selectChromiumBrand,
  selectManagedTabsForCleanup,
  sensitiveFieldCategory,
  sensitivePressDecision,
  stableSafetyMaterial,
  shouldKeepPlainTextCandidate,
  validateFillValue
} from "../extension/src/shared/pure";

describe("BrowseWeave extension pure safety functions", () => {
  it("pins the bridge address to the loopback WebSocket", () => {
    expect(BRIDGE_URL).toBe("ws://127.0.0.1:32110");
  });

  it("classifies and masks password, verification-code, and card fields", () => {
    const password = { type: "password", name: "account_password" };
    const otp = { autocomplete: "one-time-code", name: "verification_code" };
    const card = { autocomplete: "cc-number", name: "cardNumber" };

    expect(sensitiveFieldCategory(password)).toBe("password");
    expect(sensitiveFieldCategory(otp)).toBe("2fa");
    expect(sensitiveFieldCategory(card)).toBe("payment");
    expect(maskSensitiveValue("çok-gizli", password)).toBe("[MASKED:password]");
    expect(maskSensitiveValue("123456", otp)).toBe("[MASKED:2fa]");
    expect(maskSensitiveValue("4111111111111111", card)).toBe("[MASKED:payment]");
  });

  it("masks likely secrets in untrusted approval descriptions", () => {
    const masked = maskUntrustedApprovalDescription(
      "Password: hunter2 token=abcdefghijklmnopqrstuvwxyz1234567890 card 4111 1111 1111 1111"
    );
    expect(masked).not.toContain("hunter2");
    expect(masked).not.toContain("abcdefghijklmnopqrstuvwxyz1234567890");
    expect(masked).not.toContain("4111 1111 1111 1111");
    expect(masked).toContain("[MASKED]");
  });

  it("reads PNG dimensions in an MV3 worker without DOM Image", () => {
    const onePixelPng = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
    expect(captureImageDimensions(onePixelPng)).toEqual({ width: 1, height: 1 });
    expect(() => captureImageDimensions("data:text/plain;base64,SGVsbG8=")).toThrow(/supported PNG or JPEG/);
  });

  it("caps the BrowseWeave tab ledger at 10 and releases manually closed tabs", () => {
    const tenTabs = Array.from({ length: MAX_MANAGED_TABS }, (_, index) => index + 1);
    expect(canCreateManagedTab(tenTabs)).toBe(false);
    expect(canCreateManagedTab(tenTabs.filter((id) => id !== 4))).toBe(true);
    expect(normalizeManagedTabIds([4, 2, 4, -1, "7", 3.5, 8])).toEqual([2, 4, 8]);
  });

  it("selects only BrowseWeave-owned tabs for bulk cleanup", () => {
    const managed = [11, 12, 13];
    expect(selectManagedTabsForCleanup(managed)).toEqual([11, 12, 13]);
    expect(selectManagedTabsForCleanup(managed, [12, 999, 42])).toEqual([12]);
    expect(selectManagedTabsForCleanup([], [999])).toEqual([]);
  });

  it("rejects a user tab on single close and removes a managed tab from the ledger", () => {
    const managed = [11, 12, 13];
    expect(isManagedTabOwned(managed, 999)).toBe(false);
    expect(managedTabsAfterClose(managed, 999)).toEqual([11, 12, 13]);
    expect(isManagedTabOwned(managed, 12)).toBe(true);
    expect(managedTabsAfterClose(managed, 12)).toEqual([11, 13]);
  });

  it("keeps execution closed when an approved risk disappears or its target changes", () => {
    expect(approvalGuardDecision({
      hasRisk: false,
      approved: true,
      revalidateOnly: false,
      suppliedFingerprint: "sha256:old"
    })).toBe("approval_context_changed");
    expect(approvalGuardDecision({
      hasRisk: true,
      approved: true,
      revalidateOnly: false,
      currentFingerprint: "sha256:new",
      suppliedFingerprint: "sha256:old"
    })).toBe("approval_required");
    expect(approvalGuardDecision({
      hasRisk: true,
      approved: false,
      revalidateOnly: true,
      currentFingerprint: "sha256:new"
    })).toBe("approval_required");
    expect(approvalGuardDecision({
      hasRisk: false,
      approved: false,
      revalidateOnly: true
    })).toBe("approval_no_longer_required");
  });

  it("keeps ordinary interactions outside the approval gate", () => {
    expect(classifyRisk({ action: "click", tag: "button", text: "Sonraki sayfa" })).toBeNull();
    expect(classifyRisk({ action: "type", tag: "input", name: "first_name" })).toBeNull();
  });

  it("gates external navigation by origin while allowing same-origin and loopback targets", () => {
    expect(externalNavigationRisk(
      "https://app.example.com/account",
      "https://app.example.com/help",
      "existing_tab"
    )).toBeNull();
    expect(externalNavigationRisk(
      "https://app.example.com/account",
      "https://auth.example.com/login",
      "existing_tab"
    )).toMatchObject({ category: "external_navigation", destinationOrigin: "https://auth.example.com" });
    expect(externalNavigationRisk(undefined, "http://127.0.0.1:4173", "new_tab")).toBeNull();
    expect(externalNavigationRisk(undefined, "https://example.com", "new_tab"))
      .toMatchObject({ category: "external_navigation", destinationOrigin: "https://example.com" });
    expect(externalNavigationRisk(undefined, "about:blank", "new_tab")).toBeNull();
    expect(externalNavigationRisk("about:blank", "https://example.com", "existing_tab"))
      .toMatchObject({
        category: "external_navigation",
        destinationOrigin: "https://example.com",
        reason: "Leaving a blank or unknown-origin tab"
      });
    expect(externalNavigationRisk(undefined, "https://example.com", "existing_tab"))
      .toMatchObject({ category: "external_navigation", destinationOrigin: "https://example.com" });
    expect(externalNavigationRisk("about:blank", "http://localhost:4173", "existing_tab")).toBeNull();
  });

  it("allows only navigation keys on one-time-code and payment widgets", () => {
    expect(sensitivePressDecision({ autocomplete: "one-time-code" }, "Enter"))
      .toEqual({ disposition: "reject", category: "2fa" });
    expect(sensitivePressDecision({ role: "textbox", ariaLabel: "Doğrulama kodu" }, "Tab"))
      .toEqual({ disposition: "allow_navigation", category: "2fa" });
    expect(sensitivePressDecision({ autocomplete: "cc-number" }, " "))
      .toEqual({ disposition: "reject", category: "payment" });
    expect(sensitivePressDecision({ role: "textbox", ariaLabel: "Kart numarası" }, "1"))
      .toEqual({ disposition: "reject", category: "payment" });
    // A payment signal from either classifier rejects, even when the label also
    // looks like a password.
    expect(sensitivePressDecision({ type: "password", ariaLabel: "Ödeme şifresi" }, "1"))
      .toEqual({ disposition: "reject", category: "payment" });
  });

  it("keeps keys available on password and account-security targets", () => {
    // Neither is a human-entry-only class: submitting or moving through a login
    // form is ordinary work, and an account-security effect is already reachable
    // by clicking the same control. Both stay in the approval channel instead of
    // a dead end no approval can open.
    expect(sensitivePressDecision({ type: "password", name: "password" }, "Enter"))
      .toEqual({ disposition: "normal" });
    expect(sensitivePressDecision({ role: "textbox", ariaLabel: "Custom login password" }, "a"))
      .toEqual({ disposition: "normal" });
    expect(sensitivePressDecision({ role: "button", text: "Account security" }, "Enter"))
      .toEqual({ disposition: "normal" });
    expect(classifyRisk({ role: "button", text: "Account security", action: "press", key: "Enter" }))
      .toEqual({ category: "security", reason: "Account security or access setting" });
    // The value itself is still refused by the type and form-fill paths, which
    // rely on this classification staying intact.
    expect(sensitiveFieldCategory({ type: "password", name: "password" })).toBe("password");
    expect(sensitivePressDecision({ role: "textbox", ariaLabel: "Project name" }, "a"))
      .toEqual({ disposition: "normal" });
  });

  it("exempts only safe GET search forms from general submit approval", () => {
    const safeSearch = {
      action: "click",
      tag: "button",
      text: "Ara",
      isSubmit: true,
      insideForm: true,
      formMethod: "get",
      formIsSearch: true,
      formHasSensitiveField: false
    };
    expect(classifyRisk(safeSearch)).toBeNull();
    expect(classifyRisk({ ...safeSearch, formMethod: "post" })).toMatchObject({ category: "form_submit" });
    expect(classifyRisk({ ...safeSearch, formHasSensitiveField: true })).toMatchObject({ category: "form_submit" });
    expect(classifyRisk({ ...safeSearch, text: "Ödeme ara" })).toMatchObject({ category: "payment" });
  });

  it.each([
    [{ action: "click", tag: "button", text: "Mesajı gönder" }, "message"],
    [{ action: "click", tag: "button", text: "Hesabı sil" }, "delete"],
    [{ action: "click", tag: "button", text: "Ödemeyi tamamla" }, "payment"],
    [{ action: "click", tag: "a", text: "Güvenlik ayarları" }, "security"],
    [{ action: "type", tag: "input", type: "password" }, "password"],
    [{ action: "type", tag: "input", autocomplete: "one-time-code" }, "2fa"],
    [{ action: "click", tag: "button", isSubmit: true }, "form_submit"],
    [{ action: "press", tag: "input", insideForm: true, key: "Enter" }, "form_submit"]
  ] as const)("marks a risky action as %s", (input, category) => {
    expect(classifyRisk(input)).toMatchObject({ category });
  });

  it("masks sensitive URL parameters while preserving a normal search term", () => {
    const output = new URL(redactUrl("https://example.com/search?q=zen&access_token=abc&session-id=xyz#oauth-secret"));
    expect(output.searchParams.get("q")).toBe("zen");
    expect(output.searchParams.get("access_token")).toBe("[MASKED]");
    expect(output.searchParams.get("session-id")).toBe("[MASKED]");
    expect(output.hash).toBe("#fragment-redacted");
  });

  it("scopes managed tabs to the agent that opened them", () => {
    const alice = "11111111-2222-4333-8444-555555555555";
    const bob = "99999999-8888-4777-8666-555555555555";
    expect(isAgentId(alice)).toBe(true);
    expect(isAgentId("not-an-agent")).toBe(false);
    expect(isAgentId(undefined)).toBe(false);

    const ledger = [{ id: 1, owner: alice }, { id: 2, owner: bob }, { id: 3, owner: null }];
    expect(agentOwnsManagedTab(ledger, 1, alice)).toBe(true);
    // Another agent's tab: readable, never drivable.
    expect(agentOwnsManagedTab(ledger, 2, alice)).toBe(false);
    // A ledger written before ownership existed answers to nobody, so whichever
    // agent connects first cannot claim it.
    expect(agentOwnsManagedTab(ledger, 3, alice)).toBe(false);
    expect(agentOwnsManagedTab(ledger, 3, bob)).toBe(false);
    // A tab BrowseWeave never opened is not in the ledger at all.
    expect(managedTabOwner(ledger, 99)).toBeUndefined();
    // No identity means no ownership, so a command without one cannot drive
    // tabs that belong to a real agent.
    expect(agentOwnsManagedTab(ledger, 1, null)).toBe(false);

    // A malformed owner degrades to unowned rather than failing the ledger.
    expect(normalizeManagedTabLedger([{ id: 4, owner: "bogus" }])).toEqual([{ id: 4, owner: null }]);
    expect(normalizeManagedTabLedger([{ id: 5 }, { id: 5, owner: alice }])).toEqual([{ id: 5, owner: null }]);
    expect(normalizeManagedTabLedger("nope")).toEqual([]);
  });

  it("gives each agent its own allowance under one shared ceiling", () => {
    const alice = "11111111-2222-4333-8444-555555555555";
    const bob = "99999999-8888-4777-8666-555555555555";
    const own = (owner: string, count: number, from: number) =>
      Array.from({ length: count }, (unused, index) => ({ id: from + index, owner }));

    // Alice at her allowance cannot open more, but Bob is untouched by it:
    // neither agent can starve the other by opening first.
    const aliceFull = own(alice, MAX_MANAGED_TABS, 1);
    expect(canCreateManagedTabForAgent(aliceFull, alice)).toBe(false);
    expect(canCreateManagedTabForAgent(aliceFull, bob)).toBe(true);

    // The shared ceiling still bounds the browser itself.
    const atCeiling = [...own(alice, MAX_MANAGED_TABS, 1), ...own(bob, MAX_MANAGED_TABS, 100)];
    expect(atCeiling).toHaveLength(MAX_MANAGED_TABS_TOTAL);
    expect(canCreateManagedTabForAgent(atCeiling, bob)).toBe(false);
    expect(canCreateManagedTabForAgent(atCeiling, "77777777-6666-4555-8444-333333333333")).toBe(false);

    // Without an identity nothing may be opened as owned.
    expect(canCreateManagedTabForAgent([], null)).toBe(false);
  });

  it("cleans up only the caller's tabs, plus the ones no agent owns", () => {
    const alice = "11111111-2222-4333-8444-555555555555";
    const bob = "99999999-8888-4777-8666-555555555555";
    const ledger = [{ id: 1, owner: alice }, { id: 2, owner: bob }, { id: 3, owner: null }];

    // The default cleanup that ends a session must not destroy the other
    // session's work; unowned tabs are collectable so they cannot hold the
    // shared ceiling forever with nobody able to reclaim them.
    expect(selectManagedTabsForAgentCleanup(ledger, alice)).toEqual([1, 3]);
    expect(selectManagedTabsForAgentCleanup(ledger, bob)).toEqual([2, 3]);
    // An explicit request is still intersected with what the caller may close.
    expect(selectManagedTabsForAgentCleanup(ledger, alice, [1, 2, 3])).toEqual([1, 3]);
    expect(selectManagedTabsForAgentCleanup(ledger, alice, [2])).toEqual([]);
    expect(selectManagedTabsForAgentCleanup(ledger, null)).toEqual([3]);
  });

  it("compacts only an oversized subframe URL, and keeps the omission visible", () => {
    // A short embed URL is usually the part that identifies the frame.
    const short = "https://player.example.com/embed?video=42";
    expect(compactSubframeUrl(short)).toBe(short);

    // A real search-results page embeds this widget; its query alone is 2.3 KB
    // of base64 state that no caller acts on, while the frame is addressed by
    // frame_id. Untrimmed it outweighs the page content it displaces.
    const widget = `https://ogs.google.com/widget/app?hl=tr&xstg=${"A".repeat(2_300)}`;
    const compacted = compactSubframeUrl(widget);
    expect(compacted).toBe("https://ogs.google.com/widget/app?[TRIMMED]");
    expect(compacted.length).toBeLessThan(widget.length / 40);

    // Origin and path survive, so the reader still knows which document it is.
    expect(compactSubframeUrl(`https://www.youtube.com/embed/?embed_config=${"B".repeat(500)}`))
      .toBe("https://www.youtube.com/embed/?[TRIMMED]");

    // Sensitive values are still masked before any length decision. The mask is
    // percent-encoded because redactUrl sets it through searchParams.
    expect(compactSubframeUrl("https://example.com/f?access_token=abc"))
      .toBe("https://example.com/f?access_token=%5BMASKED%5D");

    // A path long enough on its own is still bounded.
    const longPath = `https://example.com/${"p".repeat(400)}`;
    expect(compactSubframeUrl(longPath).length).toBeLessThanOrEqual(200 + "[TRIMMED]".length);

    // Something that is not a URL cannot grow the budget either.
    expect(compactSubframeUrl("x".repeat(1_000)).length).toBeLessThanOrEqual(200 + "[TRIMMED]".length);
  });

  it("allows navigation only to HTTP, HTTPS, and about:blank", () => {
    expect(normalizeNavigationUrl("https://example.com/path")).toBe("https://example.com/path");
    expect(normalizeNavigationUrl("about:blank")).toBe("about:blank");
    expect(() => normalizeNavigationUrl("javascript:alert(1)")).toThrow(/HTTP or HTTPS/);
    expect(() => normalizeNavigationUrl("file:///etc/passwd")).toThrow(/HTTP or HTTPS/);
    expect(() => normalizeNavigationUrl("https://user:pass@example.com")).toThrow(/username or password/);
  });

  it("bounds text and accepts only generated reference syntax", () => {
    expect(normalizeText("  bir   iki  ")).toBe("bir iki");
    expect(normalizeText("abcdef", 4)).toBe("abc…");
    expect(isStableRef("bw-12")).toBe(true);
    expect(isStableRef("bw-0")).toBe(false);
    expect(isStableRef("element-12")).toBe(false);
  });

  it("selects Google Chrome over generic Chromium for every UA-CH brand order", () => {
    const chrome = { brand: "Google Chrome", version: "150" };
    const chromium = { brand: "Chromium", version: "150" };
    const grease = { brand: "Not(A:Brand", version: "99" };
    for (const brands of [
      [chrome, chromium, grease],
      [chrome, grease, chromium],
      [chromium, chrome, grease],
      [chromium, grease, chrome],
      [grease, chrome, chromium],
      [grease, chromium, chrome]
    ]) expect(selectChromiumBrand(brands)).toEqual(chrome);
    expect(selectChromiumBrand([grease, chromium])).toEqual(chromium);
    expect(selectChromiumBrand([grease])).toBeUndefined();
    expect(selectChromiumBrand(null)).toBeUndefined();
  });

  it("strictly validates fill_form values for checkbox, radio, and text controls", () => {
    expect(validateFillValue("checkbox", true)).toEqual({ kind: "checkbox", checked: true });
    expect(validateFillValue("checkbox", false)).toEqual({ kind: "checkbox", checked: false });
    expect(validateFillValue("radio", "premium")).toEqual({ kind: "radio", value: "premium" });
    expect(validateFillValue("text", "Mehmet")).toEqual({ kind: "text", text: "Mehmet" });
    expect(() => validateFillValue("checkbox", "true")).toThrow(/true or false/);
    expect(() => validateFillValue("radio", true)).toThrow(/must be text/);
    expect(() => validateFillValue("text", 42)).toThrow(/must be text/);
  });

  it("clamps tab pagination to safe limits", () => {
    expect(normalizePagination(undefined, undefined)).toEqual({ limit: 100, offset: 0 });
    expect(normalizePagination(25, 50)).toEqual({ limit: 25, offset: 50 });
    expect(normalizePagination(999, -10)).toEqual({ limit: 200, offset: 0 });
  });

  it("bounds scroll deltas by 2,000 pixels and the container edge", () => {
    expect(boundedScroll(100, 1_000, 300)).toEqual({ position: 400, appliedDelta: 300 });
    expect(boundedScroll(900, 1_000, 5_000)).toEqual({ position: 1_000, appliedDelta: 100 });
    expect(boundedScroll(20, 1_000, -5_000)).toEqual({ position: 0, appliedDelta: -20 });
  });

  it("normalizes snapshot modes with compact defaults and hard limits", () => {
    expect(normalizeSnapshotOptions(undefined, undefined, undefined)).toEqual({
      mode: "balanced",
      maxElements: 260,
      query: "",
      offset: 0
    });
    expect(normalizeSnapshotOptions("interactive", 9_999, "  ödeme   düğmesi ")).toEqual({
      mode: "interactive",
      maxElements: 400,
      query: "ödeme düğmesi",
      offset: 0
    });
    expect(normalizeSnapshotOptions("full", 9_999, "x")).toMatchObject({ mode: "full", maxElements: 1_200 });
    expect(normalizeSnapshotOptions("bilinmeyen", 20, "x")).toMatchObject({ mode: "balanced", maxElements: 20 });
  });

  it("bounds the snapshot continuation offset", () => {
    expect(normalizeSnapshotOptions("balanced", 20, "", 140)).toMatchObject({ offset: 140 });
    expect(normalizeSnapshotOptions("balanced", 20, "", -5)).toMatchObject({ offset: 0 });
    expect(normalizeSnapshotOptions("balanced", 20, "", 1.5)).toMatchObject({ offset: 0 });
    expect(normalizeSnapshotOptions("balanced", 20, "", "140")).toMatchObject({ offset: 0 });
    expect(normalizeSnapshotOptions("balanced", 20, "", 10_000_000))
      .toMatchObject({ offset: MAX_SNAPSHOT_OFFSET });
  });

  it("round-trips a snapshot cursor and refuses anything it did not produce", () => {
    const cursor = formatSnapshotCursor(new Map([[3, 12], [0, 140]]));
    // Frames are ordered so the same position always produces the same cursor.
    expect(cursor).toBe("c1:0=140,3=12");
    expect(parseSnapshotCursor(cursor)).toEqual(new Map([[0, 140], [3, 12]]));

    // A frame that delivered nothing carries no position.
    expect(formatSnapshotCursor(new Map([[0, 0]]))).toBe("");
    expect(formatSnapshotCursor(new Map())).toBe("");
    expect(formatSnapshotCursor(new Map([[0, MAX_SNAPSHOT_OFFSET + 1]]))).toBe("");
    expect(formatSnapshotCursor(new Map([[-1, 10]]))).toBe("");

    for (const value of [
      undefined,
      "",
      "c1:",
      "c2:0=1",
      "0=1",
      "c1:0=1,",
      "c1:0=1,0=2",
      "c1:a=1",
      "c1:0=99999999",
      `c1:0=${MAX_SNAPSHOT_OFFSET + 1}`,
      `c1:${"0=1,".repeat(200)}0=2`
    ]) expect(parseSnapshotCursor(value)).toBeNull();
  });

  it("minimally separates added, changed, and removed refs between snapshots", () => {
    const previous = {
      frames: [{ frame_id: 0, title: "A", elements: [
        { ref: "bw-1", text: "aynı" },
        { ref: "bw-2", text: "eski" },
        { ref: "bw-3", text: "kaldır" }
      ] }],
      incomplete_frames: []
    };
    const current = {
      frames: [{ frame_id: 0, title: "B", elements: [
        { ref: "bw-1", text: "aynı" },
        { ref: "bw-2", text: "yeni" },
        { ref: "bw-4", text: "eklendi" }
      ] }],
      incomplete_frames: []
    };
    const delta = diffSnapshots(previous, current);
    expect(delta.added).toEqual([{ frame_id: 0, element: { ref: "bw-4", text: "eklendi" } }]);
    expect(delta.changed).toEqual([{ frame_id: 0, element: { ref: "bw-2", text: "yeni" } }]);
    expect(delta.removed).toEqual([{ frame_id: 0, ref: "bw-3" }]);
    expect(delta.frame_changes).toMatchObject([{ frame_id: 0, state: "changed" }]);
    expect(delta.order_changed_frames).toEqual([0]);
  });

  it("creates an order-independent approval fingerprint in full SHA-256 form", async () => {
    const first = await approvalFingerprint({ action: "click", target: { ref: "bw-1", role: "button" } });
    const same = await approvalFingerprint({ target: { role: "button", ref: "bw-1" }, action: "click" });
    const changed = await approvalFingerprint({ action: "click", target: { ref: "bw-2", role: "button" } });
    expect(isApprovalFingerprint(first)).toBe(true);
    expect(first).toBe(same);
    expect(changed).not.toBe(first);
  });

  it("keeps different sensitive navigation query values distinct inside the fingerprint", async () => {
    const first = await approvalFingerprint({
      action: "navigate",
      url: "https://example.com/callback?access_token=first-secret"
    });
    const second = await approvalFingerprint({
      action: "navigate",
      url: "https://example.com/callback?access_token=second-secret"
    });
    expect(first).not.toBe(second);
  });

  it("detects target material changed across the SHA-256 await boundary with a synchronous token", async () => {
    const material = { href: "https://example.com/one", target: { ref: "bw-1", role: "button" } };
    const before = stableSafetyMaterial(material);
    const digest = approvalFingerprint(material);
    material.href = "https://example.com/two";
    await digest;
    expect(stableSafetyMaterial(material)).not.toBe(before);
  });

  it("collects light DOM and open shadow-root results without crossing closed roots", () => {
    const lightTarget = { id: "light", shadowRoot: null };
    const shadowTarget = { id: "shadow", shadowRoot: null };
    const closedTarget = { id: "closed", shadowRoot: null };
    const openRoot = {
      querySelectorAll: (selector: string) => selector === ".target" ? [shadowTarget] : []
    };
    const openHost = { shadowRoot: openRoot };
    const closedHost = { shadowRoot: null, hiddenChild: closedTarget };
    const fakeDocument = {
      querySelectorAll: (selector: string) => selector === "*" ? [openHost, closedHost] : [lightTarget]
    };

    const results = queryAllOpenElements(".target", fakeDocument as unknown as ParentNode);
    expect(results).toEqual([lightTarget, shadowTarget]);
    expect(results).not.toContain(closedTarget);
  });

  it("accepts only concise meaningful text from role-less SPA content", () => {
    expect(isMeaningfulPlainText("Sipariş durumu: hazırlanıyor")).toBe(true);
    expect(isMeaningfulPlainText("42")).toBe(true);
    expect(isMeaningfulPlainText("   ")).toBe(false);
    expect(isMeaningfulPlainText("---")).toBe(false);
    expect(isMeaningfulPlainText("x".repeat(401))).toBe(false);
    expect(shouldKeepPlainTextCandidate({
      text: "Hello World",
      directText: "",
      hasMeaningfulDescendant: true,
      hasSameTextDescendant: false
    })).toBe(false);
    expect(shouldKeepPlainTextCandidate({
      text: "Durum: Hazır",
      directText: "Durum:",
      hasMeaningfulDescendant: true,
      hasSameTextDescendant: false
    })).toBe(true);
  });

  it("caps select options at 30 while preserving an out-of-limit selected value", () => {
    const raw = Array.from({ length: 40 }, (_, index) => ({
      value: `v${index}`,
      label: `Seçenek ${index}`,
      selected: index === 39
    }));
    const compact = compactSelectOptions(raw, 30);
    expect(compact.options).toHaveLength(30);
    expect(compact.optionsTruncated).toBe(true);
    expect(compact.options.some((option) => option.value === "v39" && option.selected)).toBe(true);
    expect(compactSelectOptions(raw.slice(0, 2), 30, true).options.every((option) => option.value === "[MASKED]")).toBe(true);
  });

  it("connects shadow content to a light-DOM main area through composed ancestry", () => {
    const documentRoot = {};
    const main = { parentElement: null, getRootNode: () => documentRoot };
    const host = { parentElement: main, getRootNode: () => documentRoot };
    const shadowRoot = { host };
    const shadowParagraph = { parentElement: null, getRootNode: () => shadowRoot };
    expect(isComposedDescendant(main as unknown as Element, shadowParagraph as unknown as Element)).toBe(true);
  });

  it("normalizes wait and screenshot options to safe limits", () => {
    expect(normalizeWaitOptions(10, 9_000)).toEqual({ timeoutMs: 250, quietMs: 3_000 });
    expect(normalizeWaitOptions(99_000, 1)).toEqual({ timeoutMs: 15_000, quietMs: 100 });
    expect(normalizeScreenshotOptions(undefined, undefined)).toEqual({ format: "jpeg", quality: 85 });
    expect(normalizeScreenshotOptions("jpeg", 150)).toEqual({ format: "jpeg", quality: 100 });
    expect(normalizeScreenshotOptions("png", 40)).toEqual({ format: "png", quality: null });
  });

  it("maps screenshot pixels to zoom- and HiDPI-aware CSS coordinates", () => {
    expect(mapVisualCoordinates(960, 540, "screenshot_pixels", 1920, 1080, 1280, 720)).toEqual({
      x: 640,
      y: 360,
      coordinateSpace: "screenshot_pixels"
    });
    expect(mapVisualCoordinates(640, 360, "css_viewport", undefined, undefined, 1280, 720)).toEqual({
      x: 640,
      y: 360,
      coordinateSpace: "css_viewport"
    });
    expect(() => mapVisualCoordinates(10, 10, "screenshot_pixels", undefined, 1080, 1280, 720))
      .toThrow(/screenshot_width and screenshot_height/);
  });

  it("binds a screenshot exactly to document, viewport, and scroll state", () => {
    const capture = normalizeViewportState({
      viewport_css_width: 1280,
      viewport_css_height: 720,
      device_pixel_ratio: 1.5,
      scroll_x: 0,
      scroll_y: 240,
      document_epoch: "document-epoch-a"
    });
    expect(sameViewportState(capture, { ...capture })).toBe(true);
    expect(sameViewportState(capture, { ...capture, scroll_y: 241 })).toBe(false);
    expect(sameViewportState(capture, { ...capture, document_epoch: "document-epoch-b" })).toBe(false);
    expect(() => normalizeViewportState({ ...capture, document_epoch: "" })).toThrow(/document identity/);
  });

  it("paces keystrokes within a bounded budget and keeps long text on the fast path", () => {
    expect(keystrokeIntervalMs(0)).toBe(0);
    expect(keystrokeIntervalMs(1)).toBe(0);
    // Short strings are capped so a few characters cannot each wait too long.
    expect(keystrokeIntervalMs(5)).toBe(TYPING_MAX_INTERVAL_MS);
    // The budget is shared across the string, so total latency stays bounded.
    const interval = keystrokeIntervalMs(200);
    expect(interval).toBeGreaterThan(0);
    expect(interval * 199).toBeLessThanOrEqual(1_200);
    // Beyond the paced ceiling the original zero-delay behaviour is restored so
    // a large paste cannot approach the command timeout.
    expect(keystrokeIntervalMs(401)).toBe(0);
    expect(keystrokeIntervalMs(10_000)).toBe(0);
    expect(keystrokeIntervalMs(Number.NaN)).toBe(0);
  });

  it("splits a scroll into bounded steps that sum to the requested distance", () => {
    expect(scrollStepDeltas(0)).toEqual([]);
    expect(scrollStepDeltas(Number.NaN)).toEqual([]);
    for (const distance of [1, 120, 700, -700, 5_000, -12_345]) {
      const steps = scrollStepDeltas(distance);
      expect(steps.length).toBeGreaterThanOrEqual(1);
      expect(steps.reduce((total, step) => total + step, 0)).toBe(distance);
      expect(steps.every((step) => Number.isInteger(step))).toBe(true);
      expect(steps.every((step) => distance > 0 ? step >= 0 : step <= 0)).toBe(true);
      expect(steps.every((step) => Math.abs(step) <= 360)).toBe(true);
    }
    expect(scrollStepDeltas(100).length).toBe(1);
  });

  it("shares one bounded typing budget across a large form batch", () => {
    const lengths = new Array<number>(25).fill(51);
    const interval = fillBatchKeystrokeIntervalMs(lengths);
    expect(interval).toBeGreaterThan(0);
    expect(interval * lengths.reduce((sum, length) => sum + length - 1, 0)).toBeLessThanOrEqual(10_000);
    expect(fillBatchKeystrokeIntervalMs([10_000, 10_000])).toBe(0);
  });

  it("ends every pointer approach path exactly on the target", () => {
    const path = pointerApproachPoints({ x: 0, y: 0 }, { x: 300, y: 150 });
    expect(path).toHaveLength(3);
    expect(path.at(-1)).toEqual({ x: 300, y: 150 });
    expect(path.at(0)).not.toEqual({ x: 300, y: 150 });
    // A zero-length move still terminates on the target rather than emitting nothing.
    expect(pointerApproachPoints({ x: 10, y: 10 }, { x: 10, y: 10 }).at(-1)).toEqual({ x: 10, y: 10 });
    expect(pointerApproachPoints({ x: Number.NaN, y: 0 }, { x: 10, y: 10 })).toEqual([]);
  });

  it("keeps editing tight, commits conservatively, and backs off under stress", () => {
    expect(mutationIntervalMs({ action: "type" })).toBe(MUTATION_INTERVAL_CONTINUING_MS);
    expect(mutationIntervalMs({ action: "fill_form" })).toBe(MUTATION_INTERVAL_CONTINUING_MS);
    expect(mutationIntervalMs({ action: "scroll" })).toBe(MUTATION_INTERVAL_CONTINUING_MS);
    expect(mutationIntervalMs({ action: "press", key: "a" })).toBe(MUTATION_INTERVAL_CONTINUING_MS);
    // Anything that commits or navigates keeps the original conservative floor.
    expect(mutationIntervalMs({ action: "click" })).toBe(MUTATION_INTERVAL_COMMITTING_MS);
    expect(mutationIntervalMs({ action: "navigate" })).toBe(MUTATION_INTERVAL_COMMITTING_MS);
    expect(mutationIntervalMs({ action: "press", key: "Enter" })).toBe(MUTATION_INTERVAL_COMMITTING_MS);
    expect(mutationIntervalMs({ action: "press", key: " " })).toBe(MUTATION_INTERVAL_COMMITTING_MS);
    expect(mutationIntervalMs({ action: "press", key: "Space" })).toBe(MUTATION_INTERVAL_COMMITTING_MS);
    // Stress outranks every other classification.
    expect(mutationIntervalMs({ action: "type", stressed: true })).toBe(MUTATION_INTERVAL_STRESSED_MS);
    expect(mutationIntervalMs({ action: "click", stressed: true })).toBe(MUTATION_INTERVAL_STRESSED_MS);
    expect(MUTATION_INTERVAL_STRESSED_MS).toBeGreaterThan(MUTATION_INTERVAL_COMMITTING_MS);
  });
});
