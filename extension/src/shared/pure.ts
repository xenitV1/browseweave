export const BRIDGE_URL = "ws://127.0.0.1:32110" as const;
export { PROTOCOL_VERSION } from "../../../src/core/protocol";
export const TOKEN_STORAGE_KEY = "bridge_token" as const;
export const INSTALLATION_ID_STORAGE_KEY = "installation_id" as const;
export const MAX_MANAGED_TABS = 10 as const;

export type ApprovalGuardDecision =
  | "allow"
  | "approval_required"
  | "approval_context_changed"
  | "approval_no_longer_required";

/**
 * Makes the approval TOCTOU policy explicit and reusable in both page and
 * navigation guards. A revalidation request is observational only: it can
 * never return `allow` while a risk is present.
 */
export function approvalGuardDecision(input: {
  hasRisk: boolean;
  approved: boolean;
  revalidateOnly: boolean;
  currentFingerprint?: string;
  suppliedFingerprint?: string;
}): ApprovalGuardDecision {
  if (!input.hasRisk) {
    if (input.revalidateOnly) return "approval_no_longer_required";
    if (input.approved) return "approval_context_changed";
    return "allow";
  }
  if (input.revalidateOnly) return "approval_required";
  if (input.approved && input.currentFingerprint === input.suppliedFingerprint) return "allow";
  return "approval_required";
}

/** Accepts only real browser tab IDs and removes duplicates without guessing ownership. */
export function normalizeManagedTabIds(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is number => (
    typeof item === "number" && Number.isSafeInteger(item) && item > 0
  )))].sort((left, right) => left - right);
}

export function canCreateManagedTab(value: unknown): boolean {
  return normalizeManagedTabIds(value).length < MAX_MANAGED_TABS;
}

/**
 * Intersects a cleanup request with the ownership ledger. IDs not created by
 * BrowseWeave are deliberately ignored and therefore can never be closed by
 * bulk cleanup.
 */
export function selectManagedTabsForCleanup(tracked: unknown, requested?: unknown): number[] {
  const managed = normalizeManagedTabIds(tracked);
  if (requested === undefined) return managed;
  const requestedSet = new Set(normalizeManagedTabIds(requested));
  return managed.filter((tabId) => requestedSet.has(tabId));
}

/** A single-tab close is allowed only when the session ownership ledger contains it. */
export function isManagedTabOwned(tracked: unknown, target: unknown): boolean {
  return typeof target === "number" && Number.isSafeInteger(target) && target > 0 &&
    normalizeManagedTabIds(tracked).includes(target);
}

/** Returns the ledger state that must be persisted after a confirmed managed close. */
export function managedTabsAfterClose(tracked: unknown, closedTabId: unknown): number[] {
  if (!isManagedTabOwned(tracked, closedTabId)) return normalizeManagedTabIds(tracked);
  return normalizeManagedTabIds(tracked).filter((tabId) => tabId !== closedTabId);
}

export type RiskCategory =
  | "form_submit"
  | "message"
  | "payment"
  | "delete"
  | "password"
  | "2fa"
  | "security"
  | "external_navigation"
  | "visual_click"
  | "file_attach";

export interface FieldDescriptor {
  tag?: string;
  role?: string;
  type?: string;
  name?: string;
  id?: string;
  autocomplete?: string;
  ariaLabel?: string;
  placeholder?: string;
  text?: string;
  value?: string;
  href?: string;
  formAction?: string;
  formMethod?: string;
  insideForm?: boolean;
  isSubmit?: boolean;
  formHasSensitiveField?: boolean;
  formIsSearch?: boolean;
  url?: string;
}

export interface RiskInput extends FieldDescriptor {
  action: string;
  key?: string;
}

export interface RiskAssessment {
  category: RiskCategory;
  reason: string;
}

const SENSITIVE_QUERY_KEYS = /(?:^|_)(?:access|auth|authorization|code|credential|key|otp|pass|password|secret|session|signature|token)(?:$|_)/i;
const OTP_WORDS = /(?:^|[^\p{L}\p{N}_])(?:2fa|mfa|otp|one[\s_-]*time|verification[\s_-]*code|security[\s_-]*code|doğrulama[\s_-]*(?:kodu|kod)|tek[\s_-]*kullanımlık)(?=$|[^\p{L}\p{N}_])/iu;
const PASSWORD_WORDS = /(?:^|[^\p{L}\p{N}_])(?:pass(?:word|code)?|parola|şifre|sifre|pin)(?=$|[^\p{L}\p{N}_])/iu;
const PAYMENT_WORDS = /(?:^|[^\p{L}\p{N}_])(?:payment|pay now|checkout|purchase|place order|buy now|credit card|debit card|card number|cvv|cvc|ödeme(?:yi)?|odeme(?:yi)?|satın al|satin al|siparişi ver|siparisi ver|kart numarası|kart numarasi)(?=$|[^\p{L}\p{N}_])/iu;
const DELETE_WORDS = /(?:^|[^\p{L}\p{N}_])(?:delete|remove|erase|destroy|close account|cancel account|sil|kaldır|kaldir|hesabı kapat|hesabi kapat|kalıcı olarak|kalici olarak)(?=$|[^\p{L}\p{N}_])/iu;
const MESSAGE_WORDS = /(?:^|[^\p{L}\p{N}_])(?:send message|send reply|post reply|publish|share now|submit comment|gönder|gonder|mesajı gönder|mesaji gonder|yanıtla|yanitla|yayınla|yayinla|paylaş|paylas)(?=$|[^\p{L}\p{N}_])/iu;
const SECURITY_WORDS = /(?:^|[^\p{L}\p{N}_])(?:security|privacy settings|account access|recovery|trusted device|active sessions?|güvenlik|guvenlik|hesap erişimi|hesap erisimi|kurtarma|oturumlar)(?=$|[^\p{L}\p{N}_])/iu;
const SEARCH_WORDS = /(?:^|[^\p{L}\p{N}_])(?:search|query|ara|arama|sorgu)(?=$|[^\p{L}\p{N}_])/iu;

export function normalizeText(value: unknown, maxLength = 240): string {
  if (typeof value !== "string") {
    return "";
  }
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }
  return `${normalized.slice(0, Math.max(0, maxLength - 1))}…`;
}

export interface ChromiumBrandVersion {
  brand: string;
  version: string;
}

/**
 * UA-CH deliberately randomizes brand-array order. Prefer the real Chrome
 * brand over the generic engine label, then retain a safe non-GREASE fallback.
 */
export function selectChromiumBrand(value: unknown): ChromiumBrandVersion | undefined {
  if (!Array.isArray(value)) return undefined;
  const brands = value.filter((entry): entry is ChromiumBrandVersion => (
    entry !== null && typeof entry === "object" && !Array.isArray(entry) &&
    typeof (entry as { brand?: unknown }).brand === "string" &&
    typeof (entry as { version?: unknown }).version === "string" &&
    (entry as ChromiumBrandVersion).brand.trim().length > 0 &&
    !/not.?a.?brand/iu.test((entry as ChromiumBrandVersion).brand)
  ));
  return brands.find((entry) => entry.brand.trim().toLowerCase() === "google chrome") ??
    brands.find((entry) => entry.brand.trim().toLowerCase() === "chromium") ??
    brands[0];
}

/**
 * Approval descriptions originate outside the extension UI. Keep them useful,
 * but never render likely secrets or unbounded/control-character text.
 */
export function maskUntrustedApprovalDescription(value: unknown, maxLength = 280): string {
  const normalized = normalizeText(
    typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f-\u009f]/gu, " ") : "",
    Math.max(1, maxLength)
  );
  if (!normalized) return "No additional details were provided.";
  return normalized
    .replace(
      /\b(password|passcode|passwd|token|secret|authorization|api[_ -]?key|otp|pin|cvv|cvc)\s*[:=]\s*[^\s,;]+/giu,
      "$1=[MASKED]"
    )
    .replace(/\b(?:\d[ -]?){6,19}\b/gu, "[MASKED:number]")
    .replace(/\b[A-Za-z0-9_-]{32,}\b/gu, "[MASKED:token]");
}

function decodeBase64DataUrl(dataUrl: string): Uint8Array {
  const match = /^data:image\/(?:png|jpeg);base64,([A-Za-z0-9+/=]+)$/u.exec(dataUrl);
  if (!match?.[1]) throw new Error("The screenshot data URL is not a supported PNG or JPEG image.");
  const binary = globalThis.atob(match[1]);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function readBigEndian16(bytes: Uint8Array, offset: number): number {
  const first = bytes[offset];
  const second = bytes[offset + 1];
  if (first === undefined || second === undefined) throw new Error("The screenshot header is truncated.");
  return (first << 8) | second;
}

function readBigEndian32(bytes: Uint8Array, offset: number): number {
  const first = bytes[offset];
  const second = bytes[offset + 1];
  const third = bytes[offset + 2];
  const fourth = bytes[offset + 3];
  if (first === undefined || second === undefined || third === undefined || fourth === undefined) {
    throw new Error("The screenshot header is truncated.");
  }
  return ((first * 0x1000000) + (second << 16) + (third << 8) + fourth) >>> 0;
}

/** Reads capture dimensions without DOM APIs, so it is safe in MV3 workers. */
export function captureImageDimensions(dataUrl: string): { width: number; height: number } {
  const bytes = decodeBase64DataUrl(dataUrl);
  const isPng = bytes.length >= 24 &&
    bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47 &&
    bytes[12] === 0x49 && bytes[13] === 0x48 && bytes[14] === 0x44 && bytes[15] === 0x52;
  if (isPng) {
    const width = readBigEndian32(bytes, 16);
    const height = readBigEndian32(bytes, 20);
    if (width > 0 && height > 0) return { width, height };
  }

  if (bytes[0] === 0xff && bytes[1] === 0xd8) {
    let offset = 2;
    const startOfFrameMarkers = new Set([
      0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7,
      0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf
    ]);
    while (offset + 8 < bytes.length) {
      while (bytes[offset] === 0xff) offset += 1;
      const marker = bytes[offset];
      offset += 1;
      if (marker === undefined || marker === 0xd9 || marker === 0xda) break;
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      const segmentLength = readBigEndian16(bytes, offset);
      if (segmentLength < 2 || offset + segmentLength > bytes.length) break;
      if (startOfFrameMarkers.has(marker)) {
        const height = readBigEndian16(bytes, offset + 3);
        const width = readBigEndian16(bytes, offset + 5);
        if (width > 0 && height > 0) return { width, height };
      }
      offset += segmentLength;
    }
  }
  throw new Error("The screenshot dimensions could not be read safely.");
}

function descriptorText(descriptor: FieldDescriptor): string {
  return [
    descriptor.tag,
    descriptor.role,
    descriptor.type,
    descriptor.name,
    descriptor.id,
    descriptor.autocomplete,
    descriptor.ariaLabel,
    descriptor.placeholder,
    descriptor.text,
    descriptor.href,
    descriptor.formAction,
    descriptor.url
  ]
    .filter((value): value is string => typeof value === "string")
    .join(" ")
    .toLocaleLowerCase();
}

export function sensitiveFieldCategory(descriptor: FieldDescriptor): "password" | "2fa" | "payment" | null {
  const type = (descriptor.type || "").toLowerCase();
  const autocomplete = (descriptor.autocomplete || "").toLowerCase();
  const combined = descriptorText(descriptor);

  if (autocomplete.includes("one-time-code") || OTP_WORDS.test(combined)) {
    return "2fa";
  }
  if (type === "password" || autocomplete.includes("password") || PASSWORD_WORDS.test(combined)) {
    return "password";
  }
  if (
    autocomplete.split(/\s+/).some((token) => token.startsWith("cc-")) ||
    /\b(?:card|credit|debit|cvv|cvc|iban|kart)\b/i.test(combined)
  ) {
    return "payment";
  }
  return null;
}

export function maskSensitiveValue(value: unknown, descriptor: FieldDescriptor): string {
  const category = sensitiveFieldCategory(descriptor);
  if (category) {
    return `[MASKED:${category}]`;
  }
  return normalizeText(value, 300);
}

export function classifyRisk(input: RiskInput): RiskAssessment | null {
  const action = input.action.toLowerCase();
  const combined = descriptorText(input);
  const sensitiveCategory = sensitiveFieldCategory(input);

  if (["type", "fill_form"].includes(action) && sensitiveCategory) {
    return {
      category: sensitiveCategory,
      reason: sensitiveCategory === "2fa"
        ? "Entering a one-time verification code"
        : sensitiveCategory === "payment"
          ? "Entering payment or card information"
          : "Entering a password"
    };
  }

  if (PAYMENT_WORDS.test(combined) || (action === "click" && sensitiveCategory === "payment")) {
    return { category: "payment", reason: "Payment or purchase action" };
  }
  if (OTP_WORDS.test(combined) || (action === "click" && sensitiveCategory === "2fa")) {
    return { category: "2fa", reason: "Two-factor authentication action" };
  }
  if (PASSWORD_WORDS.test(combined) || (action === "click" && sensitiveCategory === "password")) {
    return { category: "password", reason: "Password or PIN action" };
  }
  if (SECURITY_WORDS.test(combined)) {
    return { category: "security", reason: "Account security or access setting" };
  }
  if (DELETE_WORDS.test(combined)) {
    return { category: "delete", reason: "Deletion or a hard-to-reverse action" };
  }
  if (MESSAGE_WORDS.test(combined)) {
    return { category: "message", reason: "Sending a message, comment, or content" };
  }

  const enterMaySubmit = action === "press" && input.key === "Enter" && input.insideForm;
  if (input.isSubmit || enterMaySubmit) {
    if (isSafeSearchSubmission(input)) return null;
    return { category: "form_submit", reason: "Submitting a form" };
  }
  return null;
}

export function isSafeSearchSubmission(input: RiskInput): boolean {
  const method = (input.formMethod || "get").trim().toLowerCase();
  if (method !== "get" || input.formHasSensitiveField === true) return false;
  const hasSubmitShape = input.isSubmit === true || (input.action === "press" && input.key === "Enter" && input.insideForm === true);
  if (!hasSubmitShape) return false;
  return input.formIsSearch === true || SEARCH_WORDS.test(descriptorText(input));
}

/**
 * Categories whose value only the human's own keystrokes may produce: a
 * one-time code lives on the user's own device and is burned by a wrong or
 * stale attempt, and card data is financial. Both stay outside command-driven
 * key events entirely.
 */
export type HumanEntryOnlyCategory = "2fa" | "payment";

const HUMAN_ENTRY_ONLY_CATEGORIES: readonly string[] = ["2fa", "payment"];

export type SensitivePressDecision =
  | { disposition: "normal" }
  | { disposition: "allow_navigation"; category: HumanEntryOnlyCategory }
  | { disposition: "reject"; category: HumanEntryOnlyCategory };

/**
 * Key events can be handled by custom widgets even when the control is not a
 * native input, so a one-time-code or payment-looking target keeps only
 * non-mutating focus/navigation keys.
 *
 * Two classes are deliberately not rejected here. Password targets accept keys
 * because submitting or moving through a login form is ordinary work; the value
 * itself is still refused by the type and form-fill paths, which keep it on the
 * dedicated credential handoff. Account-security targets carry a
 * hard-to-reverse effect rather than a secret, and the identical effect is
 * reachable by clicking the same control. Both therefore belong in the ordinary
 * approval channel instead of a dead end that no approval can open.
 */
export function sensitivePressDecision(descriptor: FieldDescriptor, key: unknown): SensitivePressDecision {
  const risk = classifyRisk({ ...descriptor, action: "press", key: typeof key === "string" ? key : "" });
  // Either classifier is enough to reject: a password-looking label must not
  // mask a card or one-time-code signal coming from the other one.
  const category = [sensitiveFieldCategory(descriptor), risk?.category]
    .find((value): value is HumanEntryOnlyCategory => (
      typeof value === "string" && HUMAN_ENTRY_ONLY_CATEGORIES.includes(value)
    )) ?? null;
  if (!category) return { disposition: "normal" };
  const safeNavigationKeys = new Set([
    "Tab", "Escape", "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Home", "End", "PageUp", "PageDown"
  ]);
  return safeNavigationKeys.has(String(key))
    ? { disposition: "allow_navigation", category }
    : { disposition: "reject", category };
}

function parsedWebOrigin(value: unknown): URL | null {
  if (typeof value !== "string" || value.length > 4096) return null;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed : null;
  } catch {
    return null;
  }
}

export function isLoopbackWebUrl(value: unknown): boolean {
  const parsed = parsedWebOrigin(value);
  if (!parsed) return false;
  const hostname = parsed.hostname.toLowerCase();
  return hostname === "localhost" || hostname.endsWith(".localhost") ||
    hostname === "[::1]" || hostname === "::1" || /^127(?:\.\d{1,3}){3}$/u.test(hostname);
}

export function externalNavigationRisk(
  currentUrl: unknown,
  destinationUrl: unknown,
  mode: "existing_tab" | "new_tab"
): (RiskAssessment & { destinationOrigin: string }) | null {
  if (mode === "new_tab" && destinationUrl === "about:blank") return null;
  const destination = parsedWebOrigin(destinationUrl);
  if (!destination) return null;
  if (mode === "new_tab") {
    return isLoopbackWebUrl(destination.href)
      ? null
      : {
          category: "external_navigation",
          reason: "Opening a non-loopback site in a new tab",
          destinationOrigin: destination.origin
        };
  }
  const current = parsedWebOrigin(currentUrl);
  if (current?.origin === destination.origin) return null;
  if (!current && isLoopbackWebUrl(destination.href)) return null;
  return {
    category: "external_navigation",
    reason: current ? "Leaving the current site" : "Leaving a blank or unknown-origin tab",
    destinationOrigin: destination.origin
  };
}

export type ValidatedFillValue =
  | { kind: "checkbox"; checked: boolean }
  | { kind: "radio"; value: string }
  | { kind: "text"; text: string };

export function validateFillValue(controlType: unknown, value: unknown): ValidatedFillValue {
  const type = typeof controlType === "string" ? controlType.toLowerCase() : "text";
  if (type === "checkbox") {
    if (typeof value !== "boolean") throw new Error("A checkbox value must be true or false.");
    return { kind: "checkbox", checked: value };
  }
  if (type === "radio") {
    if (typeof value !== "string") throw new Error("A radio-group value must be text.");
    if (value.length > 10_000) throw new Error("The radio value exceeds the safe length limit.");
    return { kind: "radio", value };
  }
  if (typeof value !== "string") throw new Error("A form-field value must be text.");
  return { kind: "text", text: value };
}

export function normalizePagination(limit: unknown, offset: unknown): { limit: number; offset: number } {
  const normalizedLimit = typeof limit === "number" && Number.isInteger(limit)
    ? Math.min(200, Math.max(1, limit))
    : 100;
  const normalizedOffset = typeof offset === "number" && Number.isInteger(offset)
    ? Math.max(0, offset)
    : 0;
  return { limit: normalizedLimit, offset: normalizedOffset };
}

export type SnapshotMode = "interactive" | "balanced" | "content" | "full";

export interface SnapshotOptions {
  mode: SnapshotMode;
  maxElements: number;
  query: string;
  /** How many already-delivered matches to skip, for reading past a cut. */
  offset: number;
}

/** Bounds the skip so a hostile or confused cursor cannot walk forever. */
export const MAX_SNAPSHOT_OFFSET = 20_000 as const;

export function normalizeSnapshotOptions(
  mode: unknown,
  maxElements: unknown,
  query: unknown,
  offset?: unknown
): SnapshotOptions {
  const normalizedMode: SnapshotMode = ["interactive", "balanced", "content", "full"].includes(String(mode))
    ? mode as SnapshotMode
    : "balanced";
  const defaults: Record<SnapshotMode, number> = {
    interactive: 180,
    balanced: 260,
    content: 220,
    full: 600
  };
  const hardLimits: Record<SnapshotMode, number> = {
    interactive: 400,
    balanced: 600,
    content: 500,
    full: 1_200
  };
  const requested = typeof maxElements === "number" && Number.isInteger(maxElements)
    ? maxElements
    : defaults[normalizedMode];
  const requestedOffset = typeof offset === "number" && Number.isInteger(offset) ? offset : 0;
  return {
    mode: normalizedMode,
    maxElements: Math.min(hardLimits[normalizedMode], Math.max(1, requested)),
    query: normalizeText(query, 200),
    offset: Math.min(MAX_SNAPSHOT_OFFSET, Math.max(0, requestedOffset))
  };
}

/**
 * A snapshot cursor records how many matches each frame has already delivered.
 *
 * It is a position in document order, not a set of element identities: a page
 * that changed between reads can repeat or skip an element. That is the same
 * assumption `since_snapshot_id` already makes, and it keeps the cursor small
 * enough to be an opaque string the caller passes straight back.
 */
const SNAPSHOT_CURSOR_PATTERN = /^c1:\d{1,7}=\d{1,7}(?:,\d{1,7}=\d{1,7})*$/u;
export const MAX_SNAPSHOT_CURSOR_LENGTH = 512 as const;

export function formatSnapshotCursor(offsets: ReadonlyMap<number, number>): string {
  const parts = [...offsets.entries()]
    .filter(([frameId, offset]) => (
      Number.isSafeInteger(frameId) && frameId >= 0 && frameId <= 9_999_999 &&
      Number.isSafeInteger(offset) && offset > 0 && offset <= MAX_SNAPSHOT_OFFSET
    ))
    .sort((left, right) => left[0] - right[0])
    .map(([frameId, offset]) => `${frameId}=${offset}`);
  if (parts.length === 0) return "";
  const cursor = `c1:${parts.join(",")}`;
  return cursor.length <= MAX_SNAPSHOT_CURSOR_LENGTH ? cursor : "";
}

/**
 * Returns per-frame offsets, or null when the value is not a cursor this
 * version produced. Frames that no longer exist are simply not applied by the
 * caller, so a real page whose iframes come and go still pages forward.
 */
export function parseSnapshotCursor(value: unknown): Map<number, number> | null {
  if (typeof value !== "string" || value.length > MAX_SNAPSHOT_CURSOR_LENGTH) return null;
  if (!SNAPSHOT_CURSOR_PATTERN.test(value)) return null;
  const offsets = new Map<number, number>();
  for (const part of value.slice(3).split(",")) {
    const [rawFrame, rawOffset] = part.split("=");
    const frameId = Number(rawFrame);
    const offset = Number(rawOffset);
    if (!Number.isSafeInteger(frameId) || !Number.isSafeInteger(offset)) return null;
    if (offset > MAX_SNAPSHOT_OFFSET) return null;
    if (offsets.has(frameId)) return null;
    offsets.set(frameId, offset);
  }
  return offsets.size > 0 ? offsets : null;
}

function snapshotFrames(snapshot: Record<string, unknown>): Array<Record<string, unknown>> {
  return Array.isArray(snapshot.frames)
    ? snapshot.frames.filter((frame): frame is Record<string, unknown> => Boolean(frame) && typeof frame === "object" && !Array.isArray(frame))
    : [];
}

function frameElements(frame: Record<string, unknown>): Array<Record<string, unknown>> {
  return Array.isArray(frame.elements)
    ? frame.elements.filter((element): element is Record<string, unknown> => Boolean(element) && typeof element === "object" && !Array.isArray(element))
    : [];
}

export function diffSnapshots(previous: Record<string, unknown>, current: Record<string, unknown>): Record<string, unknown> {
  const previousFrames = snapshotFrames(previous);
  const currentFrames = snapshotFrames(current);
  const previousElements = new Map<string, { frame_id: number; element: Record<string, unknown> }>();
  const currentElements = new Map<string, { frame_id: number; element: Record<string, unknown> }>();
  const previousFrameMeta = new Map<number, Record<string, unknown>>();
  const currentFrameMeta = new Map<number, Record<string, unknown>>();
  const previousOrder = new Map<number, string>();
  const currentOrder = new Map<number, string>();

  const indexFrames = (
    frames: Array<Record<string, unknown>>,
    elementIndex: Map<string, { frame_id: number; element: Record<string, unknown> }>,
    metaIndex: Map<number, Record<string, unknown>>,
    orderIndex: Map<number, string>
  ): void => {
    for (const frame of frames) {
      const frameId = typeof frame.frame_id === "number" ? frame.frame_id : 0;
      const { elements: _elements, ...metadata } = frame;
      metaIndex.set(frameId, metadata);
      const refs: string[] = [];
      for (const element of frameElements(frame)) {
        if (typeof element.ref !== "string") continue;
        refs.push(element.ref);
        elementIndex.set(`${frameId}:${element.ref}`, { frame_id: frameId, element });
      }
      orderIndex.set(frameId, refs.join("\u0000"));
    }
  };

  indexFrames(previousFrames, previousElements, previousFrameMeta, previousOrder);
  indexFrames(currentFrames, currentElements, currentFrameMeta, currentOrder);

  const added: Array<Record<string, unknown>> = [];
  const changed: Array<Record<string, unknown>> = [];
  const removed: Array<Record<string, unknown>> = [];
  for (const [key, currentElement] of currentElements) {
    const previousElement = previousElements.get(key);
    if (!previousElement) added.push(currentElement);
    else if (JSON.stringify(previousElement.element) !== JSON.stringify(currentElement.element)) changed.push(currentElement);
  }
  for (const [key, previousElement] of previousElements) {
    if (!currentElements.has(key)) removed.push({ frame_id: previousElement.frame_id, ref: previousElement.element.ref });
  }

  const frameChanges: Array<Record<string, unknown>> = [];
  const removedFrames: number[] = [];
  const orderChanged: number[] = [];
  for (const [frameId, metadata] of currentFrameMeta) {
    const previousMetadata = previousFrameMeta.get(frameId);
    if (!previousMetadata || JSON.stringify(previousMetadata) !== JSON.stringify(metadata)) {
      frameChanges.push({ frame_id: frameId, state: previousMetadata ? "changed" : "added", metadata });
    }
    if (previousOrder.has(frameId) && previousOrder.get(frameId) !== currentOrder.get(frameId)) orderChanged.push(frameId);
  }
  for (const frameId of previousFrameMeta.keys()) {
    if (!currentFrameMeta.has(frameId)) removedFrames.push(frameId);
  }

  const delta: Record<string, unknown> = {
    added,
    changed,
    removed,
    frame_changes: frameChanges,
    removed_frames: removedFrames,
    order_changed_frames: orderChanged
  };
  if (JSON.stringify(previous.incomplete_frames) !== JSON.stringify(current.incomplete_frames)) {
    delta.incomplete_frames = current.incomplete_frames;
  }
  return delta;
}

export function boundedScroll(current: number, maximum: number, requestedDelta: number): { position: number; appliedDelta: number } {
  const safeCurrent = Number.isFinite(current) ? Math.max(0, current) : 0;
  const safeMaximum = Number.isFinite(maximum) ? Math.max(0, maximum) : 0;
  const safeDelta = Number.isFinite(requestedDelta)
    ? Math.min(2_000, Math.max(-2_000, requestedDelta))
    : 0;
  const position = Math.min(safeMaximum, Math.max(0, safeCurrent + safeDelta));
  return { position, appliedDelta: position - safeCurrent };
}

export function stableSafetyMaterial(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (Array.isArray(value)) return `[${value.map(stableSafetyMaterial).join(",")}]`;
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((key) => record[key] !== undefined)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableSafetyMaterial(record[key])}`)
      .join(",")}}`;
  }
  return "null";
}

export async function approvalFingerprint(material: unknown): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stableSafetyMaterial(material))));
  return `sha256:${[...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

export function isApprovalFingerprint(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

export function isMeaningfulPlainText(value: unknown): boolean {
  const text = normalizeText(value, 401);
  return text.length >= 2 && text.length <= 400 && /[\p{L}\p{N}]/u.test(text);
}

export function shouldKeepPlainTextCandidate(input: {
  text: unknown;
  directText: unknown;
  hasMeaningfulDescendant: boolean;
  hasSameTextDescendant: boolean;
}): boolean {
  if (!isMeaningfulPlainText(input.text) || input.hasSameTextDescendant) return false;
  return !input.hasMeaningfulDescendant || isMeaningfulPlainText(input.directText);
}

export function normalizeWaitOptions(timeout: unknown, quietMs: unknown): { timeoutMs: number; quietMs: number } {
  const timeoutMs = typeof timeout === "number" && Number.isFinite(timeout)
    ? Math.min(15_000, Math.max(250, Math.trunc(timeout)))
    : 5_000;
  const normalizedQuiet = typeof quietMs === "number" && Number.isFinite(quietMs)
    ? Math.min(3_000, Math.max(100, Math.trunc(quietMs)))
    : 500;
  return { timeoutMs, quietMs: normalizedQuiet };
}

export function normalizeScreenshotOptions(format: unknown, quality: unknown): {
  format: "jpeg" | "png";
  quality: number | null;
} {
  const normalizedFormat = format === "png" ? "png" : "jpeg";
  const normalizedQuality = typeof quality === "number" && Number.isFinite(quality)
    ? Math.min(100, Math.max(30, Math.trunc(quality)))
    : 85;
  return { format: normalizedFormat, quality: normalizedFormat === "jpeg" ? normalizedQuality : null };
}

export interface ViewportState {
  viewport_css_width: number;
  viewport_css_height: number;
  device_pixel_ratio: number;
  scroll_x: number;
  scroll_y: number;
  document_epoch: string;
}

export function normalizeViewportState(value: unknown): ViewportState {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The page viewport state could not be read.");
  }
  const record = value as Record<string, unknown>;
  const width = record.viewport_css_width;
  const height = record.viewport_css_height;
  const dpr = record.device_pixel_ratio;
  const scrollX = record.scroll_x;
  const scrollY = record.scroll_y;
  const documentEpoch = record.document_epoch;
  if (
    typeof width !== "number" || !Number.isFinite(width) || width <= 0 ||
    typeof height !== "number" || !Number.isFinite(height) || height <= 0 ||
    typeof dpr !== "number" || !Number.isFinite(dpr) || dpr <= 0 ||
    typeof scrollX !== "number" || !Number.isFinite(scrollX) ||
    typeof scrollY !== "number" || !Number.isFinite(scrollY) ||
    typeof documentEpoch !== "string" || documentEpoch.length < 8 || documentEpoch.length > 128
  ) {
    throw new Error("The page viewport size, scroll position, or document identity is invalid.");
  }
  return {
    viewport_css_width: width,
    viewport_css_height: height,
    device_pixel_ratio: dpr,
    scroll_x: scrollX,
    scroll_y: scrollY,
    document_epoch: documentEpoch
  };
}

export function sameViewportState(left: ViewportState, right: ViewportState): boolean {
  return (
    left.viewport_css_width === right.viewport_css_width &&
    left.viewport_css_height === right.viewport_css_height &&
    left.device_pixel_ratio === right.device_pixel_ratio &&
    left.scroll_x === right.scroll_x &&
    left.scroll_y === right.scroll_y &&
    left.document_epoch === right.document_epoch
  );
}

export function mapVisualCoordinates(
  x: unknown,
  y: unknown,
  coordinateSpace: unknown,
  screenshotWidth: unknown,
  screenshotHeight: unknown,
  viewportWidth: unknown,
  viewportHeight: unknown
): { x: number; y: number; coordinateSpace: "screenshot_pixels" | "css_viewport" } {
  if (typeof x !== "number" || !Number.isFinite(x) || typeof y !== "number" || !Number.isFinite(y)) {
    throw new Error("Finite x and y coordinates are required for a visual click.");
  }
  if (
    typeof viewportWidth !== "number" || !Number.isFinite(viewportWidth) || viewportWidth <= 0 ||
    typeof viewportHeight !== "number" || !Number.isFinite(viewportHeight) || viewportHeight <= 0
  ) {
    throw new Error("The page CSS viewport dimensions could not be read.");
  }
  if (coordinateSpace === "css_viewport") {
    return { x, y, coordinateSpace: "css_viewport" };
  }
  if (
    typeof screenshotWidth !== "number" || !Number.isFinite(screenshotWidth) || screenshotWidth <= 0 ||
    typeof screenshotHeight !== "number" || !Number.isFinite(screenshotHeight) || screenshotHeight <= 0
  ) {
    throw new Error("screenshot_width and screenshot_height are required for screenshot-pixel coordinates.");
  }
  return {
    x: x * viewportWidth / screenshotWidth,
    y: y * viewportHeight / screenshotHeight,
    coordinateSpace: "screenshot_pixels"
  };
}

export interface CompactSelectOption {
  value: string;
  label: string;
  selected: boolean;
}

export function compactSelectOptions(
  rawOptions: Array<{ value: unknown; label: unknown; selected: unknown }>,
  requestedLimit = 30,
  maskValues = false
): { options: CompactSelectOption[]; optionsTruncated: boolean } {
  const limit = Math.min(30, Math.max(1, Math.trunc(requestedLimit) || 30));
  const normalized = rawOptions.map((option, index) => ({
    index,
    value: maskValues ? "[MASKED]" : normalizeText(option.value, 100),
    label: normalizeText(option.label, 120),
    selected: option.selected === true
  }));
  const picked = new Map<number, (typeof normalized)[number]>();
  for (const option of normalized.filter((candidate) => candidate.selected)) {
    if (picked.size >= limit) break;
    picked.set(option.index, option);
  }
  for (const option of normalized) {
    if (picked.size >= limit) break;
    picked.set(option.index, option);
  }
  const options = [...picked.values()]
    .sort((left, right) => left.index - right.index)
    .map(({ index: _index, ...option }) => option);
  return { options, optionsTruncated: normalized.length > options.length };
}

export function redactUrl(rawUrl: unknown): string {
  const value = normalizeText(rawUrl, 4096);
  if (!value) {
    return "";
  }
  try {
    const parsed = new URL(value);
    if (parsed.username) parsed.username = "[MASKED]";
    if (parsed.password) parsed.password = "[MASKED]";
    for (const key of [...parsed.searchParams.keys()]) {
      if (SENSITIVE_QUERY_KEYS.test(key.replace(/[-.]/g, "_"))) {
        parsed.searchParams.set(key, "[MASKED]");
      }
    }
    if (parsed.hash) parsed.hash = "#fragment-redacted";
    return parsed.toString();
  } catch {
    return value;
  }
}

export function normalizeNavigationUrl(rawUrl: unknown): string {
  if (typeof rawUrl !== "string" || !rawUrl.trim()) {
    throw new Error("A valid web address is required.");
  }
  if (rawUrl.trim() === "about:blank") {
    return "about:blank";
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error("The web address must be absolute, for example https://example.com.");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("Only HTTP or HTTPS web addresses can be opened.");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Web addresses containing a username or password are not accepted.");
  }
  if (parsed.href.length > 4096) {
    throw new Error("The web address exceeds the safe length limit.");
  }
  return parsed.href;
}

export function isStableRef(value: unknown): value is string {
  return typeof value === "string" && /^bw-[1-9]\d*$/.test(value);
}

export function asFiniteInteger(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && Number.isFinite(value)
    ? value
    : fallback;
}

export const TYPING_TOTAL_BUDGET_MS = 1_200;
export const TYPING_MAX_INTERVAL_MS = 24;
export const TYPING_MAX_PACED_CHARS = 400;

/**
 * Dispatching a whole string with no interval starves debounced autocomplete,
 * asynchronous framework state, and per-keystroke validators, so pages observe
 * an input burst they were never written to handle. The interval spreads a
 * bounded budget across the string; long text keeps the original zero-delay
 * path so a large paste cannot approach the command timeout.
 */
export function keystrokeIntervalMs(
  textLength: number,
  budgetMs = TYPING_TOTAL_BUDGET_MS,
  maxIntervalMs = TYPING_MAX_INTERVAL_MS,
  maxPacedChars = TYPING_MAX_PACED_CHARS
): number {
  if (!Number.isFinite(textLength)) return 0;
  const length = Math.trunc(textLength);
  if (length <= 1 || length > Math.trunc(maxPacedChars)) return 0;
  return Math.max(0, Math.min(Math.trunc(maxIntervalMs), Math.floor(Math.max(0, budgetMs) / (length - 1))));
}

export const SCROLL_MAX_STEP_PX = 360;

/**
 * A single jump skips every intermediate offset, so `IntersectionObserver`
 * callbacks, infinite-scroll handlers, and virtualised rows for the traversed
 * region never run and a later snapshot legitimately reports missing content.
 * The returned deltas always sum to the requested distance.
 */
export function scrollStepDeltas(
  delta: number,
  maxStepPx = SCROLL_MAX_STEP_PX
): number[] {
  if (!Number.isFinite(delta) || delta === 0) return [];
  const limit = Math.max(1, Math.trunc(maxStepPx));
  const steps = Math.max(1, Math.ceil(Math.abs(delta) / limit));
  const base = Math.trunc(delta / steps);
  const deltas = new Array<number>(steps).fill(base);
  const remainder = delta - base * steps;
  const direction = Math.sign(remainder);
  for (let index = 0; index < Math.abs(remainder); index += 1) deltas[index]! += direction;
  return deltas;
}

export interface PointerPoint {
  x: number;
  y: number;
}

export const POINTER_APPROACH_STEPS = 3;

/**
 * Hover-driven menus commonly open on movement rather than on a single
 * `pointerover` at the target centre, so a path-free entry leaves their items
 * absent from the next snapshot. The final point is always the exact target.
 */
export function pointerApproachPoints(
  from: PointerPoint,
  to: PointerPoint,
  steps = POINTER_APPROACH_STEPS
): PointerPoint[] {
  if (![from.x, from.y, to.x, to.y].every((value) => Number.isFinite(value))) return [];
  const count = Math.max(1, Math.trunc(steps));
  const points: PointerPoint[] = [];
  for (let index = 1; index <= count; index += 1) {
    const ratio = index / count;
    points.push({
      x: Math.round(from.x + (to.x - from.x) * ratio),
      y: Math.round(from.y + (to.y - from.y) * ratio)
    });
  }
  return points;
}

export const MUTATION_INTERVAL_CONTINUING_MS = 120;
export const MUTATION_INTERVAL_COMMITTING_MS = 750;
export const MUTATION_INTERVAL_STRESSED_MS = 2_500;
export const FILL_BATCH_TYPING_BUDGET_MS = 10_000;

/** One interval shared by every paced text field, keeping the whole batch bounded. */
export function fillBatchKeystrokeIntervalMs(
  textLengths: readonly number[],
  budgetMs = FILL_BATCH_TYPING_BUDGET_MS
): number {
  const pacedTransitions = textLengths.reduce((total, rawLength) => {
    if (!Number.isFinite(rawLength)) return total;
    const length = Math.trunc(rawLength);
    return length > 1 && length <= TYPING_MAX_PACED_CHARS ? total + length - 1 : total;
  }, 0);
  if (pacedTransitions === 0) return 0;
  return Math.max(0, Math.min(TYPING_MAX_INTERVAL_MS, Math.floor(Math.max(0, budgetMs) / pacedTransitions)));
}

/** Actions that continue an interaction the caller already began on this tab. */
const CONTINUING_INTERACTION_ACTIONS = new Set<string>(["type", "fill_form", "hover", "scroll", "press"]);
/** Keys that commit the surrounding form rather than continue editing it. */
const COMMITTING_KEYS = new Set<string>(["Enter", "NumpadEnter", " ", "Space", "Spacebar"]);

/**
 * A uniform floor is simultaneously slower than necessary inside one
 * interaction and too eager once a site signals stress. Editing keystrokes and
 * scrolling stay tight, anything that commits or navigates keeps the
 * conservative interval, and a stressed tab backs off well beyond both.
 */
export function mutationIntervalMs(input: {
  action: string;
  key?: unknown;
  stressed?: boolean;
}): number {
  if (input.stressed === true) return MUTATION_INTERVAL_STRESSED_MS;
  if (input.action === "press" && typeof input.key === "string" && COMMITTING_KEYS.has(input.key)) {
    return MUTATION_INTERVAL_COMMITTING_MS;
  }
  return CONTINUING_INTERACTION_ACTIONS.has(input.action)
    ? MUTATION_INTERVAL_CONTINUING_MS
    : MUTATION_INTERVAL_COMMITTING_MS;
}
