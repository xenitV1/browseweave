import {
  buildSnapshot,
  createRefRegistry,
  deepestActiveElement,
  describeElement,
  focusableElements,
  isEditable,
  isVisible,
  normalizeQueryOptions,
  queryAllOpenElements,
  queryElements
} from "../shared/dom-utils";
import {
  approvalGuardDecision,
  boundedScroll,
  classifyRisk,
  externalNavigationRisk,
  approvalFingerprint,
  fillBatchKeystrokeIntervalMs,
  isStableRef,
  keystrokeIntervalMs,
  mapVisualCoordinates,
  normalizeSnapshotOptions,
  normalizeText,
  normalizeViewportState,
  normalizeWaitOptions,
  pointerApproachPoints,
  sameViewportState,
  scrollStepDeltas,
  sensitiveFieldCategory,
  sensitivePressDecision,
  stableSafetyMaterial,
  validateFillValue,
  type PointerPoint,
  type RiskAssessment,
  type ValidatedFillValue,
  type ViewportState
} from "../shared/pure";
import type { ApprovalSource } from "../../../src/core/protocol";
import {
  safeCredentialLabel,
  scrubCredentialValues,
  validateCredentialCommandPayload,
  type CredentialCommandSpec,
  type CredentialFieldSpec,
  type CredentialKind,
  type RemoteCredentialField
} from "../security/credentials";
import {
  SETUP_CONNECTING_TEXT,
  SETUP_CONNECT_BUTTON_ID,
  SETUP_ERROR_TEXT,
  SETUP_ROOT_ID,
  SETUP_STATUS_ID,
  SETUP_SUCCESS_TEXT,
  parseSetupPageUrl,
  setupDomContractMatches,
  trustedSetupClick
} from "../setup/setup-pairing";

declare global {
  interface Window {
    __zenCodexBridgeContentReady?: boolean;
    __browseWeaveContentReady?: boolean;
  }
}

interface ContentRequest {
  kind: "bridge:content-command";
  action: string;
  payload?: Record<string, unknown>;
  approved?: boolean;
  approval_fingerprint?: string;
  revalidate_only?: boolean;
  approval_context?: { tab_id: number; frame_id: number };
  approval_source?: ApprovalSource;
}

interface ContentResult {
  ok: boolean;
  result?: unknown;
  error?: {
    code: string;
    message: string;
    category?: string;
    approval_fingerprint?: string;
    details?: Record<string, unknown>;
  };
}

class ContentError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly category?: string,
    readonly details?: Record<string, unknown>,
    readonly approvalFingerprint?: string
  ) {
    super(message);
  }
}

const registry = createRefRegistry();
const DOCUMENT_EPOCH = crypto.randomUUID();
const RISK_BINDING_TTL_MS = 10 * 60_000;
const MAX_RISK_BINDINGS = 100;

interface HumanInterventionSignal {
  requires_human: true;
  kind: "captcha" | "challenge" | "webauthn" | "http_403" | "http_429";
  message: string;
  pause_origin: boolean;
  evidence: string[];
}

function visibleText(elements: Element[], maxElements = 8): string {
  return normalizeText(
    elements
      .filter((element) => isVisible(element))
      .slice(0, maxElements)
      .map((element) => (element as HTMLElement).innerText || element.textContent || "")
      .join(" "),
    4_000
  ).toLowerCase();
}

/**
 * Detect only visible DOM/title indicators. This never solves, clicks, spoofs,
 * or attempts to bypass a challenge.
 */
function detectHumanIntervention(): HumanInterventionSignal | null {
  const title = normalizeText(document.title, 240).toLowerCase();
  const topText = normalizeText(document.body?.innerText || "", 4_000).toLowerCase();
  const dialogText = visibleText(queryAllOpenElements("dialog, [role='dialog'], [aria-modal='true']", document));
  const evidence: string[] = [];

  const rateLimited = /(?:^|\b)(?:429|too many requests|rate limit(?:ed| exceeded)?)(?:\b|$)/iu;
  if (rateLimited.test(title) || rateLimited.test(topText.slice(0, 1_500))) {
    evidence.push(rateLimited.test(title) ? "page_title" : "visible_error_text");
    return {
      requires_human: true,
      kind: "http_429",
      message: "This origin is showing a visible rate-limit response. BrowseWeave paused automated actions; wait and continue manually.",
      pause_origin: true,
      evidence
    };
  }

  const forbidden = /(?:^|\b)(?:403 forbidden|error 403|access denied|request forbidden)(?:\b|$)/iu;
  if (forbidden.test(title) || forbidden.test(topText.slice(0, 1_500))) {
    evidence.push(forbidden.test(title) ? "page_title" : "visible_error_text");
    return {
      requires_human: true,
      kind: "http_403",
      message: "This origin is showing a visible access-denied response. BrowseWeave paused automated actions; review it manually.",
      pause_origin: true,
      evidence
    };
  }

  const webAuthn = /\b(?:security key|passkey|webauthn|touch your security key|insert your security key|use another device)\b/iu;
  if (webAuthn.test(dialogText)) {
    return {
      requires_human: true,
      kind: "webauthn",
      message: "A visible passkey or security-key step requires direct user presence in the browser.",
      pause_origin: false,
      evidence: ["visible_security_dialog"]
    };
  }

  const captchaSelector = [
    "iframe[src*='recaptcha']",
    "iframe[src*='hcaptcha']",
    "iframe[src*='challenges.cloudflare.com']",
    "iframe[title*='captcha' i]",
    "[data-sitekey]",
    "input[name*='captcha' i]",
    "[id*='captcha' i]",
    "[class*='captcha' i]"
  ].join(", ");
  const captchaElement = queryAllOpenElements(captchaSelector, document).find((element) => isVisible(element));
  const captchaText = /\b(?:captcha|verify (?:that )?you are human|i am human|i'm not a robot)\b/iu;
  if (captchaElement || captchaText.test(title) || captchaText.test(dialogText)) {
    if (captchaElement) evidence.push("visible_captcha_widget");
    if (captchaText.test(title)) evidence.push("page_title");
    if (captchaText.test(dialogText)) evidence.push("visible_challenge_dialog");
    return {
      requires_human: true,
      kind: "captcha",
      message: "A visible CAPTCHA requires the user to take over in the browser. BrowseWeave will not solve or bypass it.",
      pause_origin: false,
      evidence
    };
  }

  const challengeText = /\b(?:checking your browser|security verification|verify you are human|performing security verification|just a moment)\b/iu;
  if (challengeText.test(title) || challengeText.test(topText.slice(0, 2_000)) || challengeText.test(dialogText)) {
    if (challengeText.test(title)) evidence.push("page_title");
    if (challengeText.test(topText.slice(0, 2_000))) evidence.push("visible_challenge_text");
    if (challengeText.test(dialogText)) evidence.push("visible_challenge_dialog");
    return {
      requires_human: true,
      kind: "challenge",
      message: "A visible browser-security challenge requires manual user completion.",
      pause_origin: false,
      evidence
    };
  }
  return null;
}

function currentViewportState(): ViewportState {
  return {
    viewport_css_width: innerWidth,
    viewport_css_height: innerHeight,
    device_pixel_ratio: devicePixelRatio,
    scroll_x: Math.round(scrollX),
    scroll_y: Math.round(scrollY),
    document_epoch: DOCUMENT_EPOCH
  };
}

function expectedCaptureViewport(payload: Record<string, unknown>): ViewportState {
  if (typeof payload.screenshot_id !== "string" || !/^shot-[a-f0-9]{32}$/u.test(payload.screenshot_id)) {
    throw new ContentError("stale_screenshot", "No current screenshot ID was found. Take a new screenshot.");
  }
  if (typeof payload.__screenshot_expires_at !== "number" || payload.__screenshot_expires_at <= Date.now()) {
    throw new ContentError("stale_screenshot", "The screenshot's safe-use window expired. Take a new screenshot.");
  }
  try {
    return normalizeViewportState(payload.__capture_viewport);
  } catch {
    throw new ContentError("stale_screenshot", "The screenshot could not be bound to the page state. Take a new screenshot.");
  }
}

function assertCaptureViewport(expected: ViewportState): void {
  if (!sameViewportState(expected, currentViewportState())) {
    throw new ContentError("stale_screenshot", "The page size or scroll position changed after capture. Take a new screenshot.");
  }
}

function elementForRef(rawRef: unknown): Element {
  if (!isStableRef(rawRef)) {
    throw new ContentError("invalid_ref", "A valid element reference is required.");
  }
  const element = registry.resolve(rawRef);
  if (!element) {
    throw new ContentError("stale_ref", "The element reference is stale because the page changed. Take a new snapshot.");
  }
  return element;
}

function ensureVisible(element: Element): void {
  if (!isVisible(element)) {
    throw new ContentError("element_not_visible", "The target element is not currently visible.");
  }
}

interface RiskTarget {
  action: string;
  element: Element;
  key?: string;
  forcedRisk?: RiskAssessment;
  context?: Record<string, unknown>;
}

function composedClosest(element: Element, selector: string): Element | null {
  let current: Element | null = element;
  while (current) {
    const match = current.closest(selector);
    if (match) return match;
    const root = current.getRootNode();
    current = root instanceof ShadowRoot ? root.host : null;
  }
  return null;
}

function liveActivationDestination(target: RiskTarget): string {
  if (target.action !== "click" && target.action !== "click_at" && !(target.action === "press" && target.key === "Enter")) {
    return "";
  }
  const anchor = composedClosest(target.element, "a[href]");
  if (anchor instanceof HTMLAnchorElement) return anchor.href;
  const control = composedClosest(target.element, "button, input") as HTMLButtonElement | HTMLInputElement | null;
  const isSubmit = control instanceof HTMLButtonElement
    ? (control.type || "submit") === "submit"
    : control instanceof HTMLInputElement && ["submit", "image"].includes(control.type);
  const form = isSubmit
    ? control?.form ?? null
    : target.action === "press" && target.key === "Enter"
      ? (target.element instanceof HTMLInputElement || target.element instanceof HTMLButtonElement
          ? target.element.form
          : target.element.closest("form"))
      : null;
  if (!form) return "";
  if (isSubmit && control && "formAction" in control && control.formAction) return control.formAction;
  return form.action || location.href;
}

function stableRiskDescriptor(descriptor: ReturnType<typeof describeElement>): Record<string, unknown> {
  // The requested value must never enter an approval description or binding.
  // Everything else is target identity/material that a page can change.
  const { value: _value, ...stable } = descriptor;
  return stable;
}

function riskForTarget(target: RiskTarget, descriptor: ReturnType<typeof describeElement>): RiskAssessment | null {
  const insideForm = target.action === "press" && target.key === "Enter"
    ? Boolean(descriptor.insideForm && !(target.element instanceof HTMLTextAreaElement) && !(target.element as HTMLElement).isContentEditable)
    : descriptor.insideForm;
  const external = externalNavigationRisk(location.href, liveActivationDestination(target), "existing_tab");
  return target.forcedRisk || external || classifyRisk({
    ...descriptor,
    action: target.action,
    ...(insideForm === undefined ? {} : { insideForm }),
    ...(target.key === undefined ? {} : { key: target.key })
  });
}

function synchronousRiskMaterial(targets: RiskTarget[]): string {
  return stableSafetyMaterial({
    document_epoch: DOCUMENT_EPOCH,
    origin: location.origin,
    location_href: location.href,
    targets: targets.map((target) => {
      const descriptor = describeElement(target.element);
      const ref = registry.refFor(target.element);
      return {
        action: target.action,
        key: target.key || "",
        ref,
        connected: target.element.isConnected && registry.resolve(ref) === target.element,
        visible: isVisible(target.element),
        disabled: "disabled" in target.element && Boolean((target.element as HTMLButtonElement).disabled),
        read_only: "readOnly" in target.element && Boolean((target.element as HTMLInputElement).readOnly),
        inert: target.element.closest("[inert]") !== null,
        aria_disabled: target.element.getAttribute("aria-disabled") || "",
        descriptor: stableRiskDescriptor(descriptor),
        risk: riskForTarget(target, descriptor),
        destination_url: liveActivationDestination(target),
        context: target.context || {}
      };
    })
  });
}

interface RiskGuardToken {
  synchronousMaterial: string;
}

interface StoredRiskBinding {
  targets: RiskTarget[];
  synchronousMaterial: string;
  destinationOrigin: string;
  expiresAt: number;
}

const storedRiskBindings = new Map<string, StoredRiskBinding>();

function rememberRiskBinding(fingerprint: string, targets: RiskTarget[], synchronousMaterial: string): void {
  const now = Date.now();
  for (const [id, binding] of storedRiskBindings) {
    if (binding.expiresAt <= now) storedRiskBindings.delete(id);
  }
  const destination = targets
    .map((target) => externalNavigationRisk(location.href, liveActivationDestination(target), "existing_tab"))
    .find((risk) => risk !== null);
  storedRiskBindings.set(fingerprint, {
    targets: [...targets],
    synchronousMaterial,
    destinationOrigin: destination?.destinationOrigin || "",
    expiresAt: now + RISK_BINDING_TTL_MS
  });
  while (storedRiskBindings.size > MAX_RISK_BINDINGS) {
    const oldest = storedRiskBindings.keys().next().value;
    if (typeof oldest !== "string") break;
    storedRiskBindings.delete(oldest);
  }
}

function assertRiskTargetsUnchanged(targets: RiskTarget[], token: RiskGuardToken): void {
  if (synchronousRiskMaterial(targets) !== token.synchronousMaterial) {
    throw new ContentError(
      "approval_context_changed",
      "The page URL or target changed while its safety context was being verified. Nothing was executed."
    );
  }
}

function rejectOrdinarySensitiveInput(element: Element): void {
  const category = sensitiveFieldCategory(describeElement(element));
  if (!category) return;
  throw new ContentError(
    "credential_channel_required",
    category === "2fa"
      ? "One-time codes require direct user entry in the browser and cannot be sent through an AI command."
      : category === "payment"
        ? "Payment-card fields cannot be filled through ordinary browser commands."
        : "Password fields require the dedicated BrowseWeave credential handoff or an explicit one-use origin permission."
  );
}

async function guardRisks(targets: RiskTarget[], request: ContentRequest): Promise<RiskGuardToken> {
  const synchronousMaterial = synchronousRiskMaterial(targets);
  const assessed = targets.flatMap((target) => {
    const descriptor = describeElement(target.element);
    const risk = riskForTarget(target, descriptor);
    return risk ? [{ target, descriptor, risk }] : [];
  });
  if (assessed.length === 0) {
    const decision = approvalGuardDecision({
      hasRisk: false,
      approved: request.approved === true,
      revalidateOnly: request.revalidate_only === true,
      ...(request.approval_fingerprint === undefined ? {} : { suppliedFingerprint: request.approval_fingerprint })
    });
    if (decision === "allow") return { synchronousMaterial };
    throw new ContentError(
      decision,
      decision === "approval_no_longer_required"
        ? "The live target no longer requires approval. The previous approval context was invalidated without executing the action."
        : "The live target no longer matches the approved risk context. The action was not executed."
    );
  }

  const context = request.approval_context || { tab_id: -1, frame_id: -1 };
  const fingerprint = await approvalFingerprint({
    version: 1,
    document_epoch: DOCUMENT_EPOCH,
    tab_id: context.tab_id,
    frame_id: context.frame_id,
    targets: assessed.map(({ target, descriptor, risk }) => ({
      action: target.action,
      key: target.key || "",
      ref: registry.refFor(target.element),
      descriptor: stableRiskDescriptor(descriptor),
      risk,
      destination_url: liveActivationDestination(target),
      context: target.context || {}
    })),
    origin: location.origin,
    location_href: location.href
  });
  const decision = approvalGuardDecision({
    hasRisk: true,
    approved: request.approved === true,
    revalidateOnly: request.revalidate_only === true,
    currentFingerprint: fingerprint,
    ...(request.approval_fingerprint === undefined ? {} : { suppliedFingerprint: request.approval_fingerprint })
  });
  if (decision === "allow") return { synchronousMaterial };

  const first = assessed[0]!;
  const firstDestination = externalNavigationRisk(
    location.href,
    liveActivationDestination(first.target),
    "existing_tab"
  );
  assertRiskTargetsUnchanged(targets, { synchronousMaterial });
  rememberRiskBinding(fingerprint, targets, synchronousMaterial);
  throw new ContentError(
    "approval_required",
    request.revalidate_only === true
      ? "The live risk context was revalidated without executing the action."
      : request.approved === true
      ? "The target changed after approval. A new user approval is required."
      : `User approval is required for: ${first.risk.reason}.`,
    first.risk.category,
    {
      action: first.target.action,
      targets: assessed.map(({ target, descriptor, risk }) => ({
        ref: registry.refFor(target.element),
        target: normalizeText(descriptor.text || descriptor.ariaLabel || descriptor.tag, 120),
        category: risk.category
      })),
      ...(firstDestination ? { destination_origin: firstDestination.destinationOrigin } : {})
    },
    fingerprint
  );
}

function dispatchPointer(element: Element, type: string, button = 0): void {
  const rect = element.getBoundingClientRect();
  const init: PointerEventInit = {
    bubbles: true,
    cancelable: true,
    composed: true,
    button,
    buttons: type.endsWith("down") ? 1 : 0,
    clientX: rect.left + rect.width / 2,
    clientY: rect.top + rect.height / 2,
    pointerId: 1,
    pointerType: "mouse",
    isPrimary: true
  };
  if (typeof PointerEvent === "function") {
    element.dispatchEvent(new PointerEvent(type, init));
  } else {
    element.dispatchEvent(new MouseEvent(type.replace("pointer", "mouse"), init));
  }
}

function dispatchMouse(element: Element, type: string, button = 0): void {
  const rect = element.getBoundingClientRect();
  element.dispatchEvent(new MouseEvent(type, {
    bubbles: true,
    cancelable: true,
    composed: true,
    button,
    buttons: type === "mousedown" ? 1 : 0,
    clientX: rect.left + rect.width / 2,
    clientY: rect.top + rect.height / 2
  }));
}

/** Last position this document's synthetic pointer reached, for movement paths. */
let lastPointerPoint: PointerPoint | undefined;

/**
 * Emits a short movement path ending exactly on the target. Menus and other
 * hover-driven widgets frequently gate on movement rather than on a bare
 * `pointerover`, so entering without a path leaves their content unopened and
 * therefore missing from the next snapshot.
 */
function approachPointer(element: Element, x: number, y: number): void {
  const from = lastPointerPoint ?? { x: Math.max(0, x - 48), y: Math.max(0, y - 36) };
  for (const point of pointerApproachPoints(from, { x, y })) {
    dispatchPointerAt(element, "pointermove", point.x, point.y, 0);
    dispatchMouseAt(element, "mousemove", point.x, point.y, 0);
  }
  lastPointerPoint = { x, y };
}

function approachPointerToElement(element: Element): void {
  const rect = element.getBoundingClientRect();
  approachPointer(element, rect.left + rect.width / 2, rect.top + rect.height / 2);
}

function delay(milliseconds: number): Promise<void> {
  return new Promise<void>((resolve) => { setTimeout(resolve, milliseconds); });
}

function nextAnimationFrame(): Promise<void> {
  return new Promise<void>((resolve) => { requestAnimationFrame(() => resolve()); });
}

function rejectUnsupportedClickTarget(element: Element): void {
  const labelledControl = composedClosest(element, "label") instanceof HTMLLabelElement
    ? (composedClosest(element, "label") as HTMLLabelElement).control
    : null;
  if (
    (element instanceof HTMLInputElement && element.type === "file") ||
    (labelledControl instanceof HTMLInputElement && labelledControl.type === "file")
  ) {
    throw new ContentError(
      "file_picker_unsupported",
      "File pickers require direct user action in the browser and cannot be opened by BrowseWeave."
    );
  }
  if (composedClosest(element, "a[download]") instanceof HTMLAnchorElement) {
    throw new ContentError(
      "download_unsupported",
      "Downloads require direct user action in this release because BrowseWeave cannot verify their completion or destination."
    );
  }
}

function clickElement(
  element: Element,
  payload: Record<string, unknown>,
  safetyCheck: () => void = () => undefined
): Record<string, unknown> {
  ensureVisible(element);
  rejectUnsupportedClickTarget(element);
  const buttonName = typeof payload.button === "string" ? payload.button : "left";
  if (buttonName !== "left") {
    throw new ContentError("unsupported_button", "Only left-click is supported in this release.");
  }
  const clickCount = typeof payload.click_count === "number"
    ? Math.min(3, Math.max(1, Math.trunc(payload.click_count)))
    : 1;
  (element as HTMLElement).scrollIntoView({ block: "center", inline: "center", behavior: "auto" });
  (element as HTMLElement).focus({ preventScroll: true });
  safetyCheck();
  approachPointerToElement(element);
  safetyCheck();

  for (let index = 0; index < clickCount; index += 1) {
    safetyCheck();
    dispatchPointer(element, "pointerover");
    safetyCheck();
    dispatchMouse(element, "mouseover");
    safetyCheck();
    dispatchPointer(element, "pointerdown");
    safetyCheck();
    dispatchMouse(element, "mousedown");
    safetyCheck();
    dispatchPointer(element, "pointerup");
    safetyCheck();
    dispatchMouse(element, "mouseup");
    if (typeof (element as HTMLElement).click === "function") {
      // Focus and the synthetic pre-click events above can run hostile page
      // handlers. Revalidate the live descriptor and destination at the last
      // synchronous boundary before native activation.
      safetyCheck();
      (element as HTMLElement).click();
    } else {
      safetyCheck();
      dispatchMouse(element, "click");
    }
  }
  if (clickCount === 2) {
    safetyCheck();
    dispatchMouse(element, "dblclick");
  }
  return { ref: registry.refFor(element), clicked: true, click_count: clickCount };
}

function dispatchPointerAt(element: Element, type: string, x: number, y: number, buttons: number): void {
  const init: PointerEventInit = {
    bubbles: !type.endsWith("enter") && !type.endsWith("leave"),
    cancelable: true,
    composed: true,
    button: 0,
    buttons,
    clientX: x,
    clientY: y,
    pointerId: 1,
    pointerType: "mouse",
    isPrimary: true
  };
  if (typeof PointerEvent === "function") element.dispatchEvent(new PointerEvent(type, init));
  else element.dispatchEvent(new MouseEvent(type.replace("pointer", "mouse"), init));
}

function dispatchMouseAt(element: Element, type: string, x: number, y: number, buttons: number, detail = 0): void {
  element.dispatchEvent(new MouseEvent(type, {
    bubbles: type !== "mouseenter" && type !== "mouseleave",
    cancelable: true,
    composed: true,
    button: 0,
    buttons,
    clientX: x,
    clientY: y,
    detail
  }));
}

function hoverElement(element: Element): Record<string, unknown> {
  ensureVisible(element);
  (element as HTMLElement).scrollIntoView({ block: "center", inline: "center", behavior: "auto" });
  const rect = element.getBoundingClientRect();
  const x = rect.left + rect.width / 2;
  const y = rect.top + rect.height / 2;
  approachPointer(element, x, y);
  dispatchPointerAt(element, "pointerover", x, y, 0);
  dispatchMouseAt(element, "mouseover", x, y, 0);
  dispatchPointerAt(element, "pointerenter", x, y, 0);
  dispatchMouseAt(element, "mouseenter", x, y, 0);
  dispatchPointerAt(element, "pointermove", x, y, 0);
  dispatchMouseAt(element, "mousemove", x, y, 0);
  return { ref: registry.refFor(element), hovered: true };
}

function deepElementFromPoint(x: number, y: number): Element | null {
  let target = document.elementFromPoint(x, y);
  const visited = new Set<Element>();
  while (target?.shadowRoot && !visited.has(target)) {
    visited.add(target);
    const deeper = target.shadowRoot.elementFromPoint(x, y);
    if (!deeper || deeper === target) break;
    target = deeper;
  }
  return target;
}

function clickAt(
  element: Element,
  x: number,
  y: number,
  clickCount: number,
  safetyCheck: () => void = () => undefined
): Record<string, unknown> {
  rejectUnsupportedClickTarget(element);
  if (element instanceof HTMLInputElement && element.type === "file") {
    throw new ContentError("file_picker_unsupported", "A file picker cannot be opened with a visual click.");
  }
  for (let index = 1; index <= clickCount; index += 1) {
    safetyCheck();
    dispatchPointerAt(element, "pointerover", x, y, 0);
    safetyCheck();
    dispatchMouseAt(element, "mouseover", x, y, 0);
    safetyCheck();
    dispatchPointerAt(element, "pointerdown", x, y, 1);
    safetyCheck();
    dispatchMouseAt(element, "mousedown", x, y, 1, index);
    safetyCheck();
    dispatchPointerAt(element, "pointerup", x, y, 0);
    safetyCheck();
    dispatchMouseAt(element, "mouseup", x, y, 0, index);
    // Mouse handlers may mutate the target. Keep this check immediately next
    // to the event that can activate the element's default action.
    safetyCheck();
    dispatchMouseAt(element, "click", x, y, 0, index);
  }
  if (clickCount === 2) {
    safetyCheck();
    dispatchMouseAt(element, "dblclick", x, y, 0, 2);
  }
  return { ref: registry.refFor(element), clicked: true, click_count: clickCount, x, y };
}

function keyboardInit(key: string, modifiers: string[] = []): KeyboardEventInit {
  return {
    key,
    code: key.length === 1
      ? /[a-z]/i.test(key) ? `Key${key.toUpperCase()}` : /\d/.test(key) ? `Digit${key}` : ""
      : key,
    bubbles: true,
    cancelable: true,
    composed: true,
    altKey: modifiers.includes("Alt"),
    ctrlKey: modifiers.includes("Control") || modifiers.includes("Ctrl"),
    metaKey: modifiers.includes("Meta"),
    shiftKey: modifiers.includes("Shift")
  };
}

function emitKeyboard(element: Element, type: "keydown" | "keypress" | "keyup", key: string, modifiers: string[] = []): boolean {
  return element.dispatchEvent(new KeyboardEvent(type, keyboardInit(key, modifiers)));
}

function nativeValueSetter(element: HTMLInputElement | HTMLTextAreaElement, value: string): void {
  const prototype = element instanceof HTMLTextAreaElement
    ? HTMLTextAreaElement.prototype
    : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;
  if (setter) setter.call(element, value);
  else element.value = value;
}

function dispatchInput(element: Element, inputType: string, data: string | null): void {
  try {
    element.dispatchEvent(new InputEvent("input", {
      bubbles: true,
      composed: true,
      inputType,
      data
    }));
  } catch {
    element.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  }
}

function dispatchBeforeInput(element: Element, inputType: string, data: string | null): boolean {
  try {
    return element.dispatchEvent(new InputEvent("beforeinput", {
      bubbles: true,
      cancelable: true,
      composed: true,
      inputType,
      data
    }));
  } catch {
    return true;
  }
}

async function typeIntoElement(
  element: Element,
  text: string,
  clear: boolean,
  safetyCheck: () => void = () => undefined,
  maximumKeystrokeIntervalMs = Number.POSITIVE_INFINITY
): Promise<Record<string, unknown>> {
  ensureVisible(element);
  if (!isEditable(element)) {
    throw new ContentError("not_editable", "The target element is not editable.");
  }
  if (text.length > 100_000) {
    throw new ContentError("text_too_large", "The text exceeds the safe input length limit.");
  }
  const htmlElement = element as HTMLElement;
  htmlElement.scrollIntoView({ block: "center", inline: "nearest", behavior: "auto" });
  htmlElement.focus({ preventScroll: true });
  safetyCheck();

  if (element instanceof HTMLSelectElement) {
    const option = [...element.options].find((candidate) =>
      candidate.value === text || normalizeText(candidate.label || candidate.text) === normalizeText(text)
    );
    if (!option) throw new ContentError("option_not_found", "The requested option was not found in the select element.");
    safetyCheck();
    element.value = option.value;
    dispatchInput(element, "insertReplacementText", option.value);
    element.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    return { ref: registry.refFor(element), typed: true, selected: normalizeText(option.label || option.text, 160) };
  }

  if (element instanceof HTMLInputElement && element.type === "file") {
    throw new ContentError("file_picker_unsupported", "File pickers are outside this release's web-page control scope.");
  }

  if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
    let value = element.value;
    if (clear && element.value) {
      safetyCheck();
      if (!dispatchBeforeInput(element, "deleteContentBackward", null)) {
        throw new ContentError("input_cancelled", "The page prevented the current field value from being cleared.");
      }
      safetyCheck();
      nativeValueSetter(element, "");
      value = "";
      dispatchInput(element, "deleteContentBackward", null);
    } else if (clear) {
      value = "";
    }
    const keystrokeInterval = Math.min(
      keystrokeIntervalMs(text.length),
      Math.max(0, Math.trunc(maximumKeystrokeIntervalMs))
    );
    for (const character of text) {
      safetyCheck();
      emitKeyboard(element, "keydown", character);
      safetyCheck();
      emitKeyboard(element, "keypress", character);
      safetyCheck();
      if (dispatchBeforeInput(element, "insertText", character)) {
        safetyCheck();
        value += character;
        nativeValueSetter(element, value);
        dispatchInput(element, "insertText", character);
      }
      emitKeyboard(element, "keyup", character);
      if (keystrokeInterval > 0) {
        // Yields to the page's event loop so debounced and asynchronous
        // per-keystroke handlers observe intermediate values.
        await delay(keystrokeInterval);
        safetyCheck();
      }
    }
    element.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    return { ref: registry.refFor(element), typed: true, length: text.length };
  }

  if (htmlElement.isContentEditable) {
    safetyCheck();
    if (clear) {
      const selection = getSelection();
      const range = document.createRange();
      range.selectNodeContents(htmlElement);
      selection?.removeAllRanges();
      selection?.addRange(range);
      safetyCheck();
      document.execCommand("delete", false);
    }
    safetyCheck();
    const inserted = document.execCommand("insertText", false, text);
    if (!inserted) {
      htmlElement.textContent = `${clear ? "" : htmlElement.textContent || ""}${text}`;
      dispatchInput(element, "insertText", text);
    }
    element.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    return { ref: registry.refFor(element), typed: true, length: text.length };
  }
  throw new ContentError("not_editable", "The target element is not editable.");
}

function radioOptionFor(element: HTMLInputElement, value: string): HTMLInputElement {
  const candidates = element.name
    ? queryAllOpenElements<HTMLInputElement>("input[type='radio']")
      .filter((candidate) =>
        candidate.name === element.name &&
        candidate.form === element.form &&
        candidate.getRootNode() === element.getRootNode()
      )
    : [element];
  const option = candidates.find((candidate) => candidate.value === value);
  if (!option) throw new ContentError("radio_option_not_found", "The requested value was not found in the radio group.");
  return option;
}

function prepareFillTarget(element: Element, value: unknown, clear: boolean): {
  element: Element;
  value: ValidatedFillValue;
  clear: boolean;
} {
  const controlType = element instanceof HTMLInputElement ? element.type : "text";
  let validated: ValidatedFillValue;
  try {
    validated = validateFillValue(controlType, value);
  } catch (error) {
    throw new ContentError("invalid_field_value", error instanceof Error ? error.message : "The form-field value is invalid.");
  }

  let target = element;
  if (validated.kind === "radio") {
    if (!(element instanceof HTMLInputElement) || element.type !== "radio") {
      throw new ContentError("invalid_field_value", "A radio value can only be applied to a radio field.");
    }
    target = radioOptionFor(element, validated.value);
  }

  ensureVisible(target);
  if (validated.kind === "text") {
    if (!isEditable(target)) throw new ContentError("not_editable", "One of the form targets is not editable.");
    if (validated.text.length > 100_000) throw new ContentError("text_too_large", "The text exceeds the safe input length limit.");
  } else if (!(target instanceof HTMLInputElement) || target.disabled) {
    throw new ContentError("not_editable", "The checkbox or radio field cannot be changed.");
  }
  return { element: target, value: validated, clear };
}

async function applyPreparedFill(
  field: ReturnType<typeof prepareFillTarget>,
  safetyCheck: () => void = () => undefined,
  maximumKeystrokeIntervalMs = Number.POSITIVE_INFINITY
): Promise<Record<string, unknown>> {
  if (field.value.kind === "text") {
    return typeIntoElement(field.element, field.value.text, field.clear, safetyCheck, maximumKeystrokeIntervalMs);
  }
  const input = field.element as HTMLInputElement;
  const desired = field.value.kind === "checkbox" ? field.value.checked : true;
  const changed = input.checked !== desired;
  if (changed) clickElement(input, { button: "left", click_count: 1 }, safetyCheck);
  if (input.checked !== desired) {
    throw new ContentError("toggle_blocked", "The page blocked the checkbox or radio change.");
  }
  return {
    ref: registry.refFor(input),
    changed,
    checked: input.checked,
    ...(field.value.kind === "radio" ? { value: input.value } : {})
  };
}

interface FillBatchField {
  ref: string;
  value: unknown;
  clear: boolean;
}

function validateFillBatchFields(value: unknown): FillBatchField[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new ContentError("invalid_fields", "At least one field to fill is required.");
  }
  if (value.length > 100) {
    throw new ContentError("too_many_fields", "At most 100 fields can be filled in one action.");
  }
  const refs = new Set<string>();
  return value.map((rawField) => {
    if (!rawField || typeof rawField !== "object" || Array.isArray(rawField)) {
      throw new ContentError("invalid_fields", "A form field is invalid.");
    }
    const field = rawField as Record<string, unknown>;
    if (!isStableRef(field.ref) || refs.has(field.ref)) {
      throw new ContentError("invalid_fields", "Every form field requires a unique valid ref.");
    }
    if (!("value" in field)) throw new ContentError("invalid_field_value", "Every form field must include a value.");
    refs.add(field.ref);
    return { ref: field.ref, value: field.value, clear: field.clear !== false };
  });
}

function prepareFillBatch(fields: FillBatchField[]): Array<ReturnType<typeof prepareFillTarget>> {
  return fields.map((field) => {
    const element = elementForRef(field.ref);
    rejectOrdinarySensitiveInput(element);
    return prepareFillTarget(element, field.value, field.clear);
  });
}

function fillBatchMaterial(
  fields: FillBatchField[],
  prepared: Array<ReturnType<typeof prepareFillTarget>>
): Record<string, unknown> {
  return {
    version: 1,
    purpose: "fill_form_batch",
    document_epoch: DOCUMENT_EPOCH,
    origin: location.origin,
    location_href: location.href,
    fields: prepared.map((item, index) => ({
      requested_ref: fields[index]?.ref || "",
      resolved_ref: registry.refFor(item.element),
      descriptor: stableRiskDescriptor(describeElement(item.element)),
      value_kind: item.value.kind,
      clear: item.clear
    }))
  };
}

function partialFillFailure(error: unknown, completedRefs: string[]): ContentError {
  const partial = {
    filled_count: completedRefs.length,
    filled_refs: [...completedRefs]
  };
  if (error instanceof ContentError) {
    return new ContentError(
      error.code,
      error.message,
      error.category,
      { ...(error.details || {}), ...partial },
      error.approvalFingerprint
    );
  }
  return new ContentError(
    "fill_form_context_changed",
    "The form changed during the batch. No additional field was filled.",
    undefined,
    partial
  );
}

function normalizeModifiers(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const allowed = new Set(["Alt", "Control", "Ctrl", "Meta", "Shift"]);
  return value.filter((item): item is string => typeof item === "string" && allowed.has(item));
}

async function pressKey(
  element: Element,
  key: string,
  modifiers: string[],
  safetyCheck: () => void = () => undefined
): Promise<Record<string, unknown>> {
  ensureVisible(element);
  (element as HTMLElement).focus({ preventScroll: true });
  safetyCheck();
  const continueDefault = emitKeyboard(element, "keydown", key, modifiers);
  safetyCheck();
  if (key.length === 1) emitKeyboard(element, "keypress", key, modifiers);
  safetyCheck();

  if (continueDefault && key === "Enter") {
    if (element instanceof HTMLTextAreaElement || (element as HTMLElement).isContentEditable) {
      await typeIntoElement(element, "\n", false);
    } else {
      const form = element instanceof HTMLInputElement || element instanceof HTMLButtonElement
        ? element.form
        : element.closest("form");
      if (form) form.requestSubmit();
      else if (element instanceof HTMLButtonElement || element instanceof HTMLAnchorElement) element.click();
    }
  } else if (continueDefault && key === " " && (element instanceof HTMLButtonElement || element instanceof HTMLAnchorElement)) {
    element.click();
  } else if (continueDefault && key === "Tab") {
    const focusables = focusableElements();
    const currentIndex = focusables.indexOf(element as HTMLElement);
    const direction = modifiers.includes("Shift") ? -1 : 1;
    const nextIndex = currentIndex < 0
      ? 0
      : (currentIndex + direction + focusables.length) % focusables.length;
    focusables[nextIndex]?.focus();
  } else if (continueDefault && key === "Escape") {
    (element as HTMLElement).blur();
  }
  emitKeyboard(element, "keyup", key, modifiers);
  return { ref: registry.refFor(element), pressed: key };
}

function nearestScrollContainer(element: Element, horizontal: boolean): HTMLElement {
  let candidate: HTMLElement | null = element instanceof HTMLElement ? element : element.parentElement;
  while (candidate && candidate !== document.body && candidate !== document.documentElement) {
    const style = getComputedStyle(candidate);
    const overflow = horizontal ? style.overflowX : style.overflowY;
    const hasRoom = horizontal
      ? candidate.scrollWidth > candidate.clientWidth
      : candidate.scrollHeight > candidate.clientHeight;
    if (hasRoom && /^(?:auto|scroll|overlay)$/.test(overflow)) return candidate;
    const root = candidate.getRootNode();
    candidate = candidate.parentElement || (root instanceof ShadowRoot ? root.host as HTMLElement : null);
  }
  return (document.scrollingElement || document.documentElement) as HTMLElement;
}

async function scrollPage(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  const amount = typeof payload.amount === "number" && Number.isFinite(payload.amount)
    ? Math.max(1, Math.abs(payload.amount))
    : 600;
  const direction = typeof payload.direction === "string" ? payload.direction : "down";
  const deltas: Record<string, readonly [number, number]> = {
    up: [0, -amount],
    down: [0, amount],
    left: [-amount, 0],
    right: [amount, 0]
  };
  const delta = deltas[direction];
  if (!delta) throw new ContentError("invalid_direction", "The scroll direction must be up, down, left, or right.");

  const target = payload.ref !== undefined ? elementForRef(payload.ref) : document.documentElement;
  const horizontal = delta[0] !== 0;
  const container = nearestScrollContainer(target, horizontal);
  const maximumX = Math.max(0, container.scrollWidth - container.clientWidth);
  const maximumY = Math.max(0, container.scrollHeight - container.clientHeight);
  const nextX = boundedScroll(container.scrollLeft, maximumX, delta[0]);
  const nextY = boundedScroll(container.scrollTop, maximumY, delta[1]);
  // Stepping the offset lets IntersectionObserver, infinite-scroll, and
  // virtualised-list handlers run for the traversed region instead of being
  // skipped by a single jump.
  const stepsX = scrollStepDeltas(nextX.appliedDelta);
  const stepsY = scrollStepDeltas(nextY.appliedDelta);
  let stepX = container.scrollLeft;
  let stepY = container.scrollTop;
  for (let index = 0; index < Math.max(stepsX.length, stepsY.length); index += 1) {
    stepX += stepsX[index] ?? 0;
    stepY += stepsY[index] ?? 0;
    container.scrollTo({ left: stepX, top: stepY, behavior: "auto" });
    await nextAnimationFrame();
  }
  container.scrollTo({ left: nextX.position, top: nextY.position, behavior: "auto" });
  await nextAnimationFrame();
  const documentContainer = container === document.scrollingElement || container === document.documentElement || container === document.body;
  return {
    container_ref: documentContainer ? "document" : registry.refFor(container),
    scroll_x: Math.round(container.scrollLeft),
    scroll_y: Math.round(container.scrollTop),
    delta_x: Math.round(nextX.appliedDelta),
    delta_y: Math.round(nextY.appliedDelta)
  };
}

function pageContainsText(text: string): boolean {
  const needle = text.replace(/\s+/g, " ").trim().toLocaleLowerCase("tr-TR");
  if (!needle) return false;
  const lightText = (document.body?.innerText || "").replace(/\s+/g, " ").toLocaleLowerCase("tr-TR");
  if (lightText.includes(needle)) return true;
  return queryAllOpenElements<HTMLElement>("*").some((element) => {
    if (!(element.getRootNode() instanceof ShadowRoot) || !isVisible(element)) return false;
    const value = (element.innerText || element.textContent || "").replace(/\s+/g, " ").toLocaleLowerCase("tr-TR");
    return value.includes(needle);
  });
}

async function pollUntil(
  condition: () => boolean,
  timeoutMs: number,
  conditionName: string
): Promise<Record<string, unknown>> {
  const started = performance.now();
  while (true) {
    if (condition()) return { condition: conditionName, matched: true, elapsed_ms: Math.round(performance.now() - started) };
    const elapsed = performance.now() - started;
    if (elapsed >= timeoutMs) throw new ContentError("wait_timeout", `The wait condition was not met within ${timeoutMs} ms.`);
    await new Promise((resolve) => setTimeout(resolve, Math.min(100, timeoutMs - elapsed)));
  }
}

async function waitForDomQuiet(timeoutMs: number, quietMs: number): Promise<Record<string, unknown>> {
  const started = performance.now();
  let lastMutation = started;
  let lastRootScan = 0;
  const observed = new Set<Node>();
  const observer = new MutationObserver(() => { lastMutation = performance.now(); });
  const addRoots = (): void => {
    if (document.documentElement && !observed.has(document.documentElement)) {
      observed.add(document.documentElement);
      observer.observe(document.documentElement, { subtree: true, childList: true, attributes: true, characterData: true });
    }
    for (const host of queryAllOpenElements<HTMLElement>("*")) {
      if (host.shadowRoot && !observed.has(host.shadowRoot)) {
        observed.add(host.shadowRoot);
        observer.observe(host.shadowRoot, { subtree: true, childList: true, attributes: true, characterData: true });
      }
    }
  };

  try {
    addRoots();
    lastRootScan = performance.now();
    while (true) {
      const now = performance.now();
      if (now - lastMutation >= quietMs) {
        return { condition: "dom_quiet", matched: true, elapsed_ms: Math.round(now - started), quiet_ms: quietMs };
      }
      if (now - started >= timeoutMs) throw new ContentError("wait_timeout", `The DOM did not become quiet within ${timeoutMs} ms.`);
      if (now - lastRootScan >= 500) {
        addRoots();
        lastRootScan = now;
      }
      await new Promise((resolve) => setTimeout(resolve, Math.min(100, quietMs, timeoutMs - (now - started))));
    }
  } finally {
    observer.disconnect();
  }
}

async function waitForContent(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  const condition = typeof payload.condition === "string" ? payload.condition : "";
  const options = normalizeWaitOptions(payload.timeout_ms ?? payload.timeout, payload.quiet_ms);
  if (condition === "dom_quiet") return waitForDomQuiet(options.timeoutMs, options.quietMs);
  if (condition === "text_present" || condition === "text_absent") {
    const text = typeof payload.text === "string" ? payload.text : typeof payload.value === "string" ? payload.value : "";
    if (!text.trim()) throw new ContentError("invalid_wait", "text is required for a text wait condition.");
    return pollUntil(
      () => condition === "text_present" ? pageContainsText(text) : !pageContainsText(text),
      options.timeoutMs,
      condition
    );
  }
  if (condition === "ref_visible" || condition === "ref_hidden") {
    if (!isStableRef(payload.ref)) throw new ContentError("invalid_ref", "A valid ref is required for this wait condition.");
    return pollUntil(() => {
      const element = registry.resolve(payload.ref as string);
      const visible = Boolean(element && isVisible(element));
      return condition === "ref_visible" ? visible : !visible;
    }, options.timeoutMs, condition);
  }
  throw new ContentError("invalid_wait", "Unsupported page wait condition.");
}

interface PreparedCredentialField {
  ref: string;
  kind: CredentialKind;
  element: HTMLInputElement;
  label: string;
}

interface PreparedCredentialBinding {
  origin: string;
  documentEpoch: string;
  fingerprint: string;
  fields: PreparedCredentialField[];
  submit: boolean;
  form: HTMLFormElement | null;
  synchronousMaterial: string;
}

type CapturedCredentialBinding = Omit<PreparedCredentialBinding, "fingerprint">;

function credentialElement(spec: CredentialFieldSpec): PreparedCredentialField {
  const element = elementForRef(spec.ref);
  ensureVisible(element);
  if (!(element instanceof HTMLInputElement) || element.disabled || element.readOnly) {
    throw new ContentError("credential_field_invalid", "Credential fields must be visible, editable input controls.");
  }
  const descriptor = describeElement(element);
  const sensitive = sensitiveFieldCategory(descriptor);
  if (spec.kind === "password") {
    if (element.type !== "password" || sensitive !== "password") {
      throw new ContentError("credential_field_mismatch", "The requested password ref is not a password input.");
    }
  } else {
    if (!new Set(["text", "email", "tel"]).has(element.type) || sensitive !== null) {
      throw new ContentError(
        "credential_field_mismatch",
        "The requested username ref is not a normal username, email, or phone input. OTP and payment fields are never accepted."
      );
    }
  }
  return {
    ref: spec.ref,
    kind: spec.kind,
    element,
    label: safeCredentialLabel(descriptor.text || descriptor.ariaLabel || descriptor.placeholder, spec.kind)
  };
}

function stableCredentialDescriptor(field: PreparedCredentialField): Record<string, unknown> {
  const descriptor = describeElement(field.element);
  return {
    ref: field.ref,
    kind: field.kind,
    tag: descriptor.tag || "",
    type: descriptor.type || "",
    name: descriptor.name || "",
    id: descriptor.id || "",
    autocomplete: descriptor.autocomplete || "",
    aria_label: descriptor.ariaLabel || "",
    placeholder: descriptor.placeholder || "",
    label: field.label,
    form_action: descriptor.formAction || "",
    form_method: descriptor.formMethod || ""
  };
}

function captureCredentialBinding(
  specs: CredentialFieldSpec[],
  submit: boolean
): CapturedCredentialBinding {
  if (location.protocol !== "https:" || location.origin === "null") {
    throw new ContentError("credential_https_required", "Credentials can be filled only on an HTTPS origin.");
  }
  const fields = specs.map(credentialElement);
  const form = submit ? fields[0]?.element.form ?? null : null;
  if (submit && (!form || fields.some((field) => field.element.form !== form))) {
    throw new ContentError(
      "credential_form_mismatch",
      "Automatic sign-in requires every requested credential field to share one containing form."
    );
  }
  if (submit && form && new URL(form.action || location.href, location.href).origin !== location.origin) {
    throw new ContentError(
      "credential_cross_origin_submit",
      "Automatic credential submission to another origin is blocked. Fill without submit and review the final sign-in action directly."
    );
  }
  const material = {
    version: 1,
    purpose: "credential_binding",
    document_epoch: DOCUMENT_EPOCH,
    origin: location.origin,
    submit,
    fields: fields.map(stableCredentialDescriptor),
    form: form ? {
      action: new URL(form.action || location.href, location.href).origin + new URL(form.action || location.href, location.href).pathname,
      method: (form.method || "get").toLowerCase()
    } : null
  };
  return {
    origin: location.origin,
    documentEpoch: DOCUMENT_EPOCH,
    fields,
    submit,
    form,
    synchronousMaterial: stableSafetyMaterial(material)
  };
}

async function prepareCredentialBinding(
  specs: CredentialFieldSpec[],
  submit: boolean
): Promise<PreparedCredentialBinding> {
  const captured = captureCredentialBinding(specs, submit);
  return {
    ...captured,
    fingerprint: await approvalFingerprint(JSON.parse(captured.synchronousMaterial) as unknown)
  };
}

function assertCredentialBindingUnchanged(
  expected: PreparedCredentialBinding,
  specs: CredentialFieldSpec[],
  submit: boolean
): CapturedCredentialBinding {
  const current = captureCredentialBinding(specs, submit);
  if (current.synchronousMaterial !== expected.synchronousMaterial) {
    throw new ContentError(
      "credential_binding_changed",
      "The credential target changed while its document binding was being verified. No additional value was filled."
    );
  }
  return current;
}

async function credentialPrepare(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  let command: CredentialCommandSpec<CredentialFieldSpec>;
  try {
    command = validateCredentialCommandPayload(payload, false);
  } catch (error) {
    throw new ContentError("invalid_credential_request", error instanceof Error ? error.message : "The credential request is invalid.");
  }
  const binding = await prepareCredentialBinding(command.fields, command.submit);
  const verifiedBinding = assertCredentialBindingUnchanged(binding, command.fields, command.submit);
  return {
    origin: binding.origin,
    document_epoch: binding.documentEpoch,
    binding_fingerprint: binding.fingerprint,
    fields: verifiedBinding.fields.map((field) => ({ ref: field.ref, kind: field.kind, label: field.label })),
    submit: binding.submit
  };
}

async function credentialApply(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  let command: CredentialCommandSpec<RemoteCredentialField>;
  try {
    command = validateCredentialCommandPayload({
      tab_id: payload.tab_id,
      frame_id: payload.frame_id,
      fields: payload.fields,
      submit: payload.submit
    }, true);
  } catch (error) {
    throw new ContentError("invalid_credential_request", error instanceof Error ? error.message : "The credential request is invalid.");
  }
  if (
    typeof payload.origin !== "string" || payload.origin !== location.origin ||
    typeof payload.document_epoch !== "string" || payload.document_epoch !== DOCUMENT_EPOCH ||
    typeof payload.binding_fingerprint !== "string" || !/^sha256:[a-f0-9]{64}$/u.test(payload.binding_fingerprint)
  ) {
    throw new ContentError("credential_binding_changed", "The credential target document or HTTPS origin changed before use.");
  }
  const binding = await prepareCredentialBinding(command.fields, command.submit);
  if (binding.fingerprint !== payload.binding_fingerprint) {
    throw new ContentError("credential_binding_changed", "The credential fields changed after they were bound. No value was submitted.");
  }
  assertCredentialBindingUnchanged(binding, command.fields, command.submit);

  const valuesByRef = new Map(command.fields.map((field) => [field.ref, field]));
  const applicationOrder = [...binding.fields].sort((left, right) => (
    left.kind === right.kind ? 0 : left.kind === "username" ? -1 : 1
  ));
  let filledFields = 0;
  for (const originallyBoundField of applicationOrder) {
    const liveBinding = await prepareCredentialBinding(command.fields, command.submit);
    if (liveBinding.fingerprint !== binding.fingerprint) {
      throw new ContentError(
        "credential_binding_changed",
        "The page changed while credentials were being entered. No additional value was filled.",
        undefined,
        { filled_fields: filledFields, field_kinds: applicationOrder.slice(0, filledFields).map((field) => field.kind) }
      );
    }
    const verifiedLiveBinding = assertCredentialBindingUnchanged(liveBinding, command.fields, command.submit);
    const boundField = verifiedLiveBinding.fields.find((field) => field.ref === originallyBoundField.ref);
    if (!boundField || boundField.kind !== originallyBoundField.kind) {
      throw new ContentError("credential_binding_changed", "The credential field set changed before use.");
    }
    const field = valuesByRef.get(boundField.ref) as RemoteCredentialField | undefined;
    if (!field || field.kind !== boundField.kind) {
      throw new ContentError("credential_binding_changed", "The credential field set changed before use.");
    }
    await typeIntoElement(
      boundField.element,
      field.value,
      true,
      () => { assertCredentialBindingUnchanged(liveBinding, command.fields, command.submit); }
    );
    filledFields += 1;
  }

  const finalBinding = await prepareCredentialBinding(command.fields, command.submit);
  if (finalBinding.fingerprint !== binding.fingerprint) {
    throw new ContentError("credential_binding_changed", "The page changed while credentials were being entered. The form was not submitted.");
  }
  const verifiedFinalBinding = assertCredentialBindingUnchanged(finalBinding, command.fields, command.submit);
  if (command.submit) {
    if (!verifiedFinalBinding.form) throw new ContentError("credential_form_mismatch", "The bound sign-in form is no longer available.");
    verifiedFinalBinding.form.requestSubmit();
  }
  return {
    filled_fields: command.fields.length,
    field_kinds: command.fields.map((field) => field.kind),
    submitted: command.submit
  };
}

interface AttachableFilePayload {
  name: string;
  mime_type: string;
  sha256: string;
  size: number;
  base64: string;
}

function parseAttachableFile(value: unknown): AttachableFilePayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ContentError("attach_file_invalid", "The file to attach was not supplied correctly.");
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record.name !== "string" || record.name.length === 0 || record.name.length > 255 ||
    /[/\\\0]/u.test(record.name) ||
    typeof record.mime_type !== "string" || !/^[\w.+-]+\/[\w.+-]+$/u.test(record.mime_type) ||
    typeof record.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(record.sha256) ||
    typeof record.size !== "number" || !Number.isSafeInteger(record.size) || record.size < 0 ||
    typeof record.base64 !== "string" || !/^[A-Za-z0-9+/=]*$/u.test(record.base64)
  ) {
    throw new ContentError("attach_file_invalid", "The file to attach was not supplied correctly.");
  }
  return record as unknown as AttachableFilePayload;
}

function decodeBase64Bytes(base64: string): Uint8Array<ArrayBuffer> {
  const binary = globalThis.atob(base64);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function fileInputForAttachment(element: Element): HTMLInputElement {
  if (element instanceof HTMLInputElement && element.type === "file") return element;
  const labelled = composedClosest(element, "label");
  if (labelled instanceof HTMLLabelElement && labelled.control instanceof HTMLInputElement && labelled.control.type === "file") {
    return labelled.control;
  }
  throw new ContentError(
    "attach_file_target_invalid",
    "That element is not a file input. Take a fresh snapshot and use the ref of the file field itself."
  );
}

/**
 * Places a file into a form without going near the operating-system picker,
 * which no extension can drive and which would block the tab if opened. The
 * file is assigned through a DataTransfer, exactly as a drag-and-drop upload
 * would deliver it, then the page is notified with input and change.
 */
async function attachFile(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  const element = elementForRef(payload.ref);
  const input = fileInputForAttachment(element);
  if (input.disabled) throw new ContentError("attach_file_target_invalid", "That file input is disabled.");
  ensureVisible(input);

  const spec = parseAttachableFile(payload.file);
  const bytes = decodeBase64Bytes(spec.base64);
  if (bytes.byteLength !== spec.size) {
    throw new ContentError("attach_file_invalid", "The attached file did not arrive intact.");
  }
  const file = new File([bytes], spec.name, { type: spec.mime_type, lastModified: Date.now() });
  const transfer = new DataTransfer();
  transfer.items.add(file);

  input.focus({ preventScroll: true });
  try {
    input.files = transfer.files;
  } catch (error) {
    throw new ContentError(
      "attach_file_rejected",
      `The page did not accept the attached file: ${error instanceof Error ? error.message : "unknown error"}`
    );
  }
  if (input.files?.length !== 1 || input.files[0]?.name !== spec.name) {
    throw new ContentError("attach_file_rejected", "The page did not retain the attached file.");
  }
  dispatchInput(input, "insertReplacementText", null);
  input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));

  return {
    ref: registry.refFor(input),
    attached: true,
    file_name: spec.name,
    mime_type: spec.mime_type,
    size: spec.size,
    sha256: spec.sha256
  };
}

async function approvalTargetProbe(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  const material = {
    version: 1,
    purpose: "approval_target",
    document_epoch: DOCUMENT_EPOCH,
    origin: location.origin,
    location_href: location.href
  };
  const synchronousMaterial = stableSafetyMaterial(material);
  const bindingFingerprint = await approvalFingerprint(material);
  if (stableSafetyMaterial({
    version: 1,
    purpose: "approval_target",
    document_epoch: DOCUMENT_EPOCH,
    origin: location.origin,
    location_href: location.href
  }) !== synchronousMaterial) {
    throw new ContentError("approval_context_changed", "The approval target document changed while it was being verified.");
  }
  let destinationOrigin = "";
  if (payload.require_risk_binding === true) {
    const fingerprint = typeof payload.approval_fingerprint === "string" ? payload.approval_fingerprint : "";
    const binding = storedRiskBindings.get(fingerprint);
    if (!binding || binding.expiresAt <= Date.now()) {
      if (binding) storedRiskBindings.delete(fingerprint);
      throw new ContentError("approval_context_changed", "The live approval target is no longer available. Request a new approval.");
    }
    if (synchronousRiskMaterial(binding.targets) !== binding.synchronousMaterial) {
      storedRiskBindings.delete(fingerprint);
      throw new ContentError("approval_context_changed", "The page URL or target changed before approval.");
    }
    destinationOrigin = binding.destinationOrigin;
  }
  return {
    origin: location.origin,
    document_epoch: DOCUMENT_EPOCH,
    binding_fingerprint: bindingFingerprint,
    destination_origin: destinationOrigin
  };
}

async function execute(request: ContentRequest): Promise<unknown> {
  const payload = request.payload || {};

  switch (request.action) {
    case "safety_probe":
      return detectHumanIntervention() ?? { requires_human: false };
    case "query":
      return queryElements(registry, normalizeQueryOptions(
        payload.selector,
        payload.attributes,
        payload.limit,
        payload.include_text
      ));
    case "snapshot": {
      const options = normalizeSnapshotOptions(
        payload.mode,
        payload.max_elements,
        payload.query,
        payload.offset
      );
      return buildSnapshot(registry, options);
    }
    case "click": {
      const element = elementForRef(payload.ref);
      rejectUnsupportedClickTarget(element);
      const targets = [{ action: "click", element }];
      const guard = await guardRisks(targets, request);
      assertRiskTargetsUnchanged(targets, guard);
      return clickElement(element, payload, () => { assertRiskTargetsUnchanged(targets, guard); });
    }
    case "hover": {
      const element = elementForRef(payload.ref);
      return hoverElement(element);
    }
    case "attach_file": {
      const input = fileInputForAttachment(elementForRef(payload.ref));
      // Attaching a local file is unconditionally sensitive; it is never left
      // to the heuristics, in the same way a semantic-free coordinate click is
      // never left to them.
      const targets: RiskTarget[] = [{
        action: "attach_file",
        element: input,
        forcedRisk: { category: "file_attach", reason: "Attaching a local file to this page" },
        context: {
          file_name: normalizeText((payload.file as Record<string, unknown> | undefined)?.name, 160),
          sha256: normalizeText((payload.file as Record<string, unknown> | undefined)?.sha256, 64)
        }
      }];
      const guard = await guardRisks(targets, request);
      assertRiskTargetsUnchanged(targets, guard);
      return attachFile(payload);
    }
    case "click_at": {
      const captureViewport = expectedCaptureViewport(payload);
      assertCaptureViewport(captureViewport);
      let mapped: ReturnType<typeof mapVisualCoordinates>;
      try {
        mapped = mapVisualCoordinates(
          payload.x,
          payload.y,
          payload.coordinate_space,
          payload.screenshot_width,
          payload.screenshot_height,
          innerWidth,
          innerHeight
        );
      } catch (error) {
        throw new ContentError("invalid_coordinates", error instanceof Error ? error.message : "The visual-click coordinates are invalid.");
      }
      const { x, y } = mapped;
      if (!Number.isFinite(x) || !Number.isFinite(y) || x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) {
        throw new ContentError("invalid_coordinates", "Click coordinates must be inside the visible viewport.");
      }
      if (payload.button !== undefined && payload.button !== "left") {
        throw new ContentError("unsupported_button", "A visual click supports only the left button.");
      }
      const clickCount = typeof payload.click_count === "number"
        ? Math.min(2, Math.max(1, Math.trunc(payload.click_count)))
        : 1;
      const element = deepElementFromPoint(x, y);
      if (!element) throw new ContentError("element_not_found", "No clickable page element was found at these coordinates.");
      rejectUnsupportedClickTarget(element);
      const targets: RiskTarget[] = [{
        action: "click_at",
        element,
        forcedRisk: { category: "visual_click", reason: "Visual click using screenshot coordinates" },
        context: {
          x,
          y,
          source_x: payload.x,
          source_y: payload.y,
          coordinate_space: mapped.coordinateSpace,
          screenshot_id: payload.screenshot_id,
          screenshot_width: payload.screenshot_width,
          screenshot_height: payload.screenshot_height,
          capture_viewport: captureViewport,
          click_count: clickCount
        }
      }];
      const guard = await guardRisks(targets, request);
      assertRiskTargetsUnchanged(targets, guard);
      assertCaptureViewport(captureViewport);
      if (deepElementFromPoint(x, y) !== element) {
        throw new ContentError("stale_screenshot", "The target at these coordinates changed after capture. Take a new screenshot.");
      }
      return {
        ...clickAt(element, x, y, clickCount, () => { assertRiskTargetsUnchanged(targets, guard); }),
        screenshot_id: payload.screenshot_id,
        source_x: payload.x,
        source_y: payload.y,
        coordinate_space: mapped.coordinateSpace
      };
    }
    case "type": {
      const element = elementForRef(payload.ref);
      rejectOrdinarySensitiveInput(element);
      const text = typeof payload.text === "string"
        ? payload.text
        : typeof payload.value === "string" ? payload.value : null;
      if (text === null) throw new ContentError("invalid_text", "Text to enter is required.");
      const targets = [{ action: "type", element }];
      const guard = await guardRisks(targets, request);
      assertRiskTargetsUnchanged(targets, guard);
      return typeIntoElement(
        element,
        text,
        payload.clear !== false,
        () => {
          rejectOrdinarySensitiveInput(element);
          assertRiskTargetsUnchanged(targets, guard);
        }
      );
    }
    case "fill_form": {
      const fields = validateFillBatchFields(payload.fields);
      const initialPrepared = prepareFillBatch(fields);
      const expectedBatchMaterial = stableSafetyMaterial(fillBatchMaterial(fields, initialPrepared));
      const maximumKeystrokeInterval = fillBatchKeystrokeIntervalMs(initialPrepared.map((field) => (
        field.value.kind === "text" ? field.value.text.length : 0
      )));
      const fillDeadline = performance.now() + 20_000;
      const assertFillDeadline = (): void => {
        if (performance.now() > fillDeadline) {
          throw new ContentError(
            "fill_form_time_budget_exceeded",
            "The form batch stopped before the bridge timeout. Retry only the fields reported as unfinished."
          );
        }
      };
      await guardRisks(initialPrepared.map((field) => ({ action: "fill_form", element: field.element })), request);
      const results: Record<string, unknown>[] = [];
      const completedRefs: string[] = [];
      for (let index = 0; index < fields.length; index += 1) {
        try {
          // Input/change handlers from an earlier field may replace, relabel, or
          // reclassify a later target. Re-resolve and re-check the entire batch
          // immediately before every individual write.
          const currentPrepared = prepareFillBatch(fields);
          assertFillDeadline();
          const currentBatchMaterial = stableSafetyMaterial(fillBatchMaterial(fields, currentPrepared));
          if (currentBatchMaterial !== expectedBatchMaterial) {
            throw new ContentError(
              "fill_form_context_changed",
              "The form targets changed during the batch. No additional field was filled."
            );
          }
          const targets = currentPrepared.map((field) => ({ action: "fill_form", element: field.element }));
          const guard = await guardRisks(targets, request);
          assertRiskTargetsUnchanged(targets, guard);
          const current = currentPrepared[index];
          if (!current) throw new ContentError("fill_form_context_changed", "The next form target is no longer available.");
          results.push(await applyPreparedFill(current, () => {
            assertFillDeadline();
            const latestPrepared = prepareFillBatch(fields);
            if (stableSafetyMaterial(fillBatchMaterial(fields, latestPrepared)) !== expectedBatchMaterial) {
              throw new ContentError("fill_form_context_changed", "The form targets changed during the batch.");
            }
            assertRiskTargetsUnchanged(targets, guard);
          }, maximumKeystrokeInterval));
          completedRefs.push(fields[index]!.ref);
        } catch (error) {
          throw partialFillFailure(error, completedRefs);
        }
      }
      return { filled: results.length, fields: results };
    }
    case "press": {
      const currentActive = deepestActiveElement();
      const element = payload.ref !== undefined
        ? elementForRef(payload.ref)
        : currentActive && currentActive !== document.body
          ? currentActive
          : null;
      if (!element) throw new ContentError("no_active_element", "There is no active element to receive the key.");
      const key = typeof payload.key === "string" ? payload.key : "";
      if (!key || key.length > 32) throw new ContentError("invalid_key", "A valid key name is required.");
      const sensitiveDecision = sensitivePressDecision(describeElement(element), key);
      if (sensitiveDecision.disposition === "reject") {
        const message = sensitiveDecision.category === "2fa"
          ? "One-time codes require direct user entry in the browser."
          : "Payment controls require direct user action in the browser.";
        throw new ContentError("sensitive_key_unsupported", message, sensitiveDecision.category);
      }
      if (sensitiveDecision.disposition === "allow_navigation") {
        const targets = [{ action: "press", element, key }];
        const token = { synchronousMaterial: synchronousRiskMaterial(targets) };
        return pressKey(element, key, normalizeModifiers(payload.modifiers), () => {
          if (sensitivePressDecision(describeElement(element), key).disposition !== "allow_navigation") {
            throw new ContentError("sensitive_key_unsupported", "The sensitive target changed before the key event.");
          }
          assertRiskTargetsUnchanged(targets, token);
        });
      }
      const targets = [{ action: "press", element, key }];
      const guard = await guardRisks(targets, request);
      assertRiskTargetsUnchanged(targets, guard);
      return pressKey(
        element,
        key,
        normalizeModifiers(payload.modifiers),
        () => { assertRiskTargetsUnchanged(targets, guard); }
      );
    }
    case "scroll":
      return scrollPage(payload);
    case "wait":
      return waitForContent(payload);
    case "viewport":
      return currentViewportState();
    case "approval_target_probe":
      return approvalTargetProbe(payload);
    case "credential_prepare":
      return credentialPrepare(payload);
    case "credential_apply":
      return credentialApply(payload);
    default:
      throw new ContentError("unsupported_content_action", "This page action is not supported.");
  }
}

async function handleMessage(message: unknown): Promise<ContentResult | undefined> {
  if (!message || typeof message !== "object" || (message as ContentRequest).kind !== "bridge:content-command") {
    return undefined;
  }
  const request = message as ContentRequest;
  try {
    return { ok: true, result: await execute(request) };
  } catch (error) {
    if (error instanceof ContentError) {
      const payload: NonNullable<ContentResult["error"]> = { code: error.code, message: error.message };
      if (error.category) payload.category = error.category;
      if (error.approvalFingerprint) payload.approval_fingerprint = error.approvalFingerprint;
      if (error.details) payload.details = error.details;
      return { ok: false, error: payload };
    }
    return {
      ok: false,
      error: {
        code: "page_action_failed",
        message: error instanceof Error ? error.message : "The page action could not be completed."
      }
    };
  } finally {
    if (request.action === "credential_apply") scrubCredentialValues(request.payload);
  }
}

/**
 * The installer page has a deliberately tiny capability surface. A valid
 * setup URL never receives the normal page-automation message listener.
 */
function initializeSetupPage(): boolean {
  const page = parseSetupPageUrl(location.href, true);
  if (!page) return false;
  if (window.top !== window) return true;

  const roots = document.querySelectorAll<HTMLElement>(`#${SETUP_ROOT_ID}`);
  const buttons = document.querySelectorAll<HTMLButtonElement>(`#${SETUP_CONNECT_BUTTON_ID}`);
  const statuses = document.querySelectorAll<HTMLElement>(`#${SETUP_STATUS_ID}`);
  const root = roots.length === 1 ? roots[0] : undefined;
  const button = buttons.length === 1 ? buttons[0] : undefined;
  const status = statuses.length === 1 ? statuses[0] : undefined;
  const valid = !!root && !!button && !!status && root.tagName === "MAIN" && button.tagName === "BUTTON" &&
    root.contains(button) && root.contains(status) &&
    setupDomContractMatches({
      rootId: root.id,
      setupIdAttribute: root.getAttribute("data-setup-id"),
      buttonId: button.id,
      buttonText: button.textContent ?? "",
      statusId: status.id
    }, page.setupId);

  if (!valid || !root || !button || !status) {
    for (const candidate of buttons) candidate.disabled = true;
    if (status) status.textContent = SETUP_ERROR_TEXT;
    return true;
  }

  const refreshDirectives = document.querySelectorAll<HTMLMetaElement>("#browseweave-auto-refresh");
  if (refreshDirectives.length === 1 && refreshDirectives[0]?.tagName === "META") {
    refreshDirectives[0].remove();
  }

  let attempted = false;
  button.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopImmediatePropagation();
    if (attempted || !trustedSetupClick(event.isTrusted, button.id, button.textContent ?? "")) return;
    attempted = true;
    button.disabled = true;
    status.textContent = SETUP_CONNECTING_TEXT;
    if (!setupDomContractMatches({
      rootId: root.id,
      setupIdAttribute: root.getAttribute("data-setup-id"),
      buttonId: button.id,
      buttonText: button.textContent ?? "",
      statusId: status.id
    }, page.setupId)) {
      status.textContent = SETUP_ERROR_TEXT;
      return;
    }
    void browser.runtime.sendMessage({
      kind: "setup:pair",
      setup_id: page.setupId
    }).then((response: unknown) => {
      const record = response && typeof response === "object" ? response as Record<string, unknown> : null;
      status.textContent = record?.ok === true ? SETUP_SUCCESS_TEXT : SETUP_ERROR_TEXT;
    }).catch(() => {
      status.textContent = SETUP_ERROR_TEXT;
    });
  }, { capture: true });
  return true;
}

if (!window.__browseWeaveContentReady && !window.__zenCodexBridgeContentReady) {
  window.__browseWeaveContentReady = true;
  window.__zenCodexBridgeContentReady = true;
  if (!initializeSetupPage()) browser.runtime.onMessage.addListener(handleMessage);
}
