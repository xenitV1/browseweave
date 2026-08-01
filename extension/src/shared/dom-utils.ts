import {
  compactSelectOptions,
  isMeaningfulPlainText,
  maskSensitiveValue,
  normalizeSnapshotOptions,
  normalizeText,
  redactUrl,
  sensitiveFieldCategory,
  shouldKeepPlainTextCandidate,
  type FieldDescriptor,
  type SnapshotMode,
  type SnapshotOptions
} from "./pure";

type SummaryKind = "interactive" | "heading" | "landmark" | "content" | "structural";

export interface ElementSummary {
  ref: string;
  tag: string;
  kind: SummaryKind;
  role?: string;
  name?: string;
  text?: string;
  type?: string;
  value?: string;
  checked?: boolean;
  disabled?: boolean;
  required?: boolean;
  editable?: boolean;
  href?: string;
  options?: Array<{ value: string; label: string; selected: boolean }>;
  options_truncated?: boolean;
  sensitive?: "password" | "2fa" | "payment";
  bounds?: { x: number; y: number; width: number; height: number };
}

export interface FrameSnapshot {
  url: string;
  title: string;
  language: string;
  viewport: { width: number; height: number; scroll_x: number; scroll_y: number };
  mode: SnapshotMode;
  max_elements: number;
  query?: string;
  page: {
    description?: string;
    canonical?: string;
    headings: Array<{ level: number; text: string }>;
    landmarks: Array<{ role: string; name?: string }>;
    counts: { interactive: number; content: number };
  };
  active_element_ref?: string;
  elements: ElementSummary[];
  truncated: boolean;
  /** Matches skipped because a cursor said they were already delivered. */
  offset?: number;
}

export interface RefRegistry {
  refFor(element: Element): string;
  resolve(ref: string): Element | null;
  prune(): void;
}

const CANDIDATE_SELECTOR = [
  "a[href]",
  "button",
  "input:not([type='hidden'])",
  "select",
  "textarea",
  "summary",
  "[contenteditable='true']",
  "[role]",
  "[tabindex]",
  "h1", "h2", "h3", "h4", "h5", "h6",
  "main", "nav", "aside", "header", "footer", "article", "section", "form", "div", "span",
  "p", "li", "label", "legend", "td", "th", "blockquote", "pre", "dt", "dd", "figcaption"
].join(",");

const INTERACTIVE_ROLES = new Set([
  "button", "link", "checkbox", "radio", "combobox", "listbox", "menuitem",
  "option", "slider", "spinbutton", "switch", "tab", "textbox", "treeitem"
]);

export function queryAllOpenElements<T extends Element = Element>(
  selector: string,
  startRoot: ParentNode = document
): T[] {
  const pending: ParentNode[] = [startRoot];
  const visited = new Set<ParentNode>();
  const results: T[] = [];
  let scannedHosts = 0;

  while (pending.length > 0 && visited.size < 256 && scannedHosts < 100_000) {
    const root = pending.shift();
    if (!root || visited.has(root)) continue;
    visited.add(root);
    results.push(...root.querySelectorAll<T>(selector));
    for (const host of root.querySelectorAll<Element>("*")) {
      scannedHosts += 1;
      if (scannedHosts >= 100_000) break;
      if (host.shadowRoot && !visited.has(host.shadowRoot)) pending.push(host.shadowRoot);
    }
  }
  return results;
}

export function deepestActiveElement(): Element | null {
  let active: Element | null = document.activeElement;
  while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
  return active;
}

export function isComposedDescendant(ancestor: Element, element: Element): boolean {
  let current: Element | null = element;
  while (current) {
    if (current === ancestor) return true;
    if (current.parentElement) {
      current = current.parentElement;
      continue;
    }
    const root = current.getRootNode();
    current = root && typeof root === "object" && "host" in root
      ? (root as ShadowRoot).host
      : null;
  }
  return false;
}

export function createRefRegistry(): RefRegistry {
  const elementToRef = new WeakMap<Element, string>();
  const refToElement = new Map<string, Element>();
  let nextRef = 1;

  return {
    refFor(element: Element): string {
      const existing = elementToRef.get(element);
      if (existing) return existing;
      const ref = `bw-${nextRef++}`;
      elementToRef.set(element, ref);
      refToElement.set(ref, element);
      return ref;
    },
    resolve(ref: string): Element | null {
      const element = refToElement.get(ref);
      if (!element || !element.isConnected) {
        if (element) refToElement.delete(ref);
        return null;
      }
      return element;
    },
    prune(): void {
      for (const [ref, element] of refToElement) {
        if (!element.isConnected) refToElement.delete(ref);
      }
    }
  };
}

function hasHiddenAncestor(element: Element): boolean {
  let current: Element | null = element;
  while (current) {
    if (current.closest("[hidden], [inert], [aria-hidden='true']")) return true;
    const root = current.getRootNode();
    current = root instanceof ShadowRoot ? root.host : null;
  }
  return false;
}

export function isVisible(element: Element): boolean {
  if (hasHiddenAncestor(element)) return false;
  const style = getComputedStyle(element);
  if (
    style.display === "none" ||
    style.visibility === "hidden" ||
    style.visibility === "collapse" ||
    Number.parseFloat(style.opacity || "1") === 0
  ) {
    return false;
  }
  const rects = element.getClientRects();
  if (rects.length === 0) return false;
  return [...rects].some((rect) => rect.width > 0 && rect.height > 0);
}

function textByIds(ids: string, owner?: Element): string {
  const root = owner?.getRootNode();
  const getById = (id: string): Element | null =>
    root instanceof ShadowRoot ? root.getElementById(id) : document.getElementById(id);
  return normalizeText(
    ids
      .split(/\s+/)
      .map((id) => getById(id)?.textContent || "")
      .join(" "),
    240
  );
}

function associatedLabel(element: Element): string {
  if (element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement) {
    const labels = element.labels ? [...element.labels] : [];
    return normalizeText(labels.map((label) => label.innerText || label.textContent || "").join(" "), 240);
  }
  return "";
}

export function accessibleName(element: Element): string {
  const labelledBy = element.getAttribute("aria-labelledby");
  if (labelledBy) {
    const value = textByIds(labelledBy, element);
    if (value) return value;
  }
  const ariaLabel = normalizeText(element.getAttribute("aria-label"), 240);
  if (ariaLabel) return ariaLabel;
  const label = associatedLabel(element);
  if (label) return label;
  if (element instanceof HTMLImageElement) {
    const alt = normalizeText(element.alt, 240);
    if (alt) return alt;
  }
  if (
    element instanceof HTMLInputElement ||
    element instanceof HTMLTextAreaElement
  ) {
    const placeholder = normalizeText(element.placeholder, 240);
    if (placeholder) return placeholder;
  }
  const title = normalizeText(element.getAttribute("title"), 240);
  if (title) return title;
  return normalizeText((element as HTMLElement).innerText || element.textContent || "", 240);
}

export function implicitRole(element: Element): string {
  const explicit = normalizeText(element.getAttribute("role"), 50);
  if (explicit) return explicit.split(" ")[0] || "";
  const tag = element.tagName.toLowerCase();
  if (tag === "a" && element.hasAttribute("href")) return "link";
  if (tag === "button") return "button";
  if (tag === "select") return "combobox";
  if (tag === "textarea") return "textbox";
  if (/^h[1-6]$/.test(tag)) return "heading";
  if (tag === "input") {
    const type = (element.getAttribute("type") || "text").toLowerCase();
    if (["button", "submit", "reset", "image"].includes(type)) return "button";
    if (type === "checkbox") return "checkbox";
    if (type === "radio") return "radio";
    if (type === "range") return "slider";
    return "textbox";
  }
  if (element.getAttribute("contenteditable") === "true") return "textbox";
  return "";
}

function isInteractiveCandidate(element: Element): boolean {
  const tag = element.tagName.toLowerCase();
  if (["a", "button", "input", "select", "textarea", "summary"].includes(tag)) return true;
  if ((element as HTMLElement).isContentEditable) return true;
  if (element.hasAttribute("tabindex") && (element as HTMLElement).tabIndex >= 0) return true;
  return INTERACTIVE_ROLES.has(implicitRole(element));
}

function isHeadingCandidate(element: Element): boolean {
  return /^h[1-6]$/i.test(element.tagName) || implicitRole(element) === "heading";
}

function landmarkRole(element: Element): string {
  const role = implicitRole(element);
  if (["main", "navigation", "banner", "contentinfo", "complementary", "search", "region", "form"].includes(role)) {
    return role;
  }
  const tag = element.tagName.toLowerCase();
  return {
    main: "main",
    nav: "navigation",
    aside: "complementary",
    header: "banner",
    footer: "contentinfo",
    form: "form"
  }[tag] || "";
}

function isContentCandidate(element: Element): boolean {
  return /^(?:h[1-6]|p|li|blockquote|pre|td|th|dt|dd|figcaption)$/i.test(element.tagName);
}

const SEMANTIC_TEXT_DESCENDANT_SELECTOR = [
  "a[href]", "button", "input", "select", "textarea", "summary", "[role]", "[tabindex]",
  "h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "label", "legend", "td", "th",
  "blockquote", "pre", "dt", "dd", "figcaption"
].join(",");

function meaningfulPlainTextCandidates(candidates: Element[]): Element[] {
  const textByElement = new Map<Element, string>();
  const directTextByElement = new Map<Element, string>();
  for (const element of candidates) {
    if (!/^(?:div|span)$/i.test(element.tagName)) continue;
    if (element.hasAttribute("role") || isInteractiveCandidate(element)) continue;
    if (element.querySelector(SEMANTIC_TEXT_DESCENDANT_SELECTOR)) continue;
    const text = normalizeText((element as HTMLElement).innerText || element.textContent || "", 401);
    if (isMeaningfulPlainText(text)) {
      textByElement.set(element, text);
      directTextByElement.set(element, normalizeText(
        [...element.childNodes]
          .filter((node) => node.nodeType === Node.TEXT_NODE)
          .map((node) => node.textContent || "")
          .join(" "),
        401
      ));
    }
  }

  const ancestorsWithMeaningfulDescendants = new Set<Element>();
  const ancestorsWithSameText = new Set<Element>();
  for (const [element, text] of textByElement) {
    let ancestor = element.parentElement;
    while (ancestor) {
      if (textByElement.has(ancestor)) {
        ancestorsWithMeaningfulDescendants.add(ancestor);
        if (textByElement.get(ancestor) === text) ancestorsWithSameText.add(ancestor);
      }
      ancestor = ancestor.parentElement;
    }
  }
  return [...textByElement.keys()].filter((element) => shouldKeepPlainTextCandidate({
    text: textByElement.get(element),
    directText: directTextByElement.get(element),
    hasMeaningfulDescendant: ancestorsWithMeaningfulDescendants.has(element),
    hasSameTextDescendant: ancestorsWithSameText.has(element)
  }));
}

function summaryKind(element: Element, meaningfulPlainText = false): SummaryKind {
  if (isInteractiveCandidate(element)) return "interactive";
  if (isHeadingCandidate(element)) return "heading";
  if (landmarkRole(element)) return "landmark";
  if (isContentCandidate(element) || meaningfulPlainText) return "content";
  return "structural";
}

function explicitAccessibleName(element: Element): string {
  const labelledBy = element.getAttribute("aria-labelledby");
  if (labelledBy) {
    const value = textByIds(labelledBy, element);
    if (value) return value;
  }
  return normalizeText(element.getAttribute("aria-label") || element.getAttribute("title"), 120);
}

function isDisabled(element: Element): boolean {
  return (
    ("disabled" in element && Boolean((element as HTMLButtonElement).disabled)) ||
    element.getAttribute("aria-disabled") === "true"
  );
}

export function isEditable(element: Element): boolean {
  if (element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement) return !element.disabled;
  if (element instanceof HTMLInputElement) {
    return !element.disabled && !["button", "submit", "reset", "checkbox", "radio", "file", "image", "hidden"].includes(element.type);
  }
  return (element as HTMLElement).isContentEditable;
}

function formFor(element: Element): HTMLFormElement | null {
  if (element instanceof HTMLInputElement || element instanceof HTMLButtonElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement) {
    return element.form;
  }
  return element.closest("form");
}

function isSubmitControl(element: Element): boolean {
  if (element instanceof HTMLButtonElement) return (element.type || "submit") === "submit";
  return element instanceof HTMLInputElement && ["submit", "image"].includes(element.type);
}

function isSearchForm(form: HTMLFormElement): boolean {
  if (form.getAttribute("role")?.toLowerCase() === "search") return true;
  try {
    if (/(?:^|\/)(?:search|ara|arama|query|sorgu)(?:\/|$)/iu.test(new URL(form.action, location.href).pathname)) return true;
  } catch {
    // Invalid form actions are not treated as search forms.
  }
  return [...form.elements].some((field) => {
    if (field instanceof HTMLInputElement && field.type === "search") return true;
    const name = (field.getAttribute("name") || field.id || "").trim().toLocaleLowerCase("tr-TR");
    if (["q", "query", "search", "ara", "arama", "sorgu"].includes(name)) return true;
    if (field instanceof HTMLButtonElement || (field instanceof HTMLInputElement && ["submit", "button"].includes(field.type))) {
      const label = accessibleName(field).toLocaleLowerCase("tr-TR");
      return /^(?:search|ara|arama|sorgula)$/.test(label);
    }
    return false;
  });
}

export function describeElement(element: Element): FieldDescriptor {
  const form = formFor(element);
  const inputType = element instanceof HTMLInputElement
    ? element.type
    : element instanceof HTMLButtonElement
      ? element.type
      : element.getAttribute("type") || "";
  return {
    tag: element.tagName.toLowerCase(),
    role: implicitRole(element),
    type: inputType,
    name: element.getAttribute("name") || "",
    id: element.id,
    autocomplete: element.getAttribute("autocomplete") || "",
    ariaLabel: element.getAttribute("aria-label") || "",
    placeholder: element.getAttribute("placeholder") || "",
    text: accessibleName(element),
    href: element instanceof HTMLAnchorElement ? redactUrl(element.href) : "",
    formAction: form ? redactUrl(form.action) : "",
    formMethod: form?.method || "",
    insideForm: Boolean(form),
    isSubmit: isSubmitControl(element),
    formIsSearch: Boolean(form && isSearchForm(form)),
    formHasSensitiveField: Boolean(form && [...form.elements].some((field) => sensitiveFieldCategory({
      type: field.getAttribute("type") || "",
      name: field.getAttribute("name") || "",
      id: field.id,
      autocomplete: field.getAttribute("autocomplete") || "",
      ariaLabel: field.getAttribute("aria-label") || "",
      placeholder: field.getAttribute("placeholder") || ""
    })))
  };
}

function fieldValue(element: Element, descriptor: FieldDescriptor): string | undefined {
  if (element instanceof HTMLSelectElement) {
    const selected = [...element.selectedOptions].map((option) => option.label || option.text).join(", ");
    return maskSensitiveValue(selected, descriptor);
  }
  if (element instanceof HTMLInputElement && element.type === "file") {
    // The browser reports a fake path, but the basename is still local
    // filesystem detail that does not belong in model context.
    return element.files?.length ? `[ATTACHED:${element.files.length}]` : "";
  }
  if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
    return maskSensitiveValue(element.value, descriptor);
  }
  if ((element as HTMLElement).isContentEditable) {
    return maskSensitiveValue((element as HTMLElement).innerText, descriptor);
  }
  return undefined;
}

function summarizeElement(
  element: Element,
  registry: RefRegistry,
  mode: SnapshotMode,
  meaningfulPlainText: boolean
): ElementSummary | null {
  if (!isVisible(element)) return null;
  const descriptor = describeElement(element);
  const kind = summaryKind(element, meaningfulPlainText);
  const rawName = accessibleName(element);
  const role = implicitRole(element);
  const text = normalizeText((element as HTMLElement).innerText || element.textContent || "", 240);
  if (!rawName && !text && !isEditable(element) && kind !== "interactive") return null;
  const summary: ElementSummary = {
    ref: registry.refFor(element),
    tag: element.tagName.toLowerCase(),
    kind
  };
  if (mode === "full") {
    const rect = element.getBoundingClientRect();
    summary.bounds = {
      x: Math.round(rect.x),
      y: Math.round(rect.y),
      width: Math.round(rect.width),
      height: Math.round(rect.height)
    };
  }
  if (role) summary.role = role;
  if (kind === "content" || kind === "heading") {
    if (text) summary.text = text;
  } else if (kind === "landmark" || kind === "structural") {
    const explicitName = explicitAccessibleName(element);
    if (explicitName) summary.name = explicitName;
  } else {
    if (rawName) summary.name = rawName;
    if (text && text !== rawName) summary.text = text;
  }
  if (descriptor.type) summary.type = descriptor.type;
  const value = fieldValue(element, descriptor);
  if (value) summary.value = value;
  if (element instanceof HTMLSelectElement) {
    const compact = compactSelectOptions(
      [...element.options].map((option) => ({ value: option.value, label: option.label || option.text, selected: option.selected })),
      30,
      Boolean(sensitiveFieldCategory(descriptor))
    );
    summary.options = compact.options;
    if (compact.optionsTruncated) summary.options_truncated = true;
  }
  if (element instanceof HTMLInputElement && ["checkbox", "radio"].includes(element.type)) summary.checked = element.checked;
  if (isDisabled(element)) summary.disabled = true;
  if (element.hasAttribute("required") || element.getAttribute("aria-required") === "true") summary.required = true;
  if (isEditable(element)) summary.editable = true;
  if (element instanceof HTMLAnchorElement) summary.href = redactUrl(element.href);
  const sensitive = sensitiveFieldCategory(descriptor);
  if (sensitive) summary.sensitive = sensitive;
  return summary;
}

function uniqueElements(groups: Element[][]): Element[] {
  const seen = new Set<Element>();
  const result: Element[] = [];
  for (const group of groups) {
    for (const element of group) {
      if (seen.has(element)) continue;
      seen.add(element);
      result.push(element);
    }
  }
  return result;
}

function pageSummary(
  visibleCandidates: Element[],
  interactiveCandidates: Element[],
  contentCandidates: Element[]
): FrameSnapshot["page"] {
  const page: FrameSnapshot["page"] = {
    headings: visibleCandidates
      .filter(isHeadingCandidate)
      .slice(0, 12)
      .map((heading) => ({
        level: /^h[1-6]$/i.test(heading.tagName) ? Number(heading.tagName.slice(1)) : 0,
        text: normalizeText((heading as HTMLElement).innerText || heading.textContent || "", 160)
      }))
      .filter((heading) => Boolean(heading.text)),
    landmarks: visibleCandidates
      .map((element) => ({ role: landmarkRole(element), name: explicitAccessibleName(element) }))
      .filter((landmark) => Boolean(landmark.role))
      .slice(0, 16)
      .map((landmark) => landmark.name ? landmark : { role: landmark.role }),
    counts: {
      interactive: interactiveCandidates.length,
      content: contentCandidates.length
    }
  };
  const description = normalizeText(document.querySelector<HTMLMetaElement>("meta[name='description']")?.content, 300);
  if (description) page.description = description;
  const canonical = redactUrl(document.querySelector<HTMLLinkElement>("link[rel='canonical']")?.href || "");
  if (canonical) page.canonical = canonical;
  return page;
}

function matchesQuery(summary: ElementSummary, query: string): boolean {
  if (!query) return true;
  const haystack = [
    summary.tag,
    summary.kind,
    summary.role,
    summary.name,
    summary.text,
    summary.type,
    summary.value,
    summary.href,
    summary.options ? JSON.stringify(summary.options) : ""
  ].filter((value): value is string => typeof value === "string").join(" ").toLocaleLowerCase("tr-TR");
  return haystack.includes(query.toLocaleLowerCase("tr-TR"));
}

export function buildSnapshot(registry: RefRegistry, requested: Partial<SnapshotOptions> = {}): FrameSnapshot {
  registry.prune();
  const options = normalizeSnapshotOptions(
    requested.mode,
    requested.maxElements,
    requested.query,
    requested.offset
  );
  const rawVisibleCandidates = queryAllOpenElements(CANDIDATE_SELECTOR).filter(isVisible);
  const allPlainTextCandidates = meaningfulPlainTextCandidates(rawVisibleCandidates);
  const queryLower = options.query.toLocaleLowerCase("tr-TR");
  const prioritizedPlainText = queryLower
    ? [...allPlainTextCandidates].sort((left, right) => {
      const leftMatch = normalizeText((left as HTMLElement).innerText || left.textContent || "", 401).toLocaleLowerCase("tr-TR").includes(queryLower);
      const rightMatch = normalizeText((right as HTMLElement).innerText || right.textContent || "", 401).toLocaleLowerCase("tr-TR").includes(queryLower);
      return Number(rightMatch) - Number(leftMatch);
    })
    : allPlainTextCandidates;
  const allowedPlainText = new Set(prioritizedPlainText.slice(0, options.mode === "full" ? 500 : 160));
  const visibleCandidates = rawVisibleCandidates.filter((element) => {
    if (!/^(?:div|span)$/i.test(element.tagName) || element.hasAttribute("role") || isInteractiveCandidate(element)) return true;
    return allowedPlainText.has(element);
  });
  const interactiveCandidates = visibleCandidates.filter(isInteractiveCandidate);
  const headingCandidates = visibleCandidates.filter(isHeadingCandidate);
  const landmarkCandidates = visibleCandidates.filter((element) => Boolean(landmarkRole(element)));
  const mainRoot = queryAllOpenElements("main,[role='main'],article")[0] || null;
  const contentCandidates = visibleCandidates.filter((element) =>
    (isContentCandidate(element) || allowedPlainText.has(element)) &&
    (
      !mainRoot ||
      isComposedDescendant(mainRoot, element) ||
      Boolean(queryLower && normalizeText((element as HTMLElement).innerText || element.textContent || "", 401)
        .toLocaleLowerCase("tr-TR")
        .includes(queryLower))
    )
  );
  const candidates = options.mode === "interactive"
    ? interactiveCandidates
    : options.mode === "content"
      ? contentCandidates
      : options.mode === "balanced"
        ? uniqueElements([interactiveCandidates, headingCandidates, landmarkCandidates, contentCandidates])
        : visibleCandidates;
  const elements: ElementSummary[] = [];
  let truncated = false;
  // Skipped matches are still summarized, so refs stay identical to the refs a
  // reader saw on the page before the cursor.
  let matched = 0;

  for (const candidate of candidates) {
    const summary = summarizeElement(candidate, registry, options.mode, allowedPlainText.has(candidate));
    if (!summary || !matchesQuery(summary, options.query)) continue;
    matched += 1;
    if (matched <= options.offset) continue;
    if (elements.length >= options.maxElements) {
      truncated = true;
      break;
    }
    elements.push(summary);
  }

  const snapshot: FrameSnapshot = {
    url: redactUrl(location.href),
    title: normalizeText(document.title, 300),
    language: normalizeText(document.documentElement.lang, 30),
    mode: options.mode,
    max_elements: options.maxElements,
    page: pageSummary(visibleCandidates, interactiveCandidates, contentCandidates),
    viewport: {
      width: window.innerWidth,
      height: window.innerHeight,
      scroll_x: Math.round(window.scrollX),
      scroll_y: Math.round(window.scrollY)
    },
    elements,
    truncated
  };
  if (options.query) snapshot.query = options.query;
  if (options.offset > 0) snapshot.offset = options.offset;
  const activeElement = deepestActiveElement();
  if (activeElement && activeElement !== document.body && isVisible(activeElement)) {
    snapshot.active_element_ref = registry.refFor(activeElement);
  }
  return snapshot;
}

export function focusableElements(): HTMLElement[] {
  return queryAllOpenElements<HTMLElement>(
    "a[href],button,input:not([type='hidden']),select,textarea,[contenteditable='true'],[tabindex]"
  ).filter((element) => isVisible(element) && !isDisabled(element) && element.tabIndex >= 0);
}

/**
 * Reads whatever the caller asks for, instead of whatever was anticipated.
 *
 * A snapshot reports what a reader can act on, so it deliberately carries
 * almost nothing from `<head>` and no counts at all: asking it for meta tags,
 * JSON-LD, or alt-text coverage is not slow, it is impossible. The alternative
 * an agent reaches for is arbitrary script execution, which an extension cannot
 * offer on a page that sets a strict CSP, and which puts unmasked values into
 * model context.
 *
 * A CSS selector plus the attributes to project covers that ground without
 * executing anything: a selector is matched, never evaluated. Predicates the
 * caller would have written in JavaScript are already expressible — `img:not([alt])`
 * counts missing alt text, `a[rel~=nofollow]` counts nofollow links — and
 * `matched` reports the full count even when `limit` returns fewer rows.
 *
 * Values are not returned raw. URL attributes are resolved and redacted, and a
 * form value is masked through exactly the same field classification a snapshot
 * uses, so querying `input` cannot lift a password into the transcript.
 */
export interface QueryOptions {
  selector: string;
  attributes: readonly string[];
  limit: number;
  includeText: boolean;
}

export interface QueryRow {
  ref: string;
  tag: string;
  attributes: Record<string, string | null>;
  text?: string;
}

const QUERY_LIMITS = {
  attributes: 12,
  attributeName: 60,
  attributeValue: 500,
  text: 300,
  rows: 500
} as const;

/** Attributes whose value is a URL: resolved against the document, then redacted. */
const URL_ATTRIBUTES = new Set([
  "href", "src", "action", "formaction", "poster", "cite", "data-src", "longdesc", "ping"
]);

export function normalizeQueryOptions(
  selector: unknown,
  attributes: unknown,
  limit: unknown,
  includeText: unknown
): QueryOptions {
  const cleanSelector = normalizeText(selector, 300);
  if (!cleanSelector) throw new Error("A CSS selector is required.");
  const requested = Array.isArray(attributes) ? attributes : [];
  const names: string[] = [];
  for (const entry of requested) {
    const name = normalizeText(entry, QUERY_LIMITS.attributeName).toLowerCase();
    // A selector-shaped or whitespace-bearing name is a caller mistake, not an
    // attribute; refusing it early beats returning silent nulls.
    if (!name || /[^a-z0-9_:.-]/u.test(name) || names.includes(name)) continue;
    if (names.length >= QUERY_LIMITS.attributes) break;
    names.push(name);
  }
  const requestedLimit = typeof limit === "number" && Number.isFinite(limit) ? Math.floor(limit) : 50;
  return {
    selector: cleanSelector,
    attributes: names,
    limit: Math.max(0, Math.min(QUERY_LIMITS.rows, requestedLimit)),
    includeText: includeText !== false
  };
}

function projectAttribute(element: Element, name: string): string | null {
  if (name === "value") {
    const descriptor = describeElement(element);
    const masked = fieldValue(element, descriptor);
    return masked === undefined ? null : normalizeText(masked, QUERY_LIMITS.attributeValue);
  }
  const raw = element.getAttribute(name);
  if (raw === null) return null;
  if (URL_ATTRIBUTES.has(name)) {
    // The property form is already resolved against the document base, so a
    // relative href reports the address the browser would actually visit.
    const resolved = (element as unknown as Record<string, unknown>)[name === "data-src" ? "src" : name];
    const absolute = typeof resolved === "string" && resolved ? resolved : raw;
    return normalizeText(redactUrl(absolute), QUERY_LIMITS.attributeValue);
  }
  return normalizeText(raw, QUERY_LIMITS.attributeValue);
}

export function queryElements(
  registry: RefRegistry,
  options: QueryOptions,
  root: ParentNode = document
): { selector: string; matched: number; returned: number; truncated: boolean; rows: QueryRow[] } {
  let matches: Element[];
  try {
    matches = queryAllOpenElements(options.selector, root);
  } catch {
    throw new Error(`The CSS selector is not valid: ${options.selector}`);
  }
  const rows = matches.slice(0, options.limit).map((element) => {
    const attributes: Record<string, string | null> = {};
    for (const name of options.attributes) attributes[name] = projectAttribute(element, name);
    const row: QueryRow = {
      ref: registry.refFor(element),
      tag: element.tagName.toLowerCase(),
      attributes
    };
    if (options.includeText) {
      row.text = normalizeText((element as HTMLElement).innerText || element.textContent || "", QUERY_LIMITS.text);
    }
    return row;
  });
  return {
    selector: options.selector,
    // The full count is reported even when limit returns fewer rows, so a
    // caller can count without paying to read.
    matched: matches.length,
    returned: rows.length,
    truncated: matches.length > rows.length,
    rows
  };
}
