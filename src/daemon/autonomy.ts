/**
 * Owner-declared autonomous approval policy.
 *
 * Detected sensitive actions normally stop and wait for a single-use human
 * decision relayed by the MCP client. That channel needs MCP elicitation, so a
 * client without it can never finish a detected action, and an owner who is
 * driving a long browser task themselves may not want a prompt per click.
 *
 * This section lets the machine's owner pre-authorize named risk categories.
 * It lives in the same owner-only `policy.json` as the file-attach allowlist:
 * the daemon never writes it, an MCP caller cannot set it, and page content
 * cannot reach it. Widening BrowseWeave's authority therefore still requires a
 * deliberate human edit outside the running system.
 *
 * Default deny: with no policy file, every detected action still waits for a
 * human decision.
 */
import { policySection, readPolicyDocument } from "./policy.js";

export const AUTONOMY_POLICY_SECTION = "autonomous_actions" as const;

/**
 * Risk categories the extension can report. Keep in sync with `RiskCategory`
 * in `extension/src/shared/pure.ts`.
 */
export const AUTONOMOUS_RISK_CATEGORIES = [
  "form_submit",
  "message",
  "external_navigation",
  "visual_click",
  "delete",
  "payment",
  "security",
  "password",
  "2fa",
  "file_attach"
] as const;

export type AutonomousRiskCategory = (typeof AUTONOMOUS_RISK_CATEGORIES)[number];

/**
 * Low-risk categories covered by the short `{ enabled: true }` policy.
 * Ordinary reads, typing, scrolling, and same-site navigation do not report a
 * risk category at all and therefore remain uninterrupted without appearing
 * here. These two categories cover the remaining routine transitions while
 * the irreversible or disclosure-prone categories below always stop.
 */
export const DEFAULT_AUTONOMOUS_RISK_CATEGORIES = [
  "form_submit",
  "external_navigation"
] as const satisfies readonly AutonomousRiskCategory[];

/**
 * Categories that an owner-wide policy may never approve.
 *
 * They disclose data, are hard to reverse, affect account security, or use a
 * lower-confidence visual target. Keeping this as a daemon-side invariant
 * means a stale policy or a mistaken extension category cannot turn them into
 * unattended actions.
 */
export const ALWAYS_CONFIRM_RISK_CATEGORIES = [
  "message",
  "visual_click",
  "delete",
  "payment",
  "security",
  "password",
  "2fa",
  "file_attach"
] as const satisfies readonly AutonomousRiskCategory[];

const alwaysConfirmCategories: ReadonlySet<string> = new Set<string>(ALWAYS_CONFIRM_RISK_CATEGORIES);

export interface AutonomyPolicy {
  readonly enabled: boolean;
  /** Risk categories that may execute without a per-action human decision. */
  readonly categories: ReadonlySet<string>;
}

export const DISABLED_AUTONOMY_POLICY: AutonomyPolicy = {
  enabled: false,
  categories: new Set<string>()
};

function parsePolicy(section: Record<string, unknown> | undefined): AutonomyPolicy {
  if (section === undefined) return DISABLED_AUTONOMY_POLICY;
  if (typeof section.enabled !== "boolean") {
    throw new Error(`${AUTONOMY_POLICY_SECTION}.enabled must be true or false.`);
  }
  if (!section.enabled) return DISABLED_AUTONOMY_POLICY;

  const known: ReadonlySet<string> = new Set<string>(AUTONOMOUS_RISK_CATEGORIES);
  const raw = section.categories;
  if (raw === undefined) {
    return { enabled: true, categories: new Set<string>(DEFAULT_AUTONOMOUS_RISK_CATEGORIES) };
  }
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error(
      `${AUTONOMY_POLICY_SECTION}.categories must be a non-empty array of risk categories when present.`
    );
  }
  const categories = new Set<string>();
  for (const entry of raw) {
    if (typeof entry !== "string" || !known.has(entry)) {
      throw new Error(
        `${AUTONOMY_POLICY_SECTION}.categories contains an unknown risk category. ` +
        `Allowed values: ${AUTONOMOUS_RISK_CATEGORIES.join(", ")}.`
      );
    }
    if (alwaysConfirmCategories.has(entry)) {
      throw new Error(
        `${AUTONOMY_POLICY_SECTION}.categories cannot make ${entry} autonomous; ` +
        "that category always requires a per-action human decision."
      );
    }
    categories.add(entry);
  }
  return { enabled: true, categories };
}

export async function loadAutonomyPolicy(configDir: string): Promise<AutonomyPolicy> {
  return parsePolicy(policySection(await readPolicyDocument(configDir), AUTONOMY_POLICY_SECTION));
}

/**
 * Decides whether the owner pre-authorized this exact risk category.
 *
 * An absent or unrecognized category is never covered. A future BrowseWeave
 * risk class therefore keeps waiting for a human decision instead of being
 * silently swept into a policy the owner wrote before it existed.
 */
export function isAutonomousCategory(policy: AutonomyPolicy, category: string | undefined): boolean {
  if (!policy.enabled || typeof category !== "string") return false;
  if (alwaysConfirmCategories.has(category)) return false;
  return policy.categories.has(category);
}

/** Status-safe view of the policy, for `browser_status` and diagnostics. */
export function autonomyPolicySummary(policy: AutonomyPolicy): { enabled: boolean; categories: string[] } {
  return {
    enabled: policy.enabled,
    categories: AUTONOMOUS_RISK_CATEGORIES.filter((category) =>
      !alwaysConfirmCategories.has(category) && policy.categories.has(category)
    )
  };
}
