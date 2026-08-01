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
 * Covered when the owner enables the section without naming categories.
 *
 * `file_attach` is deliberately excluded: it sends a local file from the
 * computer to a website, so it stays behind the exact-file confirmation unless
 * the owner names it explicitly.
 */
const DEFAULT_CATEGORIES: readonly AutonomousRiskCategory[] = AUTONOMOUS_RISK_CATEGORIES
  .filter((category) => category !== "file_attach");

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
    return { enabled: true, categories: new Set<string>(DEFAULT_CATEGORIES) };
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
  return policy.categories.has(category);
}

/** Status-safe view of the policy, for `browser_status` and diagnostics. */
export function autonomyPolicySummary(policy: AutonomyPolicy): { enabled: boolean; categories: string[] } {
  return {
    enabled: policy.enabled,
    categories: AUTONOMOUS_RISK_CATEGORIES.filter((category) => policy.categories.has(category))
  };
}
