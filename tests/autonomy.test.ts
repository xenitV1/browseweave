import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AUTONOMOUS_RISK_CATEGORIES,
  DEFAULT_AUTONOMOUS_RISK_CATEGORIES,
  EXPLICIT_ONLY_RISK_CATEGORIES,
  DISABLED_AUTONOMY_POLICY,
  autonomyPolicySummary,
  isAutonomousCategory,
  loadAutonomyPolicy
} from "../src/daemon/autonomy.js";
import { policyPath } from "../src/daemon/policy.js";

const roots: string[] = [];

async function writePolicy(section: unknown): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), "browseweave-autonomy-"));
  roots.push(root);
  const configDir = path.join(root, "config");
  await mkdir(configDir, { recursive: true, mode: 0o700 });
  await writeFile(policyPath(configDir), JSON.stringify({ autonomous_actions: section }), { mode: 0o600 });
  await chmod(policyPath(configDir), 0o600);
  return configDir;
}

afterEach(async () => {
  while (roots.length) {
    const root = roots.pop();
    if (root) await rm(root, { recursive: true, force: true });
  }
});

describe("autonomous action policy", () => {
  it("is off until the owner writes a policy", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "browseweave-autonomy-"));
    roots.push(root);
    const configDir = path.join(root, "config");
    await mkdir(configDir, { recursive: true, mode: 0o700 });
    expect(await loadAutonomyPolicy(configDir)).toEqual(DISABLED_AUTONOMY_POLICY);
    expect(isAutonomousCategory(DISABLED_AUTONOMY_POLICY, "form_submit")).toBe(false);
  });

  it("stays off for an explicitly disabled section", async () => {
    const configDir = await writePolicy({ enabled: false, categories: ["delete"] });
    expect(await loadAutonomyPolicy(configDir)).toEqual(DISABLED_AUTONOMY_POLICY);
  });

  it("covers only routine transition categories by default", async () => {
    const configDir = await writePolicy({ enabled: true });
    const policy = await loadAutonomyPolicy(configDir);
    for (const category of AUTONOMOUS_RISK_CATEGORIES) {
      expect(isAutonomousCategory(policy, category)).toBe(
        DEFAULT_AUTONOMOUS_RISK_CATEGORIES.includes(
          category as (typeof DEFAULT_AUTONOMOUS_RISK_CATEGORIES)[number]
        )
      );
    }
    expect(autonomyPolicySummary(policy)).toEqual({
      enabled: true,
      categories: [...DEFAULT_AUTONOMOUS_RISK_CATEGORIES]
    });
  });

  it("honors an explicit list of routine categories", async () => {
    const narrow = await loadAutonomyPolicy(await writePolicy({
      enabled: true,
      categories: ["external_navigation"]
    }));
    expect(isAutonomousCategory(narrow, "form_submit")).toBe(false);
    expect(isAutonomousCategory(narrow, "external_navigation")).toBe(true);
    expect(isAutonomousCategory(narrow, "delete")).toBe(false);
    expect(autonomyPolicySummary(narrow)).toEqual({
      enabled: true,
      categories: ["external_navigation"]
    });
  });

  it("keeps a high-risk category out of the short policy until it is named", async () => {
    const short = await loadAutonomyPolicy(await writePolicy({ enabled: true }));
    for (const category of EXPLICIT_ONLY_RISK_CATEGORIES) {
      expect(isAutonomousCategory(short, category)).toBe(false);
      const named = await loadAutonomyPolicy(await writePolicy({ enabled: true, categories: [category] }));
      expect(isAutonomousCategory(named, category)).toBe(true);
      expect(autonomyPolicySummary(named)).toEqual({ enabled: true, categories: [category] });
    }
  });

  it("covers every category when the owner names them all", async () => {
    const policy = await loadAutonomyPolicy(await writePolicy({
      enabled: true,
      categories: [...AUTONOMOUS_RISK_CATEGORIES]
    }));
    for (const category of AUTONOMOUS_RISK_CATEGORIES) {
      expect(isAutonomousCategory(policy, category)).toBe(true);
    }
    expect(autonomyPolicySummary(policy)).toEqual({
      enabled: true,
      categories: [...AUTONOMOUS_RISK_CATEGORIES]
    });
  });

  it("never covers a missing or unrecognized risk category", async () => {
    const policy = await loadAutonomyPolicy(await writePolicy({ enabled: true }));
    expect(isAutonomousCategory(policy, undefined)).toBe(false);
    expect(isAutonomousCategory(policy, "sensitive_action")).toBe(false);
    expect(isAutonomousCategory(policy, "some_future_risk")).toBe(false);
  });

  it("fails closed on a malformed section instead of guessing", async () => {
    for (const section of [
      {},
      { enabled: "true" },
      { enabled: true, categories: [] },
      { enabled: true, categories: "delete" },
      { enabled: true, categories: ["delete", "not_a_category"] },
      { enabled: true, categories: ["delete", 7] }
    ]) {
      const configDir = await writePolicy(section);
      await expect(loadAutonomyPolicy(configDir)).rejects.toThrow(/autonomous_actions/u);
    }
  });
});
