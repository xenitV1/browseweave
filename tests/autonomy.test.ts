import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  AUTONOMOUS_RISK_CATEGORIES,
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

  it("covers every page-action category but never file attachment by default", async () => {
    const configDir = await writePolicy({ enabled: true });
    const policy = await loadAutonomyPolicy(configDir);
    for (const category of AUTONOMOUS_RISK_CATEGORIES) {
      expect(isAutonomousCategory(policy, category)).toBe(category !== "file_attach");
    }
    expect(autonomyPolicySummary(policy).categories).not.toContain("file_attach");
  });

  it("honors an explicit category list, including opting file attachment in", async () => {
    const narrow = await loadAutonomyPolicy(await writePolicy({
      enabled: true,
      categories: ["form_submit", "external_navigation"]
    }));
    expect(isAutonomousCategory(narrow, "form_submit")).toBe(true);
    expect(isAutonomousCategory(narrow, "delete")).toBe(false);
    expect(autonomyPolicySummary(narrow)).toEqual({
      enabled: true,
      categories: ["form_submit", "external_navigation"]
    });

    const withAttachments = await loadAutonomyPolicy(await writePolicy({
      enabled: true,
      categories: ["file_attach"]
    }));
    expect(isAutonomousCategory(withAttachments, "file_attach")).toBe(true);
    expect(isAutonomousCategory(withAttachments, "payment")).toBe(false);
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
