import { mkdtemp, rm, symlink, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  DISABLED_SESSION_APPROVAL_POLICY,
  createSessionChallenge,
  loadSessionApprovalPolicy,
  sessionChallengeMatches
} from "../src/daemon/session-approval.js";
import { policyPath } from "../src/daemon/policy.js";
import {
  SESSION_APPROVABLE_RISKS,
  SESSION_CHALLENGE_PATTERN,
  isSessionApprovableRisk,
  normalizeSessionChallenge
} from "../src/core/protocol.js";

const directories: string[] = [];

async function policyDirectory(contents?: string, mode = 0o600): Promise<string> {
  const directory = await mkdtemp(path.join(tmpdir(), "browseweave-policy-"));
  directories.push(directory);
  if (contents !== undefined) {
    const file = policyPath(directory);
    await writeFile(file, contents, { mode });
    await chmod(file, mode);
  }
  return directory;
}

afterEach(async () => {
  while (directories.length) {
    const directory = directories.pop();
    if (directory) await rm(directory, { recursive: true, force: true });
  }
});

describe("session approval tiers", () => {
  it("never admits a risk class that must stay with the extension-signed decision", () => {
    for (const risk of ["payment", "delete", "password", "2fa", "security", "visual_click"]) {
      expect(isSessionApprovableRisk(risk)).toBe(false);
    }
    for (const risk of SESSION_APPROVABLE_RISKS) {
      expect(isSessionApprovableRisk(risk)).toBe(true);
    }
    expect(isSessionApprovableRisk(undefined)).toBe(false);
    expect(isSessionApprovableRisk("")).toBe(false);
  });
});

describe("session confirmation challenge", () => {
  it("issues four-word phrases that match the shared contract", () => {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const challenge = createSessionChallenge();
      expect(SESSION_CHALLENGE_PATTERN.test(challenge)).toBe(true);
      expect(challenge.split(" ")).toHaveLength(4);
    }
  });

  it("does not repeat a phrase across requests", () => {
    const seen = new Set(Array.from({ length: 200 }, () => createSessionChallenge()));
    expect(seen.size).toBeGreaterThan(150);
  });

  it("accepts natural retyping but rejects anything else", () => {
    const challenge = createSessionChallenge();
    expect(sessionChallengeMatches(challenge, challenge)).toBe(true);
    expect(sessionChallengeMatches(challenge, `  ${challenge.toUpperCase()}  `)).toBe(true);
    expect(sessionChallengeMatches(challenge, challenge.replace(/ /gu, "  "))).toBe(true);

    expect(sessionChallengeMatches(challenge, "")).toBe(false);
    expect(sessionChallengeMatches(challenge, undefined)).toBe(false);
    expect(sessionChallengeMatches(challenge, challenge.split(" ").slice(0, 3).join(" "))).toBe(false);
    expect(sessionChallengeMatches(challenge, `${challenge} extra`)).toBe(false);
    expect(sessionChallengeMatches(challenge, createSessionChallenge().split(" ").reverse().join(" "))).toBe(false);
    // A prefix must not pass, or the phrase could be recovered word by word.
    const [first, second] = challenge.split(" ");
    expect(sessionChallengeMatches(challenge, `${first} ${second} zzz zzz`)).toBe(false);
  });

  it("normalizes only whitespace and case", () => {
    expect(normalizeSessionChallenge("  Amber   Cedar\tFlint  Onyx ")).toBe("amber cedar flint onyx");
    expect(normalizeSessionChallenge(42)).toBe("");
  });
});

describe("session approval policy file", () => {
  it("leaves the feature off when no policy file exists", async () => {
    const directory = await policyDirectory();
    expect(await loadSessionApprovalPolicy(directory)).toEqual(DISABLED_SESSION_APPROVAL_POLICY);
  });

  it("enables only the risks the owner listed", async () => {
    const directory = await policyDirectory(
      JSON.stringify({ session_approval: { enabled: true, risks: ["form_submit"] } })
    );
    const policy = await loadSessionApprovalPolicy(directory);
    expect(policy.enabled).toBe(true);
    expect([...policy.risks]).toEqual(["form_submit"]);
    expect(policy.risks.has("message")).toBe(false);
  });

  it("defaults to every session-approvable risk when the list is omitted", async () => {
    const directory = await policyDirectory(JSON.stringify({ session_approval: { enabled: true } }));
    const policy = await loadSessionApprovalPolicy(directory);
    expect([...policy.risks].sort()).toEqual([...SESSION_APPROVABLE_RISKS].sort());
  });

  it("refuses a policy that tries to widen authority beyond the tier", async () => {
    const directory = await policyDirectory(
      JSON.stringify({ session_approval: { enabled: true, risks: ["form_submit", "payment"] } })
    );
    await expect(loadSessionApprovalPolicy(directory)).rejects.toThrow(/may contain only/);
  });

  it("never lets the AI session authorize a local-file upload", async () => {
    const directory = await policyDirectory(
      JSON.stringify({ session_approval: { enabled: true, risks: ["file_attach"] } })
    );
    await expect(loadSessionApprovalPolicy(directory)).rejects.toThrow(/may contain only/);
  });

  it("fails closed on an invalid or damaged policy rather than falling back", async () => {
    const broken = await policyDirectory("{ not json");
    await expect(loadSessionApprovalPolicy(broken)).rejects.toThrow(/not valid JSON/);

    const wrongType = await policyDirectory(JSON.stringify({ session_approval: { enabled: "yes" } }));
    await expect(loadSessionApprovalPolicy(wrongType)).rejects.toThrow(/must be true or false/);

    const emptyRisks = await policyDirectory(JSON.stringify({ session_approval: { enabled: true, risks: [] } }));
    await expect(loadSessionApprovalPolicy(emptyRisks)).rejects.toThrow(/non-empty array/);
  });

  it("treats an explicitly disabled policy as off", async () => {
    const directory = await policyDirectory(
      JSON.stringify({ session_approval: { enabled: false, risks: ["form_submit"] } })
    );
    expect(await loadSessionApprovalPolicy(directory)).toEqual(DISABLED_SESSION_APPROVAL_POLICY);
  });

  it.runIf(process.platform !== "win32")("refuses a group- or world-readable policy file", async () => {
    const directory = await policyDirectory(JSON.stringify({ session_approval: { enabled: true } }), 0o644);
    await expect(loadSessionApprovalPolicy(directory)).rejects.toThrow(/permissions are unsafe/);
  });

  it.runIf(process.platform !== "win32")("refuses a symlinked policy file", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "browseweave-policy-"));
    directories.push(directory);
    const real = path.join(directory, "elsewhere.json");
    await writeFile(real, JSON.stringify({ session_approval: { enabled: true } }), { mode: 0o600 });
    await symlink(real, policyPath(directory));
    await expect(loadSessionApprovalPolicy(directory)).rejects.toThrow(/not a safe regular file/);
  });
});
