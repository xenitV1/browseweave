/**
 * Confirmation challenges and policy for approvals a human gives in the MCP
 * client session instead of the browser extension popup.
 *
 * The challenge is generated here and travels only over authenticated loopback
 * IPC into the MCP server's elicitation message. It must never reach a tool
 * result, the audit log, extension UI, a page DOM or URL, or daemon output.
 */
import { randomInt, timingSafeEqual } from "node:crypto";
import { constants as fsConstants, lstat, open } from "node:fs/promises";
import path from "node:path";
import {
  SESSION_APPROVABLE_RISKS,
  SESSION_CHALLENGE_PATTERN,
  isSessionApprovableRisk,
  normalizeSessionChallenge
} from "../core/protocol.js";

export const SESSION_POLICY_FILE_NAME = "policy.json" as const;
export const SESSION_CHALLENGE_WORDS = 4;
const MAX_POLICY_BYTES = 8 * 1024;

/**
 * Short, unambiguous, keyboard-simple words. The list is fixed so a challenge
 * is always easy to read back and retype under time pressure.
 */
const CHALLENGE_WORDS: readonly string[] = (
  "amber anchor apple arch arrow aspen atlas autumn bamboo basil beacon beam " +
  "birch bison blossom bolt branch brass bridge bronze brook button cabin cactus " +
  "camel candle canvas canyon carbon cedar chalk cherry chorus cinder circle " +
  "citrus clay clever cliff clover cobalt comet copper coral cotton crane crater " +
  "crest crimson crystal cypress daisy dawn delta denim desert diamond dune " +
  "echo ember emerald ether fable falcon fern fiber fjord flint forest fossil " +
  "fox galaxy garden garnet gentle ginger glacier glass gold granite grove " +
  "harbor harvest hazel heron hollow honey horizon ice indigo iris island ivory " +
  "jade jasmine jetty jungle juniper kernel kettle lagoon lantern lark laurel " +
  "lemon lentil lilac linen lotus lumen lunar lupine maple marble marsh meadow " +
  "melon mesa meteor mint mirror mist monsoon moss motion nectar nettle nimbus " +
  "noble north oak oasis ocean olive onyx opal orbit orchard otter oxide " +
  "pantry papaya parcel pastel pebble pepper petal pewter pigeon pillar pine " +
  "pixel plateau plum pollen poplar prairie prism pulse quartz quill quiver " +
  "radish rain raven reef ribbon ridge ripple river robin rope rosemary rust " +
  "saffron sage salt sandy sapling savory scarlet sequoia shale shell shore " +
  "signal silk silver slate slope smoke socket solar sorrel spark spiral spring " +
  "spruce stable steel stone storm stream summit sunset syrup tandem tempo " +
  "thicket thistle thunder timber tonic topaz torch trellis tulip tundra turret " +
  "umber valley vanilla velvet vertex vessel violet vista walnut willow window " +
  "winter wombat yarrow yellow zenith zephyr zinc"
).split(" ");

export interface SessionApprovalPolicy {
  readonly enabled: boolean;
  /** Risk classes the owner opted in, always a subset of SESSION_APPROVABLE_RISKS. */
  readonly risks: ReadonlySet<string>;
}

export const DISABLED_SESSION_APPROVAL_POLICY: SessionApprovalPolicy = {
  enabled: false,
  risks: new Set<string>()
};

export function sessionPolicyPath(configDir: string): string {
  return path.join(configDir, SESSION_POLICY_FILE_NAME);
}

/** Unbiased selection; `randomInt` rejects modulo-skewed draws internally. */
export function createSessionChallenge(words = SESSION_CHALLENGE_WORDS): string {
  const chosen: string[] = [];
  for (let index = 0; index < words; index += 1) {
    chosen.push(CHALLENGE_WORDS[randomInt(CHALLENGE_WORDS.length)] as string);
  }
  return chosen.join(" ");
}

/**
 * Constant-time comparison after whitespace and case normalisation, so a human
 * may retype the phrase naturally without the check leaking length or prefix.
 */
export function sessionChallengeMatches(expected: string, candidate: unknown): boolean {
  const normalized = normalizeSessionChallenge(candidate);
  if (!SESSION_CHALLENGE_PATTERN.test(normalized) || !SESSION_CHALLENGE_PATTERN.test(expected)) return false;
  const expectedBytes = Buffer.from(expected, "utf8");
  const candidateBytes = Buffer.from(normalized, "utf8");
  if (expectedBytes.byteLength !== candidateBytes.byteLength) return false;
  return timingSafeEqual(expectedBytes, candidateBytes);
}

function parsePolicy(contents: string): SessionApprovalPolicy {
  let value: unknown;
  try {
    value = JSON.parse(contents) as unknown;
  } catch {
    throw new Error("The BrowseWeave policy file is not valid JSON.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The BrowseWeave policy file must contain a JSON object.");
  }
  const record = (value as Record<string, unknown>).session_approval;
  if (record === undefined) return DISABLED_SESSION_APPROVAL_POLICY;
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("session_approval must be a JSON object.");
  }
  const section = record as Record<string, unknown>;
  if (typeof section.enabled !== "boolean") {
    throw new Error("session_approval.enabled must be true or false.");
  }
  if (!section.enabled) return DISABLED_SESSION_APPROVAL_POLICY;
  const rawRisks = section.risks ?? [...SESSION_APPROVABLE_RISKS];
  if (!Array.isArray(rawRisks) || rawRisks.length === 0) {
    throw new Error("session_approval.risks must be a non-empty array.");
  }
  for (const risk of rawRisks) {
    if (!isSessionApprovableRisk(risk)) {
      throw new Error(
        `session_approval.risks may contain only ${SESSION_APPROVABLE_RISKS.join(", ")}.`
      );
    }
  }
  return { enabled: true, risks: new Set(rawRisks as string[]) };
}

/**
 * Reads the owner-only policy file. A missing file leaves session approval off.
 * A present but unsafe or invalid file fails closed rather than falling back to
 * a default, so a damaged policy can never silently widen authority.
 */
export async function loadSessionApprovalPolicy(configDir: string): Promise<SessionApprovalPolicy> {
  const policyPath = sessionPolicyPath(configDir);
  let info;
  try {
    info = await lstat(policyPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return DISABLED_SESSION_APPROVAL_POLICY;
    throw error;
  }
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`The BrowseWeave policy file is not a safe regular file: ${policyPath}`);
  }
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error(`The BrowseWeave policy file is not owned by the current user: ${policyPath}`);
  }
  if (process.platform !== "win32" && (info.mode & 0o077) !== 0) {
    throw new Error(`The BrowseWeave policy file permissions are unsafe. Restrict it to its owner: ${policyPath}`);
  }
  if (info.size > MAX_POLICY_BYTES) {
    throw new Error(`The BrowseWeave policy file exceeds ${MAX_POLICY_BYTES} bytes: ${policyPath}`);
  }
  const handle = await open(policyPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    return parsePolicy(await handle.readFile("utf8"));
  } finally {
    await handle.close();
  }
}
