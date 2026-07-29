import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { APP_VERSION } from "../src/core/version.js";
import { installBundledAgentSkills } from "../src/setup/skill-install.js";

const PROJECT_ROOT = fileURLToPath(new URL("../", import.meta.url));
const roots: string[] = [];

async function temporaryRoot(label: string): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), `browseweave-${label}-`));
  roots.push(root);
  return root;
}

async function packageWithSkill(root: string, contents: string): Promise<string> {
  const packageRoot = path.join(root, "package");
  await mkdir(path.join(packageRoot, "skills", "browseweave"), { recursive: true });
  await writeFile(path.join(packageRoot, "skills", "browseweave", "SKILL.md"), contents, "utf8");
  return packageRoot;
}

async function bundledSkill(): Promise<string> {
  return await readFile(path.join(PROJECT_ROOT, "skills", "browseweave", "SKILL.md"), "utf8");
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("bundled agent-skill installation", () => {
  it("installs the exact npm-bundled skill for Codex and Claude Code idempotently", async () => {
    const root = await temporaryRoot("skills");
    const home = path.join(root, "home");
    await mkdir(home);
    const expected = await bundledSkill();

    const first = await installBundledAgentSkills({
      packageRoot: PROJECT_ROOT,
      home,
      version: APP_VERSION
    });
    expect(first).toEqual([
      { client: "codex", path: path.join(home, ".agents", "skills", "browseweave"), status: "installed" },
      { client: "claude-code", path: path.join(home, ".claude", "skills", "browseweave"), status: "installed" }
    ]);

    for (const result of first) {
      expect(await readFile(path.join(result.path, "SKILL.md"), "utf8")).toBe(expected);
      expect(JSON.parse(await readFile(path.join(result.path, ".browseweave-skill.json"), "utf8"))).toMatchObject({
        managed_by: "BrowseWeave",
        marker_version: 1,
        skill_name: "browseweave",
        package_version: APP_VERSION,
        content_sha256: expect.stringMatching(/^[a-f0-9]{64}$/u)
      });
      if (process.platform !== "win32") {
        expect((await stat(path.join(result.path, "SKILL.md"))).mode & 0o777).toBe(0o600);
      }
    }

    const second = await installBundledAgentSkills({
      packageRoot: PROJECT_ROOT,
      home,
      version: APP_VERSION
    });
    expect(second.map(({ status }) => status)).toEqual(["unchanged", "unchanged"]);
  });

  it("updates only an unchanged BrowseWeave-managed copy", async () => {
    const root = await temporaryRoot("skill-update");
    const home = path.join(root, "home");
    await mkdir(home);
    const original = await bundledSkill();
    const firstPackage = await packageWithSkill(path.join(root, "first"), original);
    await installBundledAgentSkills({ packageRoot: firstPackage, home, version: APP_VERSION });

    const updated = `${original}\n<!-- transfer-case -->\n`;
    const secondPackage = await packageWithSkill(path.join(root, "second"), updated);
    const results = await installBundledAgentSkills({
      packageRoot: secondPackage,
      home,
      version: "0.1.0-beta.6"
    });
    expect(results.map(({ status }) => status)).toEqual(["updated", "updated"]);
    for (const result of results) {
      expect(await readFile(path.join(result.path, "SKILL.md"), "utf8")).toBe(updated);
    }
  });

  it("adopts an exact existing copy but never overwrites a foreign same-named skill", async () => {
    const root = await temporaryRoot("skill-foreign");
    const home = path.join(root, "home");
    const exactTarget = path.join(home, ".agents", "skills", "browseweave");
    const foreignTarget = path.join(home, ".claude", "skills", "browseweave");
    await mkdir(exactTarget, { recursive: true });
    await mkdir(foreignTarget, { recursive: true });
    const expected = await bundledSkill();
    await writeFile(path.join(exactTarget, "SKILL.md"), expected, "utf8");
    await writeFile(path.join(foreignTarget, "SKILL.md"), "user-owned instructions\n", "utf8");

    await expect(installBundledAgentSkills({
      packageRoot: PROJECT_ROOT,
      home,
      version: APP_VERSION
    })).rejects.toThrow(/user-managed browseweave skill/iu);
    await expect(readFile(path.join(exactTarget, ".browseweave-skill.json"), "utf8")).rejects.toMatchObject({
      code: "ENOENT"
    });
    expect(await readFile(path.join(foreignTarget, "SKILL.md"), "utf8")).toBe("user-owned instructions\n");
  });

  it("refuses a modified managed copy without changing either client target", async () => {
    const root = await temporaryRoot("skill-tamper");
    const home = path.join(root, "home");
    await mkdir(home);
    await installBundledAgentSkills({ packageRoot: PROJECT_ROOT, home, version: APP_VERSION });
    const codexSkill = path.join(home, ".agents", "skills", "browseweave", "SKILL.md");
    const claudeSkill = path.join(home, ".claude", "skills", "browseweave", "SKILL.md");
    const claudeBefore = await readFile(claudeSkill, "utf8");
    await writeFile(codexSkill, "locally modified\n", "utf8");

    await expect(installBundledAgentSkills({
      packageRoot: PROJECT_ROOT,
      home,
      version: APP_VERSION
    })).rejects.toThrow(/was modified/iu);
    expect(await readFile(codexSkill, "utf8")).toBe("locally modified\n");
    expect(await readFile(claudeSkill, "utf8")).toBe(claudeBefore);
  });

  it.runIf(process.platform !== "win32")("refuses a symlinked skill destination", async () => {
    const root = await temporaryRoot("skill-symlink");
    const home = path.join(root, "home");
    const outside = path.join(root, "outside");
    await mkdir(path.join(home, ".agents", "skills"), { recursive: true });
    await mkdir(path.join(home, ".claude", "skills"), { recursive: true });
    await mkdir(outside);
    await symlink(outside, path.join(home, ".agents", "skills", "browseweave"));

    await expect(installBundledAgentSkills({
      packageRoot: PROJECT_ROOT,
      home,
      version: APP_VERSION
    })).rejects.toThrow(/foreign or unsafe/iu);
    expect(await readdir(outside)).toEqual([]);
  });
});
