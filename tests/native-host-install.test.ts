import { chmod, lstat, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installNativeHostRegistration, uninstallNativeHostRegistration } from "../src/native-host-install.js";
import { createNativeHostRegistrationPlan } from "../src/native-host-plan.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map(async (root) => await rm(root, { recursive: true, force: true })));
});

async function harness() {
  const home = await mkdtemp(path.join(tmpdir(), "browseweave-native-install-"));
  roots.push(home);
  const plan = createNativeHostRegistrationPlan({
    platform: "linux",
    home,
    nodePath: "/usr/bin/node",
    nativeHostScriptPath: "/opt/browseweave/native-host.js",
    firefoxExtensionIds: ["browseweave@local.invalid"]
  });
  return { home, plan };
}

describe("owner-safe native host artifact installation", () => {
  it("installs an executable managed launcher and exact private Firefox manifest idempotently", async () => {
    const { home, plan } = await harness();
    await installNativeHostRegistration(plan, home);
    await installNativeHostRegistration(plan, home);

    expect(await readFile(plan.launcher!.path, "utf8")).toBe(plan.launcher!.content);
    expect((await lstat(plan.launcher!.path)).mode & 0o777).toBe(0o700);
    expect(await readFile(plan.manifests[0]!.path, "utf8")).toBe(plan.manifests[0]!.content);
    expect((await lstat(plan.manifests[0]!.path)).mode & 0o777).toBe(0o600);
  });

  it("upgrades only an intact BrowseWeave-owned launcher while keeping the stable manifest path", async () => {
    const { home, plan } = await harness();
    await installNativeHostRegistration(plan, home);
    const upgraded = createNativeHostRegistrationPlan({
      platform: "linux",
      home,
      nodePath: "/opt/browseweave-v2/node",
      nativeHostScriptPath: "/opt/browseweave-v2/native-host.js",
      firefoxExtensionIds: ["browseweave@local.invalid"]
    });
    expect(upgraded.launcher!.path).toBe(plan.launcher!.path);
    expect(upgraded.manifests[0]!.content).toBe(plan.manifests[0]!.content);
    await installNativeHostRegistration(upgraded, home);
    expect(await readFile(upgraded.launcher!.path, "utf8")).toBe(upgraded.launcher!.content);
  });

  it("refuses foreign or tampered launcher and manifest files without overwriting them", async () => {
    const { home, plan } = await harness();
    await installNativeHostRegistration(plan, home);
    await writeFile(plan.launcher!.path, `${plan.launcher!.content}# tampered\n`, "utf8");
    await expect(installNativeHostRegistration(plan, home)).rejects.toThrow(/foreign.*launcher/iu);
    expect(await readFile(plan.launcher!.path, "utf8")).toContain("tampered");

    await writeFile(plan.launcher!.path, plan.launcher!.content, "utf8");
    await chmod(plan.launcher!.path, 0o700);
    await writeFile(plan.manifests[0]!.path, "{}\n", "utf8");
    await expect(installNativeHostRegistration(plan, home)).rejects.toThrow(/foreign.*firefox/iu);
    expect(await readFile(plan.manifests[0]!.path, "utf8")).toBe("{}\n");
  });

  it("refuses symlinked artifacts and directory components", async () => {
    const { home, plan } = await harness();
    await symlink(tmpdir(), path.join(home, ".mozilla"));
    await expect(installNativeHostRegistration(plan, home)).rejects.toThrow(/not a real directory/iu);
  });

  it("uninstalls only exact manifests and an intact managed launcher", async () => {
    const { home, plan } = await harness();
    await installNativeHostRegistration(plan, home);
    await uninstallNativeHostRegistration(plan, home);
    await expect(lstat(plan.launcher!.path)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(plan.manifests[0]!.path)).rejects.toMatchObject({ code: "ENOENT" });
  });
});
