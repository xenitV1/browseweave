import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { minimizePurgeTargets, purgeOwnedApplicationDirectories } from "../src/native/purge-data.js";

const roots: string[] = [];

afterEach(async () => {
  const { rm } = await import("node:fs/promises");
  await Promise.all(roots.splice(0).map(async (root) => await rm(root, { recursive: true, force: true })));
});

async function rootFixture(): Promise<string> {
  const createdRoot = await mkdtemp(path.join(tmpdir(), "browseweave-purge-"));
  const root = await realpath(createdRoot);
  roots.push(root);
  return root;
}

describe("BrowseWeave local data purge", () => {
  it("collapses nested targets to the exact application root", async () => {
    const root = await rootFixture();
    const app = path.join(root, "BrowseWeave");
    expect(minimizePurgeTargets([
      path.join(app, "Config"),
      path.join(app, "Runtime"),
      app
    ])).toEqual([app]);
  });

  it("removes an owned application directory and its contents", async () => {
    const root = await rootFixture();
    const app = path.join(root, "browseweave");
    await mkdir(app, { recursive: true });
    await writeFile(path.join(app, "pairing-token"), "dummy", { mode: 0o600 });
    await expect(purgeOwnedApplicationDirectories([app])).resolves.toEqual([app]);
    await expect(import("node:fs/promises").then(({ lstat }) => lstat(app))).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("refuses broad or unrelated directory names", async () => {
    const root = await rootFixture();
    expect(() => minimizePurgeTargets([root])).toThrow(/unexpected name/iu);
    expect(() => minimizePurgeTargets([path.parse(root).root])).toThrow(/unsafe/iu);
  });

  it("refuses a symlink instead of following it", async () => {
    const root = await rootFixture();
    const destination = path.join(root, "destination");
    const linked = path.join(root, "browseweave");
    await mkdir(destination);
    await symlink(destination, linked, "dir");
    await expect(purgeOwnedApplicationDirectories([linked])).rejects.toThrow(/safe application directory/iu);
    await expect(import("node:fs/promises").then(({ lstat }) => lstat(destination))).resolves.toBeDefined();
  });
});
