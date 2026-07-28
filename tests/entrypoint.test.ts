import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { isDirectExecution } from "../src/core/entrypoint.js";

describe("public entrypoint detection", () => {
  it("recognizes an npm-style symlink as direct execution", () => {
    const directory = mkdtempSync(path.join(tmpdir(), "browseweave-entrypoint-"));
    try {
      const target = path.join(directory, "cli.js");
      const npmBin = path.join(directory, "browseweave");
      writeFileSync(target, "#!/usr/bin/env node\n", { mode: 0o700 });
      symlinkSync(target, npmBin);
      expect(isDirectExecution(pathToFileURL(target).href, npmBin)).toBe(true);
      expect(isDirectExecution(pathToFileURL(target).href, path.join(directory, "missing"))).toBe(false);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
