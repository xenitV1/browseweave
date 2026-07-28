import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { APP_VERSION } from "../src/version.js";

const cli = fileURLToPath(new URL("../dist/src/cli.js", import.meta.url));

describe("public CLI surface", () => {
  it("keeps guided setup public without exposing a pairing-token command", () => {
    const result = spawnSync(process.execPath, [cli, "--help"], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain(`npx browseweave@${APP_VERSION} setup`);
    expect(result.stdout).toContain("Pairing credentials are never printed");
    expect(result.stdout).not.toContain("pairing-token");
  });

  it("rejects the removed legacy display command without printing data", () => {
    const result = spawnSync(process.execPath, [cli, "pairing-token", "--show", "--browser", "chrome"], {
      encoding: "utf8",
      timeout: 10_000,
      maxBuffer: 64 * 1024
    });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("Unknown command: pairing-token");
  });
});
