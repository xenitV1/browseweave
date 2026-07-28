import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const qaScript = fileURLToPath(new URL("../scripts/live-isolated-bridge-qa.mjs", import.meta.url));
const launcherSource = readFileSync(new URL("../scripts/live-isolated-browser.mjs", import.meta.url), "utf8");

describe("isolated bridge QA marker recovery", () => {
  it("passes its dependency-injected behavioral recovery self-test", () => {
    const result = spawnSync(process.execPath, [qaScript, "--self-test"], {
      encoding: "utf8",
      timeout: 15_000,
      maxBuffer: 64 * 1024
    });

    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toContain("recovery policy, bounded polling");
    expect(result.stdout).toContain("failure cleanup, and delayed-startup race handling");
  });

  it("enables recovery only for the launcher's exact credential-skipped loopback QA child", () => {
    const start = launcherSource.indexOf("async function runAutomatedBridgeQa");
    const end = launcherSource.indexOf("async function runBrowser", start);
    const source = launcherSource.slice(start, end);

    expect(start).toBeGreaterThanOrEqual(0);
    expect(end).toBeGreaterThan(start);
    expect(source).toContain('"--browser-id"');
    expect(source).toContain('"--skip-credential"');
    expect(source).toContain('"--allow-http-loopback-fixture"');
    expect(source).toContain('"--recover-missing-marker"');
  });
});
