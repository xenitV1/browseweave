import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { APP_VERSION, BROWSER_EXTENSION_VERSION } from "../src/core/version.js";
import { browserExtensionVersion, releaseDistTag } from "../scripts/version-helpers.mjs";

describe("application version", () => {
  it("matches package.json", async () => {
    const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8")) as {
      version?: unknown;
    };
    expect(APP_VERSION).toBe(packageJson.version);
    expect(BROWSER_EXTENSION_VERSION).toBe(browserExtensionVersion(packageJson.version));
  });

  it("keeps package-lock executable metadata aligned with package.json", async () => {
    const [packageJson, packageLock] = await Promise.all([
      readFile(new URL("../package.json", import.meta.url), "utf8").then((value) => JSON.parse(value)),
      readFile(new URL("../package-lock.json", import.meta.url), "utf8").then((value) => JSON.parse(value))
    ]) as [{ bin?: unknown }, { packages?: { ""?: { bin?: unknown } } }];
    expect(packageLock.packages?.[""]?.bin).toEqual(packageJson.bin);
  });

  it("keeps prereleases off npm's latest dist-tag", () => {
    expect(releaseDistTag("1.2.3")).toBe("latest");
    expect(releaseDistTag("1.2.3-alpha.4")).toBe("alpha");
    expect(releaseDistTag("1.2.3-beta.4")).toBe("beta");
    expect(releaseDistTag("1.2.3-rc.4")).toBe("rc");
    expect(() => releaseDistTag("1.2.3-preview.4")).toThrow(/stable SemVer/iu);
  });

  it("maps prerelease channels to ordered browser-store-safe versions", () => {
    expect(browserExtensionVersion("1.2.3-alpha.0")).toBe("1.2.3.1");
    expect(browserExtensionVersion("1.2.3-beta.0")).toBe("1.2.3.10001");
    expect(browserExtensionVersion("1.2.3-rc.0")).toBe("1.2.3.20001");
    expect(browserExtensionVersion("1.2.3")).toBe("1.2.3.65535");
  });

  it("rejects unsupported or out-of-range release versions", () => {
    expect(() => browserExtensionVersion("1.2.3-preview.1")).toThrow(/stable SemVer/iu);
    expect(() => browserExtensionVersion("65536.0.0")).toThrow(/range/iu);
    expect(() => browserExtensionVersion("1.2.3-beta.10000")).toThrow(/sequence/iu);
  });
});
