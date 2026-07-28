import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { browserExtensionVersion, parseReleaseVersion } from "./version-helpers.mjs";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectDirectory = path.resolve(scriptDirectory, "..");
const distRoot = path.join(projectDirectory, "extension", "dist");
const packageJson = JSON.parse(await readFile(path.join(projectDirectory, "package.json"), "utf8"));
parseReleaseVersion(packageJson.version);
const expectedBrowserVersion = browserExtensionVersion(packageJson.version);

const requiredFiles = [
  "manifest.json",
  "background.js",
  "content.js",
  "popup.html",
  "popup.js",
  "options.html",
  "options.js",
  "icons/icon-16.png",
  "icons/icon-32.png",
  "icons/icon-48.png",
  "icons/icon-96.png",
  "icons/icon-128.png",
  "styles/ui.css",
  "PRIVACY.md",
  "THIRD_PARTY_NOTICES.md",
  "LICENSE"
];
const iconEntries = {
  16: "icons/icon-16.png",
  32: "icons/icon-32.png",
  48: "icons/icon-48.png",
  96: "icons/icon-96.png",
  128: "icons/icon-128.png"
};
const actionIconEntries = {
  16: "icons/icon-16.png",
  32: "icons/icon-32.png",
  48: "icons/icon-48.png"
};
const firefoxPermissions = ["<all_urls>", "tabs", "webNavigation", "storage", "nativeMessaging"];
const chromiumPermissions = ["tabs", "webNavigation", "storage", "scripting", "nativeMessaging"];
const firefoxDisclosure = [
  "authenticationInfo",
  "browsingActivity",
  "financialAndPaymentInfo",
  "healthInfo",
  "locationInfo",
  "personalCommunications",
  "personallyIdentifyingInfo",
  "searchTerms",
  "websiteActivity",
  "websiteContent"
];
const firefoxCsp = "script-src 'self'; object-src 'self'; connect-src 'self' ws://127.0.0.1:32110";
const chromiumCsp = "script-src 'self'; object-src 'self'; connect-src 'self' ws://127.0.0.1:32110";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertExactKeys(value, expected, label) {
  assert(value !== null && typeof value === "object" && !Array.isArray(value), `${label} must be an object.`);
  const actualKeys = Object.keys(value).sort();
  const expectedKeys = [...expected].sort();
  assert(JSON.stringify(actualKeys) === JSON.stringify(expectedKeys),
    `${label} keys must be exactly ${expectedKeys.join(", ")}; received ${actualKeys.join(", ") || "none"}.`);
}

function assertExactArray(values, expected, label) {
  assert(Array.isArray(values), `${label} must be an array.`);
  assert(new Set(values).size === values.length, `${label} must not contain duplicates.`);
  assert(values.length === expected.length && expected.every((value) => values.includes(value)),
    `${label} must be exactly ${expected.join(", ") || "an empty list"}.`);
}

function assertExactMapping(value, expected, label) {
  assertExactKeys(value, Object.keys(expected), label);
  for (const [key, expectedValue] of Object.entries(expected)) {
    assert(value[key] === expectedValue, `${label}.${key} must be ${expectedValue}.`);
  }
}

function assertCommonManifest(targetName, manifest, topLevelKeys) {
  assertExactKeys(manifest, topLevelKeys, `${targetName}: manifest`);
  assert(manifest.name === "BrowseWeave", `${targetName}: extension name must be BrowseWeave.`);
  assert(manifest.version === expectedBrowserVersion,
    `${targetName}: numeric manifest version must match the mapped package version.`);
  assert(manifest.version_name === packageJson.version,
    `${targetName}: manifest version_name must match package.json.`);
  assertExactMapping(manifest.icons, iconEntries, `${targetName}: icons`);

  assertExactKeys(manifest.options_ui, ["page", "open_in_tab"], `${targetName}: options_ui`);
  assert(manifest.options_ui.page === "options.html", `${targetName}: options page is missing.`);
  assert(manifest.options_ui.open_in_tab === true, `${targetName}: options page must open in a tab.`);

  assert(Array.isArray(manifest.content_scripts) && manifest.content_scripts.length === 1,
    `${targetName}: exactly one shared content script declaration is expected.`);
  const contentScript = manifest.content_scripts[0];
  assertExactKeys(contentScript, ["matches", "js", "run_at", "all_frames", "match_about_blank"],
    `${targetName}: content script declaration`);
  assertExactArray(contentScript.matches, ["<all_urls>"], `${targetName}: content script matches`);
  assertExactArray(contentScript.js, ["content.js"], `${targetName}: content script files`);
  assert(contentScript.run_at === "document_idle", `${targetName}: content script run_at must be document_idle.`);
  assert(contentScript.all_frames === true, `${targetName}: content script must cover all frames.`);
  assert(contentScript.match_about_blank === true,
    `${targetName}: content script must preserve match_about_blank coverage.`);
}

async function validateCommonFiles(targetName) {
  const directory = path.join(distRoot, targetName);
  for (const file of requiredFiles) await access(path.join(directory, file));

  const background = await readFile(path.join(directory, "background.js"), "utf8");
  assert(background.includes("ws://127.0.0.1:32110"), `${targetName}: local bridge endpoint is missing.`);
  assert(background.includes("webextension-polyfill"), `${targetName}: bundled WebExtension polyfill is missing.`);
  const notice = await readFile(path.join(directory, "THIRD_PARTY_NOTICES.md"), "utf8");
  assert(notice.includes("webextension-polyfill") && notice.includes("0.12.0")
    && notice.includes("Mozilla Public License 2.0")
    && notice.includes("https://github.com/mozilla/webextension-polyfill/tree/0.12.0"),
  `${targetName}: exact MPL notice and corresponding-source link are missing.`);
  const [projectLicense, bundledLicense] = await Promise.all([
    readFile(path.join(projectDirectory, "LICENSE"), "utf8"),
    readFile(path.join(directory, "LICENSE"), "utf8")
  ]);
  assert(bundledLicense === projectLicense, `${targetName}: bundled MIT LICENSE differs from the project license.`);
  for (const bundleName of ["background.js", "content.js", "popup.js", "options.js"]) {
    const bundle = await readFile(path.join(directory, bundleName), "utf8");
    assert(bundle.startsWith("/*! BrowseWeave third-party notices: THIRD_PARTY_NOTICES.md."),
      `${targetName}: ${bundleName} is missing the third-party notice banner.`);
    assert(bundle.includes("https://github.com/mozilla/webextension-polyfill/tree/0.12.0"),
      `${targetName}: ${bundleName} is missing the exact MPL source pointer.`);
  }

  for (const htmlName of ["popup.html", "options.html"]) {
    const html = await readFile(path.join(directory, htmlName), "utf8");
    assert(!/(?:src|href)\s*=\s*["']https?:\/\//iu.test(html),
      `${targetName}: ${htmlName} references remotely hosted executable or UI content.`);
  }

  const nestedManifestTemplates = await readdir(directory);
  assert(!nestedManifestTemplates.includes("manifests"), `${targetName}: source manifest templates leaked into the build.`);
}

function validateFirefoxManifest(manifest) {
  const targetName = "firefox-mv2";
  assertCommonManifest(targetName, manifest, [
    "manifest_version",
    "name",
    "version",
    "version_name",
    "description",
    "icons",
    "permissions",
    "background",
    "browser_action",
    "options_ui",
    "content_scripts",
    "content_security_policy",
    "browser_specific_settings"
  ]);

  assert(manifest.manifest_version === 2, `${targetName}: manifest_version 2 is required.`);
  assertExactArray(manifest.permissions, firefoxPermissions, `${targetName}: permissions`);

  assertExactKeys(manifest.background, ["scripts", "persistent"], `${targetName}: background`);
  assertExactArray(manifest.background.scripts, ["background.js"], `${targetName}: background scripts`);
  assert(manifest.background.persistent === true, `${targetName}: persistent background page is required.`);

  assertExactKeys(manifest.browser_action, ["default_title", "default_popup", "default_icon"],
    `${targetName}: browser_action`);
  assert(manifest.browser_action.default_title === "BrowseWeave", `${targetName}: browser action title is unexpected.`);
  assert(manifest.browser_action.default_popup === "popup.html", `${targetName}: browser_action is missing.`);
  assertExactMapping(manifest.browser_action.default_icon, actionIconEntries, `${targetName}: browser_action icons`);

  assert(manifest.content_security_policy === firefoxCsp, `${targetName}: extension CSP is unexpected.`);
  assertExactKeys(manifest.browser_specific_settings, ["gecko"], `${targetName}: browser_specific_settings`);
  const gecko = manifest.browser_specific_settings.gecko;
  assertExactKeys(gecko, ["id", "strict_min_version", "data_collection_permissions"], `${targetName}: gecko settings`);
  assert(gecko.id === "browseweave@local.invalid", `${targetName}: fixed Gecko extension id is missing or changed.`);
  assert(gecko.strict_min_version === "142.0", `${targetName}: Firefox 142 minimum is required.`);
  const disclosure = gecko.data_collection_permissions;
  assertExactKeys(disclosure, ["required", "optional"], `${targetName}: Gecko data collection disclosure`);
  assertExactArray(disclosure.required, firefoxDisclosure, `${targetName}: required Gecko data collection disclosure`);
  assertExactArray(disclosure.optional, [], `${targetName}: optional Gecko data collection disclosure`);
}

function validateChromiumManifest(manifest) {
  const targetName = "chromium-mv3";
  assertCommonManifest(targetName, manifest, [
    "manifest_version",
    "name",
    "version",
    "version_name",
    "description",
    "icons",
    "minimum_chrome_version",
    "permissions",
    "host_permissions",
    "background",
    "action",
    "options_ui",
    "content_scripts",
    "content_security_policy"
  ]);

  assert(manifest.manifest_version === 3, `${targetName}: manifest_version 3 is required.`);
  assert(manifest.minimum_chrome_version === "116", `${targetName}: Chrome 116 minimum is required.`);
  assertExactArray(manifest.permissions, chromiumPermissions, `${targetName}: permissions`);
  assertExactArray(manifest.host_permissions, ["<all_urls>"], `${targetName}: host permissions`);

  assertExactKeys(manifest.background, ["service_worker"], `${targetName}: background`);
  assert(manifest.background.service_worker === "background.js", `${targetName}: service worker background is missing.`);

  assertExactKeys(manifest.action, ["default_title", "default_popup", "default_icon"], `${targetName}: action`);
  assert(manifest.action.default_title === "BrowseWeave", `${targetName}: action title is unexpected.`);
  assert(manifest.action.default_popup === "popup.html", `${targetName}: action is missing.`);
  assertExactMapping(manifest.action.default_icon, actionIconEntries, `${targetName}: action icons`);

  assertExactKeys(manifest.content_security_policy, ["extension_pages"], `${targetName}: content_security_policy`);
  assert(manifest.content_security_policy.extension_pages === chromiumCsp, `${targetName}: extension page CSP is unexpected.`);
}

async function expectManifestRejection(label, validator, original, mutate) {
  const candidate = structuredClone(original);
  mutate(candidate);
  try {
    validator(candidate);
  } catch {
    return;
  }
  throw new Error(`Manifest validator self-test failed to reject ${label}.`);
}

async function runManifestValidatorSelfTests(firefoxManifest, chromiumManifest) {
  const targets = [
    ["firefox-mv2", validateFirefoxManifest, firefoxManifest],
    ["chromium-mv3", validateChromiumManifest, chromiumManifest]
  ];
  const forbiddenTopLevelFields = {
    optional_permissions: [],
    externally_connectable: { matches: ["https://example.invalid/*"] },
    update_url: "https://example.invalid/update.xml",
    web_accessible_resources: ["content.js"]
  };

  for (const [targetName, validator, manifest] of targets) {
    for (const [field, value] of Object.entries(forbiddenTopLevelFields)) {
      await expectManifestRejection(`${targetName} ${field}`, validator, manifest, (candidate) => {
        candidate[field] = value;
      });
    }
    await expectManifestRejection(`${targetName} extra permission`, validator, manifest, (candidate) => {
      candidate.permissions.push("cookies");
    });
    await expectManifestRejection(`${targetName} missing nativeMessaging permission`, validator, manifest, (candidate) => {
      candidate.permissions = candidate.permissions.filter((permission) => permission !== "nativeMessaging");
    });
    await expectManifestRejection(`${targetName} extra content script`, validator, manifest, (candidate) => {
      candidate.content_scripts[0].js.push("unexpected.js");
    });
    await expectManifestRejection(`${targetName} extra content script key`, validator, manifest, (candidate) => {
      candidate.content_scripts[0].world = "MAIN";
    });
  }

  await expectManifestRejection("firefox-mv2 extra background script", validateFirefoxManifest, firefoxManifest,
    (candidate) => candidate.background.scripts.push("unexpected.js"));
  await expectManifestRejection("chromium-mv3 extra background scripts key", validateChromiumManifest, chromiumManifest,
    (candidate) => { candidate.background.scripts = ["unexpected.js"]; });
  await expectManifestRejection("chromium-mv3 extra host permission", validateChromiumManifest, chromiumManifest,
    (candidate) => candidate.host_permissions.push("https://example.invalid/*"));
}

const firefoxManifest = JSON.parse(await readFile(path.join(distRoot, "firefox-mv2", "manifest.json"), "utf8"));
const chromiumManifest = JSON.parse(await readFile(path.join(distRoot, "chromium-mv3", "manifest.json"), "utf8"));

validateFirefoxManifest(firefoxManifest);
validateChromiumManifest(chromiumManifest);
await validateCommonFiles("firefox-mv2");
await validateCommonFiles("chromium-mv3");
await runManifestValidatorSelfTests(firefoxManifest, chromiumManifest);

console.error("BrowseWeave Firefox MV2 and Chromium MV3 builds passed exact manifest and structural validation.");
