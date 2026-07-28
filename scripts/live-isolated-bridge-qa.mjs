#!/usr/bin/env node

let callBridge;

const DUMMY_USERNAME = "qa-user@example.invalid";
const DUMMY_PASSWORD = "BrowseWeave-Dummy-Only-42!";
const checks = [];

function fail(message) {
  throw new Error(message);
}

function ensure(condition, message) {
  if (!condition) fail(message);
}

function asRecord(value, label) {
  ensure(value !== null && typeof value === "object" && !Array.isArray(value), `${label} is not a valid object.`);
  return value;
}

function numberValue(value, label) {
  ensure(typeof value === "number" && Number.isFinite(value), `${label} is not a finite number.`);
  return value;
}

function mark(label) {
  checks.push(label);
  process.stdout.write(`✓ ${label}\n`);
}

function parseArguments(argv) {
  if (argv.length === 1 && argv[0] === "--self-test") return { selfTest: true };
  let fixtureUrl;
  let browserId;
  let includeCredentials = true;
  let allowHttpLoopbackFixture = false;
  let recoverMissingMarker = false;
  let credentialTimeoutMs = 5 * 60_000;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--fixture-url") {
      fixtureUrl = argv[index + 1];
      index += 1;
      continue;
    }
    if (argument === "--browser-id") {
      browserId = argv[index + 1];
      index += 1;
      continue;
    }
    if (argument === "--skip-credential") {
      includeCredentials = false;
      continue;
    }
    if (argument === "--allow-http-loopback-fixture") {
      allowHttpLoopbackFixture = true;
      continue;
    }
    if (argument === "--recover-missing-marker") {
      recoverMissingMarker = true;
      continue;
    }
    if (argument === "--credential-timeout-ms") {
      credentialTimeoutMs = Number(argv[index + 1]);
      index += 1;
      continue;
    }
    if (argument === "--help" || argument === "-h") {
      process.stdout.write(
        "Usage: node scripts/live-isolated-bridge-qa.mjs --fixture-url 'https://localhost:41732/live-isolated-qa.html?qa_run=...' [--browser-id browser-...] [--skip-credential] [--allow-http-loopback-fixture] [--recover-missing-marker] [--credential-timeout-ms 300000]\n" +
        "       node scripts/live-isolated-bridge-qa.mjs --self-test\n\n" +
        "Run only against the disposable browser started by live-isolated-browser.mjs. HTTP is accepted only on loopback when credentials are explicitly skipped; marker recovery is reserved for that launcher's exact browser ID.\n"
      );
      process.exit(0);
    }
    fail(`Unknown option: ${argument}`);
  }
  ensure(typeof fixtureUrl === "string", "--fixture-url is required.");
  if (browserId !== undefined) {
    ensure(/^browser-[a-f0-9]{24}$/u.test(browserId), "--browser-id is not a valid BrowseWeave browser ID.");
  }
  ensure(
    Number.isSafeInteger(credentialTimeoutMs) && credentialTimeoutMs >= 10_000 && credentialTimeoutMs <= 5 * 60_000,
    "--credential-timeout-ms must be an integer between 10000 and 300000."
  );
  const parsed = new URL(fixtureUrl);
  const exactHttpLoopback = parsed.protocol === "http:" &&
    (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost") &&
    allowHttpLoopbackFixture && !includeCredentials;
  ensure(
    parsed.protocol === "https:" || exactHttpLoopback,
    "The isolated fixture must use HTTPS, except for explicit loopback-only QA with credentials skipped."
  );
  ensure(
    parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1",
    "The isolated fixture host must be an exact loopback name or address."
  );
  ensure(
    !allowHttpLoopbackFixture || exactHttpLoopback,
    "--allow-http-loopback-fixture requires an HTTP loopback fixture and --skip-credential."
  );
  ensure(parsed.pathname === "/live-isolated-qa.html", "The isolated fixture path is invalid.");
  ensure(!parsed.username && !parsed.password && !parsed.hash, "The isolated fixture URL must not contain credentials or a fragment.");
  const qaRunValues = parsed.searchParams.getAll("qa_run");
  ensure(qaRunValues.length === 1 && /^[a-f0-9]{24}$/u.test(qaRunValues[0]), "The isolated fixture URL has no single valid qa_run marker.");
  ensure([...parsed.searchParams.keys()].every((key) => key === "qa_run"), "The initial isolated fixture URL contains unexpected parameters.");
  if (recoverMissingMarker) {
    ensure(browserId !== undefined, "--recover-missing-marker requires an exact --browser-id.");
    ensure(
      exactHttpLoopback,
      "--recover-missing-marker is allowed only with an HTTP loopback fixture, --allow-http-loopback-fixture, and --skip-credential."
    );
  }
  return { fixtureUrl: parsed.toString(), browserId, includeCredentials, credentialTimeoutMs, recoverMissingMarker };
}

async function browserCall(browserId, method, params = {}, timeoutMs) {
  return await callBridge(method, { browser_id: browserId, ...params }, timeoutMs);
}

async function listTabs(browserId) {
  const tabs = [];
  let offset = 0;
  while (true) {
    const page = asRecord(await browserCall(browserId, "list_tabs", { limit: 100, offset }), "Tab list");
    ensure(Array.isArray(page.tabs), "Tab list is missing.");
    tabs.push(...page.tabs.map((tab) => asRecord(tab, "Tab")));
    if (page.has_more !== true) return tabs;
    offset = numberValue(page.next_offset, "next_offset");
  }
}

function sameFixtureMarker(rawUrl, fixtureUrl) {
  if (typeof rawUrl !== "string") return false;
  try {
    const candidate = new URL(rawUrl);
    const expected = new URL(fixtureUrl);
    const candidateRuns = candidate.searchParams.getAll("qa_run");
    const expectedRuns = expected.searchParams.getAll("qa_run");
    return candidate.protocol === expected.protocol && candidate.hostname === expected.hostname &&
      candidate.port === expected.port && candidate.pathname === expected.pathname &&
      candidateRuns.length === 1 && expectedRuns.length === 1 && candidateRuns[0] === expectedRuns[0] &&
      candidate.searchParams.get("managed_index") === null &&
      [...candidate.searchParams.keys()].every((key) => key === "qa_run");
  } catch {
    return false;
  }
}

function safeUrlShape(rawUrl) {
  if (typeof rawUrl !== "string") return "<unavailable>";
  try {
    const parsed = new URL(rawUrl);
    const scheme = parsed.protocol.replace(/:$/u, "") || "<none>";
    const host = parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost"
      ? parsed.hostname
      : parsed.protocol === "moz-extension:" || parsed.protocol === "chrome-extension:"
        ? "<extension>"
        : parsed.hostname
          ? "<other>"
          : "<none>";
    const path = parsed.pathname === "/live-isolated-qa.html"
      ? parsed.pathname
      : /^\/setup\/[a-f0-9]{24}$/u.test(parsed.pathname)
        ? "/setup/<id>"
        : /^\/guided-setup\/[a-f0-9]{24}$/u.test(parsed.pathname)
          ? "/guided-setup/<id>"
          : parsed.pathname === "/options.html" || parsed.pathname === "/popup.html"
            ? parsed.pathname
            : "/<other>";
    const queryKeys = [...new Set(parsed.searchParams.keys())]
      .map((key) => key.replace(/[^A-Za-z0-9_.-]/gu, "?").slice(0, 32) || "<empty>")
      .sort();
    return `${scheme}://${host}${parsed.port ? `:${parsed.port}` : ""}${path}` +
      `?keys=${queryKeys.length > 0 ? queryKeys.join(",") : "<none>"}`;
  } catch {
    return "<unavailable>";
  }
}

function safeTabShapeSummary(tabs) {
  const counts = new Map();
  for (const tab of tabs.slice(0, 50)) {
    const shape = safeUrlShape(tab.url);
    counts.set(shape, (counts.get(shape) || 0) + 1);
  }
  return [...counts.entries()].slice(0, 12).map(([shape, count]) => `${count}x ${shape}`).join("; ") || "none";
}

function managedTabExercisePlan(markerManaged) {
  const initialManagedCount = markerManaged ? 1 : 0;
  return {
    initialManagedCount,
    additionalTabs: 10 - initialManagedCount,
    rejectedManagedIndex: 11 - initialManagedCount
  };
}

function positiveIntegerValue(value, label) {
  ensure(typeof value === "number" && Number.isSafeInteger(value) && value > 0, `${label} is not a positive integer.`);
  return value;
}

function exactFixtureUrlForRecovery(fixtureUrl) {
  const fixture = new URL(fixtureUrl);
  const qaRuns = fixture.searchParams.getAll("qa_run");
  ensure(
    fixture.protocol === "http:" &&
    (fixture.hostname === "127.0.0.1" || fixture.hostname === "localhost") &&
    fixture.pathname === "/live-isolated-qa.html" &&
    !fixture.username && !fixture.password && !fixture.hash &&
    qaRuns.length === 1 && /^[a-f0-9]{24}$/u.test(qaRuns[0]) &&
    [...fixture.searchParams.keys()].every((key) => key === "qa_run"),
    "Fixture recovery refused a non-exact HTTP loopback URL."
  );
  return fixture;
}

function selectProtectedPreExistingTab(tabs) {
  const usable = tabs.filter((tab) => (
    typeof tab.id === "number" && Number.isSafeInteger(tab.id) && tab.id > 0
  ));
  const setupTab = usable.find((tab) => {
    if (typeof tab.url !== "string") return false;
    try {
      const parsed = new URL(tab.url);
      return /^\/(?:setup|guided-setup)\/[a-f0-9]{24}$/u.test(parsed.pathname);
    } catch {
      return false;
    }
  });
  return setupTab || usable.find((tab) => tab.active === true) || usable[0];
}

async function cleanupRecoveryCreation(dependencies, browserId, createdTabId) {
  const requested = createdTabId === undefined ? undefined : [createdTabId];
  return await dependencies.cleanupManagedTabs(browserId, "Failed fixture-recovery cleanup", requested);
}

async function recoverMissingFixture(browserId, fixtureUrl, originalTabs, dependencies) {
  exactFixtureUrlForRecovery(fixtureUrl);
  const cleanup = await dependencies.cleanupManagedTabs(browserId, "Pre-fallback managed-tab cleanup");
  ensure(cleanup.managed_tab_count === 0, "The disposable browser retained a managed tab before fixture recovery.");

  const preExistingTabs = await dependencies.listTabs(browserId);
  const lateMarkers = preExistingTabs.filter((tab) => sameFixtureMarker(tab.url, fixtureUrl));
  ensure(
    lateMarkers.length <= 1,
    `More than one startup fixture appeared before recovery. Safe URL shapes: ${safeTabShapeSummary(preExistingTabs)}`
  );
  if (lateMarkers.length === 1) {
    const markerTabId = positiveIntegerValue(lateMarkers[0].id, "Late marker tab ID");
    return { browserId, tab: lateMarkers[0], protectedTabId: markerTabId, markerManaged: false };
  }

  const protectedTab = selectProtectedPreExistingTab(preExistingTabs);
  ensure(
    Boolean(protectedTab),
    `The disposable browser has no pre-existing tab to protect. Safe URL shapes: ${safeTabShapeSummary(preExistingTabs)}`
  );
  const protectedTabId = positiveIntegerValue(protectedTab.id, "Protected pre-existing tab ID");
  let creationAttempted = false;
  let createdTabId;
  try {
    creationAttempted = true;
    const created = asRecord(await dependencies.browserCall(browserId, "new_tab", {
      url: fixtureUrl,
      active: true
    }), "Recovered fixture tab");
    createdTabId = positiveIntegerValue(created.tab_id, "Recovered marker tab ID");
    ensure(createdTabId !== protectedTabId, "Fixture recovery did not preserve a separate pre-existing tab.");
    ensure(created.managed_tab_count === 1 && created.managed_tab_limit === 10, "Fixture recovery returned an invalid managed-tab ledger.");
    await dependencies.browserCall(browserId, "wait", {
      tab_id: createdTabId,
      condition: "load_complete",
      timeout_ms: 10_000
    });
    await dependencies.sleep(150);
    const recoveredTabs = await dependencies.listTabs(browserId);
    const markerTabs = recoveredTabs.filter((tab) => sameFixtureMarker(tab.url, fixtureUrl));
    const createdMarker = markerTabs.find((tab) => tab.id === createdTabId);
    const preExistingMarkers = markerTabs.filter((tab) => tab.id !== createdTabId);
    if (preExistingMarkers.length === 1) {
      await cleanupRecoveryCreation(dependencies, browserId, createdTabId);
      creationAttempted = false;
      const settledTabs = await dependencies.listTabs(browserId);
      const settledMarkers = settledTabs.filter((tab) => sameFixtureMarker(tab.url, fixtureUrl));
      ensure(
        settledMarkers.length === 1 && settledMarkers[0].id === preExistingMarkers[0].id,
        `Fixture recovery could not resolve a delayed-startup race. Safe URL shapes: ${safeTabShapeSummary(settledTabs)}`
      );
      const settledMarkerId = positiveIntegerValue(settledMarkers[0].id, "Delayed startup marker tab ID");
      return { browserId, tab: settledMarkers[0], protectedTabId: settledMarkerId, markerManaged: false };
    }
    ensure(
      preExistingMarkers.length === 0 && markerTabs.length === 1 && Boolean(createdMarker),
      `The exact loopback fixture could not be recovered uniquely. Safe URL shapes: ${safeTabShapeSummary(recoveredTabs)}`
    );
    process.stdout.write(
      `The startup fixture tab was absent; QA recovered it through the authenticated loopback-only new-tab action. ` +
      `Original safe URL shapes: ${safeTabShapeSummary(originalTabs)}\n`
    );
    return {
      browserId,
      tab: createdMarker,
      protectedTabId,
      markerManaged: true
    };
  } catch (error) {
    if (!creationAttempted) throw error;
    try {
      await cleanupRecoveryCreation(dependencies, browserId, createdTabId);
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], "Fixture recovery failed and its managed tab could not be cleaned up.");
    }
    throw error;
  }
}

async function selectIsolatedBrowser(status, requestedBrowserId, fixtureUrl, options = {}) {
  ensure(Array.isArray(status.connected_browsers), "BrowseWeave status does not contain connected_browsers.");
  const candidates = status.connected_browsers
    .map((browser) => asRecord(browser, "Connected browser"))
    .filter((browser) => requestedBrowserId === undefined || browser.browser_id === requestedBrowserId);
  ensure(candidates.length > 0, "The requested disposable browser is not connected to BrowseWeave.");
  const dependencies = {
    browserCall: options.browserCall || browserCall,
    cleanupManagedTabs: options.cleanupManagedTabs || cleanupManagedTabsWithRetry,
    listTabs: options.listTabs || listTabs,
    now: options.now || Date.now,
    sleep: options.sleep || ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)))
  };
  const pollTimeoutMs = options.pollTimeoutMs === undefined ? 3_000 : options.pollTimeoutMs;
  ensure(Number.isSafeInteger(pollTimeoutMs) && pollTimeoutMs >= 0 && pollTimeoutMs <= 10_000, "The marker polling window is invalid.");
  const deadline = dependencies.now() + pollTimeoutMs;
  let latest = [];
  do {
    const matches = [];
    latest = [];
    for (const browser of candidates) {
      ensure(typeof browser.browser_id === "string", "A connected browser has no browser_id.");
      const tabs = await dependencies.listTabs(browser.browser_id);
      latest.push({ browserId: browser.browser_id, tabs });
      const markerTabs = tabs.filter((tab) => sameFixtureMarker(tab.url, fixtureUrl));
      for (const tab of markerTabs) matches.push({ browserId: browser.browser_id, tab });
    }
    if (matches.length === 1) {
      return {
        ...matches[0],
        protectedTabId: numberValue(matches[0].tab.id, "Marker tab ID"),
        markerManaged: false
      };
    }
    ensure(
      matches.length === 0,
      `More than one connected browser contains the live-QA marker. Safe URL shapes: ${latest.map((entry) => safeTabShapeSummary(entry.tabs)).join(" | ")}`
    );
    if (dependencies.now() >= deadline) break;
    await dependencies.sleep(150);
  } while (true);
  ensure(
    options.recoverMissingMarker === true,
    `No connected browser contains the exact disposable live-QA marker tab. Safe URL shapes: ${latest.map((entry) => safeTabShapeSummary(entry.tabs)).join(" | ")}`
  );
  ensure(requestedBrowserId !== undefined, "A missing fixture tab can be recovered only with one exact disposable browser ID.");
  ensure(
    candidates.length === 1 && latest.length === 1 && candidates[0].browser_id === requestedBrowserId,
    "A missing fixture tab can be recovered only for one exact disposable browser."
  );
  const browserId = latest[0].browserId;
  const tabs = latest[0].tabs;
  return await recoverMissingFixture(browserId, fixtureUrl, tabs, dependencies);
}

function snapshotFrames(snapshot) {
  const record = asRecord(snapshot, "Snapshot");
  ensure(Array.isArray(record.frames), "Snapshot frames are missing.");
  return record.frames.map((frame) => asRecord(frame, "Snapshot frame"));
}

function frameElements(frame) {
  return Array.isArray(frame.elements)
    ? frame.elements.map((element) => asRecord(element, "Snapshot element"))
    : [];
}

function findElement(snapshot, label, accessibleName, options = {}) {
  const expected = accessibleName.toLocaleLowerCase("en-US");
  for (const frame of snapshotFrames(snapshot)) {
    const frameId = numberValue(frame.frame_id, "frame_id");
    for (const element of frameElements(frame)) {
      const name = typeof element.name === "string" ? element.name.toLocaleLowerCase("en-US") : "";
      const nameMatches = options.allowLabelContents === true
        ? name === expected || name.startsWith(`${expected} `)
        : name === expected;
      const tagMatches = options.tag === undefined || element.tag === options.tag;
      if (frameId === 0 && nameMatches && tagMatches) {
        ensure(typeof element.ref === "string", `${label} has no stable element ref.`);
        return { frameId, ref: element.ref, element };
      }
    }
  }
  fail(`${label} was not found in the isolated fixture snapshot.`);
}

function parseImageDimensions(dataUrl) {
  const match = /^data:(image\/(?:png|jpeg));base64,([A-Za-z0-9+/=]+)$/u.exec(dataUrl);
  ensure(Boolean(match), "Screenshot data format is invalid.");
  const bytes = Buffer.from(match[2], "base64");
  if (match[1] === "image/png") {
    ensure(bytes.length >= 24, "PNG screenshot is incomplete.");
    return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
  }
  ensure(bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8, "JPEG screenshot is incomplete.");
  const frames = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
  let offset = 2;
  while (offset + 8 < bytes.length) {
    if (bytes[offset] !== 0xff) {
      offset += 1;
      continue;
    }
    const marker = bytes[offset + 1];
    if (marker === 0xd8 || marker === 0xd9 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      offset += 2;
      continue;
    }
    const length = bytes.readUInt16BE(offset + 2);
    ensure(length >= 2 && offset + 2 + length <= bytes.length, "JPEG segment length is invalid.");
    if (frames.has(marker) && length >= 7) {
      return { width: bytes.readUInt16BE(offset + 7), height: bytes.readUInt16BE(offset + 5) };
    }
    offset += 2 + length;
  }
  fail("JPEG dimensions were not found.");
}

async function expectRejected(operation, expectedFragments, label) {
  try {
    await operation();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    ensure(expectedFragments.some((fragment) => message.includes(fragment)), `${label} failed for an unexpected reason: ${message.slice(0, 300)}`);
    return;
  }
  fail(`${label} unexpectedly succeeded.`);
}

async function verifyBasicInteraction(browserId, markerTabId) {
  await browserCall(browserId, "activate_tab", { tab_id: markerTabId, focus_window: true });
  await browserCall(browserId, "wait", { tab_id: markerTabId, condition: "load_complete", timeout_ms: 10_000 });
  const snapshot = asRecord(await browserCall(browserId, "snapshot", {
    tab_id: markerTabId,
    mode: "interactive",
    max_elements: 80,
    max_chars: 8_000
  }), "Initial fixture snapshot");
  const name = findElement(snapshot, "QA display name", "QA display name");
  const mode = findElement(snapshot, "QA mode", "QA mode", { tag: "select", allowLabelContents: true });
  const confirmation = findElement(snapshot, "QA confirmation", "QA confirmation");
  await browserCall(browserId, "fill_form", {
    tab_id: markerTabId,
    frame_id: 0,
    fields: [
      { ref: name.ref, value: "Isolated QA", clear: true },
      { ref: mode.ref, value: "isolated", clear: true },
      { ref: confirmation.ref, value: true, clear: true }
    ]
  });
  await browserCall(browserId, "wait", {
    tab_id: markerTabId,
    frame_id: 0,
    condition: "text_present",
    value: "Ordinary form verified",
    timeout_ms: 5_000
  });
  mark("MV3/MV2 content connection, compact snapshot, and ordinary form interaction");

  const screenshot = asRecord(await browserCall(browserId, "screenshot", {
    tab_id: markerTabId,
    format: "jpeg",
    quality: 55
  }), "Screenshot");
  ensure(typeof screenshot.data_url === "string", "Screenshot data is missing.");
  const image = parseImageDimensions(screenshot.data_url);
  ensure(screenshot.image_width === image.width && screenshot.image_height === image.height, "Screenshot metadata does not match its bytes.");
  ensure(image.width > 0 && image.height > 0, "Screenshot dimensions are invalid.");
  mark("visible screenshot and dimension metadata");
}

async function cleanupManagedTabsWithRetry(browserId, label, requestedTabIds) {
  const deadline = Date.now() + 5_000;
  const allClosed = new Set();
  const requested = requestedTabIds === undefined ? undefined : new Set(requestedTabIds);
  let lastCount = -1;
  do {
    const cleanup = asRecord(await browserCall(
      browserId,
      "cleanup_tabs",
      requestedTabIds === undefined ? {} : { tab_ids: requestedTabIds }
    ), label);
    ensure(Array.isArray(cleanup.closed_tab_ids), `${label} did not report closed tab IDs.`);
    ensure(Array.isArray(cleanup.remaining_tab_ids), `${label} did not report remaining tab IDs.`);
    ensure(
      Number.isSafeInteger(cleanup.managed_tab_count) &&
      cleanup.managed_tab_count === cleanup.remaining_tab_ids.length,
      `${label} returned an inconsistent managed-tab count.`
    );
    for (const tabId of cleanup.closed_tab_ids) {
      ensure(Number.isSafeInteger(tabId) && tabId > 0, `${label} reported an invalid closed tab ID.`);
      allClosed.add(tabId);
    }
    lastCount = cleanup.managed_tab_count;
    const requestedRemain = requested === undefined
      ? lastCount > 0
      : cleanup.remaining_tab_ids.some((tabId) => requested.has(tabId));
    if (!requestedRemain) return { ...cleanup, closed_tab_ids: [...allClosed] };
    await new Promise((resolve) => setTimeout(resolve, 150));
  } while (Date.now() < deadline);
  if (requested === undefined) {
    fail(`${label} left ${lastCount} managed tab${lastCount === 1 ? "" : "s"} after bounded retries.`);
  }
  fail(`${label} left its requested managed tab open after bounded retries (${lastCount} total remain).`);
}

async function verifyManagedTabs(browserId, markerTabId, fixtureUrl, options) {
  if (!options.markerManaged) await cleanupManagedTabsWithRetry(browserId, "Initial managed-tab cleanup");
  await expectRejected(
    () => browserCall(browserId, "close_tab", { tab_id: options.protectedTabId }),
    ["(tab_not_managed)", "can close only tabs it created"],
    "Pre-existing fixture-tab close protection"
  );
  mark("pre-existing disposable tab is rejected by close_tab");

  const managedTabIds = options.markerManaged ? [markerTabId] : [];
  const plan = managedTabExercisePlan(options.markerManaged);
  const initialManagedCount = plan.initialManagedCount;
  let exerciseError;
  try {
    const parsed = new URL(fixtureUrl);
    for (let index = 1; index <= plan.additionalTabs; index += 1) {
      parsed.searchParams.set("managed_index", String(index));
      const created = asRecord(await browserCall(browserId, "new_tab", {
        url: parsed.toString(),
        active: false
      }), `Managed tab ${index}`);
      managedTabIds.push(numberValue(created.tab_id, `managed tab ${index} ID`));
      ensure(created.managed_tab_count === initialManagedCount + index, `Managed-tab count is incorrect after tab ${index}.`);
      ensure(created.managed_tab_limit === 10, "The managed-tab limit is not 10.");
    }
    parsed.searchParams.set("managed_index", String(plan.rejectedManagedIndex));
    await expectRejected(
      () => browserCall(browserId, "new_tab", { url: parsed.toString(), active: false }),
      ["(managed_tab_limit)", "already has 10 open tabs"],
      "Eleventh managed tab"
    );
    mark("10 managed tabs allowed and the 11th rejected");
  } catch (error) {
    exerciseError = error;
  }
  let cleanup;
  let cleanupError;
  try {
    cleanup = await cleanupManagedTabsWithRetry(browserId, "Managed-tab cleanup");
    if (managedTabIds.length === 10) {
      const closed = new Set(cleanup.closed_tab_ids);
      ensure(managedTabIds.every((tabId) => closed.has(tabId)), "Cleanup did not close every BrowseWeave-created tab.");
    }
  } catch (error) {
    cleanupError = error;
  }
  if (exerciseError) {
    if (cleanupError) {
      const exerciseMessage = exerciseError instanceof Error ? exerciseError.message : String(exerciseError);
      const cleanupMessage = cleanupError instanceof Error ? cleanupError.message : String(cleanupError);
      fail(`Managed-tab exercise failed: ${exerciseMessage}; cleanup also failed: ${cleanupMessage}`);
    }
    throw exerciseError;
  }
  if (cleanupError) throw cleanupError;

  const tabsAfterCleanup = await listTabs(browserId);
  ensure(tabsAfterCleanup.some((tab) => tab.id === options.protectedTabId), "Cleanup closed the protected pre-existing tab.");
  if (!options.markerManaged) {
    ensure(tabsAfterCleanup.some((tab) => tab.id === markerTabId), "Cleanup closed the pre-existing marker tab.");
  }
  mark("cleanup closed only BrowseWeave-managed tabs and preserved the pre-existing tab");
}

async function waitForDummyCredentialStatus(browserId, tabId, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastProgress = 0;
  while (Date.now() < deadline) {
    try {
      await browserCall(browserId, "wait", {
        tab_id: tabId,
        frame_id: 0,
        condition: "text_present",
        value: "Dummy credentials filled locally",
        timeout_ms: Math.min(5_000, Math.max(250, deadline - Date.now()))
      }, 10_000);
      return;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!message.includes("wait_timeout")) throw error;
      if (Date.now() - lastProgress >= 20_000) {
        process.stdout.write("Waiting for the trusted extension popup to complete the dummy handoff…\n");
        lastProgress = Date.now();
      }
    }
  }
  fail("The dummy local credential handoff was not completed before its five-minute expiry.");
}

async function verifyLocalCredentialHandoff(browserId, markerTabId, timeoutMs) {
  await browserCall(browserId, "activate_tab", { tab_id: markerTabId, focus_window: true });
  const snapshot = asRecord(await browserCall(browserId, "snapshot", {
    tab_id: markerTabId,
    mode: "interactive",
    max_elements: 80,
    max_chars: 8_000
  }), "Credential fixture snapshot");
  const username = findElement(snapshot, "QA username", "QA username");
  const password = findElement(snapshot, "QA password", "QA password");
  const handoff = asRecord(await browserCall(browserId, "credential_handoff_prepare", {
    tab_id: markerTabId,
    frame_id: 0,
    fields: [
      { ref: username.ref, kind: "username" },
      { ref: password.ref, kind: "password" }
    ],
    submit: false
  }), "Local credential handoff");
  ensure(handoff.requires_human === true, "The local credential operation did not require trusted human UI.");
  const topFrame = snapshotFrames(snapshot).find((frame) => frame.frame_id === 0);
  ensure(Boolean(topFrame) && typeof topFrame.url === "string", "The top-frame URL is missing from the credential snapshot.");
  ensure(handoff.origin === new URL(topFrame.url).origin, "The credential handoff origin does not match the browser snapshot.");
  const serializedHandoff = JSON.stringify(handoff);
  ensure(!serializedHandoff.includes(DUMMY_USERNAME) && !serializedHandoff.includes(DUMMY_PASSWORD), "Credential values leaked into the MCP/daemon handoff response.");

  process.stdout.write(
    "\nComplete this one step in the disposable browser's trusted BrowseWeave popup:\n" +
    `  Username: ${DUMMY_USERNAME}\n` +
    `  Password: ${DUMMY_PASSWORD}\n` +
    "Choose Fill once. These are public test strings, not real credentials.\n\n"
  );
  await waitForDummyCredentialStatus(browserId, markerTabId, timeoutMs);

  const after = asRecord(await browserCall(browserId, "snapshot", {
    tab_id: markerTabId,
    mode: "interactive",
    max_elements: 80,
    max_chars: 8_000
  }), "Post-credential snapshot");
  ensure(!JSON.stringify(after).includes(DUMMY_PASSWORD), "The password appeared in a browser snapshot after local handoff.");
  await browserCall(browserId, "reload", { tab_id: markerTabId, bypass_cache: true });
  await browserCall(browserId, "wait", { tab_id: markerTabId, condition: "load_complete", timeout_ms: 10_000 });
  mark("extension-owned one-use local credential handoff with no password in bridge output");
}

async function runQaSelfTest() {
  const marker = "a".repeat(24);
  const browserId = `browser-${"b".repeat(24)}`;
  const setupId = "c".repeat(24);
  const fixtureUrl = `http://127.0.0.1:41732/live-isolated-qa.html?qa_run=${marker}`;
  const setupTab = {
    id: 1,
    active: true,
    url: `http://127.0.0.1:41732/guided-setup/${setupId}`
  };
  const status = { connected_browsers: [{ browser_id: browserId }] };

  const expectFailure = async (operation, expectedFragment) => {
    try {
      await operation();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      ensure(message.includes(expectedFragment), `Self-test failed for an unexpected reason: ${message}`);
      return;
    }
    fail(`Self-test unexpectedly succeeded; expected ${expectedFragment}.`);
  };
  const expectParseFailure = (argumentsList, expectedFragment) => {
    let message = "";
    try {
      parseArguments(argumentsList);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }
    ensure(message.includes(expectedFragment), `Argument self-test failed for an unexpected reason: ${message || "no error"}`);
  };
  const makeHarness = ({ failWait = false, delayedOriginal = false } = {}) => {
    let tabs = [{ ...setupTab }];
    const managed = new Set();
    const calls = [];
    let delayedOriginalAdded = false;
    const listTabsForTest = async () => {
      calls.push({ method: "list_tabs" });
      if (delayedOriginal && managed.has(99) && !delayedOriginalAdded) {
        delayedOriginalAdded = true;
        tabs.push({ id: 2, active: false, url: fixtureUrl });
      }
      return tabs.map((tab) => ({ ...tab }));
    };
    const cleanupForTest = async (_browserId, _label, requestedTabIds) => {
      const selected = requestedTabIds === undefined ? [...managed] : requestedTabIds.filter((id) => managed.has(id));
      calls.push({ method: "cleanup_tabs", requested: requestedTabIds === undefined ? "all" : [...requestedTabIds] });
      for (const id of selected) managed.delete(id);
      tabs = tabs.filter((tab) => !selected.includes(tab.id));
      return {
        closed_tab_ids: selected,
        remaining_tab_ids: [...managed],
        managed_tab_count: managed.size
      };
    };
    const browserCallForTest = async (_browserId, method, params) => {
      calls.push({ method, params });
      if (method === "new_tab") {
        tabs.push({ id: 99, active: params.active === true, url: params.url });
        managed.add(99);
        return {
          tab_id: 99,
          managed_tab_count: managed.size,
          managed_tab_limit: 10
        };
      }
      if (method === "wait") {
        if (failWait) throw new Error("injected wait failure");
        return { matched: true };
      }
      fail(`Unexpected self-test browser method: ${method}`);
    };
    return {
      calls,
      managed,
      currentTabs: () => tabs.map((tab) => ({ ...tab })),
      dependencies: {
        browserCall: browserCallForTest,
        cleanupManagedTabs: cleanupForTest,
        listTabs: listTabsForTest,
        now: () => 0,
        sleep: async () => undefined
      }
    };
  };

  ensure(sameFixtureMarker(fixtureUrl, fixtureUrl), "The exact fixture matcher rejected its canonical URL.");
  ensure(!sameFixtureMarker(`${fixtureUrl}&extra=1`, fixtureUrl), "The exact fixture matcher accepted an extra query key.");
  ensure(!sameFixtureMarker(`${fixtureUrl}&managed_index=1`, fixtureUrl), "The exact fixture matcher accepted a managed tab.");
  ensure(!sameFixtureMarker(`${fixtureUrl}&qa_run=${marker}`, fixtureUrl), "The exact fixture matcher accepted a duplicate qa_run marker.");
  const hiddenValue = "must-not-appear";
  const shape = safeUrlShape(`http://127.0.0.1:45678/setup/${marker}?qa_run=${marker}&token=${hiddenValue}&%0Aevil=x`);
  ensure(shape.includes("/setup/<id>") && shape.includes("qa_run") && shape.includes("token"), "Safe URL-shape diagnostics lost required structure.");
  ensure(
    !shape.includes(marker) && !shape.includes(hiddenValue) && !shape.includes("\n"),
    "Safe URL-shape diagnostics exposed a value, setup ID, or control character."
  );
  const preExistingPlan = managedTabExercisePlan(false);
  const recoveredPlan = managedTabExercisePlan(true);
  ensure(
    preExistingPlan.initialManagedCount === 0 && preExistingPlan.additionalTabs === 10 && preExistingPlan.rejectedManagedIndex === 11 &&
    recoveredPlan.initialManagedCount === 1 && recoveredPlan.additionalTabs === 9 && recoveredPlan.rejectedManagedIndex === 10,
    "The managed-tab fallback plan did not preserve the exact total limit of 10."
  );

  const recoveryArguments = [
    "--fixture-url", fixtureUrl,
    "--browser-id", browserId,
    "--skip-credential",
    "--allow-http-loopback-fixture",
    "--recover-missing-marker"
  ];
  const recoveryOptions = parseArguments(recoveryArguments);
  ensure(
    recoveryOptions.recoverMissingMarker === true && recoveryOptions.includeCredentials === false && recoveryOptions.browserId === browserId,
    "The exact internal recovery arguments were not accepted."
  );
  expectParseFailure(
    recoveryArguments.filter((argument, index) => argument !== "--browser-id" && recoveryArguments[index - 1] !== "--browser-id"),
    "requires an exact --browser-id"
  );
  expectParseFailure([
    "--fixture-url", `https://localhost:41732/live-isolated-qa.html?qa_run=${marker}`,
    "--browser-id", browserId,
    "--recover-missing-marker"
  ], "allowed only with an HTTP loopback fixture");
  expectParseFailure([
    "--fixture-url", `${fixtureUrl}&qa_run=${marker}`,
    "--skip-credential",
    "--allow-http-loopback-fixture"
  ], "no single valid qa_run marker");

  let pollTick = 0;
  let pollCount = 0;
  let pollMutations = 0;
  const polled = await selectIsolatedBrowser(status, browserId, fixtureUrl, {
    recoverMissingMarker: false,
    pollTimeoutMs: 300,
    now: () => pollTick,
    sleep: async (milliseconds) => { pollTick += milliseconds; },
    listTabs: async () => {
      pollCount += 1;
      return pollCount === 1 ? [{ ...setupTab }] : [{ ...setupTab }, { id: 2, active: false, url: fixtureUrl }];
    },
    cleanupManagedTabs: async () => { pollMutations += 1; fail("Polling must not clean tabs."); },
    browserCall: async () => { pollMutations += 1; fail("Polling must not create tabs."); }
  });
  ensure(polled.markerManaged === false && polled.tab.id === 2 && pollMutations === 0, "A late startup marker was not selected without mutation.");

  let refusedMutations = 0;
  await expectFailure(() => selectIsolatedBrowser(status, browserId, fixtureUrl, {
    recoverMissingMarker: false,
    pollTimeoutMs: 0,
    now: () => 0,
    sleep: async () => undefined,
    listTabs: async () => [{ ...setupTab }],
    cleanupManagedTabs: async () => { refusedMutations += 1; return {}; },
    browserCall: async () => { refusedMutations += 1; return {}; }
  }), "No connected browser contains");
  ensure(refusedMutations === 0, "Recovery-disabled marker selection mutated the browser.");

  const recoveredHarness = makeHarness();
  const recovered = await selectIsolatedBrowser(status, browserId, fixtureUrl, {
    recoverMissingMarker: true,
    pollTimeoutMs: 0,
    ...recoveredHarness.dependencies
  });
  ensure(
    recovered.markerManaged === true && recovered.tab.id === 99 && recovered.protectedTabId === 1 && recoveredHarness.managed.has(99),
    "Managed fixture recovery did not preserve its exact ownership and protection state."
  );
  await recoveredHarness.dependencies.cleanupManagedTabs(browserId, "Self-test cleanup", [99]);

  const failedHarness = makeHarness({ failWait: true });
  await expectFailure(() => selectIsolatedBrowser(status, browserId, fixtureUrl, {
    recoverMissingMarker: true,
    pollTimeoutMs: 0,
    ...failedHarness.dependencies
  }), "injected wait failure");
  ensure(
    failedHarness.managed.size === 0 && !failedHarness.currentTabs().some((tab) => tab.id === 99) &&
    failedHarness.calls.some((call) => call.method === "cleanup_tabs" && Array.isArray(call.requested) && call.requested[0] === 99),
    "A failed recovery did not clean exactly its created managed tab."
  );

  const raceHarness = makeHarness({ delayedOriginal: true });
  const raced = await selectIsolatedBrowser(status, browserId, fixtureUrl, {
    recoverMissingMarker: true,
    pollTimeoutMs: 0,
    ...raceHarness.dependencies
  });
  ensure(
    raced.markerManaged === false && raced.tab.id === 2 && raceHarness.managed.size === 0 &&
    raceHarness.currentTabs().filter((tab) => sameFixtureMarker(tab.url, fixtureUrl)).length === 1 &&
    !raceHarness.currentTabs().some((tab) => tab.id === 99),
    "A delayed original marker left a managed duplicate or selected the wrong tab."
  );

  process.stdout.write(
    "Isolated bridge-QA self-test passed: recovery policy, bounded polling, exact marker matching, value-free diagnostics, " +
    "managed fallback accounting, failure cleanup, and delayed-startup race handling.\n"
  );
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.selfTest) {
    await runQaSelfTest();
    return;
  }
  ({ callBridge } = await import("../dist/src/bridge/ipc-client.js"));
  const status = asRecord(await callBridge("status"), "BrowseWeave status");
  ensure(status.service === "browseweave" && status.protocol_version === 3, "The authenticated service is not BrowseWeave protocol v3.");
  ensure(status.pending_approvals === 0, "Live QA refuses to start while a prior approval is pending.");
  const selected = await selectIsolatedBrowser(status, options.browserId, options.fixtureUrl, {
    recoverMissingMarker: options.recoverMissingMarker
  });
  ensure(
    !selected.markerManaged || options.includeCredentials === false,
    "A recovered managed fixture cannot be used for credential handoff."
  );
  const browserId = selected.browserId;
  const markerTabId = numberValue(selected.tab.id, "Marker tab ID");
  mark("authenticated daemon and exact disposable marker tab");

  try {
    await verifyBasicInteraction(browserId, markerTabId);
    await verifyManagedTabs(browserId, markerTabId, options.fixtureUrl, {
      markerManaged: selected.markerManaged,
      protectedTabId: selected.protectedTabId
    });
    if (options.includeCredentials) {
      await verifyLocalCredentialHandoff(browserId, markerTabId, options.credentialTimeoutMs);
    } else {
      process.stdout.write("Credential handoff skipped by explicit option.\n");
    }
    const finalStatus = asRecord(await callBridge("status"), "Final BrowseWeave status");
    ensure(finalStatus.pending_approvals === 0, "Live QA left a pending approval behind.");
    process.stdout.write(`\nIsolated live QA passed: ${checks.length} checks. Close the disposable browser now.\n`);
  } finally {
    await browserCall(browserId, "cleanup_tabs").catch(() => undefined);
  }
}

main().catch((error) => {
  process.stderr.write(`Isolated live QA failed: ${error instanceof Error ? error.message.slice(0, 700) : String(error)}\n`);
  process.exitCode = 1;
});
