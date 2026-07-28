#!/usr/bin/env node

import { callBridge } from "../dist/src/ipc-client.js";

const FIXTURE_URL = "http://127.0.0.1:41731/interaction.html";
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

function isFixtureUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    return url.origin === "http://127.0.0.1:41731" && url.pathname === "/interaction.html";
  } catch {
    return false;
  }
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

function findElement(snapshot, label, predicate) {
  for (const frame of snapshotFrames(snapshot)) {
    const frameId = numberValue(frame.frame_id, "frame_id");
    for (const element of frameElements(frame)) {
      if (predicate(element, frameId)) {
        ensure(typeof element.ref === "string", `${label} does not have an element ref.`);
        return { frameId, ref: element.ref, element };
      }
    }
  }
  fail(`${label} was not found in the snapshot.`);
}

function named(name, extra = () => true) {
  const needle = name.toLocaleLowerCase("en-US");
  return (element, frameId) => {
    const candidate = typeof element.name === "string" ? element.name.toLocaleLowerCase("en-US") : "";
    return candidate.includes(needle) && extra(element, frameId);
  };
}

function textIncludes(text) {
  const needle = text.toLocaleLowerCase("en-US");
  return (element) => {
    const candidate = [element.name, element.text, element.value]
      .filter((value) => typeof value === "string")
      .join(" ")
      .toLocaleLowerCase("en-US");
    return candidate.includes(needle);
  };
}

function parseImageDimensions(dataUrl) {
  const match = /^data:(image\/(?:png|jpeg));base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl);
  ensure(Boolean(match), "Screenshot data format is invalid.");
  const mimeType = match[1];
  const bytes = Buffer.from(match[2], "base64");
  if (mimeType === "image/png") {
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

function parseArguments(argv) {
  let tabId;
  let browserId;
  let open = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--open") {
      open = true;
      continue;
    }
    if (argument === "--tab-id") {
      const raw = argv[index + 1];
      const parsed = Number(raw);
      ensure(Number.isInteger(parsed) && parsed > 0, "--tab-id requires a positive integer.");
      tabId = parsed;
      index += 1;
      continue;
    }
    if (argument === "--browser-id") {
      const raw = argv[index + 1];
      ensure(typeof raw === "string" && /^browser-[a-f0-9]{24}$/u.test(raw), "--browser-id requires a BrowseWeave browser ID.");
      browserId = raw;
      index += 1;
      continue;
    }
    if (argument === "--help") {
      process.stdout.write(
        "Usage: npm run smoke:live -- [--browser-id browser-...] [--tab-id 123] [--open]\n" +
        "Finds the local fixture tab. With --open, BrowseWeave opens and later cleans up a managed fixture tab.\n"
      );
      process.exit(0);
    }
    fail(`Unknown option: ${argument}`);
  }
  return { browserId, tabId, open };
}

async function browserCall(browserId, method, params = {}) {
  return await callBridge(method, { browser_id: browserId, ...params });
}

function selectBrowser(status, requestedBrowserId) {
  ensure(Array.isArray(status.connected_browsers), "BrowseWeave status did not include connected_browsers.");
  const browsers = status.connected_browsers.map((browser) => asRecord(browser, "Connected browser"));
  ensure(browsers.length > 0, "No authenticated browser extension is connected to BrowseWeave.");
  if (requestedBrowserId !== undefined) {
    const selected = browsers.find((browser) => browser.browser_id === requestedBrowserId);
    ensure(Boolean(selected), `The requested browser is not connected: ${requestedBrowserId}`);
    return requestedBrowserId;
  }
  ensure(
    browsers.length === 1,
    "More than one browser is connected. Re-run with --browser-id from browseweave status."
  );
  ensure(typeof browsers[0].browser_id === "string", "The connected browser did not include a browser_id.");
  return browsers[0].browser_id;
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

async function selectFixtureTab(browserId, arguments_) {
  const tabs = await listTabs(browserId);
  if (arguments_.tabId !== undefined) {
    const selected = tabs.find((tab) => tab.id === arguments_.tabId);
    ensure(Boolean(selected), "The requested browser tab was not found.");
    ensure(isFixtureUrl(selected.url), "For safety, the live smoke runs only in the local interaction.html tab.");
    return { tabId: arguments_.tabId, managedBySmoke: false };
  }

  const candidates = tabs.filter((tab) => isFixtureUrl(tab.url));
  const selected = candidates.find((tab) => tab.active === true) || candidates[0];
  if (selected) return { tabId: numberValue(selected.id, "Fixture tab_id"), managedBySmoke: false };
  ensure(arguments_.open, `The local fixture tab is not open. Open ${FIXTURE_URL} in the selected browser or use --open.`);
  const created = asRecord(await browserCall(browserId, "new_tab", { url: FIXTURE_URL, active: true }), "New tab result");
  return { tabId: numberValue(created.tab_id, "New fixture tab_id"), managedBySmoke: true };
}

async function main() {
  const arguments_ = parseArguments(process.argv.slice(2));
  const status = asRecord(await callBridge("status"), "Bridge status");
  const browserId = selectBrowser(status, arguments_.browserId);
  mark("local service and authenticated browser connection");

  const selection = await selectFixtureTab(browserId, arguments_);
  const { tabId } = selection;
  try {
    await browserCall(browserId, "activate_tab", { tab_id: tabId, focus_window: true });
    await browserCall(browserId, "wait", { tab_id: tabId, condition: "load_complete", timeout_ms: 5_000 });

  const compactParams = { tab_id: tabId, mode: "interactive", max_elements: 90, max_chars: 9_000 };
  let snapshot = asRecord(await browserCall(browserId, "snapshot", compactParams), "Initial snapshot");
  const topFrame = snapshotFrames(snapshot).find((frame) => frame.frame_id === 0);
  ensure(Boolean(topFrame) && isFixtureUrl(topFrame.url), "The tab is not the safe local fixture; no interaction was performed.");
  const firstSnapshotId = snapshot.snapshot_id;
  ensure(typeof firstSnapshotId === "string", "The initial snapshot ID is missing.");
  mark("compact snapshot and safe-page verification");

  const reset = findElement(snapshot, "Reset button", named("Reset test state", (_element, frameId) => frameId === 0));
  await browserCall(browserId, "click", { tab_id: tabId, frame_id: reset.frameId, ref: reset.ref });

  const personName = findElement(snapshot, "Name field", named("Name", (element, frameId) => frameId === 0 && element.tag === "input"));
  const workMode = findElement(snapshot, "Work mode", named("Work mode", (_element, frameId) => frameId === 0));
  const shortNote = findElement(snapshot, "Short note", named("Short note", (_element, frameId) => frameId === 0));
  const notices = findElement(snapshot, "Notification option", named("Show notifications", (_element, frameId) => frameId === 0));
  const soloRadio = findElement(snapshot, "Radio group", named("Solo workspace", (_element, frameId) => frameId === 0));
  await browserCall(browserId, "fill_form", {
    tab_id: tabId,
    frame_id: 0,
    fields: [
      { ref: personName.ref, value: "Ada", clear: true },
      { ref: workMode.ref, value: "team", clear: true },
      { ref: shortNote.ref, value: "Local test", clear: true },
      { ref: notices.ref, value: true, clear: true },
      { ref: soloRadio.ref, value: "team", clear: true }
    ]
  });

  const shadowInput = findElement(snapshot, "Shadow DOM field", named("Shadow field", (_element, frameId) => frameId === 0));
  await browserCall(browserId, "type", { tab_id: tabId, frame_id: 0, ref: shadowInput.ref, text: "Open shadow", clear: true });
  const shadowButton = findElement(snapshot, "Shadow DOM button", named("Update shadow status", (_element, frameId) => frameId === 0));
  await browserCall(browserId, "click", { tab_id: tabId, frame_id: 0, ref: shadowButton.ref });
  await browserCall(browserId, "wait", { tab_id: tabId, frame_id: 0, condition: "text_present", value: "Open shadow root worked", timeout_ms: 2_000 });

  snapshot = asRecord(await browserCall(browserId, "snapshot", compactParams), "Field verification snapshot");
  ensure(findElement(snapshot, "Filled name", named("Name", (element) => element.tag === "input")).element.value === "Ada", "Text field was not filled.");
  ensure(findElement(snapshot, "Filled select", named("Work mode")).element.value === "Team", "Select value did not change.");
  ensure(findElement(snapshot, "Filled checkbox", named("Show notifications")).element.checked === true, "Checkbox was not selected.");
  ensure(findElement(snapshot, "Filled radio", named("Team workspace")).element.checked === true, "Radio option was not selected.");
  ensure(findElement(snapshot, "Filled Shadow field", named("Shadow field")).element.value === "Open shadow", "Shadow DOM field was not filled.");
  mark("text/select/textarea/checkbox/radio and open Shadow DOM");

  const update = findElement(snapshot, "Normal button", named("Update local status", (_element, frameId) => frameId === 0));
  await browserCall(browserId, "click", { tab_id: tabId, frame_id: 0, ref: update.ref });
  await browserCall(browserId, "wait", { tab_id: tabId, frame_id: 0, condition: "text_present", value: "Normal button worked", timeout_ms: 2_000 });

  const hoverTarget = findElement(snapshot, "Hover target", named("Hint area", (_element, frameId) => frameId === 0));
  await browserCall(browserId, "hover", { tab_id: tabId, frame_id: 0, ref: hoverTarget.ref });
  await browserCall(browserId, "wait", { tab_id: tabId, frame_id: 0, condition: "text_present", value: "Hint is visible", timeout_ms: 2_000 });

  const delayed = findElement(snapshot, "Delayed button", named("Start delayed change", (_element, frameId) => frameId === 0));
  await browserCall(browserId, "click", { tab_id: tabId, frame_id: 0, ref: delayed.ref });
  await browserCall(browserId, "wait", { tab_id: tabId, frame_id: 0, condition: "text_present", value: "Delayed change completed", timeout_ms: 3_000 });
  mark("harmless click, hover, and conditional wait");

  const scrollRegion = findElement(snapshot, "Inner scroll area", named("Scrollable test list", (_element, frameId) => frameId === 0));
  const scrolled = asRecord(await browserCall(browserId, "scroll", {
    tab_id: tabId,
    frame_id: 0,
    ref: scrollRegion.ref,
    direction: "down",
    amount: 600
  }), "Scroll result");
  ensure(numberValue(scrolled.delta_y, "delta_y") > 0, "The inner scroll area did not move.");
  mark("nearest inner scroll area");

  const frameButton = findElement(snapshot, "Iframe button", named("Update frame status", (_element, frameId) => frameId !== 0));
  await browserCall(browserId, "click", { tab_id: tabId, frame_id: frameButton.frameId, ref: frameButton.ref });
  await browserCall(browserId, "wait", {
    tab_id: tabId,
    frame_id: frameButton.frameId,
    condition: "text_present",
    value: "Frame button worked",
    timeout_ms: 2_000
  });
  mark("iframe snapshot/ref/action chain");

  const changed = asRecord(await browserCall(browserId, "snapshot", { ...compactParams, since_snapshot_id: firstSnapshotId }), "Delta snapshot");
  ensure(changed.unchanged === false && changed.delta !== undefined, "The changed page did not return a delta snapshot.");
  const stable = asRecord(await browserCall(browserId, "snapshot", compactParams), "Stable snapshot");
  ensure(typeof stable.snapshot_id === "string", "Stable snapshot ID is missing.");
  const unchanged = asRecord(await browserCall(browserId, "snapshot", { ...compactParams, since_snapshot_id: stable.snapshot_id }), "Unchanged snapshot");
  ensure(unchanged.unchanged === true, "The unchanged page did not return a compact unchanged result.");
  mark("delta and unchanged context filtering");

  let canvasSnapshot = asRecord(await browserCall(browserId, "snapshot", {
    tab_id: tabId,
    mode: "full",
    query: "Visual click area",
    max_elements: 10,
    max_chars: 3_000
  }), "Canvas snapshot");
  let canvas = findElement(canvasSnapshot, "Canvas", named("Visual click area", (_element, frameId) => frameId === 0));
  await browserCall(browserId, "hover", { tab_id: tabId, frame_id: 0, ref: canvas.ref });
  canvasSnapshot = asRecord(await browserCall(browserId, "snapshot", {
    tab_id: tabId,
    mode: "full",
    query: "Visual click area",
    max_elements: 10,
    max_chars: 3_000
  }), "Current canvas snapshot");
  canvas = findElement(canvasSnapshot, "Current canvas", named("Visual click area", (_element, frameId) => frameId === 0));
  asRecord(canvas.element.bounds, "Canvas bounds");

  const screenshot = asRecord(await browserCall(browserId, "screenshot", { tab_id: tabId, format: "jpeg", quality: 55 }), "Screenshot");
  ensure(typeof screenshot.data_url === "string", "Screenshot data is missing.");
  ensure(
    typeof screenshot.screenshot_id === "string" && /^shot-[a-f0-9]{32}$/.test(screenshot.screenshot_id),
    "Screenshot security ID is missing."
  );
  const image = parseImageDimensions(screenshot.data_url);
  ensure(screenshot.image_width === image.width && screenshot.image_height === image.height, "Screenshot dimension metadata does not match the image.");
  const viewportWidth = numberValue(screenshot.viewport_css_width, "CSS viewport width");
  const viewportHeight = numberValue(screenshot.viewport_css_height, "CSS viewport height");
  ensure(image.width > 0 && image.height > 0 && viewportWidth > 0 && viewportHeight > 0, "Image dimensions are invalid.");

  const canvasState = asRecord(await browserCall(browserId, "snapshot", {
    tab_id: tabId,
    mode: "content",
    query: "Canvas has not been clicked",
    max_elements: 10,
    max_chars: 3_000
  }), "Canvas state snapshot");
  findElement(canvasState, "Unchanged canvas state", textIncludes("Canvas has not been clicked"));
  const finalStatus = asRecord(await callBridge("status"), "Final bridge status");
  ensure(finalStatus.pending_approvals === 0, "The smoke test unexpectedly left a pending approval.");
  mark("screenshot dimensions and visual-target binding data");

    process.stdout.write(`Live smoke passed: ${checks.length} checks.\n`);
  } finally {
    if (selection.managedBySmoke) {
      await browserCall(browserId, "cleanup_tabs", { tab_ids: [tabId] });
    }
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : "Unknown live smoke failure";
  process.stderr.write(`Live smoke failed: ${message.slice(0, 500)}\n`);
  process.exitCode = 1;
});
