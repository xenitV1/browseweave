import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const background = readFileSync(new URL("../extension/src/background/runtime.ts", import.meta.url), "utf8");
const content = readFileSync(new URL("../extension/src/content/runtime.ts", import.meta.url), "utf8");
const popupSource = readFileSync(new URL("../extension/src/ui/popup.ts", import.meta.url), "utf8");
const optionsSource = readFileSync(new URL("../extension/src/ui/options.ts", import.meta.url), "utf8");
const mcpSource = readFileSync(new URL("../src/mcp/server.ts", import.meta.url), "utf8");
const popupHtml = readFileSync(new URL("../extension/popup.html", import.meta.url), "utf8");
const optionsHtml = readFileSync(new URL("../extension/options.html", import.meta.url), "utf8");

function ordered(source: string, fragments: string[]): boolean {
  let cursor = -1;
  for (const fragment of fragments) {
    const next = source.indexOf(fragment, cursor + 1);
    if (next < 0) return false;
    cursor = next;
  }
  return true;
}

describe("extension security structure", () => {
  it("checks managed ownership before a single tab can be removed", () => {
    const start = background.indexOf('if (action === "close_tab")');
    const closeCase = background.slice(start, background.indexOf('if (action === "cleanup_tabs")', start));
    expect(ordered(closeCase, ["isManagedTab(id)", '"tab_not_managed"', "tabs.remove(id)", "untrackManagedTab(id)"])).toBe(true);
  });

  it("guards every tab of a multi-tab read and reports the ones it could not read", () => {
    const collectBody = background.slice(
      background.indexOf("async function collect("),
      background.indexOf("async function guardNavigationRisk(")
    );
    // Each tab is checked on its own, and a tab that cannot be read becomes a
    // reported entry rather than a failure of the whole batch.
    expect(ordered(collectBody, [
      "tabs.get(id)",
      "tab.discarded",
      "guardHumanIntervention(tab)",
      "await snapshot(",
      "} catch (error) {",
      "unread_tabs"
    ])).toBe(true);
    // A multi-tab read is never a mutation and never consumes an approval.
    const mutating = background.slice(
      background.indexOf("const MUTATING_ACTIONS"),
      background.indexOf("const APPROVAL_CONTEXT_ACTIONS")
    );
    expect(mutating).not.toContain('"collect"');
    const approvalContext = background.slice(
      background.indexOf("const APPROVAL_CONTEXT_ACTIONS"),
      background.indexOf("let socket")
    );
    expect(approvalContext).not.toContain('"collect"');
  });

  it("binds a risky new-tab destination to a blank tab it owns before navigating", () => {
    const newTabCase = background.slice(
      background.indexOf('if (action === "new_tab")'),
      background.indexOf('throw new BridgeError("unsupported_action"', background.indexOf('if (action === "new_tab")'))
    );
    // Adoption comes before the guard so a retry lands on the same tab, and the
    // guard receives that tab as the live approval target before any navigation.
    expect(ordered(newTabCase, [
      "needsLiveBinding",
      "blankManagedTabForNavigation(active, revalidateOnly)",
      "await guardNavigationRisk(",
      "hostId,",
      "tabs.update(hostId, { url })"
    ])).toBe(true);
    // An approval-only recheck must never create a tab.
    const adoption = readFileSync(
      new URL("../extension/src/background/managed-tabs.ts", import.meta.url),
      "utf8"
    );
    const adoptionBody = adoption.slice(
      adoption.indexOf("export async function blankManagedTabForNavigation"),
      adoption.indexOf("async function createManagedTabUnlocked")
    );
    expect(ordered(adoptionBody, ["isBlankTabUrl(candidate.url)", "if (adoptOnly)", '"approval_context_changed"', "createManagedTabUnlocked"])).toBe(true);
  });

  it("lets an approved new tab reach that handler without locking the active tab", () => {
    // The blank-tab binding above is unreachable unless the dispatcher accepts an
    // approved new_tab: it refuses every action outside this set before the
    // handler runs, which stranded a granted open at "This action cannot consume
    // a page-bound approval grant" no matter how the decision was obtained.
    const approvalContext = background.slice(
      background.indexOf("const APPROVAL_CONTEXT_ACTIONS"),
      background.indexOf("let socket")
    );
    expect(approvalContext).toContain('"new_tab"');
    expect(approvalContext).toContain('"navigate"');
    // The approved target is the blank tab the unapproved attempt opened, not
    // whichever tab is active now, so new_tab must not take the active-tab lock.
    const approvedBranch = background.slice(
      background.indexOf("if (command.approved) {"),
      background.indexOf("const result = await executeCommandWithGuards")
    );
    expect(ordered(approvedBranch, [
      'command.action !== "new_tab"',
      "locksLiveTarget ? tabId(await targetTab(command.payload)) : undefined",
      "await consumeSessionApproval(command.approval_id as string)",
      "if (targetTabId !== undefined) executionPayload ="
    ])).toBe(true);
  });

  it("performs a synchronous target check after async guards and before each side effect", () => {
    const clickCase = content.slice(content.indexOf('case "click":'), content.indexOf('case "hover":'));
    const typeCase = content.slice(content.indexOf('case "type":'), content.indexOf('case "fill_form":'));
    const fillCase = content.slice(content.indexOf('case "fill_form":'), content.indexOf('case "press":'));
    expect(ordered(clickCase, ["await guardRisks", "assertRiskTargetsUnchanged", "clickElement"])).toBe(true);
    expect(ordered(typeCase, ["await guardRisks", "assertRiskTargetsUnchanged", "typeIntoElement"])).toBe(true);
    expect(ordered(fillCase, ["prepareFillBatch", "await guardRisks", "assertRiskTargetsUnchanged", "applyPreparedFill"])).toBe(true);
  });

  it("rechecks click targets after pre-click handlers and directly before activation", () => {
    const semanticClick = content.slice(
      content.indexOf("function clickElement"),
      content.indexOf("function dispatchPointerAt")
    );
    const visualClick = content.slice(
      content.indexOf("function clickAt"),
      content.indexOf("function keyboardInit")
    );
    expect(ordered(semanticClick, [
      'dispatchMouse(element, "mouseup")',
      "safetyCheck()",
      "(element as HTMLElement).click()"
    ])).toBe(true);
    expect(ordered(visualClick, [
      'dispatchMouseAt(element, "mouseup"',
      "safetyCheck()",
      'dispatchMouseAt(element, "click"'
    ])).toBe(true);
  });

  it("rejects file-picker and declared-download activations before click dispatch", () => {
    const guard = content.slice(
      content.indexOf("function rejectUnsupportedClickTarget"),
      content.indexOf("function clickElement")
    );
    const click = content.slice(content.indexOf("function clickElement"), content.indexOf("function dispatchPointerAt"));
    expect(guard).toContain('element.type === "file"');
    expect(guard).toContain('labelledControl.type === "file"');
    expect(guard).toContain('"file_picker_unsupported"');
    expect(guard).toContain('composedClosest(element, "a[download]")');
    expect(guard).toContain('"download_unsupported"');
    expect(ordered(click, ["rejectUnsupportedClickTarget(element)", "dispatchPointer"])).toBe(true);
  });

  it("consumes a local handoff inside the per-tab queue immediately before page apply", () => {
    const completion = background.slice(
      background.indexOf("async function completeLocalCredentialHandoff"),
      background.indexOf("async function waitForTabCondition")
    );
    expect(ordered(completion, [
      "runSerializedMutation(preview.tab_id",
      "guardHumanIntervention(tab)",
      "consumeLocalCredentialHandoff(handoffId)",
      'sendContentCommand(tab, handoff.frame_id, "credential_apply"'
    ])).toBe(true);
  });

  it("removes popup credential DOM immediately after send and keeps pairing secrets out of Settings", () => {
    const completion = popupSource.slice(
      popupSource.indexOf('completeCredentialButton?.addEventListener'),
      popupSource.indexOf("const result = await response")
    );
    expect(ordered(completion, ["browser.runtime.sendMessage", "credentialFields.replaceChildren()", 'field.value = ""'])).toBe(true);
    expect(popupSource).toContain('input.autocomplete = "off"');
    expect(optionsHtml).not.toContain('id="bridge-token"');
    expect(optionsHtml).not.toContain("Pairing key");
    expect(optionsSource).not.toContain("TOKEN_STORAGE_KEY");
    expect(optionsSource).not.toContain("storage.local");
    expect(optionsSource).toContain("event.isTrusted");
    expect(optionsSource).toContain('kind: "ui:native-setup"');
    expect(background).toContain('record.kind === "ui:native-setup"');
    expect(background).toContain('if (!fromOptions)');
  });

  it("keeps approve/reject controls out of the extension and renders decision details in the MCP client", () => {
    expect(popupSource).not.toContain("ui:decide-approval");
    expect(popupHtml).not.toContain("Pending approvals");
    expect(optionsHtml).not.toContain("session-approval-toggle");
    expect(mcpSource).toContain("BrowseWeave needs your confirmation");
    expect(mcpSource).toContain("File SHA-256");
    expect(mcpSource).toContain("Review them yourself before confirming");
  });

  it("ships the local logo in both English extension surfaces", () => {
    expect(popupHtml).toContain('src="icons/icon-48.png"');
    expect(optionsHtml).toContain('src="icons/icon-48.png"');
    expect(popupHtml).toContain('<html lang="en">');
    expect(optionsHtml).toContain('<html lang="en">');
  });

  it("contains no extension console logging path for credential values", () => {
    expect(`${background}\n${content}\n${popupSource}`).not.toMatch(/console\.(?:log|info|debug|warn|error)\s*\(/u);
  });
});
