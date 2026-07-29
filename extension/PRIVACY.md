# BrowseWeave extension privacy notice

BrowseWeave provides user-directed browser control to a local MCP bridge. The extension contains no advertising, analytics SDK, remote executable code, or BrowseWeave-operated telemetry service.

The extension-to-daemon connection is local, but MCP results do not necessarily stay on the computer. The user's AI client and selected model provider can receive returned page text, URLs, and screenshots under their own terms.

## Local connection

- The extension connects only to `ws://127.0.0.1:32110` on the same computer.
- After the user selects **Connect BrowseWeave**, the browser may open the locally registered `io.browseweave.setup` native helper over browser-owned standard input/output. The helper exchanges only bounded setup metadata with the local daemon and does not receive page text, screenshots, form values, or browsing history.
- Initial guided enrollment uses the installer's private short-lived loopback page and its **Connect this browser** button. **Connect BrowseWeave** in Settings is a separate later native reconnect action.
- Normal page reading or interaction happens in response to an authenticated local command. Limited browser metadata and extension state are also processed for connection health, setup, session-decision replay protection, and managed-tab cleanup.
- Page data returned through MCP may be processed by the user's chosen AI client and model provider under their own privacy terms.

## Data that may be processed

- tab titles and URLs;
- filtered visible page text, links, controls, and frame metadata;
- visible-tab screenshots when explicitly requested;
- click, type, key, hover, scroll, form, and navigation actions;
- values the user asks the AI client to enter.
- the basename, MIME type, size, hash, and bytes of a local file the user explicitly approved for one upload.

Password, one-time-code, and payment-card values are masked in snapshots. URL fragments are redacted. Typed values may pass through extension memory to complete the requested action but are not saved in the audit log.

## Local state

The extension stores a random installation ID, pairing state, and a non-exportable signing key for authenticated pairing and transport identity in browser-managed local storage/IndexedDB. The settings page has no field that displays or accepts the pairing credential.

During native or guided setup, the extension receives short-lived random setup material and expiry/binding metadata only after the user's trusted connection action. It contains no browsing data or credentials. BrowseWeave does not copy that material into a normal page, URL, clipboard, command output, MCP configuration, or model context; it is invalidated after use or expiry.

Browser session storage may contain:

- up to six bounded filtered snapshots, including returned page text, links, and controls, for delta reads;
- up to eight screenshot-binding metadata records for at most two minutes, without screenshot image bytes;
- up to 10 managed-tab IDs;
- bounded short-lived session-decision replay and human-intervention metadata; and
- local credential-handoff origin, ref, expiry, and binding metadata for at most five minutes, without credential values.

This state is cleared with the browser session/extension lifecycle, subject to browser implementation. If the user explicitly enables remote credential fallback, extension-local storage contains only a one-use permission ID, exact HTTPS origin, and creation/expiry timestamps for at most 24 hours. It contains no username or password and is removed when consumed, revoked, or expired.

For local handoff, username/password values move from this trusted popup directly to one bound HTTPS form and do not enter MCP, the daemon, or model context. For remote fallback, the chosen AI client and model provider necessarily see the user-supplied values; BrowseWeave clears its references after the one attempt and never persists, logs, echoes, or returns them. Browser or password-manager behavior is outside BrowseWeave and may have separate storage rules.

## Permissions

Broad host access, tabs, navigation, storage, Chromium scripting, and native-messaging permissions support the extension's single purpose: user-directed reading, interaction, and local setup on permitted web pages. The operating-system native-host manifest uses an exact extension ID/origin allowlist and no wildcard. Zen installed through Flatpak may show a one-time operating-system permission prompt; approve it only immediately after selecting **Connect BrowseWeave** yourself. The extension does not request cookies, browser history, bookmarks, clipboard, or saved-password access.

Private/incognito access is disabled by default. Browser UI, privileged pages, extension stores, file pickers, operating-system dialogs, CAPTCHA, WebAuthn, and hardware security-key prompts remain outside automated control.

When a sensitive action is detected, confirmation is collected by the MCP client rather than the extension. The extension has no approve/reject UI. The resulting decision is single-use and the live browser target is revalidated before execution. Pairing, credential handoff, remote credential permission, CAPTCHA, WebAuthn, and browser/operating-system prompts remain separate trusted user interactions.
