# BrowseWeave privacy notice

BrowseWeave is a local browser-control bridge. It contains no advertising, analytics SDK, behavioral telemetry, or BrowseWeave-operated cloud service.

“Local bridge” does not mean that tool results stay on the computer. Page text, URLs, and screenshots returned through MCP can be sent by the user's AI client to its selected model provider under that provider's terms.

## Data the extension can process

When it is connected and an MCP client requests browser work, BrowseWeave may
process the following data. Some limited browser metadata and extension state
may also be processed for connection health, setup, approvals, tab cleanup, and
the bounded audit log described below:

- tab titles and URLs;
- the filtered text, links, controls, and metadata visible in permitted web pages;
- a screenshot of the visible tab when explicitly requested;
- click, keyboard, scroll, hover, and navigation commands;
- values the user asks the AI client to enter into a page;
- the contents of a local file the user explicitly asked to attach, when file attachment is enabled.

Because it works on general web pages, this data can include identity, communication, search, location, health, financial, or other sensitive information. Browser-store declarations list broad categories for this reason; they do not mean BrowseWeave collects those categories for its own business use.

## Where data goes

The extension connects only to `ws://127.0.0.1:32110` on the same computer. During a user-started connection, the browser may also open the locally registered `io.browseweave.setup` native helper over browser-owned standard input/output. The helper exchanges only bounded setup metadata with the local daemon; it does not receive page text, screenshots, form values, or browsing history. Neither path sends page data directly to a BrowseWeave server.

Browser content returned by a tool becomes part of the MCP result. The selected AI client and its model provider may then process that result under their own privacy terms. Reading a private page or requesting its screenshot therefore does not guarantee that the content stays only on the computer.

## Local files

File attachment is off by default. When the owner enables it, BrowseWeave reads only files inside the directories listed in `policy.json`; it refuses hidden paths, multiple-hardlink aliases, known credential filenames and key formats, recognizable private-key content, and unsupported types. These checks cannot recognize every renamed or archived secret, so every upload also requires confirmation in the MCP client showing the exact file identity and bound action details. A file that is attached is uploaded to that website under its terms; BrowseWeave does not send it anywhere else. The audit log records the file's SHA-256, size, type, and a hash of its path — never the path or contents. The extension receives the basename and bytes for the single upload and does not persist them.

## Local storage

- A pairing credential is stored in the per-user BrowseWeave configuration directory and extension-local storage. The settings page has no field that displays or accepts it.
- During native or guided setup, the extension temporarily receives short-lived random setup material and expiry/binding metadata, not page content or user credentials. It is invalidated after use or expiry and is never placed in a web-page DOM, URL, command output, clipboard, MCP configuration, or model context.
- For an unpacked Chrome beta, the local installer reads Chrome profile Preferences files only to find enabled extension registration metadata, then accepts a single extension ID/path whose BrowseWeave files exactly match the packaged build. It does not use that step to read browser history, cookies, page text, or form values.
- For Zen Flatpak, the installer may add the one required native-messaging portal preference to `user.js` in exactly one active owner-controlled profile. It preserves unrelated lines and refuses ambiguous, symlinked, foreign-owned, or concurrently changed profile data. If changed, Zen must be fully restarted once before native reconnect.
- Each extension profile stores a random installation ID and its pairing state in extension-local storage.
- The extension stores only the IDs of tabs opened by BrowseWeave so it can enforce the 10-tab limit and close those tabs without touching the user's pre-existing tabs.
- The extension stores its non-exportable signing key in browser-managed local storage/IndexedDB for authenticated pairing and transport identity.
- Browser session storage can retain up to six bounded filtered snapshots, including the returned page text, links, and controls, for delta reads. It also retains up to eight short-lived screenshot-binding metadata records for at most two minutes; screenshot image bytes are not persisted in this cache.
- Browser session storage also holds bounded managed-tab IDs, short-lived session-decision replay metadata, human-intervention origin/message metadata, and local credential-handoff origin/ref/binding metadata. Credential values are never part of this state. Session state is cleared with the browser session/extension lifecycle, subject to browser implementation.
- If the user explicitly enables remote fallback, extension-local storage holds only a one-use permission ID, exact HTTPS origin, and creation/expiry timestamps for at most 24 hours. It holds no username or password and is deleted when consumed, revoked, or expired.
- The audit log stores only limited metadata such as timestamp, action class, outcome, stable error code, and duration.

The audit log does not store typed values, passwords, one-time codes, card values, page text, HTML, DOM snapshots, screenshots, pairing tokens, or private signing keys.

## Sensitive fields

Existing values in password, one-time-code, and payment-card fields are masked in page snapshots. URL fragments are redacted to reduce accidental OAuth-code or token exposure. Detected sensitive actions pause before execution and require confirmation in the MCP client session.

For the recommended local credential handoff, username/password values move from the trusted extension popup directly to one bound HTTPS form and do not enter MCP, the daemon, or model context. In remote fallback, the user gives those values to the AI, so the selected MCP client and model provider can see and may retain them under their own terms. BrowseWeave clears its in-memory references after the one attempt and never logs, persists, echoes, or returns the values.

## Permissions not requested

BrowseWeave does not request browser cookies, full browsing history, bookmarks, clipboard, or saved-password-vault permissions. Broad page access is requested because user-directed control must work across frames on sites the user chooses.

The extension requests native-messaging access only for local setup. The operating-system manifest uses an exact extension ID/origin allowlist and no wildcard. Zen installed through Flatpak may show a one-time operating-system permission prompt; approve it only immediately after selecting **Connect BrowseWeave** yourself.

Private/incognito browsing is disabled by default and should remain disabled unless the user explicitly accepts the additional privacy risk.

## User control and deletion

Disconnect or remove the extension to stop browser access. Remove the exact native-helper registration and per-user daemon service with:

```bash
npx browseweave@0.1.0-beta.8 local-uninstall
```

Normal uninstall preserves local configuration, state, the audit log, the private runtime, and the managed extension copy so accidental removal is recoverable.

To remove the local bridge configuration, state, runtime files, legacy BrowseWeave data, and persistent managed extension copy, explicitly run:

```bash
npx browseweave@0.1.0-beta.8 local-uninstall --purge-data
```

This destructive option removes only exact, current-user-owned BrowseWeave application directories after the service and native registration are removed. It does not remove the extension from Chrome or Zen and cannot clear browser-owned extension storage; remove the extension separately in the browser to clear that state. The Zen Flatpak native-messaging portal preference is preserved because it belongs to the user's browser profile and may be shared by a later reinstall.
