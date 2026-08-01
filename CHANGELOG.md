# Changelog

All notable changes to BrowseWeave will be documented here.

The format follows Keep a Changelog, and releases use semantic versioning.

## [Unreleased]

## [0.1.0-beta.9] - 2026-08-01

Published under the npm `beta` and `latest` dist-tags. No Chrome Web Store or Mozilla Add-ons release is claimed.

### Fixed

- An approved `browser_new_tab` now actually opens its destination. 0.1.0-beta.8 added the blank-tab binding that gives a risky destination a live document to bind a decision to, but the command dispatcher still refused `new_tab` before that handler ran, because the action was missing from the set allowed to consume a grant. Every granted open therefore ended at "This action cannot consume a page-bound approval grant" — a human decision and an `autonomous_actions` policy grant failed identically, so enabling the policy only replaced the prompt with an immediate error. `new_tab` may now consume a decision, and because its approved target is the blank tab the unapproved attempt opened rather than whichever tab is active, it does not take the active-tab lock the page-bound actions take; the binding is still enforced by the approval fingerprint, which carries that exact host tab ID.

## [0.1.0-beta.8] - 2026-08-01

Published under the npm `beta` and `latest` dist-tags. No Chrome Web Store or Mozilla Add-ons release is claimed.

### Added

- Added `browser_collect`, which reads up to 8 already-open tabs in one call under a shared character budget. Comparing pages or gathering material across search results previously cost a separate snapshot per tab, each paying the full budget alone. It runs the ordinary snapshot pipeline per tab, so refs, truncation, and per-tab `next_cursor` behave exactly as in a single-tab read and a caller can follow up on one tab with `browser_snapshot`. Tabs are read a few at a time to bound concurrent page messaging, and a tab that cannot be read — closed, privileged, unloaded by the browser, or paused waiting for the user — is reported in `unread_tabs` instead of failing the batch. It never opens, navigates, or closes a tab, and never consumes an approval. The snapshot cache also grew so that one multi-tab read cannot evict every snapshot a caller still holds a `since_snapshot_id` for.
- `browser_snapshot` now returns `next_cursor` when a result is truncated, and accepts it back as `from_cursor` to continue reading the same page where the previous result stopped. Truncation could previously only be worked around by guessing `query` terms or raising `max_chars` to its ceiling, because element order is document order and scrolling does not change what a snapshot covers. The cursor records a per-frame position, so a frame cut by its own element limit, by the shared character budget, or dropped entirely all resume correctly; a page that changed between reads can still repeat or skip an element, which is the same assumption `since_snapshot_id` makes.
- `browser_wait` accepts a `url_changed` condition for the common case of submitting a form whose destination is not known in advance. `value` optionally carries the URL last observed, so a redirect that completed before the wait started is not missed. Comparison happens on redacted URLs, the only form a caller can have seen.
- `browser_list_tabs` reports `managed: true` for tabs BrowseWeave opened, the `managed_tab_count`/`managed_tab_limit` budget, and `human_intervention_tabs` for tabs paused waiting for the user. These were previously discoverable only by failing into `managed_tab_limit`, `tab_not_managed`, or a paused-tab error.

### Fixed

- `browser_new_tab` with an HTTP(S) URL now works. Any destination outside loopback is a detected navigation, but a tab that does not exist yet has no live document to bind the decision to, so the guard failed with `approval_target_unavailable` before reaching any approval channel — a hard error no user decision and no owner policy could grant, even though the tool advertised HTTP(S) URLs. BrowseWeave now opens a blank tab it owns, binds the decision to that exact tab, and navigates it; a retry adopts the same blank tab instead of consuming another slot in the managed-tab budget, and an approval-only recheck never creates one.

## [0.1.0-beta.7] - 2026-08-01

Published under the npm `beta` and `latest` dist-tags. No Chrome Web Store or Mozilla Add-ons release is claimed.

### Added

- Added an owner-only `autonomous_actions` policy section that pre-authorizes named sensitive-action risk categories, so detected clicks, submissions, publications, and cross-site navigations execute without a per-action prompt. It is off by default and lives in the same owner-only `policy.json` as the file-attach allowlist: the daemon never writes it, no MCP method or browser command can set it, and it is read at service start. `{ "autonomous_actions": { "enabled": true } }` covers every page-action category, an explicit `categories` array narrows it, and `file_attach` is covered only when named. The live-target fingerprint check, single-use grants, automatic-replay bounds, credential handoff, path allowlist, and refused browser surfaces are unchanged; grants are audited as `policy_approved` and reported by `browser_status` and `doctor`.
- `browseweave doctor` now reports the owner policy file path and whether it exists.

### Changed

- Key presses on a password-looking target are no longer rejected in the content script either. Submitting or moving through a login form is ordinary work, and the password *value* is still refused by the type and form-fill paths, which keep it on the dedicated credential handoff. Command-driven key events now reject only one-time-code and payment-card targets, whose value only the human's own keystrokes may produce; a payment or one-time-code signal from either classifier is enough to reject, so a password-looking label cannot mask one.
- Key presses on an account-security-looking target are no longer rejected in the content script. That rejection exists to keep a secret value from being driven by a command, which covers password, one-time-code, and payment-card targets; an account-security control's risk is a hard-to-reverse effect that the same control already exposes to an ordinary click. Pressing one now goes through the normal approval channel—where a human decision or an owner-policy category can authorize it—instead of a dead end no approval could open. Password, one-time-code, and payment-card targets are unchanged and still accept only Tab, Escape, and cursor-navigation keys.

### Fixed

- A detected sensitive action in an MCP client without elicitation support now reports that the client cannot collect a confirmation, instead of reporting that the user declined. The message names the owner-policy opt-in so the failure is actionable rather than a silent dead end.

## [0.1.0-beta.6] - 2026-07-29

Published under the npm `beta` and `latest` dist-tags. No Chrome Web Store or Mozilla Add-ons release is claimed.

### Changed

- Guided setup continues to detect installed Codex, Claude Code, Cursor, and OpenCode clients before browser consent, but now normalizes every managed registration to the trusted `browseweave@latest` npm invocation. Exact older persistent-runtime entries and the legacy `browseweave-mcp` npm-bin form are migrated; unrelated or ambiguous entries remain untouched.
- OpenCode setup now checks both the XDG user configuration and an existing home-level `.opencode/opencode.json` or JSONC overlay. A verified older BrowseWeave entry in either location is upgraded so it cannot shadow the npm-backed global registration.

### Fixed

- Added the missing npm-facing `browseweave mcp` CLI subcommand used by generated Codex, Claude Code, Cursor, and OpenCode registrations. The command now starts the versioned stdio MCP server instead of exiting with `Unknown command: mcp` and surfacing as `Connection closed`.
- Increased the bounded Codex MCP-list verification window from 10 to 30 seconds so a valid standalone Codex installation is not misclassified during first setup on a busy machine.

## [0.1.0-beta.5] - 2026-07-29

Published under the npm `beta` and `latest` dist-tags. No Chrome Web Store or Mozilla Add-ons release is claimed.

### Added

- Added a focused npm-bundled BrowseWeave operating skill and automatic, idempotent installation through the explicit `setup`, `local-install`, and `mcp-add` commands. The guide is installed for Codex at `~/.agents/skills/browseweave` and Claude Code at `~/.claude/skills/browseweave`; foreign, modified, wrong-owner, or symlinked copies are preserved and fail closed. Plain npm installation remains free of lifecycle hooks.

### Changed

- Sensitive-action approval now happens only in the MCP client session. The extension no longer displays approve/reject cards or exposes a session-approval toggle, and the generated confirmation phrase and risk-tier opt-in were removed. All detected risk classes, including coordinate clicks and file attachment, use one explicit human decision relayed by the MCP client. Decisions remain short-lived, single-use, and bound to the exact action, parameters, file bytes when applicable, and revalidated live target.

### Fixed

- Fixed approved-action revalidation argument ordering so the approval source can no longer be mistaken for an approval ID while a live fingerprint is being checked.

## [0.1.0-beta.4] - 2026-07-29

Published under the npm `beta` and `latest` dist-tags. No Chrome Web Store or Mozilla Add-ons release is claimed.

### Fixed

- Fixed guided Chrome setup after relocating the unpacked extension to the visible `~/BrowseWeave/chromium-mv3` directory. Setup and post-enrollment Chrome identity discovery now share one path calculation, so exact-origin native-host registration no longer looks for the removed legacy copy under `~/.local/share` after the browser has connected.

## [0.1.0-beta.3] - 2026-07-29

Published under the npm `beta` and `latest` dist-tags. No Chrome Web Store or Mozilla Add-ons release is claimed.

### Added

- Optional local file attachment: `browser_attach_file` places one file into a page's file input without opening the operating-system file picker, which no extension can drive. It is off by default and reads only from directories listed in an owner-only `policy.json`. Hidden paths, multiple-hardlink aliases, known credential/key names, recognizable private-key content, unsupported types, oversized files, and BrowseWeave's own directories are refused; symlinks are resolved before the decision, and the open handle is re-verified so the path cannot be swapped mid-read. Every attachment requires a one-use extension-signed approval that shows the exact basename, byte size, MIME type, full SHA-256, and browser-verified site; session confirmation can never authorize a local-file upload. The absolute path never reaches the browser, the audit log stores structured file identity plus a full path hash rather than the path, and snapshots report `[ATTACHED:n]` instead of a filename.
- Optional session-confirmed approval: for form submissions, message or publish actions, and off-site navigation, a human may confirm in the MCP client session by typing a daemon-generated four-word phrase, instead of approving in the extension popup. It is off by default and requires two independent opt-ins — an owner-only `policy.json` and a toggle in extension-owned Settings. File attachment, payments, deletion, passwords, one-time codes, account security, coordinate clicks, and both credential channels always keep the extension-signed decision. The confirmation phrase never enters a tool result, the audit log, extension UI, a page, or daemon output, and one wrong phrase discards the approval. This path rests on a weaker assumption than the default — that the MCP client relays human input honestly — which `SECURITY.md` now states explicitly.
- Added `setup --all-browsers` and a source-checkout `scripts/setup-all.sh` wrapper to install locked dependencies, build once, then enroll every detected supported browser sequentially. Selected MCP clients are registered first through a trusted `browseweave@latest` npm invocation; only exact verified older BrowseWeave entries may be migrated, while foreign entries remain untouched.

### Fixed

- Typed text now yields to the page between keystrokes, so debounced autocomplete, asynchronous framework state, and per-keystroke validators observe intermediate values instead of a single burst. Text beyond the paced ceiling keeps the previous immediate path.
- Scrolling advances in bounded steps instead of one jump, so `IntersectionObserver`, infinite-scroll, and virtualised-list handlers run for the traversed region and later snapshots no longer miss lazily loaded content.
- Clicks and hovers emit a short pointer movement path ending exactly on the target, so hover-driven menus that gate on movement open as expected.
- Stopped detecting unsupported Chromium installations as Google Chrome when the native-host and profile discovery paths only support the Google Chrome layout.
- Bounded the total paced typing time of large `fill_form` batches so the extension returns before the daemon command timeout instead of executing after the caller has already failed.
- Prevented concurrent cold-frame commands from racing multiple all-frame content-script injections.
- Setup no longer reuses an in-memory browser connection after removing that connection's legacy extension directory.
- Updated the disposable-browser QA patch contract after the endpoint was removed from the Settings HTML.

### Changed

- Page snapshots read frames concurrently with a bounded limit rather than one at a time, so a page with many third-party iframes costs the slowest frame instead of their sum. Frame ordering and truncation behaviour are unchanged.
- Split the privileged extension background runtime into focused files within the same module: a dependency-free browser-API and error surface, the managed-tab ownership ledger, the credential-channel storage, and the per-installation identity and signing key. Behaviour is unchanged; the composition file is now well inside its size budget.
- Split the daemon runtime into focused files within the same module: nonce/proof/setup-encryption primitives, wire parsing and signature verification, the bounded audit log, and the pinned extension-key registry. The published `dist/src/daemon.js` export surface is unchanged.
- Per-tab mutation pacing is adaptive: editing and scrolling continue at a tighter interval, actions that commit or navigate keep the previous conservative interval, and a tab backs off well beyond both for a period after a detected challenge, 403, or 429. Pacing remains per tab rather than per origin or IP.

## [0.1.0-beta.2] - 2026-07-28

Published under the npm `beta` dist-tag. No Chrome Web Store or Mozilla Add-ons release is claimed.

### Changed

- Reorganized the Node.js runtime and browser extension into explicit domain modules with thin, stable executable facades.
- Added an automated architecture gate for module layout, dependency direction, cycle detection, shared contracts, and source-size budgets.

### Fixed

- Allowed trusted MCP clients such as Codex to update configuration beneath their own installation directory without triggering a false directory-replacement warning; executable identity, directory inode, ownership, and permission checks remain enforced.

## [0.1.0-beta.1] - 2026-07-28

Published under the npm `beta` dist-tag. No Chrome Web Store or Mozilla Add-ons release is claimed.

### Added

- Local stdio MCP server and authenticated browser bridge.
- Compact semantic snapshots, delta reads, and on-demand screenshots.
- Firefox/Zen Manifest V2 and Chrome/Chromium Manifest V3 builds.
- Extension-owned cryptographic approval for sensitive actions.
- CAPTCHA, WebAuthn, access-denial, and rate-limit human handoff.
- Cross-platform per-user service plans and MCP client configuration helpers.
- Guided exact-version setup with browser/client detection, mandatory browser consent, one-click ticket pairing, and authenticated reconnect verification.
- A trusted settings-button connection path through an exactly allowlisted native-messaging helper, with no visible or copyable pairing key.
- Native-helper ownership and integrity checks that may start only the fixed installed BrowseWeave per-user service and fail closed on foreign or modified artifacts.
- Post-enrollment discovery of one enabled byte-exact unpacked Chrome identity, followed by exact-origin native-host registration without a wildcard.
- Owner-safe Zen Flatpak portal-preference configuration that preserves unrelated profile settings and reports when a full Zen restart is required.
- Version-pinned public maintenance commands that delegate from an npm invocation to the exact persistent runtime installed by setup.
- An explicit `local-uninstall --purge-data` path for owner-safe deletion of local bridge configuration, state, runtime files, legacy data, and the managed extension copy; browser-owned extension storage still requires removing the extension in the browser.
- Ten-tab limit and explicit cleanup for BrowseWeave-managed tabs.

### Security

- Zen/Flatpak native messaging preserves the operating system's one-time permission prompt instead of bypassing it.
- CAPTCHA, WebAuthn, hardware-key, anti-bot, access-denial, and rate-limit states remain human handoff boundaries; BrowseWeave does not claim stealth or guaranteed non-detection.

### Known limitations

- Chrome and Zen remain developer-loaded extensions; persistent store installation requires stable store identities and signing.
- The Linux beta installer requires a systemd-based desktop with working `systemctl --user`; non-systemd service managers are unavailable.
- The unsigned Zen add-on is removed when Zen restarts and must be loaded again. A changed Flatpak portal preference also requires one full Zen restart before Settings reconnect.
- Windows setup is unavailable until a fixed signed `browseweave-native-host.exe` is shipped; Node.js scripts, `.cmd`, PowerShell, and shell-wrapper substitutes are rejected.
- macOS is implementation- and CI-covered but not live-verified. Clean-machine Linux beta installation and exact browser/client version smoke tests remain release gates.

[Unreleased]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.9...HEAD
[0.1.0-beta.9]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.8...v0.1.0-beta.9
[0.1.0-beta.8]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.7...v0.1.0-beta.8
[0.1.0-beta.7]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.6...v0.1.0-beta.7
[0.1.0-beta.6]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.5...v0.1.0-beta.6
[0.1.0-beta.5]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.4...v0.1.0-beta.5
[0.1.0-beta.4]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.3...v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/xenitV1/browseweave/releases/tag/v0.1.0-beta.1
