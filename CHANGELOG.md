# Changelog

All notable changes to BrowseWeave will be documented here.

The format follows Keep a Changelog, and releases use semantic versioning.

## [Unreleased]

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

[Unreleased]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.5...HEAD
[0.1.0-beta.5]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.4...v0.1.0-beta.5
[0.1.0-beta.4]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.3...v0.1.0-beta.4
[0.1.0-beta.3]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.2...v0.1.0-beta.3
[0.1.0-beta.2]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/xenitV1/browseweave/releases/tag/v0.1.0-beta.1
