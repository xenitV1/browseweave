# Changelog

All notable changes to BrowseWeave will be documented here.

The format follows Keep a Changelog, and releases use semantic versioning.

## [Unreleased]

### Fixed

- Typed text now yields to the page between keystrokes, so debounced autocomplete, asynchronous framework state, and per-keystroke validators observe intermediate values instead of a single burst. Text beyond the paced ceiling keeps the previous immediate path.
- Scrolling advances in bounded steps instead of one jump, so `IntersectionObserver`, infinite-scroll, and virtualised-list handlers run for the traversed region and later snapshots no longer miss lazily loaded content.
- Clicks and hovers emit a short pointer movement path ending exactly on the target, so hover-driven menus that gate on movement open as expected.

### Changed

- Page snapshots read frames concurrently with a bounded limit rather than one at a time, so a page with many third-party iframes costs the slowest frame instead of their sum. Frame ordering and truncation behaviour are unchanged.
- Split the privileged extension background runtime into focused files within the same module: a dependency-free browser-API and error surface, the managed-tab ownership ledger, the credential-channel storage, and the per-installation identity and signing key. Behaviour is unchanged; the composition file is now well inside its size budget.
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

[Unreleased]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.2...HEAD
[0.1.0-beta.2]: https://github.com/xenitV1/browseweave/compare/v0.1.0-beta.1...v0.1.0-beta.2
[0.1.0-beta.1]: https://github.com/xenitV1/browseweave/releases/tag/v0.1.0-beta.1
