# BrowseWeave support

BrowseWeave `0.1.0-beta.1` is a volunteer-maintained systemd-based Linux developer preview. Support is best-effort and has no response-time guarantee.

## Before opening an issue

1. Confirm that the public registry, installed runtime, and extension all show the same exact beta version.
2. Follow the guided flow in `README.md`; initial enrollment uses the private local page's **Connect this browser** button, not extension Settings.
3. Fully restart the MCP client. If Zen setup changed the Flatpak portal preference, fully restart Zen once and reload the temporary add-on.
4. Run `npx browseweave@0.1.0-beta.1 doctor` and keep only non-sensitive metadata.
5. Reproduce the problem on a public or local test page when possible.

Use the GitHub bug template for a reproducible defect and the feature template for one focused user problem. Include the operating system, browser and version, extension target, MCP client and version, exact command, expected result, actual result, and redacted diagnostics.

Never post credentials, npm or pairing tokens, private page text, browser profiles, personal paths, or unredacted screenshots. Report suspected vulnerabilities through the private process in `SECURITY.md`, not a public issue.

## Current support boundary

- A systemd-based Linux desktop with working `systemctl --user` and developer-loaded Google Chrome or Zen is the only beta scope; non-systemd service managers are unavailable.
- macOS is not live-supported; Windows, Safari, browser-store installs, and remote MCP transports are unavailable.
- Codex, Claude Code, Cursor, and OpenCode have automatic configuration helpers. Other local stdio MCP clients require manual schema adaptation.
- CAPTCHA, WebAuthn, hardware keys, privileged browser UI, operating-system dialogs, site-protection bypasses, stealth, and account-ban prevention are not supportable automation requests.
- Website-specific breakage may require a public reproduction; private account access cannot be debugged through an issue.
