<p align="center">
  <img src="assets/brand/browseweave-logo.png" width="144" alt="BrowseWeave logo">
</p>

<h1 align="center">BrowseWeave</h1>

BrowseWeave lets local MCP-compatible AI clients use the web pages already open in your real browser. It gives the model a compact semantic view for routine work, a screenshot only when visual inspection matters, and controlled interaction with ordinary HTTP(S) pages.

The MCP transport is client-neutral. Automatic configuration is currently implemented for Codex, Claude Code, Cursor, and OpenCode; other local stdio MCP clients require a manually reviewed command/args entry. The browser preview is deliberately limited to Google Chrome and Zen.

> **Linux developer preview:** `0.1.0-beta.2` is intended for explicit, version-pinned beta installation on a systemd-based Linux desktop with working `systemctl --user`. Chrome uses a user-loaded unpacked extension. Zen uses an unsigned temporary add-on. The maintainer has live-connected both browsers on that Linux environment, but clean-machine release verification remains a gate. macOS is implemented and CI-tested but not live-verified. Windows setup, non-systemd Linux service managers, Safari, and browser-store installation are unavailable.
>
> Install the npm beta from the exact version shown below. It is published under the `beta` dist-tag; the documentation does not use an unpinned `latest` install. Chrome Web Store and Mozilla Add-ons listings remain unavailable.

## What it can do

- List, select, open, navigate, reload, and close browser tabs.
- Keep at most 10 BrowseWeave-opened tabs per browser profile and close only those managed tabs during cleanup.
- Read normal web pages through four context filters instead of sending full HTML.
- Return only changes since a previous snapshot.
- Inspect iframes and open Shadow DOM.
- Click, double-click, hover, type, fill forms, press keys, scroll, and wait for page state.
- Capture the visible viewport when layout, images, canvas, or an ambiguous state matters.
- Use short-lived screenshot-bound coordinates for custom widgets that have no semantic reference.
- Heuristically detect supported sensitive-action patterns—such as messages, publishing, payments, deletion, credentials, 2FA, and security changes—and pause detected actions for human approval.
- Attach a local file to a page's file input, if the user has allowed its directory, without opening the operating-system file picker.
- Connect more than one browser profile without mixing their tab IDs or approval keys.

Attaching a file sends it from the computer to a website, so it is off by default, always requires explicit human confirmation, and only reads from directories the user listed in an owner-only `policy.json`. Hidden files and directories — which covers `.ssh`, `.gnupg`, `.aws`, `.env`, and `.npmrc` — key and credential material, and unsupported file types are never attachable, even inside an allowed directory.

```json
{ "file_attach": { "enabled": true, "allowed_directories": ["/absolute/path/to/Documents"] } }
```

BrowseWeave controls permitted content inside ordinary HTTP(S) pages. It does not control browser menus, browser settings pages, extension-store pages, operating-system dialogs, file pickers, hardware security-key dialogs, or other privileged surfaces.

## Context-efficient page vision

`browser_snapshot` supports four bounded views:

- `interactive`: buttons, links, inputs, and other actionable controls.
- `balanced`: actionable controls plus headings and short nearby meaning. This is the default.
- `content`: articles, lists, tables, and primary reading content.
- `full`: a wider but still strictly bounded fallback.

Use `query` to isolate a relevant word or section on large pages. Every result returns a `snapshot_id`; supplying it as `since_snapshot_id` returns `unchanged` when nothing relevant changed, or a compact delta when it did.

The default snapshot budget is about 12,000 characters and the hard maximum is 30,000. Screenshots are a separate tool and default to JPEG. This keeps ordinary browser work from flooding the model context with pixels or irrelevant page chrome.

## Architecture

```text
Codex / Claude Code / Cursor / OpenCode / another MCP client
                         │
                    stdio MCP
                         ▼
                  BrowseWeave MCP
                         │ authenticated loopback IPC
                         ▼
                  BrowseWeave daemon
                         │ authenticated local WebSocket
             ┌───────────┴───────────┐
             ▼                       ▼
      Zen / Firefox add-on    Chrome / Chromium extension
             │                       │
             └──── permitted web pages ────┘

Detected sensitive action ──► extension-owned approval UI ──► signed one-time decision

Trusted Connect click ──► browser native messaging ──► registered setup helper
                    └──── authenticated local IPC ────► daemon
```

The daemon binds only to `127.0.0.1`. Each extension installation owns a separate signing key. An MCP caller can request an action, but it cannot create the extension signature required to approve an action that BrowseWeave detected as sensitive. The setup helper is a narrow browser-launched process, not a general command runner: it accepts only fixed setup/cancel messages from an exactly allowlisted extension identity.

## Current support status

CI or a generated registration plan is not the same as a live end-to-end installation. Release notes will name exact versions and evidence rather than widening these claims automatically.

| Target | Beta status |
|---|---|
| systemd-based Linux + Google Chrome 116+ | Developer preview; an unpacked Manifest V3 build has been live-connected on the maintainer machine |
| systemd-based Linux + Zen based on Firefox 142+ | Developer preview; a temporary Manifest V2 build and the Flatpak portal path have been live-connected on the maintainer machine |
| macOS | Implementation and automated tests only; no live release claim |
| Windows | Unavailable; setup requires a fixed signed `browseweave-native-host.exe` that is not shipped |
| Codex, Claude Code, Cursor, OpenCode | Automatic configuration helpers are implemented; exact client versions still require release smoke tests |
| Other local stdio MCP clients | Manual configuration only after adapting the printed generic command/args entry to the client's current official schema |
| Chrome Web Store / Mozilla Add-ons | Unavailable; stable store identities and signing remain separate release gates |

Edge, Brave, Vivaldi, Firefox, Safari, remote MCP transports, and hosted browsers are not beta support claims.

## Guided beta setup

Prerequisites: a systemd-based Linux desktop where `systemctl --user` works, Node.js 22.14.0 or newer, a visible interactive terminal, and Chrome 116+ or a Zen release based on Firefox 142+. Non-systemd distributions are not supported by this beta installer. The command deliberately refuses a background pipe or hidden non-interactive shell because the browser consent must remain visible.

Pin both the package version and the requested browser/client. For example:

```bash
npx browseweave@0.1.0-beta.2 setup --browser chrome --client codex
```

Other explicit combinations are:

```bash
npx browseweave@0.1.0-beta.2 setup --browser zen --client claude-code --client cursor
npx browseweave@0.1.0-beta.2 setup --browser chrome --browser-path /absolute/path/to/chrome --client codex
npx browseweave@0.1.0-beta.2 setup --browser chrome --new-profile --client codex
npx browseweave@0.1.0-beta.2 setup --browser chrome --client opencode --opencode-v2
```

`--browser` accepts `chrome` or `zen`. If it is omitted, setup prefers Chrome when both browsers are present; specify the flag to avoid an unintended choice. For a portable or nonstandard installation, pair it with a safe absolute `--browser-path`. Use `--new-profile` only when the same browser family is already connected and you intentionally want to pair another profile.

Repeat `--client` to configure any requested combination of `codex`, `claude-code`, `cursor`, and `opencode`. If no client is specified, setup attempts every supported client it detects; explicit flags are safer. BrowseWeave preserves unrelated configuration and stops rather than overwriting an ambiguous or foreign `browseweave` entry. For another local stdio MCP client, print a generic entry and adapt it manually to that client's current official schema:

```bash
npx browseweave@0.1.0-beta.2 mcp-config generic
```

OpenCode has two incompatible configuration generations. BrowseWeave treats an `opencode` executable as V1 and an `opencode2` executable as V2; it does not guess from the contents of the file it is about to change. If both executables are installed, or neither is available on `PATH`, select the intended generation explicitly:

```bash
npx browseweave@0.1.0-beta.2 mcp-add opencode --opencode-v1
npx browseweave@0.1.0-beta.2 mcp-add opencode --opencode-v2
```

Use the same flag with `setup --client opencode`. V1 adds the server directly under `mcp` with `enabled: true`. V2 adds it under `mcp.servers` with `disabled: false` and preserves a sibling `mcp.timeout` block. A missing configuration file is created safely; a mixed, mismatched, or foreign configuration is left untouched. These layouts follow the current official [OpenCode V1 MCP documentation](https://dev.opencode.ai/docs/mcp-servers/) and [OpenCode V2 MCP documentation](https://opencode.ai/v2/docs/mcp-servers).

This is a **guided one-command setup**, not a silent browser-extension install. The command:

1. installs and verifies a persistent per-user runtime, background service, and narrow native reconnect helper without `sudo`;
2. opens the selected browser's extension-management screen and a private loopback setup page;
3. reveals the exact managed extension folder or manifest, in a short visible directory under your home folder, and opens it in your file manager while you complete the browser-required load;
4. waits for the user to return to the private setup page and select **Connect this browser**—not the extension Settings button—for initial enrollment;
5. exchanges a short-lived setup capability between that page, the extension, and the local daemon without displaying a pairing key;
6. verifies that the extension stored the credential and completed a normal authenticated reconnect;
7. after Chrome has saved the unpacked extension, discovers only the single enabled byte-exact BrowseWeave identity and registers that exact `chrome-extension://<id>/` origin; and
8. registers each selected MCP client against the persistent runtime.

The extension Settings button labeled **Connect BrowseWeave** is a later repair/reconnect path through native messaging. It is not the initial guided-setup button.

The pairing key is never shown in settings or placed in a web-page DOM, URL, command output, clipboard, MCP configuration, or model context. The daemon does not mark setup complete or replace an existing browser credential until the extension stores the new credential, reads it back, and proves that durable state in a second authenticated reconnect. Setup material expires, is single-purpose, and does not remove the browser's consent step.

The native host manifest contains an exact Firefox extension ID or exact `chrome-extension://<id>/` origin; wildcards are rejected. After validating the browser-owned caller arguments, the helper may start only the fixed, already-installed BrowseWeave per-user service. It refuses a missing, modified, foreign-owned, symlinked, or overly permissive service definition and never accepts a command, executable path, shell text, or environment override from the extension.

The extension cannot install or rewrite this operating-system helper itself. If Settings says the helper is unavailable, repair the exact beta runtime with:

```bash
npx browseweave@0.1.0-beta.2 local-install
```

In a verified source checkout, rebuild and run:

```bash
node dist/src/cli.js local-install
```

Then return to settings and select **Connect BrowseWeave** again. Do not install a helper offered by a website, and do not substitute a copied pairing key.

### Current beta limitations

- **Google Chrome:** initial enrollment uses the private local setup page. Afterward the installer authorizes only one enabled unpacked BrowseWeave copy whose files exactly match the packaged build. It refuses zero, multiple, disabled, or modified candidates and never uses a wildcard. A permanent Web Store identity is still required for store distribution.
- **Zen installed through Flatpak:** after initial enrollment, setup safely enables Zen's user-consented native-messaging portal preference in the one active owner-controlled profile. If setup reports that it changed the preference, fully quit and restart Zen once before using the Settings reconnect button. Zen may then show a one-time operating-system permission prompt; approve it only immediately after your own **Connect BrowseWeave** click and cancel an unexpected prompt.
- **Zen persistence:** the unsigned development add-on is removed when Zen restarts. Load it again from the exact managed manifest shown by setup; persistent consumer installation requires Mozilla signing.
- **macOS:** implementation and automated tests exist, but no live beta support is claimed.
- **Windows:** setup is unavailable. The required fixed signed `browseweave-native-host.exe` is not shipped, and Node.js scripts, `.cmd`, PowerShell, and shell wrappers are intentionally rejected.

### Required browser approval

Setup keeps the unpacked extension in `BrowseWeave` inside your home folder — `BrowseWeave/chromium-mv3` for Chrome and `BrowseWeave/firefox-mv2` for Zen — and opens that folder in your file manager. It deliberately does not live under a hidden directory such as `~/.local/share`, because desktop file pickers do not show those without an unhide shortcut.

Chrome requires these user actions:

1. Turn on **Developer mode** in `chrome://extensions`.
2. Select **Load unpacked**, or simply drag the opened folder onto the `chrome://extensions` page.
3. Choose the folder opened or printed by setup.

Zen requires these user actions:

1. Open `about:debugging#/runtime/this-firefox`.
2. Select **Load Temporary Add-on**.
3. Choose `manifest.json` in the folder opened or printed by setup.

The unsigned Zen development add-on is temporary and is removed when the browser restarts. A persistent public Firefox-family installation requires a future Mozilla-signed release. Chrome Web Store and Mozilla signing are separate release gates; BrowseWeave does not bypass browser consent or managed-install policies.

After setup prints **BrowseWeave setup is complete**, start a new MCP-client session and call `browser_status`. A saved client configuration is not evidence that the current client session loaded the server.

If an AI agent is helping, ask it to follow [`SKILL.md`](SKILL.md). The agent must run setup in a visible interactive terminal/PTY and leave browser loading, **Connect this browser**, any later **Connect BrowseWeave** action, and every operating-system prompt to the human.

## Run the guided setup from source

Repository contributors can build and run the same flow locally:

```bash
git clone https://github.com/xenitV1/browseweave.git
cd browseweave
npm ci --ignore-scripts
npm run build
node dist/src/cli.js setup --from-source --browser chrome --client codex
```

Use `--browser zen` for Zen and repeat `--client` when testing more than one supported MCP client. The build also creates `extension/dist/chromium-mv3` and `extension/dist/firefox-mv2`; packaged ZIP/XPI artifacts are created by `npm run package:extension`.

### Manual browser loading and diagnostics

During guided setup, the terminal prints the active managed extension path and
private local setup URL before trying to open the browser. Those printed values
are the recovery path for that setup attempt and remain usable until its shown
expiry.

After public beta setup, run maintenance and diagnostics through the same pinned package version. The public command delegates to the exact persistent runtime installed by setup rather than registering an ephemeral npm-cache path:

```bash
npx browseweave@0.1.0-beta.2 doctor
npx browseweave@0.1.0-beta.2 extension-path chrome
npx browseweave@0.1.0-beta.2 extension-path zen
```

`extension-path` is not a replacement for the active guided setup and does not install the native helper. The current settings page has no pairing-key field. If native setup fails, use the verified installer/Repair path above or rerun guided setup; never ask a user to expose a pairing key to an LLM, agent, MCP client, captured terminal, website, issue, log, or commit.

### Uninstall and local data

Normal uninstall removes the native registration and background service but preserves local configuration, state, runtime files, and the managed extension copy:

```bash
npx browseweave@0.1.0-beta.2 local-uninstall
```

Only when the user explicitly wants those local application directories deleted, add `--purge-data`. Then remove BrowseWeave separately from Chrome or Zen to clear browser-owned extension storage. Purge deliberately preserves Zen's browser-profile portal preference.

## Human approval and site-respectful operation

Approval normally happens in the browser extension. Optionally, the browser owner may allow a narrower path where the human confirms in the AI client session instead, by typing a phrase BrowseWeave generates. It is off by default, covers only form submissions, message/publish actions, and off-site navigation, and requires enabling it in **both** an owner-only `policy.json` and extension Settings. Payments, deletion, credentials, two-factor codes, account-security changes, and coordinate clicks always stay in the extension. It is deliberately weaker than the default: it trusts the AI client to relay what the human actually typed. Read [SECURITY.md](SECURITY.md#session-confirmed-approval-and-what-it-changes) before enabling it.

```json
{ "session_approval": { "enabled": true, "risks": ["form_submit", "message", "external_navigation"] } }
```

BrowseWeave applies this approval flow only when its supported heuristics classify a requested action as sensitive. Those heuristics can produce false positives and false negatives; they do not guarantee that every risky action will be detected. For an action that is detected, BrowseWeave sends the action details to the target browser extension, shows them in extension-owned UI, and accepts only a signed, short-lived, single-use decision. If the page, target, tab, parameters, or live target fingerprint changes, the old approval is invalid. The UI shows the browser-verified current pre-action destination; page JavaScript, server behavior, or a later redirect can still change the final destination. This reduces risk but is not a complete safety guarantee.

BrowseWeave uses the user's visible browser; it does not use WebDriver, headless mode, or Marionette. That removes one common automation signal, but no software can honestly guarantee that a website will never detect automation or restrict an account.

To reduce user and site risk, BrowseWeave is designed to:

- serialize and conservatively pace mutations per browser tab; separate tabs or browser profiles can still act in parallel;
- stop instead of retry-looping when visible page/title/DOM signals indicate access denial, a 403/429 response page, or a security challenge; WebExtensions do not expose every real network response status;
- hand CAPTCHA, WebAuthn, hardware-key, and anti-bot challenges to the human;
- pause supported sensitive-submission patterns for a fresh one-use approval, without claiming complete duplicate-submission prevention;
- avoid fingerprint spoofing, proxy rotation, CAPTCHA solving, and stealth claims.

Users remain responsible for each site's rules and their account activity.

## Managed-tab cleanup

Tabs opened with `browser_new_tab` are tracked separately from tabs the user already had open. A browser profile can hold at most 10 of these managed tabs at once; the 11th open request fails until one is closed. Agents must close a managed tab as soon as it is no longer needed and call `browser_cleanup_tabs` at the end of every workflow, including after an error. Cleanup never closes a pre-existing user tab.

## Credentials and sign-in

BrowseWeave has two deliberately separate username/password paths:

- **Local handoff (recommended):** the agent identifies one visible HTTPS login form and asks for a five-minute handoff. The user enters the username/password in the trusted extension popup. Those values go directly from the popup to that bound form and never enter MCP, the daemon, model context, or audit log.
- **Remote fallback (off by default):** while physically at the browser, the user may grant one-use permission for the exact active HTTPS origin for 15 minutes, 1 hour, or at most 24 hours. If the user is later away, they can explicitly give the username/password to the AI. The model provider and MCP client can see those values because they are chat/tool arguments. BrowseWeave does not persist, log, echo, or return them, and the extension consumes the origin permission before attempting the fill.

Remote permission stores only its random ID, exact origin, and creation/expiry timestamps so it can remain visible and revocable. It never authorizes OTP, payment-card, CAPTCHA, recovery-code, WebAuthn, or hardware-key entry. Those steps remain manual. A site, browser, password manager, AI client, or model provider may apply its own retention rules outside BrowseWeave; review those separately before using remote fallback.

## Development and verification

```bash
npm ci --ignore-scripts
npm run build
npm test
npm run lint:extension
npm run lint:mozilla
npm run package:extension
npm run verify
```

Useful diagnostics:

```bash
npx browseweave@0.1.0-beta.2 doctor
npx browseweave@0.1.0-beta.2 mcp-config generic
```

The CI matrix builds and tests on Linux, macOS, and Windows. That proves portable code paths compile and pass automated checks; it does not turn macOS or Windows into live beta support. Browser-store signing, clean-machine installation, native GUI lifecycle, sleep/wake recovery, and exact release-browser/client smoke tests remain release gates.

## Security and privacy

- The extension does not request cookies, history, bookmarks, clipboard, or password-vault permissions.
- Password, one-time-code, and payment-card values are masked in page snapshots.
- Page content is explicitly treated as untrusted external data to limit prompt-injection risk.
- Typed values and page contents are not written to the audit log.
- No remote JavaScript or arbitrary page-provided code is executed by the extension.
- `.npmrc`, pairing tokens, signing keys, and store credentials must never be committed.

Read [SECURITY.md](SECURITY.md) and [PRIVACY.md](PRIVACY.md) before enabling the extension on sensitive sites.

## Support and license

Read [SUPPORT.md](SUPPORT.md) before opening an issue. BrowseWeave is released under the [MIT License](LICENSE); bundled third-party notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
