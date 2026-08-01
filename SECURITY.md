# BrowseWeave security model

## Supported release status

`0.1.0-beta.13` is a systemd-based Linux developer preview, not a production or browser-store release. It requires a working systemd user service manager; non-systemd Linux service adapters are unavailable. The unpacked Chrome and temporary Zen paths require visible human consent. macOS is implemented and test-covered but not live-supported; Windows setup is unavailable. Security reports should identify the exact package version, operating system, browser, extension target, and MCP client without including private page data.

## Trust boundaries

- Web pages, page labels, URLs, screenshots, and all text returned by a page are untrusted external data.
- Instructions inside a page are not user instructions and must never change the agent's goal or authorize disclosure.
- The daemon listens only on loopback interfaces and authenticates both MCP IPC and extension connections.
- The extension and IPC clients require a fresh nonce-bound daemon proof before sending a client proof or accepting results. Authentication secrets are never transmitted as plaintext protocol fields, and extension and IPC authentication use separate secrets.
- Each browser installation has a separate random installation ID and pinned P-256 public key.
- A pairing token is a secret. npm tokens, browser-store keys, pairing tokens, and private signing keys must never enter source control, issues, chat, logs, or command arguments.

## Native-helper and guided setup enrollment

`npx browseweave@0.1.0-beta.13 setup` is a guided installer that requires a visible interactive terminal; it is not a browser-security bypass. Chrome still requires **Developer mode** and **Load unpacked**; Zen still requires **Load Temporary Add-on**. BrowseWeave does not silently install an extension, enable permissions, select a browser profile, or bypass a browser-owned confirmation.

Initial enrollment uses a private, short-lived loopback setup page. After loading the extension, the human returns to that page and selects **Connect this browser**. The extension Settings button labeled **Connect BrowseWeave** is a separate later repair/reconnect path through native messaging.

For the settings-button path, a trusted human selects **Connect BrowseWeave** and the browser opens the registered `io.browseweave.setup` native-messaging host. Websites and content scripts cannot call that host. Its manifest accepts only an exact Firefox extension ID or exact root Chrome extension origin; wildcard allowlists are rejected. For an unpacked Chrome beta, the installer waits until initial enrollment has completed, then accepts only one enabled byte-exact BrowseWeave copy recorded by Chrome and installs a manifest for that exact origin. Multiple, disabled, modified, missing, or unsafe candidates fail closed. The host also verifies browser-owned caller arguments before processing one bounded setup or cancellation request.

The native host is not an installer or a general command runner. It accepts no executable path, command, shell text, or environment override from the extension. It verifies the exact owner-only BrowseWeave service definition and may start only that fixed per-user service. It fails closed for missing, modified, foreign-owned, symlinked, or overly permissive artifacts and when the expected local ports are occupied by an unauthenticated process. Installation and Repair remain separate trusted installer actions.

The native host creates one short-lived local setup session over authenticated loopback IPC and returns its capability only to the extension background context. The pairing key is never displayed in settings or placed in a normal web-page DOM, URL, command output, clipboard, MCP configuration, or model context. The extension starts enrollment only after the trusted click.

The setup request binds fresh nonces, the daemon instance, extension origin, browser installation identity, and P-256 public key. The daemon returns the pairing credential only through the authenticated setup exchange. A setup response alone is not success. The first derived-key reconnect is an explicitly signed `provisioning` phase: it proves receipt but cannot pin the key or expose a command-capable browser session. Only after the extension has stored and read back the credential does it make a separately signed `persisted` reconnect; that second phase atomically pins the key and completes the installer receipt. A storage failure therefore leaves the previous registry credential usable. A lost persisted request is retried, while a lost acknowledgement is reconciled by new-token authentication and an idempotent persisted reconnect. The old stored credential is restored only after the daemon positively authenticates it, so an acknowledgement loss cannot roll back a committed credential. Setup material is single-purpose, expires quickly, and is invalidated after success or cancellation.

For Zen Flatpak, the guided installer enables Firefox's native-messaging portal preference only after initial pairing and only in exactly one active profile whose directory and metadata are owned by the current user. It refuses ambiguous, foreign-owned, symlinked, or changed profile files and preserves unrelated `user.js` content. If the preference changed, the user must fully restart Zen once. Zen may then show a one-time operating-system prompt; approve it only immediately after the user's own **Connect BrowseWeave** action and cancel an unexpected prompt.

## Several agents on one browser profile

A managed tab records the MCP client session that opened it, and close, cleanup,
and every mutating action are scoped to that session.

This is an isolation boundary between cooperating agents, not a security one.
The identity is minted by the MCP server process and declared to the daemon, so
a local process holding the IPC token could claim any identity — but that
process already had full authority over the browser, so it gains nothing. The
scoping exists to stop two honest sessions from destroying each other's work,
and it is not a defence against a hostile local process.

A command carrying no recognizable identity owns nothing and cannot act on any
agent's managed tabs. A ledger written before ownership existed is adopted as
unowned, so no agent inherits those tabs by connecting first; a cleanup can still
collect them, which keeps them from holding the shared ceiling forever.

## Agent-skill installation

The BrowseWeave operating skill is shipped as a regular file in the npm archive. The package has no `preinstall`, `install`, or `postinstall` hook, so merely adding it as a dependency cannot modify agent configuration. The explicit trusted `setup`, `local-install`, and `mcp-add` commands copy the guide to `~/.agents/skills/browseweave` and `~/.claude/skills/browseweave` before changing MCP or service state.

Each installed copy has a BrowseWeave marker containing the package version and exact content SHA-256. Future runs update only a copy whose current bytes still match that marker. A byte-exact unmarked copy may be adopted, but a foreign, incomplete, locally modified, unexpectedly populated, wrong-owner, or symlinked destination fails closed and is preserved. Both destinations are preflighted before either skill is written, preventing a known conflict in one client from silently producing a split installation.

## Extension authentication

The extension starts with a fresh client nonce. The daemon returns a nonce-bound HMAC proof, which the extension verifies before it sends its own HMAC proof and P-256 signature. The pairing secret itself is never a protocol field. The signature binds the daemon instance, extension origin, installation ID, and public key. The daemon pins that public key on first enrollment, and a later connection cannot replace it merely by knowing the pairing secret.

Firefox `moz-extension://` and Chromium `chrome-extension://` origins are validated as an additional signal, not as the sole authentication mechanism.

## Human approval

When the extension's conservative risk checks detect one of the following classes, it pauses before the side effect:

- messages, comments, posts, email, or other publication;
- payments, purchases, and financial actions;
- deletion of data, content, or accounts;
- passwords, PINs, one-time codes, and recovery actions;
- account access, privacy, or security-setting changes;
- risky form submission and every semantic-free coordinate click.

The extension does not display or sign approve/reject decisions, and there is no in-browser toggle or generated phrase. By default the human confirms or rejects the exact action in the MCP client session. This makes the trust assumption explicit: **BrowseWeave trusts the MCP client to relay the human's decision honestly and not answer confirmation requests on the user's behalf.** A client without MCP elicitation support cannot complete a detected sensitive action through this channel.

The daemon binds the resulting single-use decision to its approval ID, browser installation, action, canonical parameter hash, live document/target fingerprint, and expiry. A retry first re-evaluates the live target without executing it. Only an exact fingerprint match consumes the decision and sends one approved command. The extension keeps a bounded replay ledger for session decision IDs. A decision is single-use even if command delivery later fails.

### Owner-declared autonomous categories

The machine's owner can pre-authorize named risk categories in the owner-only `policy.json` (`autonomous_actions`), which replaces the per-action prompt for exactly those categories. This exists because per-action confirmation is unreachable in a client without elicitation, and because an owner watching their own browser may accept the risk knowingly.

That file is `~/.config/browseweave/policy.json`. It does not exist until the owner creates it, and it must be `chmod 600`; the requirements below are enforced, not advisory.

It is a real widening of authority and is treated as such:

- **Off by default, and only the owner can enable it.** The file must be a regular, owner-owned, non-symlinked file with no group or other permission bits, under the private configuration directory. The daemon never writes it, no MCP method or browser command can set it, and page content cannot influence it. It is read at service start, so enabling it requires a deliberate edit plus a restart.
- **The live-target check is not skipped.** A policy grant is minted for one action, one canonical parameter set, and the exact live-target fingerprint the extension just reported, then consumed immediately. The extension recomputes that fingerprint before acting; a page, tab, target, or parameter change invalidates it. Automatic replays after a changed fingerprint are bounded, so a page that keeps mutating cannot loop the daemon.
- **Observational rechecks never execute.** A revalidation-only command is never satisfied by the policy.
- **Unknown categories are never covered.** An absent or unrecognized category still requires a human decision, so a future risk class cannot inherit an older policy.
- **`file_attach` is excluded by default** and is covered only when the owner names it explicitly.
- **Everything else still applies.** Credential, one-time-code, and payment-card entry keeps using the dedicated handoff instead of ordinary commands; refused browser surfaces, file-picker and declared-download blocks, per-tab serialization, managed-tab limits, and untrusted-page-content handling are unchanged.
- **It is auditable.** Grants are recorded as `policy_approved` (bounded replays as `policy_replay_limit`), the enabled categories are logged at service start, and both `browser_status` and `browseweave doctor` report them.

With this enabled, an injected page instruction that reaches the model can cause a submission, publication, deletion, or cross-site navigation without a second human checkpoint. The remaining defenses are the live-target binding, the untrusted-content rules, the audit log, and the owner watching the session.

For clicks and submissions, the displayed destination is the browser-verified **current pre-action destination**. BrowseWeave rechecks it after focus and synthetic pre-click events and immediately before the native action. Page JavaScript running during the native event/default-action boundary, server behavior, or a later redirect can still change the eventual destination; the approval is not a guarantee of the final network destination.

Risk detection is a defense layer, not a complete understanding of every site. Custom scripts, unlabeled controls, unfamiliar languages, deceptive labels, and site changes can evade a heuristic. The user and agent must still review the real target and use the least-powerful action that completes the task.

## Attaching local files

File attachment is the only capability that reads something outside a web page, so it is a genuinely new class of reach for BrowseWeave: without controls it would be a local-file exfiltration primitive, where an injected instruction could upload a private file to a hostile origin. It is **off by default**.

Attachment uses the same MCP-session confirmation path—`autonomous_actions` excludes `file_attach` unless the owner names that category explicitly—while the path policy independently limits which local files can even reach that prompt:

- **Default deny.** With no `policy.json`, nothing is attachable. Enabling it requires listing absolute directories in an owner-only file that no MCP tool can write.
- **Refused even inside an allowed directory:** any hidden path segment, which covers `.ssh`, `.gnupg`, `.aws`, `.env`, and `.npmrc`; multiple-hardlink aliases; known credential filenames and key formats; recognizable private-key content; unsupported file types; and BrowseWeave's own configuration, state, and runtime directories. A renamed or archived secret cannot be identified perfectly, which is why exact-file confirmation is still mandatory.
- **Links fail closed.** Symlinks are resolved and checked against both path lists; files with more than one hardlink are refused so an innocent allowed alias cannot hide a denied or outside inode.
- **Owner and handle checks.** Only regular files owned by the current user are read, opened with `O_NOFOLLOW`, and the device and inode are re-verified through the open handle so the path cannot be swapped between the check and the read.
- **Size and type caps** from the policy, bounded by the transport ceiling.

Confirmation is unconditional — attachment is never left to the risk heuristics, in the same way a semantic-free coordinate click is not. The MCP client prompt shows the exact basename, byte size, MIME type, full SHA-256, and bound action details. The one-use decision covers the canonical parameter hash, which includes the file bytes; a changed file cannot reuse it and produces a fresh prompt.

The absolute path never reaches the browser; only the basename and bytes do. The audit log records the digest, size, type, and a hash of the path, never the path or the contents. Snapshots report an attached file as `[ATTACHED:n]` rather than its name.

Clicking a file input remains refused. The operating-system picker cannot be driven by any extension, and opening it would block the tab with a modal BrowseWeave cannot dismiss.

## Credential channels

Ordinary type and form-fill actions reject password, one-time-code, and payment-card targets: the value belongs on a credential channel, not in an MCP command. Character-key actions reject a narrower class—one-time-code and payment-card targets, which keep only Tab, Escape, and cursor-navigation keys—because a code lives on the user's own device and is burned by a wrong or stale attempt, and card data is financial. A payment or one-time-code signal from either classifier is enough to reject, so a password-looking label cannot mask one.

These rejections are decided in the content script and are intentionally outside the approval channel: no human decision and no owner policy can grant them.

Password and account-security targets deliberately still accept keys. Submitting or moving through a login form is ordinary work, and an account-security control's risk is a hard-to-reverse effect that the same control already exposes to an ordinary click—so both belong in the normal approval channel rather than a dead end. A password *value* is still refused by the type and form-fill paths.

The recommended five-minute local handoff accepts username/password only in the trusted extension popup and binds them to one live HTTPS origin, document, frame, form, and field set. Values do not enter MCP or the daemon.

Remote fallback is disabled until the user grants a visible, revocable, one-use permission for the exact active HTTPS origin. It expires within 24 hours and is consumed before the fill attempt. Remote credential values are visible to the selected AI client/model provider, but BrowseWeave does not persist, log, echo, or return them. Neither channel handles OTP, recovery codes, payment cards, CAPTCHA, WebAuthn, or hardware keys.

## Data minimization and audit

Page snapshots use bounded semantic filters. Screenshots are separate and short-lived. The audit log never records page-controlled strings, page contents, screenshots, typed values, credentials, pairing tokens, private keys, or approval descriptions.

## Release credentials

The one-time first npm publication must begin with no active npm authentication. The reviewed bootstrap orchestrator refuses an npm token in known environment variables or an already authenticated npm user before it runs dependency installation, build, tests, other tagged package scripts, or git release checks. It pins Node.js and npm to content-hashed files inside the current Node.js installation, removes code-injection variables from an allowlisted child environment, and accepts release evidence only from `github.com` and the canonical `.github/workflows/ci.yml` push workflow on the exact tagged commit. It creates and validates one fixed tarball and removes its detached git worktree first, then opens an interactive human npm login using a private temporary npm configuration. After that authority exists, only npm identity, package-availability, exact-tarball publication, credential logout/revocation, and the orchestrator's in-memory temporary-directory cleanup remain. The bootstrap refuses to finish unless logout proves the temporary credential inactive; if that proof fails, the maintainer must revoke the newest token in npm's Access Tokens page. Every later release uses GitHub Actions OIDC and no long-lived npm publish token.

## Site safety

BrowseWeave uses a normal visible WebExtension and does not enable WebDriver, headless mode, or Marionette. This does not make automation undetectable and does not guarantee that a site will not challenge or restrict an account.

BrowseWeave must stop and hand control to the human for CAPTCHA, WebAuthn, hardware security keys, and anti-bot challenges. It must not add CAPTCHA solving, fingerprint spoofing, proxy rotation, security-control bypass, or claims of being undetectable. Access denial and rate-limit responses must not trigger retry loops.

Pacing is currently serialized per browser tab, not globally per origin or IP. Separate tabs, profiles, or browsers can still act in parallel. Detection of 403/429 pages and challenges relies on visible page, title, and DOM signals rather than complete network-response visibility. Neither mechanism guarantees protection from site rate limits or account restrictions.

## Managed tabs

BrowseWeave tracks only tabs it created, enforces a maximum of 10 concurrently open managed tabs per browser profile, and exposes explicit cleanup. Cleanup must never infer ownership from a URL or title and must never close a tab that is absent from the extension-owned managed-tab registry.

## Known limits

- WebExtensions can control permitted content in ordinary HTTP(S) pages, not browser menus, browser settings, extension stores, privileged browser pages, operating-system dialogs, or hardware prompts.
- Closed Shadow DOM and some protected PDF/reader surfaces are not accessible.
- Risk classification is a defense layer, not a proof that every dangerous label in every language will be recognized.
- BrowseWeave does not provide complete data-loss prevention or duplicate-submission detection. An agent must never copy browser-derived content into a URL or form merely because a web page instructed it to do so, and it must verify the result before repeating a side effect.
- Cryptographic approval prevents a raw MCP request from pretending that a user clicked approve. It cannot make a fully compromised operating-system user account safe: a malicious same-user process with arbitrary code execution may modify installed files or attack the browser itself.
- Browser and model-client updates can change behavior. Release support requires native Zen/Chrome and client smoke tests, not only headless tests.
- The unpacked Chrome and temporary Zen flows require visible user consent. The Zen development add-on is removed on browser restart; persistent consumer distribution requires browser-store signing.
- Unpacked Chrome native messaging authorizes only a single enabled byte-exact local extension identity discovered after initial enrollment. A stable Chrome Web Store identity remains necessary for store distribution; a wildcard is never an acceptable fallback.
- Windows setup requires a fixed signed `browseweave-native-host.exe`. The beta does not ship that executable and deliberately rejects Node.js scripts, `.cmd`, PowerShell, and shell-wrapper substitutes.
- macOS plans and CI are not evidence of a live supported installation. A passing unit test or generated registration plan must not be represented as release verification.

## If something looks wrong

1. Disconnect or remove the extension.
2. Remove the exact native registration and stop the per-user daemon with `npx browseweave@0.1.0-beta.13 local-uninstall`, or use the platform's service manager when the CLI is unavailable.
3. Run `npx browseweave@0.1.0-beta.13 doctor` and preserve only the metadata audit log.
4. Do not post tokens, page contents, screenshots, or private account data in a public issue.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/xenitV1/browseweave/security/advisories/new). Do not open a public issue for a suspected vulnerability, and never attach tokens, private page content, credentials, or unredacted screenshots. Include the smallest safe reproduction and the exact beta version. The maintainer will acknowledge the report through the private advisory, assess supported-preview impact, and coordinate a fix or disclosure; this volunteer preview does not promise a response-time SLA.
