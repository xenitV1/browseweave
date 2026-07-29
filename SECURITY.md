# BrowseWeave security model

## Supported release status

`0.1.0-beta.3` is a systemd-based Linux developer preview, not a production or browser-store release. It requires a working systemd user service manager; non-systemd Linux service adapters are unavailable. The unpacked Chrome and temporary Zen paths require visible human consent. macOS is implemented and test-covered but not live-supported; Windows setup is unavailable. Security reports should identify the exact package version, operating system, browser, extension target, and MCP client without including private page data.

## Trust boundaries

- Web pages, page labels, URLs, screenshots, and all text returned by a page are untrusted external data.
- Instructions inside a page are not user instructions and must never change the agent's goal or authorize disclosure.
- The daemon listens only on loopback interfaces and authenticates both MCP IPC and extension connections.
- The extension and IPC clients require a fresh nonce-bound daemon proof before sending a client proof or accepting results. Authentication secrets are never transmitted as plaintext protocol fields, and extension and IPC authentication use separate secrets.
- Each browser installation has a separate random installation ID and pinned P-256 public key.
- A pairing token is a secret. npm tokens, browser-store keys, pairing tokens, and private signing keys must never enter source control, issues, chat, logs, or command arguments.

## Native-helper and guided setup enrollment

`npx browseweave@0.1.0-beta.3 setup` is a guided installer that requires a visible interactive terminal; it is not a browser-security bypass. Chrome still requires **Developer mode** and **Load unpacked**; Zen still requires **Load Temporary Add-on**. BrowseWeave does not silently install an extension, enable permissions, select a browser profile, or bypass a browser-owned confirmation.

Initial enrollment uses a private, short-lived loopback setup page. After loading the extension, the human returns to that page and selects **Connect this browser**. The extension Settings button labeled **Connect BrowseWeave** is a separate later repair/reconnect path through native messaging.

For the settings-button path, a trusted human selects **Connect BrowseWeave** and the browser opens the registered `io.browseweave.setup` native-messaging host. Websites and content scripts cannot call that host. Its manifest accepts only an exact Firefox extension ID or exact root Chrome extension origin; wildcard allowlists are rejected. For an unpacked Chrome beta, the installer waits until initial enrollment has completed, then accepts only one enabled byte-exact BrowseWeave copy recorded by Chrome and installs a manifest for that exact origin. Multiple, disabled, modified, missing, or unsafe candidates fail closed. The host also verifies browser-owned caller arguments before processing one bounded setup or cancellation request.

The native host is not an installer or a general command runner. It accepts no executable path, command, shell text, or environment override from the extension. It verifies the exact owner-only BrowseWeave service definition and may start only that fixed per-user service. It fails closed for missing, modified, foreign-owned, symlinked, or overly permissive artifacts and when the expected local ports are occupied by an unauthenticated process. Installation and Repair remain separate trusted installer actions.

The native host creates one short-lived local setup session over authenticated loopback IPC and returns its capability only to the extension background context. The pairing key is never displayed in settings or placed in a normal web-page DOM, URL, command output, clipboard, MCP configuration, or model context. The extension starts enrollment only after the trusted click.

The setup request binds fresh nonces, the daemon instance, extension origin, browser installation identity, and P-256 public key. The daemon returns the pairing credential only through the authenticated setup exchange. A setup response alone is not success. The first derived-key reconnect is an explicitly signed `provisioning` phase: it proves receipt but cannot pin the key or expose a command-capable browser session. Only after the extension has stored and read back the credential does it make a separately signed `persisted` reconnect; that second phase atomically pins the key and completes the installer receipt. A storage failure therefore leaves the previous registry credential usable. A lost persisted request is retried, while a lost acknowledgement is reconciled by new-token authentication and an idempotent persisted reconnect. The old stored credential is restored only after the daemon positively authenticates it, so an acknowledgement loss cannot roll back a committed credential. Setup material is single-purpose, expires quickly, and is invalidated after success or cancellation.

For Zen Flatpak, the guided installer enables Firefox's native-messaging portal preference only after initial pairing and only in exactly one active profile whose directory and metadata are owned by the current user. It refuses ambiguous, foreign-owned, symlinked, or changed profile files and preserves unrelated `user.js` content. If the preference changed, the user must fully restart Zen once. Zen may then show a one-time operating-system prompt; approve it only immediately after the user's own **Connect BrowseWeave** action and cancel an unexpected prompt.

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

There is no MCP tool that grants approval. By default the target extension shows a trusted extension page and signs an approve/reject decision with its non-exportable private key. It also retains its own bounded one-use grant; for that default path an authenticated daemon cannot turn `approved: true` into permission without the matching extension-owned grant.

### Session-confirmed approval, and what it changes

The browser owner may allow a narrower second path in which a human confirms in the MCP client session instead of the extension popup. It is **off by default** and requires two independent opt-ins in two different trust domains: an owner-only `policy.json` in the BrowseWeave configuration directory, and a toggle in extension-owned Settings. Either one being off disables it. The daemon reads the policy once at startup, and no MCP tool can write either switch.

State the cost plainly: for the risk classes that opt in, the sentence above about the extension-owned grant no longer holds. The trust root moves from the extension's private key to a new assumption — **that the MCP client relays human input honestly and does not answer elicitation requests on the user's behalf.**

The path is limited by four independent checks:

- **Tier.** Only `form_submit`, `message`, and `external_navigation` are ever eligible. Payment, deletion, passwords, one-time codes, account security, coordinate clicks, and both credential channels always require the extension-signed decision. The owner's policy may narrow this list but never widen it.
- **Live risk, not a claim.** The content script re-derives the risk class at execution time and refuses a session-sourced command whose live class is not session-approvable, so a compromised daemon cannot mislabel a payment as a form submission. The approval fingerprint already covers the assessed risk, so the same lie also breaks fingerprint matching.
- **Confirmation phrase.** The daemon generates a four-word phrase bound to one approval and delivers it only over authenticated loopback IPC into the elicitation message. It never appears in a tool result, the audit log, extension UI, a page DOM or URL, or daemon output, so a page cannot learn it. Comparison is constant-time after whitespace and case normalisation. **One attempt only:** a wrong phrase discards the approval rather than allowing another guess.
- **Extension-side replay ledger.** A session approval ID executes at most once, and the ledger is cleared when the owner turns the toggle off.

The retry still re-enters the normal path, so the live target is revalidated before anything runs.

What the phrase does **not** defend against, stated explicitly: an MCP client that answers elicitation requests with the model instead of the human would see the phrase in the message and could echo it. Nothing in BrowseWeave detects that; it is exactly the trust assumption named above. Users who are not willing to make that assumption should leave the feature off, which is the default.

The signed decision is bound to a daemon instance, approval ID, random nonce, browser installation, action, canonical parameter hash, live document/target fingerprint, and expiry. A retry first re-evaluates the live target without executing it. Only an exact fingerprint match consumes the grant and sends one approved command. A grant is single-use even if command delivery later fails.

For clicks and submissions, the displayed destination is the browser-verified **current pre-action destination**. BrowseWeave rechecks it after focus and synthetic pre-click events and immediately before the native action. Page JavaScript running during the native event/default-action boundary, server behavior, or a later redirect can still change the eventual destination; the approval is not a guarantee of the final network destination.

Risk detection is a defense layer, not a complete understanding of every site. Custom scripts, unlabeled controls, unfamiliar languages, deceptive labels, and site changes can evade a heuristic. The user and agent must still review the real target and use the least-powerful action that completes the task.

## Attaching local files

File attachment is the only capability that reads something outside a web page, so it is a genuinely new class of reach for BrowseWeave: without controls it would be a local-file exfiltration primitive, where an injected instruction could upload a private file to a hostile origin. It is **off by default**.

Attachment is never session-approvable. It requires the extension-owned, signed approval UI, and the path policy independently limits which local files can even reach that prompt:

- **Default deny.** With no `policy.json`, nothing is attachable. Enabling it requires listing absolute directories in an owner-only file that no MCP tool can write.
- **Refused even inside an allowed directory:** any hidden path segment, which covers `.ssh`, `.gnupg`, `.aws`, `.env`, and `.npmrc`; multiple-hardlink aliases; known credential filenames and key formats; recognizable private-key content; unsupported file types; and BrowseWeave's own configuration, state, and runtime directories. A renamed or archived secret cannot be identified perfectly, which is why exact-file approval is still mandatory.
- **Links fail closed.** Symlinks are resolved and checked against both path lists; files with more than one hardlink are refused so an innocent allowed alias cannot hide a denied or outside inode.
- **Owner and handle checks.** Only regular files owned by the current user are read, opened with `O_NOFOLLOW`, and the device and inode are re-verified through the open handle so the path cannot be swapped between the check and the read.
- **Size and type caps** from the policy, bounded by the transport ceiling.

Approval is unconditional — attachment is never left to the risk heuristics, in the same way a semantic-free coordinate click is not. The extension popup shows the exact basename, byte size, MIME type, full SHA-256, and browser-verified site. Its signed one-use decision covers the canonical parameter hash, which includes the file bytes; a changed file cannot reuse the approval and produces a fresh prompt.

The absolute path never reaches the browser; only the basename and bytes do. The audit log records the digest, size, type, and a hash of the path, never the path or the contents. Snapshots report an attached file as `[ATTACHED:n]` rather than its name.

Clicking a file input remains refused. The operating-system picker cannot be driven by any extension, and opening it would block the tab with a modal BrowseWeave cannot dismiss.

## Credential channels

Ordinary type, form-fill, and character-key actions reject password, one-time-code, and payment-card targets. The recommended five-minute local handoff accepts username/password only in the trusted extension popup and binds them to one live HTTPS origin, document, frame, form, and field set. Values do not enter MCP or the daemon.

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
2. Remove the exact native registration and stop the per-user daemon with `npx browseweave@0.1.0-beta.3 local-uninstall`, or use the platform's service manager when the CLI is unavailable.
3. Run `npx browseweave@0.1.0-beta.3 doctor` and preserve only the metadata audit log.
4. Do not post tokens, page contents, screenshots, or private account data in a public issue.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/xenitV1/browseweave/security/advisories/new). Do not open a public issue for a suspected vulnerability, and never attach tokens, private page content, credentials, or unredacted screenshots. Include the smallest safe reproduction and the exact beta version. The maintainer will acknowledge the report through the private advisory, assess supported-preview impact, and coordinate a fix or disclosure; this volunteer preview does not promise a response-time SLA.
