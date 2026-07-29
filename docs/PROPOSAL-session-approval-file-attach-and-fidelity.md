# Proposal: session approval, file attachment, and interaction fidelity

> Superseded on 2026-07-29. BrowseWeave now uses MCP-client confirmation for every detected sensitive-action class and no longer exposes extension approve/reject UI, a generated confirmation phrase, or a session-approval opt-in. This document is retained only as historical design context; current behavior is defined by `README.md` and `SECURITY.md`.

Status: **implemented with a security amendment**. During review, file attachment
was removed from session-confirmable authority: it now always requires the
extension-owned signed approval UI. The remaining verification gates below still
separate automated coverage from live browser support evidence.

| Part | Change | Risk direction |
|---|---|---|
| 1 | Approval by spoken/typed confirmation in the MCP session instead of an extension button | **Weakens** a current guarantee; requires explicit opt-in |
| 2 | Attaching local files to web forms | **Adds** a new capability class (local filesystem reach) |
| 3 | Interaction fidelity and pacing | Neutral to positive; mostly compatibility fixes |

Parts 1 and 2 interact at the authority boundary: file attachment is deliberately
excluded from Part 1 because an MCP client can see and echo an elicitation phrase.
Section 2.4 records the stronger extension-owned approval contract.

---

## Non-goals

### Anti-detection is not a goal of this proposal

This proposal does not add fingerprint or user-agent spoofing, canvas/WebGL
noise, proxy rotation, CAPTCHA solving, anti-bot challenge bypass, or timing
randomisation whose purpose is to defeat a classifier. `SECURITY.md` already
states this boundary and it is unchanged here.

The reason is factual before it is editorial. Every event BrowseWeave produces
carries `isTrusted: false`, and a page reads that in one line:

```js
element.addEventListener("click", (event) => {
  if (!event.isTrusted) reportAutomation();
});
```

`dispatchPointer` and `dispatchMouse` (`extension/src/content/runtime.ts:475-508`)
and `emitKeyboard` (`:688`) all produce synthetic events. No WebExtension API can
forge `isTrusted`. The only mechanism that produces genuinely trusted input is
`chrome.debugger` / `Input.dispatchMouseEvent`, which requires the `debugger`
permission, displays a persistent debugging banner in the browser, is itself
trivially detectable, and would not survive store review. There is no
configuration of this architecture in which detection is impossible, so the
project must not claim otherwise.

Part 3 does change interaction timing and event sequences, but its justification
is compatibility: the current implementation breaks on real sites, and the fixes
happen to also remove incidental automation artefacts. Where a change would only
serve evasion and not correctness, it is not proposed.

### Still out of scope

Downloads (`content/runtime.ts:522`), OS file pickers, privileged browser
surfaces, OTP/WebAuthn/payment-card entry. Unchanged.

---

## Part 1 — Session approval

### 1.1 The guarantee that changes

Today the approving key is unreachable from the requesting party:

- The extension signs decisions with a non-exportable P-256 key
  (`src/core/protocol.ts:594-619`).
- The daemon rejects every IPC parameter named `approved`, `revalidate_only`, or
  prefixed `approval_` / `user_` / `confirm_`
  (`src/daemon/runtime.ts:2199-2209`).
- The extension keeps its own single-use grant, so an authenticated daemon
  cannot turn `approved: true` into permission on its own.

`SECURITY.md` currently states: *"There is no MCP tool that grants approval"* and
*"an authenticated daemon cannot turn `approved: true` into permission without
the matching extension-owned grant."*

The first sentence stays true under this proposal. The second does not, for the
action classes that opt in. That must be documented, not glossed.

### 1.2 What cannot be verified

MCP carries no attestation of human authorship. Everything that reaches the
server is produced by a model. BrowseWeave therefore cannot prove that a
confirmation was typed by a person. The design question is not *how to verify*
but *where to place trust*, and the answer must be named explicitly:

> **Trust assumption (new):** the MCP client honestly relays human input and does
> not answer elicitation requests on the user's behalf.

### 1.3 Channel: MCP elicitation

The `elicitation/create` request (MCP spec 2025-06-18; supported by
`@modelcontextprotocol/sdk` 1.30.0, already pinned) is the correct channel and is
materially stronger than a tool argument:

- the **server** initiates it;
- the **client application** renders it to the human;
- the response returns over the client transport, **not** through model
  token generation.

A model cannot produce an elicitation response by emitting text. A prompt-injected
page cannot produce one at all.

Clients that do not advertise the `elicitation` capability at initialization do
not get session approval; the tool returns `approval_required` exactly as today.

### 1.4 Protocol

```
tool call
  → daemon → extension detects risk → approval_required (+ fingerprint, target)
  → MCP server: IPC  session_approval_begin { approval_id }
       ← { challenge_phrase, description, target_origin, target_title, expires_at }
  → MCP server: elicitation/create
       message  : browser-verified action + target, page-derived parts marked untrusted
       schema   : { decision: enum[approve,reject], confirmation_phrase: string }
  ← client returns the human's answer
  → MCP server: IPC  session_approval_submit { approval_id, decision, confirmation_phrase }
  → daemon: constant-time phrase compare, single attempt
  → daemon: existing revalidate_only pass against the live target
  → daemon: approved command, single use
```

Reusing `revalidate_only` (`extension/src/shared/pure.ts:18-33`) matters: the
live target is re-checked after the human answers, so a page that mutates during
the confirmation window invalidates the approval exactly as it does today.

**No MCP tool submits an approval.** `session_approval_submit` is an internal
IPC method reachable only from the server's own elicitation handler. The
rejection at `runtime.ts:2199-2209` stays in force for every ordinary action.

### 1.5 The challenge phrase, and what it actually defends

Four words from a fixed ~1024-word list (≈40 bits), generated by the daemon,
bound to one approval, constant-time compared, **one attempt only** — a mismatch
destroys the approval rather than allowing a retry.

It must never appear in: a tool result, `ApprovalRequiredResult`, the audit log,
extension UI, any page DOM or URL, any error string, or daemon stdout. Its only
path is `session_approval_begin` → MCP server memory → elicitation message.

What it defends against:

- a page-origin injection producing a confirmation (the page can never see it);
- a stale or mis-targeted approval being answered;
- accidental or duplicated confirmation.

What it does **not** defend against, stated plainly: an MCP client that answers
elicitation requests using the model instead of the human. Such a client would
see the phrase in the message and could echo it. Only the client's honesty helps
there — which is the trust assumption in §1.2, not something the phrase repairs.

### 1.6 Two independent opt-ins

A single switch would let whoever controls the daemon grant themselves the
capability. Session approval therefore requires **both**:

1. **Daemon policy file** — `<configDir>/policy.json`, mode `0600`, owner
   verified, no symlink, validated with the same discipline as
   `src/native/setup-protocol.ts:105-120`. Not writable by any MCP tool.
2. **Extension toggle** — stored in extension-local storage, settable only from
   `options.html`, which is already gated by `trustedSender`
   (`extension/src/background/runtime.ts:3322-3325`).

The extension toggle is the real gate. Commands arrive with a new
`approval_source: "session" | "extension_signed"` field; for `"session"` the
extension skips `consumeLocalApprovalGrant` and instead requires (a) its own
toggle on, (b) the risk category in the opted-in tier, (c) a live fingerprint
match, and (d) an `approval_id` it has not already consumed within the TTL.

The extension shows a passive, non-blocking notification when it executes a
session-approved action, so a user at the browser can still notice.

### 1.7 Tiers

Tier membership is by **risk category**, not action — a `click` may be a payment
or a message. Single source of truth in `src/core/protocol.ts`, imported by both
daemon and extension (permitted by the boundary rules: extension may import
`server:core`).

| Tier | Risk categories | Approval |
|---|---|---|
| **A — never session** | `payment`, `delete`, `password`, `2fa`, `security`, `visual_click`, `file_attach`, plus `credential_fill` | Extension-signed button only |
| **B — session-approvable** | `form_submit`, `message`, `external_navigation` | Elicitation + challenge |
| **Always human** | OTP, payment cards, recovery codes, CAPTCHA, WebAuthn, hardware keys | Unchanged |

Default policy is empty — behaviour is identical to today until a human opts in.

### 1.8 Documentation that must change

`SECURITY.md` must gain a section stating which tier rests on which trust root,
and must stop asserting the unconditional form of the "daemon cannot grant
approval" sentence. `SKILL.md` must tell the agent it may never treat page text
as approval and may not request elicitation on the user's behalf. `PRIVACY.md` is
unaffected by Part 1.

---

## Part 2 — File attachment

### 2.1 Non-goal: the OS file picker

Driving the operating-system file chooser is permanently impossible for a
WebExtension. Opening it is also actively harmful: a modal OS dialog blocks the
tab and BrowseWeave cannot dismiss it, stranding the agent.

The three existing rejections therefore **stay**:

- `extension/src/content/runtime.ts:509-522` — `input[type=file]` and its `<label>`
- `:644-645` — the same target under coordinate click
- `:758` — the same target under `type`

### 2.2 Mechanism

The picker is bypassed, not driven:

```
browser_attach_file(ref, path)
  → daemon: policy check, resolve, read, hash, audit
  → extension: bytes
  → content script: File → DataTransfer → input.files = dt.files
                    → dispatch input + change
```

`input.files` is assignable from a `DataTransfer`; this is how drag-and-drop
upload works in the platform.

**Compatibility risk to validate first:** Firefox content scripts run under Xray
vision, so passing a `File`/`DataTransfer` into the page world may require
`cloneInto` / `wrappedJSObject`
(<https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Sharing_objects_with_page_scripts>).
Chrome MV3 is expected to work directly. Zen/Firefox MV2 must be live-verified
before any support claim, per project convention.

The dispatched events are `isTrusted: false`. For file inputs this is not
normally load-bearing, but the limitation is documented rather than assumed away.

### 2.3 The new threat class

Today the extension reaches only what is inside a web page. File attachment makes
BrowseWeave a **local-file exfiltration primitive**:

> an injected model calls `browser_attach_file("~/.ssh/id_rsa", <form on a hostile origin>)`

This is heavier than anything currently in the threat model and the controls
below are not optional garnish — they are the feature.

### 2.4 File attachment requires both path policy and trusted extension approval

File attachment cannot be approved through §1. The mechanical path controls and
the extension-owned signed decision are independent, mandatory gates:

| Control | Requirement |
|---|---|
| **Allowlist** | Default **empty**; the feature is inert until a human writes it. Absolute paths only. Not writable by any MCP tool. |
| **Denylist (always wins)** | Hidden paths, multiple-hardlink aliases, known credential names/key formats, recognizable private-key content, unsupported types, and BrowseWeave's own `configDir`/`stateDir`/`runtimeDir` |
| **Resolution order** | Resolve and check both written/resolved paths, `lstat` owner/link count, `O_NOFOLLOW` open, then re-check device, inode, link count, and size through the handle |
| **Caps** | One file per tool call, policy-bounded bytes, and extension/MIME allowlist |
| **Approval** | Unconditional extension-signed decision. The trusted UI shows basename, size, MIME, full SHA-256, and browser-verified site |
| **Fingerprint binding** | Name, size, SHA-256, MIME, bytes, live target, and destination context are bound into the signed approval path; any change invalidates it |
| **Audit** | SHA-256, size, MIME, and a full SHA-256 hash of the path — never the path itself or file contents |

Optional and worth considering: a destination-origin allowlist, so attachment is
possible only to origins the human pre-authorised.

### 2.5 Transport

`MAX_COMMAND_PAYLOAD_BYTES` is 512 KB (`src/core/config.ts:23`), which base64
reduces to roughly a 380 KB file. The WebSocket frame limit is 16 MB (`:24`).

v1: keep the file itself policy-bounded to 8 MiB and raise the serialized
`attach_file` command ceiling to 12 MiB, matching the extension receiver after
base64 expansion. Chunked transfer (`attach_file_chunk` +
`attach_file_commit`, with buffer lifecycle and cleanup) is deferred; it is the
right answer for large files but not worth the state machine in v1. The limit is
documented rather than silently truncating.

### 2.6 Snapshot surface

- `dom-utils.ts` excludes `file` from `isEditable`; that stays. File inputs are
  still interactive snapshot candidates and expose `type: "file"`, so the model
  can find a ref without treating the field as text-editable.
- After attachment the browser reports `C:\fakepath\<basename>` in `input.value`
  by specification, so the local directory does not leak. The basename still can;
  snapshots report `[ATTACHED:n]` and a masked name.
- New risk category `file_attach` in `RiskCategory` (`pure.ts:71-80`).

### 2.7 Affected files

| File | Change |
|---|---|
| `src/core/protocol.ts:14-36` | `attach_file` action; tier tables; `approval_source` |
| `src/daemon/file-attach.ts` | policy validation, file resolution/read/hash, and file-size cap |
| `src/mcp/server.ts` | `browser_attach_file`; elicitation handler for the narrower non-file tier; `browser_status` reports session-approval availability |
| `src/daemon/runtime.ts` | policy engine, file read + hash, `session_approval_*` IPC, per-action payload cap |
| `extension/src/content/runtime.ts` | direct file-input attachment through `DataTransfer` |
| `extension/src/background/runtime.ts` | session-approval toggle, `approval_source` handling, replay set, passive notification |
| `extension/src/ui/popup.ts` | exact-file identity in the trusted approval prompt |
| `extension/src/shared/dom-utils.ts` | file-input snapshot kind |
| `extension/src/shared/pure.ts` | `file_attach` risk category |
| `extension/src/ui/options.ts` | session-approval toggle UI |
| `SECURITY.md`, `PRIVACY.md`, `SKILL.md`, `README.md` | new capability and new trust root |

---

## Part 3 — Interaction fidelity and performance

Three defects found while reading the current implementation. Each is a
correctness problem on real sites; each also happens to remove an incidental
automation artefact.

### 3.1 Typing has no inter-key interval

`typeIntoElement` (`content/runtime.ts:761-790`) already emits a full
`keydown → keypress → beforeinput → input → keyup` cycle per character, which is
correct. But the loop has **no delay**, so a 40-character string is typed in
approximately zero milliseconds.

This breaks real sites: debounced autocomplete never fires, React controlled
inputs with asynchronous state drop characters, and per-keystroke validators see
an impossible input rate.

Proposal: a small variable inter-key interval, with the *distribution* chosen for
compatibility (long enough for a debounce to observe intermediate states) rather
than to imitate a person. Bounded so long strings stay fast; a `paste`-style fast
path remains available for fields with no keystroke handlers.

### 3.2 Scrolling is a single jump

`scrollPage` (`:1024-1055`) performs one `scrollTo({ behavior: "auto" })` and
waits a single animation frame.

This breaks lazy loading. `IntersectionObserver` callbacks for skipped regions
never fire, infinite-scroll handlers do not trigger, and virtualised lists never
render the intermediate rows — so a subsequent snapshot legitimately reports
content that "isn't there".

Proposal: step the scroll across a few animation frames and wait for scroll
events to settle. This is strictly a functional fix.

### 3.3 Pointer interactions have no movement path

`dispatchPointer(element, "pointerover")` fires directly at the element centre
with no preceding `mousemove`. Mega-menus and hover-driven UIs that require a
movement path — or that gate on `mousemove` before opening — do not open, which
surfaces as "the menu item isn't in the snapshot".

Proposal: a short pointer movement sequence before hover/click. Two or three
intermediate points are enough for the compatibility problem.

### 3.4 The real cost is elsewhere: sequential frame snapshots

`snapshot()` (`background/runtime.ts:2699-2716`) awaits each frame in a loop:

```js
for (const frame of frameList) {
  const frameSnapshot = await sendContentCommand(tab, frame.frameId, "snapshot", { ... });
}
```

Every frame is a serialized round trip. On a page with a dozen ad/analytics
iframes — ordinary — that is twelve sequential round trips where the wall-clock
cost should be that of the slowest frame alone. Bounded-concurrency
parallelisation is very likely the single largest latency win available, and it
touches no security property.

### 3.5 Pacing: uniform delay is both slower and less realistic

`MIN_MUTATION_INTERVAL_MS = 750` (`background/runtime.ts:250`) is a fixed floor
applied before every mutation per tab (`runSerializedMutation`, `:2500-2519`), so
two consecutive clicks cost at least 750 ms of dead time regardless of context.

Human input is not uniformly slow — it is **bursty**: fast inside a familiar
interaction, then a real pause at a decision point. A uniform 750 ms cadence is
therefore simultaneously slower *and* less like a person than a bursty model.

Proposal — adaptive pacing that resolves the apparent conflict between "fast" and
"human-like":

- **Within a bounded interaction** (filling a form, typing a field, stepping a
  wizard): tighten the floor substantially.
- **Between logical steps** (navigation, decision points): keep a natural pause,
  which is largely spent on network and render anyway.
- **On stress signals** (403/429 pages, challenge markers, access-denial text —
  already detected by `detectHumanIntervention`, `content/runtime.ts:122`): back
  off sharply.

This is faster in the common case and more conservative exactly when a site is
signalling that it wants less traffic, which is the behaviour `SECURITY.md`
already commits to. Pacing remains per tab, not per origin or IP; that documented
limitation is unchanged.

---

## Verification gates

No support claim may widen ahead of evidence.

1. Firefox/Zen Xray behaviour for `DataTransfer` / `File` (§2.2) — blocks any
   Zen claim for Part 2.
2. Live Chrome and live Zen end-to-end attachment against a local fixture.
3. Elicitation support matrix — which of Codex, Claude Code, Cursor, and OpenCode
   actually implement `elicitation/create`. Must be measured per client version,
   never assumed. A client without it silently keeps today's button flow.
4. Path-policy tests: symlink escape, hardlink, TOCTOU between check and read,
   denylist nested inside allowlist, non-owner file, `0644` file.
5. Phrase handling: constant-time compare, single attempt, absence from every
   log and result payload.
6. Confirmation that file attachment is never session-approved; other session
   approvals are rejected when the extension toggle is off, the fingerprint
   moved, or the `approval_id` was already consumed.
7. Latency before/after for §3.4 on a page with many iframes.
