# vanish — Zero-Knowledge Footprint Monitoring: Design Blueprint

**Status:** Draft for review. Security model is the primary design driver.
**Audience:** Solo developer evolving the `vanish` CLI into a multi-user, paid product.
**Date:** 2026-06-16

> **Read this first.** This document is an engineering design, not a security
> certification and not legal advice. Two gates in it are real: (1) the threat
> model and crypto envelope must be reviewed by a cryptography-literate engineer
> before any PII-handling code is written, and (2) the compliance section must be
> taken to a lawyer before launch. Where the honest answer is "get a review," it
> says so.

---

## 0. What we're building, in one paragraph

`vanish` today is a single-user CLI: a curated data-broker registry, a link
`verify` checker, CCPA/GDPR/generic removal-letter generation, and an
**identifier-free** local SQLite tracker (it records *that* you filed an opt-out,
never *who you are*). The evolution is a paid, multi-user web/desktop product
that lets an individual **monitor and shrink their own digital footprint**:
breach exposure (Have I Been Pwned), data-broker presence, and removal-request
progress over time — with a dashboard. The hard constraint that shapes every
decision below: **the server must never be able to read any user's PII.** What
lives server-side is ciphertext plus a login verifier. A server breach or a
subpoena yields nothing readable.

The CLI's existing instinct — *store the fact, never the identifier* — is the
seed of the whole security model. We are extending that principle from "the local
DB holds no PII" to "the *server* holds no readable PII, ever."

---

## 1. Design principles (the non-negotiables)

1. **Zero-knowledge / end-to-end encrypted.** The operator cannot read user PII.
   Plaintext exists only on the user's device, in memory, while they are active.
2. **Isolation by cryptography, not just access control.** Each user's data is
   encrypted under a key derived from *their* password, which never leaves their
   device. Row-level `user_id` filtering is a defense-in-depth *layer*, never the
   *boundary*. (See §2 on why — IDOR is the failure mode crypto isolation kills.)
3. **Split derivation: auth value ≠ encryption key.** The server stores only a
   hash of an authentication value and never receives the encryption key or any
   value from which it can be derived.
4. **Scanning is client-side / session-bound.** Footprint checks run on the
   user's device, or through a transient endpoint that holds plaintext only
   in-memory and persists/logs nothing. Results are encrypted *before* they touch
   storage.
5. **No hand-rolled crypto. Ever.** Use audited primitives — Argon2id for KDF,
   libsodium (`crypto_secretbox` / XChaCha20-Poly1305) or WebCrypto (AES-256-GCM)
   for symmetric encryption. No custom constructions, no novel modes, no "I'll
   just XOR a counter."
6. **Honesty in the product promise.** True ZK means some conveniences are
   impossible (background monitoring while logged out; server-side password
   reset). We say so plainly rather than quietly faking them.

---

## 2. Threat model

The threat model is the spec. Everything downstream exists to satisfy it.

### Adversaries and what they can / cannot reach

| Adversary | Capability | Reaches under this design | Does **not** reach |
|---|---|---|---|
| **Server breach (external attacker)** | Dumps the database, object store, and config | Ciphertext blobs, auth verifiers (Argon2id hashes), wrapped-key envelopes, non-sensitive metadata (subscription tier, timestamps, counts of blobs) | Any plaintext PII, breach hits, broker matches, letter contents, or the keys to decrypt them |
| **Malicious / compromised operator (insider)** | Full server access, can read all stored bytes, can read live RAM of the API process | Same as above — ciphertext + verifiers. On the *web* delivery model, can additionally **ship malicious JS** (see §2.1, the central web-vs-native risk) | Stored plaintext. Cannot passively decrypt the at-rest database. On native, cannot push code silently |
| **IDOR / OWASP API #1 (Broken Object Level Authorization)** | Authenticated user A manipulates an ID to request user B's row | At most B's **ciphertext**, which is useless: it's encrypted under B's key, which A does not have | B's plaintext. Crypto isolation makes a successful IDOR a non-event |
| **Stalker-as-user** | A legitimate, paying account holder trying to surveil someone *else* | Only their own footprint data. The product scans the *account holder's own* identifiers; it is not a lookup tool for third parties | Anyone else's data. (Design choice: no "search for a person" feature — see §5 and §8) |
| **Subpoena / legal compulsion of the operator** | Court orders the operator to hand over a user's data | Ciphertext + verifier + metadata. Operator can truthfully testify it cannot decrypt | Plaintext. There is nothing to decrypt with; the operator never held the key |
| **Network adversary (MITM)** | Intercepts traffic | TLS-protected ciphertext | Plaintext (TLS + the payloads are already E2E-encrypted beneath TLS) |
| **Device compromise (malware on the user's machine)** | Reads the user's RAM / keylogs the password | **Everything** — this is the one adversary ZK cannot defend against | — (out of scope; see §10) |

### 2.1 The one risk that splits the delivery decision

A web app **re-serves the crypto JavaScript on every page load.** A malicious or
compromised operator (or anyone who breaches the web server / CDN / build
pipeline) can ship a *targeted* build that exfiltrates the password or master key
the next time a specific user logs in. The user has no practical way to verify the
code they're running each session. **ZK-in-the-browser is therefore "trust the
operator each load," not true zero-knowledge against the operator.** This is not a
hypothetical hand-wave; it is the well-known structural weakness of browser-based
E2E crypto.

A native/desktop app ships verifiable crypto **once**, signed; updates are
discrete, inspectable events, and key handling stays in a process the operator
doesn't re-author on every use. This single fact drives the recommendation in §6.

### What this model explicitly does NOT protect against

- **A compromised user device.** Malware, a hardware keylogger, or a coerced
  unlock defeats any client-side encryption scheme. Out of scope; stated plainly.
- **A user who loses both password and recovery code.** By design, their data is
  unrecoverable (§4.4). That is the cost of real ZK.
- **Traffic-analysis / metadata inference.** The server sees *that* a user synced,
  *when*, and *roughly how much* ciphertext. It can infer activity patterns even
  though it can't read content. We minimize but cannot eliminate this (§3).

---

## 3. Data model

### Stored server-side (all non-readable or non-sensitive)

| Item | Type | Sensitivity | Notes |
|---|---|---|---|
| `user_id` | UUID | none | Opaque handle; not derived from email |
| `auth_verifier` | Argon2id hash of the **auth key** | low | Verifies login; not reversible to the password or encryption key |
| `auth_salt`, `enc_salt` | random bytes | none | Per-user KDF salts |
| `kdf_params` | Argon2id memory/time/parallelism | none | Versioned, so we can raise cost over time |
| `wrapped_key__password` | ciphertext | opaque | Master key encrypted under the password-derived wrapping key |
| `wrapped_key__recovery` | ciphertext | opaque | Master key encrypted under the recovery-code-derived wrapping key |
| `footprint_blobs[]` | ciphertext | opaque | One encrypted blob per record (breach result, broker match, removal request). Server sees size + timestamp only |
| `blob_meta` | id, created_at, version, type-tag? | low | Minimize: prefer an opaque `kind` enum only if needed for sync; ideally even the type is inside the ciphertext |
| `subscription` | tier, status, renews_at | low (billing) | Lives outside the encrypted envelope so billing/gating works server-side |
| `email_for_billing` | string | **sensitive — see note** | Required by the payment processor. Store it **at the processor (Stripe), referenced by token**, not in our DB, so our DB stays PII-free. If we must keep a contact email, treat it as the one deliberate exception and document it loudly |

### Never stored server-side (in any readable form)

- Real name, personal email(s) being monitored, phone, postal address, DOB.
- HIBP breach hits, which breaches, which brokers matched.
- Generated CCPA/GDPR letter contents (they embed identifiers).
- The password, the encryption key, the master key, or the recovery code.
- Any plaintext footprint history or exposure-over-time series.

### The opacity proof (what a DB dump looks like)

A `footprint_blobs` row is `{id, user_id, created_at, ciphertext, nonce, version}`.
`ciphertext` is XChaCha20-Poly1305 / AES-256-GCM output. Without the user's master
key — which the server never possesses — these bytes are indistinguishable from
random. An operator, an attacker, and a court all see the same thing: noise. The
**exposure graph, the breach counts, the broker list — all of it is reconstructed
client-side from decrypted blobs and exists nowhere on the server in readable
form.**

> Metadata caveat (honest): row counts and timestamps leak *activity*. The server
> can tell a user has, say, 40 footprint records and synced today — not what they
> are. If even counts matter, pad to buckets and batch syncs. For v1, accept the
> metadata leak and document it.

---

## 4. Crypto architecture

**Libraries (pick the audited path, forbid everything else):**
- KDF: **Argon2id** (`libsodium` `crypto_pwhash`, or `argon2` WASM in browser).
  Tuned to ~256–512 MB memory, 2–3 iterations; benchmark on target hardware.
- Symmetric AEAD: **libsodium `crypto_secretbox` (XChaCha20-Poly1305)** on native;
  **WebCrypto AES-256-GCM** in browser. Random 24-byte (XChaCha) / 12-byte (GCM)
  nonces per encryption, never reused.
- Key wrapping: AEAD-encrypt the master key under each wrapping key.
- All randomness from the platform CSPRNG (`randombytes_buf` / `crypto.getRandomValues`).
- **Forbidden:** custom ciphers, ECB, static nonces, MD5/SHA1 for anything,
  rolling your own KDF, `Math.random()`, storing keys in `localStorage` long-term.

### 4.1 Key derivation flow (the split)

From the user's password, derive **two independent keys** via Argon2id with
**different salts and a domain-separation label** so neither can be computed from
the other:

```
password ──Argon2id(salt_auth, "vanish-auth")──▶ AUTH_KEY  (sent to server, hashed there)
         └─Argon2id(salt_enc,  "vanish-enc")───▶ ENC_KEY   (NEVER leaves device)
```

- **AUTH_KEY** is what the server sees at login. The server stores only
  `Argon2id(AUTH_KEY)` as `auth_verifier` — a hash of a key, so even AUTH_KEY
  itself isn't recoverable from the DB. (Equivalent strength to an SRP/OPAQUE-style
  split; OPAQUE is the gold standard if you want the server to never even see
  AUTH_KEY — flagged as an upgrade in §9.)
- **ENC_KEY** never transmits. It is the **wrapping key** for the master key.

### 4.2 The master-key envelope (enables recovery without weakening ZK)

We do **not** encrypt data directly under ENC_KEY (that would make password change
re-encrypt everything). Instead:

```
At signup, device generates:  MASTER_KEY = randombytes(32)   ← encrypts all blobs
                              RECOVERY_CODE = high-entropy string (user stores it)

Wrap it twice, upload only the wrapped copies:
  wrapped_key__password = AEAD_encrypt(MASTER_KEY, key=ENC_KEY)
  wrapped_key__recovery = AEAD_encrypt(MASTER_KEY, key=Argon2id(RECOVERY_CODE, salt_rec))

All footprint data:  blob = AEAD_encrypt(record_json, key=MASTER_KEY)
```

The server stores both wrapped copies (opaque) and never sees `MASTER_KEY`,
`ENC_KEY`, or `RECOVERY_CODE`.

### 4.3 What the server sees, by event

| Event | Server receives | Server stores | Server can decrypt? |
|---|---|---|---|
| **Signup** | `user_id`, `auth_verifier`, salts, kdf_params, both `wrapped_key__*`, encrypted blobs | all of it (opaque) | **No** |
| **Login** | `AUTH_KEY` (over TLS) → compared to `auth_verifier` | nothing new (issues a session token) | **No** |
| **Sync / write** | new/updated encrypted blobs | the ciphertext | **No** |
| **Password change** | new `auth_verifier`, new `wrapped_key__password` | replaces those two | **No** — blobs untouched; only the *wrapper* changes |
| **Recovery** | new `auth_verifier`, new `wrapped_key__password` after client unwraps via recovery code | replaces those two | **No** |

The crucial property: **password change and recovery re-wrap the master key, never
the data.** Blobs are immutable under their MASTER_KEY.

### 4.4 Recovery handling (the chosen model: recovery code, ZK preserved)

- At signup the device generates a high-entropy `RECOVERY_CODE`, shows it once,
  and forces the user to download/print/store it. We keep only its *wrapped*
  master-key copy.
- **Forgot password:** user enters the recovery code on-device → device derives the
  recovery wrapping key → unwraps `MASTER_KEY` → user sets a new password → device
  derives new ENC_KEY/AUTH_KEY → re-wraps and uploads new `wrapped_key__password`
  + `auth_verifier`. Server never sees the code or the master key.
- **Lose both password and recovery code:** data is **permanently unrecoverable.**
  This is stated up front, repeatedly, in onboarding. It is a feature of the
  security model, not a bug — the operator *cannot* be the backdoor.
- (Deferred option from the design discussion: optional Shamir social recovery on
  top of the code. More resilience, more attack surface and trustee considerations.
  Out of scope for v1; revisit in §9.)

---

## 5. Auth & accounts

- **Signup:** all key material is generated client-side (§4.2). The server receives
  only `auth_verifier`, salts, params, the two wrapped-key envelopes, and (from the
  start, empty) encrypted blob storage. The server **never** receives the password,
  ENC_KEY, MASTER_KEY, or RECOVERY_CODE.
- **Login:** client derives AUTH_KEY from the typed password, sends it over TLS; the
  server checks it against `auth_verifier` and issues a **short-lived session token**
  (HTTP-only, Secure, SameSite=strict cookie, or a bearer token in the native app's
  secure store). ENC_KEY/MASTER_KEY are derived/unwrapped **in memory on the device**
  and held only for the session.
  - *Upgrade path:* replace the "send AUTH_KEY" step with **OPAQUE** (an aPAKE) so
    the server never sees AUTH_KEY even at login. Strongly recommended; flagged in §9.
- **Session handling:** access tokens are short-lived; refresh tokens rotate.
  MASTER_KEY lives in JS heap (web) / process memory (native) and is zeroized on
  logout/lock. Auto-lock on idle. Never persist MASTER_KEY to disk unencrypted; if
  "stay logged in" is offered on native, store the wrapped key in the OS keychain
  (Keychain / Credential Manager / libsecret), not raw.
- **No account enumeration, no email-link password reset** (a server-side reset
  would imply the server can re-key the user — it can't; recovery is code-based only).
- **Explicit non-feature:** there is **no "look up a person" endpoint.** The product
  only ever scans the *authenticated account holder's own* identifiers, entered on
  their device. This is what keeps "stalker-as-user" from being a product feature.

---

## 6. Delivery model: web SaaS vs. native — and the recommendation

| Dimension | (a) Web SaaS | (b) Native/desktop (Tauri preferred over Electron) |
|---|---|---|
| **Crypto delivery** | Re-served as JS **every load** → operator/CDN/build-pipeline can ship targeted key-exfiltrating code; user can't verify per-session | Shipped **once**, code-signed; updates are discrete, inspectable. Key handling stays in an on-device process |
| **True ZK vs. operator?** | **No** — it's "trust the operator each load" | **Yes** (closer) — verifiable build, reproducible builds possible |
| **Scanning** | Needs a transient server proxy for HIBP/broker calls (browser CORS); plaintext touches the server process in-memory (§7) | Calls HIBP/brokers **directly from the device**; plaintext never leaves the machine |
| **Distribution / UX** | Zero install, instant, easy updates, frictionless trial → best for conversion | Install friction, per-OS packaging, code-signing certs, update channel to maintain |
| **Solo-dev cost** | Lower to ship, but the security story has an asterisk you must disclose | Higher up-front (Tauri = Rust shell + web UI, signing on 3 OSes), stronger security story |
| **Footprint of the trusted base** | Browser + your JS + your server | Tauri uses the OS webview (smaller than Electron's bundled Chromium); Rust core for crypto/IPC |

**Recommendation: native-first with Tauri, local-first data, optional thin sync.**
Reasoning: the product's *entire value proposition is "the operator can't read your
data."* The web model structurally undermines exactly that claim (§2.1), and you'd
have to disclose the asterisk — which erodes the one thing you're selling. Tauri
ships verifiable crypto once, calls HIBP/brokers directly (no plaintext-touching
proxy needed → §7 gets simpler), and keeps keys in OS-native secure storage. It is
also the most honest continuation of the CLI's local-first ethos.

**Pragmatic sequencing for a solo dev:** build the **local-first native app first**
(it can literally wrap the existing `vanish` Python core, or reimplement the registry/
verify/letter logic in the Rust/JS shell), with encrypted local storage and *optional*
encrypted sync as a later add-on. Defer or skip the pure-web client. If you later add
web for reach, **market it as the convenience tier and disclose its weaker trust model
explicitly** — don't let the two blur.

> If you ship web at all: enforce strict CSP, Subresource Integrity on all scripts,
> consider signed/pinned releases, and tell users the honest truth about per-load
> trust. It still isn't true ZK-vs-operator. Say so.

---

## 7. Scanning architecture

Footprint checks need plaintext identifiers (an email for HIBP, a name/address for
broker matching). The server can't hold those. So:

**Native app (recommended):** scans run **entirely on-device.**
- HIBP: the device calls the HIBP API directly. Use the **k-anonymity range API**
  for password/email-hash checks where possible (send only a hash prefix), so even
  HIBP sees minimal data. The existing CLI's `audit` logic ports here directly.
- Broker presence: the device runs the existing `verify`/registry logic against the
  bundled broker registry, locally.
- Results are assembled in memory, **encrypted under MASTER_KEY on the device**, then
  the ciphertext is synced. Plaintext never leaves the machine. No scanning proxy
  exists, so there's no server process that ever sees identifiers.

**Web fallback (if built): a transient, stateless scan endpoint.**
- Plaintext identifier is sent over TLS to an endpoint that holds it **only in
  process memory**, performs the upstream call (HIBP/broker), returns the result, and
  **persists nothing and logs nothing** — no request logs, no access logs capturing
  the body, no APM payload capture, no error-tracker breadcrumbs containing PII.
- This is a *deliberate, audited* weakening: for the duration of the call, plaintext
  exists on the server. It must be: isolated, memory-only, log-suppressed, and
  documented as the web tier's explicit caveat. The result is encrypted **client-side**
  before storage; the endpoint never writes to the DB.
- This is the part most likely to leak via an overlooked log sink. **Get this
  reviewed.** Treat every framework default that captures request bodies as hostile.

**Honest framing of "monitoring."** True background monitoring (re-scanning while the
user is logged out) is **impossible under ZK** — the server has neither the
identifiers nor the key to scan on the user's behalf. So:
- The user-facing promise is **"we check your footprint every time you open the app,
  and track changes over time"** — not "we watch 24/7."
- Optionally offer **opt-in local scheduled scans** (native app, OS scheduler, runs
  on-device when the machine is on) and **encrypted notifications** the device
  computes locally. Never frame it as server-side always-on monitoring, because it
  isn't and can't be.

---

## 8. Dashboard / UX

All charts render from **decrypted-in-memory** data on the client. The server ships
only ciphertext; the dashboard is reconstructed locally each session.

**Key screens:**

1. **Footprint Overview (home).** A single "exposure score" or footprint gauge, plus
   headline counts: *N breaches*, *M brokers where you appear*, *K removals in
   progress*. One-glance "are things getting better?" The hero visual.

2. **Exposure-over-time graph.** A line/area chart of total exposure (breaches +
   active broker listings) across time. The core "footprint shrinking" narrative —
   the thing that makes the subscription feel worth it. Data points are decrypted
   historical snapshots; the **server only ever saw their ciphertext.**

3. **Breaches panel.** List of HIBP hits: which breach, date, what data classes were
   exposed, severity (reuse the CLI's existing severity classifier). Actions: mark
   acknowledged, link to "change this password" guidance.

4. **Brokers panel.** Where the user appears, by category (people-search /
   aggregator / ad-tech), each with status: *not started → letter sent → confirmed
   removed → relisted*. Built directly on the CLI's registry + identifier-free
   tracker concept, now per-user and encrypted.

5. **Removal tracker.** Kanban/timeline of removal requests and their statuses,
   mirroring the CLI's `track`/`status` lifecycle. Generate the CCPA/GDPR/generic
   letter on-device (reusing existing letter templates), copy/email it, and record
   the *fact* (encrypted) — never the letter body server-side.

6. **Scan / refresh action.** A "Check my footprint now" button that triggers the
   on-device scan (§7), shows progress, then writes encrypted deltas and animates the
   graph.

7. **Security & recovery screen.** Shows the ZK status in plain language ("your data
   is encrypted on your device; we can't read it"), lets the user re-download/verify
   their recovery code, change password, and read the honest limitations.

**UX principle:** every screen that shows PII is reconstructing it locally. Make that
*visible* — a small "decrypted on your device" indicator builds the trust the product
is selling.

---

## 9. Build phases

> **Hard rule: no code that touches user PII gets written until the threat model
> (§2) and crypto envelope (§4) are signed off by a security reviewer.** The
> sequencing below enforces that the security envelope is designed and reviewed
> *first*. This is non-negotiable for a product whose entire premise is "we can't
> read your data."

- **Phase 0 — Threat model & crypto design review (no app code).**
  Finalize §2 and §4 on paper. Write the spec for key derivation, the envelope,
  recovery, and the auth handshake. **Pay for an external security review of this
  document.** Decide OPAQUE-vs-send-AUTH_KEY now. Gate: reviewer sign-off.

- **Phase 1 — Crypto/auth core, in isolation.**
  Implement and unit/property-test the KDF split, master-key envelope, wrap/unwrap,
  recovery flow, and session handling — against test vectors, with **no PII and no
  product features.** Fuzz the encrypt/decrypt boundary. Verify nonces never repeat.
  Gate: the crypto core is reviewed and tested before anything is layered on it.

- **Phase 2 — Native shell + local-first storage (Tauri).**
  Stand up the app, encrypted local storage, login/lock/logout, recovery-code
  onboarding. Still **no network scanning** — wire the existing CLI registry/letter
  logic locally. Prove the "decrypted only in memory" property end-to-end.

- **Phase 3 — On-device scanning.**
  Port the CLI's HIBP audit and broker `verify` to run on-device. Encrypt results
  under MASTER_KEY. Build the exposure-history snapshots. Confirm plaintext never
  leaves the device.

- **Phase 4 — Optional encrypted sync.**
  Thin server: stores ciphertext blobs + verifiers + envelopes + billing metadata.
  Enforce row-level auth as defense-in-depth (IDOR still shouldn't matter, but belt
  and suspenders). Confirm the DB dump is opaque (§3 opacity proof) before shipping.

- **Phase 5 — Dashboard & UX polish.**
  The graphs/panels of §8, all client-rendered from decrypted memory.

- **Phase 6 — Billing & launch gating.**
  Stripe (PII stays at the processor), subscription tiering. **Legal review (§10)
  complete before public launch.**

- **(Deferred) Phase 7 — Web convenience tier**, only if justified, only with the
  §2.1/§6 disclosures and §7 transient-endpoint hardening, reviewed separately.

---

## 10. Compliance & legal flags — *open questions for a lawyer, not legal advice*

These are flagged as **must-resolve-before-launch.** A solo dev should not
self-adjudicate any of them.

- **Data-broker registration laws (CA, OR, TX, VT, and growing).** California
  (CCPA/DELETE Act), Oregon, Texas, and Vermont have data-broker registration
  regimes. **Open question:** does a tool that *files removals on a user's behalf* or
  *brokers footprint data* trigger any registration duty? Likely no (we're an agent
  *for* the consumer, not a seller of personal data), **but a lawyer must confirm**
  the agent-vs-broker characterization in each state.
- **Authorized-agent requirements.** Filing CCPA/GDPR removals *on behalf of* a user
  may make us an **authorized agent**, which carries its own requirements (written
  permission, verification, sometimes notarization/specific authorization language).
  The CLI sidesteps this by having the user file themselves; a SaaS that submits for
  them likely triggers it. **Must resolve:** do we (a) generate letters the user
  sends themselves (lower burden), or (b) submit as their agent (agent obligations)?
- **Breach-notification duties.** If *we* ever suffered a breach — even of ciphertext
  — notification laws may still apply depending on jurisdiction and data classes,
  even where the data is unreadable. **Open question:** does encrypted-at-rest with
  no operator-held key qualify for safe-harbor/exemption in our target states? Often
  yes, but jurisdiction-specific.
- **Privacy policy & ToS.** Must accurately describe the ZK model, the metadata we
  *can* see (§3 caveat), the recovery-means-possible-data-loss reality, and the web
  tier's weaker trust model if offered. Misstating the security model is itself a
  legal exposure (FTC "deceptive practices"). **Have counsel review the security
  claims**, not just boilerplate.
- **Payment data.** Keep cardholder data entirely at the processor (Stripe) to stay
  out of heavy PCI scope. Confirm with counsel/processor.
- **HIBP terms.** Confirm commercial-use terms and rate limits for the HIBP API at
  the scale of a paid product.

---

## 11. Open risks & honest limitations

- **Scan-vs-ZK tension (the central honest caveat).** To check a footprint you need
  plaintext identifiers. In ZK they can only exist on-device (native) or transiently
  in server memory (web). The native model resolves this cleanly; the web model does
  not, and §7's transient endpoint is the single most likely place to accidentally
  leak via a forgotten log sink. **This needs a security review whichever way we go.**
- **Recovery means possible data loss.** Lose both password and recovery code → data
  gone, by design. Support cannot help; *that is the product working as intended.*
  Some users will lose data and be angry. Set the expectation aggressively at signup.
- **Solo-operator custody risk.** A single developer holds the keys to the
  infrastructure (not the users' encryption keys, but the servers, the build
  pipeline, the signing certs). A compromised dev machine or build pipeline is the
  most realistic path to shipping malicious code — **especially in the web model
  (§2.1).** Mitigate: reproducible builds, signed releases, hardware-key-protected
  signing, minimal infra, native-first.
- **Web delivery is not true ZK-vs-operator.** Re-served crypto JS means per-load
  trust. If web ships, this must be disclosed, not buried.
- **Metadata leakage.** The server learns activity timing and volume even though it
  can't read content. Acceptable for v1 if documented; reduce later with padding/batching.
- **Browser key-handling hazards** (web): XSS becomes catastrophic (it can read the
  in-memory key). Strict CSP, no third-party scripts, SRI — and even then, see §2.1.
- **Device compromise is unsolvable here.** ZK protects against the server, not the
  user's own malware. Say so.
- **Crypto is the part you must not get clever about.** Every novel decision in §4 is
  a potential catastrophic, silent failure. **Use audited libraries, get the design
  reviewed, write test vectors, and resist optimizing the crypto.**

---

## 12. TL;DR for the solo dev

1. Design the threat model and crypto envelope **first**, get it **reviewed**, write
   **zero** PII-handling code until then.
2. Split keys: **AUTH_KEY** (server sees a hash) vs **ENC_KEY** (never leaves device);
   both from the password via Argon2id with separate salts. Data is encrypted under a
   random **MASTER_KEY** that's wrapped under both the password and a **recovery code**.
3. **Native-first (Tauri), local-first**, scanning on-device — because the web model
   structurally breaks the "operator can't read your data" promise you're selling.
4. Use **libsodium/WebCrypto + Argon2id only**. No hand-rolled crypto.
5. Be honest in the UI: no 24/7 monitoring under ZK; losing both secrets means data
   loss; the operator genuinely cannot help — and that's the point.
6. **Lawyer before launch** on authorized-agent, broker-registration, breach-notice,
   and the accuracy of your security claims.

*This blueprint is an engineering design. The crypto needs a security review and the
compliance section needs a lawyer. Both are stated as gates, not afterthoughts.*
