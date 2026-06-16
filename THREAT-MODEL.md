# vanish — Threat Model (Phase 0)

**Status:** Draft for review. **This is the third Phase 0 gate artifact** (with
[BLUEPRINT.md](./BLUEPRINT.md) and [CRYPTO-SPEC.md](./CRYPTO-SPEC.md)). Per
BLUEPRINT.md §9, **no PII-handling code may be written until this model and the
crypto spec are signed off** by a security-literate reviewer.
**Scope:** The multi-user, zero-knowledge footprint-monitoring product. This
document *formalizes* BLUEPRINT.md §2 into adversaries, assets, properties, threats,
and a traceability matrix that the controls in CRYPTO-SPEC.md must satisfy.
**Date:** 2026-06-16

> **How the three documents relate.**
> BLUEPRINT.md = *what we're building and why.*
> THREAT-MODEL.md (this) = *what must hold, against whom, and how we know.*
> CRYPTO-SPEC.md = *the exact mechanism that makes it hold.*
> The threat model is the **specification of intent**; the crypto spec is the
> **mechanism**; this document's traceability matrix (§14) is the bridge a reviewer
> uses to confirm every threat has a named control.

---

## 1. Purpose and how to use this document

This model exists to answer four questions precisely enough to audit:

1. **What are we protecting?** (Assets, §5)
2. **What must be true of the system?** (Security & privacy properties, §6 — each a
   falsifiable claim)
3. **Who are we defending against, and what can they do?** (Adversary model, §7)
4. **For each adversary × asset, what do they reach, what stops them, and what is
   left as accepted residual risk?** (§9–§13)

Use it as: (a) the sign-off checklist for the Phase 0 gate (§15); (b) the reference
a reviewer reads alongside CRYPTO-SPEC.md; (c) the document to re-open whenever the
architecture changes (a new endpoint, a new stored field, a new delivery model each
require revisiting §5/§9/§14).

---

## 2. Methodology

We combine four lenses deliberately, because no single one covers a ZK privacy
product:

- **Asset-centric analysis** — rank what we protect; the crown jewel drives everything.
- **STRIDE** (§11) — for the *security* surface (Spoofing, Tampering, Repudiation,
  Information disclosure, Denial of service, Elevation of privilege), applied per
  component and data flow.
- **LINDDUN** (§12) — for the *privacy* surface (Linkability, Identifiability,
  Non-repudiation, Detectability, Disclosure of information, Unawareness,
  Non-compliance). A footprint-privacy product whose whole pitch is "the operator
  can't profile you" must be analyzed with a privacy threat taxonomy, not only a
  security one.
- **Attack trees** (§13) — for the crown-jewel goal ("read a user's PII"), to show the
  disjoint paths an adversary would have to take and where each is cut.

Every identified threat is either **mitigated** (with a named control traced to a
CRYPTO-SPEC.md section) or **accepted** (listed in the residual-risk register, §13,
with explicit rationale). Nothing is left implicit.

---

## 3. System decomposition

### 3.1 Principals and components

| ID | Component | Location | Holds keys? |
|----|-----------|----------|-------------|
| C-DEV | Client app (Tauri native core + webview UI; or web client) | User's device | **Yes** — derives/holds keys in memory while unlocked |
| C-KEYCHAIN | OS secure store (Keychain / Credential Manager / libsecret) | User's device | Holds *wrapped* keys / tokens only |
| S-API | Sync/account backend | Operator infra | **No vault keys** — stores ciphertext + verifier + metadata |
| S-DB | Database / object store | Operator infra | Stores opaque blobs, envelopes, verifiers, metadata |
| S-SCAN | Transient scan endpoint (**web tier only**) | Operator infra | No keys; sees plaintext identifiers *in memory only* during a scan |
| EXT-HIBP | Have I Been Pwned API | Third party | n/a |
| EXT-BROKER | Data-broker sites/registry checks | Third party | n/a |
| EXT-PAY | Payment processor (Stripe) | Third party | Holds billing PII (by design, off our DB) |
| OP | Operator / solo developer | Operator org | Controls infra, build pipeline, signing keys — **not** user vault keys |

### 3.2 Data-flow and trust boundaries (native model, recommended)

```
        ┌──────────────────────── USER DEVICE (trusted by the user) ───────────────────────┐
        │                                                                                   │
 password│  C-DEV (native crypto core)                                                       │
   ─────► │   • Argon2id→STRETCHED→ENC_KEY/AUTH_KEY    • MASTER_KEY (random, in-mem)          │
        │   • scans run HERE (HIBP/broker)           • encrypt blobs under MASTER_KEY        │
        │        │ plaintext identifiers never leave this box │                              │
        │        ▼                                                                           │
        │   C-KEYCHAIN (wrapped keys/tokens only)                                            │
        └───────┬──────────────────────────────────────────────────────────────────────────┘
                │  TB-NET: TLS. Only ciphertext blobs, AUTH_KEY (MVP), wrapped keys, metadata cross here.
                ▼
        ┌──────────────────────── OPERATOR INFRA (UNTRUSTED for confidentiality) ───────────┐
        │   S-API ── S-DB:  opaque blobs · wrapped_key__{password,recovery} · auth_verifier  │
        │                    · salts · kdf_params · subscription metadata                    │
        │   (no key can decrypt any blob — see CRYPTO-SPEC §4.3/§5)                           │
        └───────────────────────────────────────────────────────────────────────────────────┘
                │ TLS                                  │ TLS (token, not body, to billing)
                ▼                                      ▼
        EXT-HIBP / EXT-BROKER  (called from device)   EXT-PAY (Stripe holds billing PII)
```

**Key boundary fact:** in the native model, **plaintext identifiers and vault keys
never cross TB-NET.** The operator infra is *untrusted for confidentiality* by
design — it is treated as hostile in this model (see adversary DA-2).

### 3.3 Web-tier delta (if ever built)

Two boundaries weaken (documented, not hidden):
- **S-SCAN** sees plaintext identifiers in memory during a scan (CRYPTO-SPEC §5/§12,
  BLUEPRINT §7) — a *transient* crossing of TB-NET in plaintext.
- **Crypto code is re-served per load** (BLUEPRINT §2.1): the boundary between
  "operator can ship code" and "user runs verified code" effectively disappears each
  session. This is the single biggest reason the native model is recommended.

### 3.4 Trusted Computing Base (TCB)

| Delivery | TCB for vault confidentiality |
|---|---|
| **Native (recommended)** | User device OS + the *one-time, signed* app binary + libsodium. Operator infra is **outside** the TCB. |
| **Web** | All of the above **plus** the operator's web/CDN/build pipeline **on every page load** — because it re-authors the crypto each session. |

---

## 4. Security objectives (the one-line promises this model defends)

- **O1 — Confidentiality against the operator.** The operator cannot read any user's
  PII, footprint data, or letter contents.
- **O2 — Confidentiality against a breach/subpoena.** A full server compromise or
  legal compulsion yields no readable user data.
- **O3 — Cryptographic per-user isolation.** One user cannot read another's data even
  with a working IDOR, because isolation is by key, not by access check.
- **O4 — Integrity.** Stored ciphertext cannot be tampered with, swapped, or
  downgraded without detection on decrypt.
- **O5 — Honest availability/recovery semantics.** Recovery works as specified;
  unrecoverable cases are exactly the documented ones (lose both secrets), never a
  silent surprise.
- **O6 — Minimal, disclosed metadata.** What the operator *can* see (existence,
  timing, volume) is enumerated and disclosed; nothing sensitive leaks beyond it.

---

## 5. Assets (ranked)

| ID | Asset | Why it matters | Sensitivity |
|----|-------|----------------|-------------|
| **AS1** | **User PII & footprint plaintext** (name/email/phone/address, breach hits, broker matches, letter contents, exposure history) | **The crown jewel.** The entire product promise is that this stays unreadable to the operator. | **Critical** |
| AS2 | `MASTER_KEY` | Decrypts all of AS1. Compromise = total break for that user. | Critical |
| AS3 | `ENC_KEY` / `STRETCHED` / the user password | Unwraps `MASTER_KEY`. | Critical |
| AS4 | `RECOVERY_CODE` / `RECOVERY_KEY` | Password-equivalent; unwraps `MASTER_KEY`. | Critical |
| AS5 | Session/refresh tokens | Authorize blob fetch/write (ciphertext only — not decryption). | High |
| AS6 | `auth_verifier`, salts, `kdf_params` | Enable the §7.1 offline dictionary attack if stolen. | Medium |
| AS7 | Vault metadata (blob counts, sizes, sync timestamps, subscription status, account existence) | Enables activity/behavioral inference even without content. | Low–Medium |
| AS8 | Billing PII (held at EXT-PAY) | Real identity/payment data; deliberately off our DB. | High (but out of our store) |
| AS9 | Operator build pipeline & code-signing keys | Compromise lets an attacker ship malicious code = bypass everything. | Critical (operational) |
| AS10 | Broker registry & app integrity | Tampering misdirects removals / erodes trust. | Medium |

**Design consequence:** because AS1's confidentiality reduces to AS2/AS3/AS4 never
reaching the server, the model's center of gravity is *key custody*, not access
control.

---

## 6. Security & privacy properties (falsifiable claims)

Each property is something a reviewer/test can attempt to *break*. The cited control
is where CRYPTO-SPEC.md enforces it.

| ID | Property (must hold) | Enforced by |
|----|----------------------|-------------|
| **P1** | The server never receives `ENC_KEY`, `MASTER_KEY`, `RECOVERY_KEY`, or any plaintext PII. | CRYPTO-SPEC §2, §3.3, §4.3, §8 (wire tables) |
| **P2** | `MASTER_KEY` is generated on-device by CSPRNG and is the *only* key that encrypts vault data. | CRYPTO-SPEC §1.5, §2 (invariant 1), §5 |
| **P3** | `AUTH_KEY` is cryptographically independent of `ENC_KEY` (learning one does not yield the other). | CRYPTO-SPEC §1.3, §3.3 |
| **P4** | Both wrapped `MASTER_KEY` copies are opaque to the server and non-interchangeable (slot/user/param-bound). | CRYPTO-SPEC §4.1 (AAD), §4.3 |
| **P5** | No AEAD nonce is ever reused under a key; random 24-byte nonces are collision-safe at scale. | CRYPTO-SPEC §1.4 |
| **P6** | Every ciphertext authenticates its context (role/user/record/version); blob-swap and downgrade are detectable. | CRYPTO-SPEC §4.1, §5, §11 |
| **P7** | A successful IDOR yields only ciphertext for a key the attacker lacks. | This doc §9 (DA-3); CRYPTO-SPEC §5, §6.3 |
| **P8** | Password change and recovery re-wrap `MASTER_KEY` only; the vault is never re-encrypted. | CRYPTO-SPEC §8.4, §8.5 |
| **P9** | Using the recovery code rotates it and invalidates the old one. | CRYPTO-SPEC §8.5.1 |
| **P10** | The auth mechanism outputs only a session token (nothing key-bearing) and is swappable MVP↔OPAQUE without touching the envelope. | CRYPTO-SPEC §6 |
| **P11** | Removal-letter identifiers are rendered in-memory client-side and never sent to or persisted by the server. | CRYPTO-SPEC §5.1 |
| **P12** | Server-visible metadata is exactly the enumerated set (AS7); nothing sensitive beyond it leaks. | This doc §12; CRYPTO-SPEC §10/§12 |
| **P13** | Key material lives in memory only while unlocked and is zeroized on lock/logout. | CRYPTO-SPEC §10 |
| **P14** | Forgetting both password and recovery code is the *only* unrecoverable state, and it is disclosed. | CRYPTO-SPEC §8.5, §12; BLUEPRINT §11 |

---

## 7. Adversary model

### 7.1 Capability primitives

We describe each adversary by which capabilities they hold:

- **NET** — Dolev-Yao network control: observe, drop, replay, modify traffic (but TLS
  intact; not a CA).
- **RD-STORE** — read operator data at rest (DB/object store/config dump).
- **WR-STORE** — modify operator data at rest.
- **RD-MEM** — read live operator process memory (S-API/S-SCAN).
- **SHIP-CODE** — cause the client to run operator-authored code (trivially true for
  web each load; requires a pushed signed update for native).
- **LEGAL** — legally compel the operator to produce what it holds / can compute.
- **USER-ACCT** — hold a valid, paid account and use all client features.
- **DEV-COMPromise** — execute code / read memory on the *victim's* device.
- **OFFLINE** — unbounded offline computation against stolen material (bounded only by
  the cryptography's work factor).

### 7.2 Adversaries

| ID | Adversary | Capabilities | In scope? |
|----|-----------|-------------|-----------|
| **DA-1** | External attacker, server breach | RD-STORE, (maybe WR-STORE, RD-MEM), OFFLINE | **Yes** |
| **DA-2** | Malicious / compromised operator (insider) | RD-STORE, WR-STORE, RD-MEM, SHIP-CODE, OFFLINE | **Yes — treated as primary** |
| **DA-3** | Authenticated user attacking other users (IDOR / OWASP-API #1) | USER-ACCT, NET (own session) | **Yes** |
| **DA-4** | Stalker-as-user (legit account, targeting a third party) | USER-ACCT | **Yes** |
| **DA-5** | Subpoena / legal compulsion of operator | LEGAL (⊇ what DA-2 can compute) | **Yes** |
| **DA-6** | Network adversary (MITM) | NET | **Yes** |
| **DA-7** | Build-pipeline / supply-chain attacker | SHIP-CODE (via AS9), WR-STORE | **Yes** |
| **DA-8** | Malware on the victim's unlocked device | DEV-COMP, RD-MEM(client) | **No — out of scope (§8, ASM-1)** |

**Modeling stance:** DA-2 (malicious operator) is treated as the *primary* adversary,
not a worst case. A ZK product that only resists external attackers but trusts its own
operator has not delivered zero-knowledge. Designing against DA-2 subsumes DA-1 and
DA-5 for confidentiality.

---

## 8. Trust boundaries

| ID | Boundary | Crossing rule |
|----|----------|---------------|
| **TB-NET** | Device ↔ operator infra | Only ciphertext blobs, wrapped keys, salts/params, `AUTH_KEY` (MVP), tokens, and metadata may cross. **Never** plaintext PII or vault keys (native). |
| **TB-PROC** | Native crypto core ↔ webview UI | Keys stay in the native core; only decrypted *display* data crosses into the UI, and only while unlocked. |
| **TB-KEYCHAIN** | App ↔ OS secure store | Only *wrapped* keys / tokens persist; never raw `MASTER_KEY`. |
| **TB-EXT** | Device ↔ HIBP/broker | Plaintext identifiers (or k-anonymity prefixes) leave the device to the third party *by necessity of the scan* — disclosed; minimized via HIBP range API. |
| **TB-CODE** | "Operator can author code" ↔ "user runs verified code" | Native: crossed only at signed-update time (inspectable). Web: crossed every load (the §3.3 weakening). |

---

## 9. Threat enumeration by adversary (reach / barrier / residual)

For each adversary: what they reach, what stops them at AS1, and what residual remains.

### DA-1 — Server breach (external)
- **Reaches:** AS6, AS7, ciphertext blobs, wrapped keys (all opaque).
- **Barrier to AS1:** needs AS2/AS3 — absent server-side (P1, P2). Blobs are AEAD
  ciphertext (P4–P6).
- **Residual:** if they also captured `auth_verifier`/salts, they may attempt the
  **offline dictionary attack** on weak passwords (→ R-1). Strong-passphrase policy +
  Argon2id cost bound it.

### DA-2 — Malicious / compromised operator (PRIMARY)
- **Reaches:** everything DA-1 reaches, **plus** RD-MEM of S-API (so, in MVP, a
  transiently-presented `AUTH_KEY` at login) **plus** SHIP-CODE.
- **Barrier to AS1 (native):** `ENC_KEY`/`MASTER_KEY` never reach S-API (P1); seeing
  `AUTH_KEY` does not yield `ENC_KEY` (P3); they cannot push code silently (native
  TCB, §3.4).
- **Residual / honest limits:**
  - **(R-1)** Offline dictionary attack on the password via captured
    `AUTH_KEY`/verifier (CRYPTO-SPEC §7.1). Closed only by **OPAQUE** (P10 upgrade).
  - **(R-2, web only)** SHIP-CODE lets a malicious operator serve key-exfiltrating JS
    per load (BLUEPRINT §2.1). **Native materially reduces this; web does not.** This
    is *the* reason native is recommended.

### DA-3 — IDOR / Broken Object Level Authorization
- **Reaches:** at most another user's **ciphertext** by manipulating ids.
- **Barrier to AS1:** that ciphertext is under the victim's `MASTER_KEY`, which the
  attacker lacks (P7). Cryptographic isolation makes a *successful* IDOR a non-event
  for confidentiality. (We still enforce row-level authz as defense-in-depth —
  CRYPTO-SPEC §6.3.)
- **Residual:** metadata of the victim (AS7) could leak via IDOR (→ R-4). Authz checks
  + opaque ids mitigate.

### DA-4 — Stalker-as-user
- **Reaches:** only their *own* footprint data.
- **Barrier:** the product has **no "look up a person" endpoint** (BLUEPRINT §5/§8); it
  only ever scans the authenticated holder's own identifiers, entered on-device. There
  is no product capability to target a third party.
- **Residual:** a stalker could still abuse it on an account they *control* for someone
  they can coerce — a social/account-takeover problem, not a crypto one (→ R-7,
  accept + note). Optional account-security features (2FA on the auth module) reduce
  takeover, but coercion is out of scope (ASM-1).

### DA-5 — Subpoena / legal compulsion
- **Reaches:** whatever the operator *holds or can compute* = AS6/AS7 + opaque blobs.
- **Barrier:** the operator holds no key and cannot compute one (P1); it can truthfully
  attest it cannot decrypt (O2). Production yields ciphertext + metadata.
- **Residual:** metadata (AS7) is producible and may itself be sensitive (activity
  timing) (→ R-4). A *forward-looking* order compelling the operator to **ship targeted
  malicious code** (DA-2/DA-7 capability) is the real risk — see R-2/R-6; native +
  reproducible builds + transparency are the only partial defenses.

### DA-6 — Network MITM
- **Reaches:** TLS-protected traffic only.
- **Barrier:** TLS, beneath which payloads are already E2E ciphertext (P1, P4–P6).
  Replay/tamper of blobs is caught by AEAD auth + AAD binding (P6).
- **Residual:** traffic-analysis metadata (timing/volume) (→ R-4).

### DA-7 — Build-pipeline / supply-chain
- **Reaches:** AS9 → SHIP-CODE → can in principle bypass *all* client-side crypto.
- **Barrier:** this is the **highest-leverage attack** and crypto cannot stop it —
  only process can. Native + code signing + reproducible builds + minimal infra +
  hardware-protected signing keys (→ R-6). **No cryptographic control closes this; it
  is an operational risk owned by the operator.**
- **Residual (R-6):** accepted with mitigations; the solo-operator custody problem
  (BLUEPRINT §11) makes it the most realistic catastrophic path.

### DA-8 — Device malware (OUT OF SCOPE)
- **Reaches:** AS1–AS4 directly on an unlocked device.
- **Barrier:** none that client-side crypto can provide (ASM-1). Zeroization (P13)
  reduces the *window*, not the *capability*.
- **Residual (R-5):** accepted, disclosed, out of scope.

### 9.1 Consolidated reach matrix

| | AS1 plaintext | AS2/3/4 keys | AS6 verifier/salt | AS7 metadata | AS9 pipeline |
|---|:---:|:---:|:---:|:---:|:---:|
| DA-1 breach | ✗ | ✗ | ✓ | ✓ | ✗ |
| DA-2 operator (native) | ✗\* | ✗\* | ✓ | ✓ | n/a |
| DA-2 operator (web) | **⚠ via R-2** | **⚠ via R-2** | ✓ | ✓ | n/a |
| DA-3 IDOR | ✗ | ✗ | ✗ | ⚠ R-4 | ✗ |
| DA-4 stalker | own only | ✗ | ✗ | own | ✗ |
| DA-5 subpoena | ✗ | ✗ | ✓ | ✓ | ✗ |
| DA-6 MITM | ✗ | ✗ | ✗ | ⚠ R-4 | ✗ |
| DA-7 supply chain | **⚠ R-6** | **⚠ R-6** | ✓ | ✓ | ✓ |
| DA-8 device (OOS) | ✓ R-5 | ✓ R-5 | n/a | n/a | n/a |

`✗` = cannot reach · `✓` = reaches (by design or accepted) · `⚠` = residual risk, see register
`*` native operator residual is R-1 (offline dict. on weak passwords), not direct read.

---

## 10. Attack-resistance summary for the crown jewel (AS1)

To read AS1, an adversary must obtain `MASTER_KEY` (AS2), which requires one of:
(a) `ENC_KEY` ← the password, (b) `RECOVERY_KEY` ← the recovery code, or (c) reading
it from device memory while unlocked. Every server-side adversary is therefore forced
off the server and onto either **guessing a human secret** (bounded by Argon2id, R-1)
or **compromising the device/code** (R-2 web, R-5, R-6) — never a direct read of
stored data. That reduction is the model's core result.

---

## 11. STRIDE analysis

| Threat | Where | Mitigation / control |
|--------|-------|----------------------|
| **S**poofing | Auth (DA-1/2/6) | Auth module verifies `AUTH_KEY` (MVP) / OPAQUE (upgrade); short-lived rotating tokens (CRYPTO-SPEC §6). TLS + cert validation for endpoint identity. |
| **T**ampering | Blobs/envelopes at rest or in transit (DA-1/2/6/7) | AEAD authentication + context AAD binding slot/user/record/version (P4, P6; CRYPTO-SPEC §4.1, §5, §11). Tamper ⇒ decrypt fails, never returns garbage. |
| **R**epudiation | Account actions | Out of primary scope (no PII in logs by design). Minimal audit trail server-side; `created_at` timestamps only. Note: ZK limits server-side accountability — accepted. |
| **I**nformation disclosure | The whole point (DA-1/2/5/6) | E2E encryption; keys never server-side (P1–P6). Residuals: R-1 (offline dict.), R-2 (web code), R-4 (metadata). |
| **D**enial of service | S-API availability | Rate-limiting, standard infra hardening. Out of crypto scope; does **not** threaten confidentiality. Note: losing server data ≠ losing user data only if the client/local copy persists — back-up semantics defined at app layer. |
| **E**levation of privilege | IDOR (DA-3), token theft (AS5) | Row-level authz as defense-in-depth; crypto isolation makes EoP yield ciphertext only (P7). Tokens are not keys (P10). |

---

## 12. LINDDUN privacy analysis

| Threat | Risk for this product | Control / residual |
|--------|----------------------|--------------------|
| **L**inkability | Can the operator link records/activity to a person? | Content is opaque (P1, P12); `user_id` is opaque, not derived from email (BLUEPRINT §3). Residual: activity *patterns* across a `user_id` are linkable (AS7 / R-4). |
| **I**dentifiability | Can the operator identify the human behind an account? | We deliberately keep billing PII at EXT-PAY, off our DB (AS8; BLUEPRINT §3). Residual: if a contact email is ever stored, that is the one disclosed exception — flag loudly. |
| **N**on-repudiation | Can a user be provably tied to data (harmful in privacy context)? | The operator *cannot* prove footprint contents (it can't read them). This is a privacy *win* here. |
| **D**etectability | Can the operator detect that a record/activity exists? | Yes — blob existence/count/timing are visible (AS7, R-4). Mitigation deferred: size-bucketing/padding/batched sync (CRYPTO-SPEC §12). Accepted for v1, disclosed. |
| **D**isclosure of information | Core threat — operator reads PII. | Defeated by E2E (P1–P6). The crown-jewel guarantee. |
| **U**nawareness | Do users misunderstand the guarantees? | **Active obligation:** UI must disclose (a) recovery = possible data loss (P14), (b) metadata visibility (P12), (c) web-tier weaker trust (R-2), (d) MVP offline-attack caveat (R-1). Misstatement is itself a risk (FTC "deceptive practices", BLUEPRINT §10). |
| **N**on-compliance | Legal/regulatory exposure | Fenced to legal review (BLUEPRINT §10): broker-registration, authorized-agent (the "tool not agent" v1 stance, CRYPTO-SPEC §5.1), breach-notification. **Must-resolve-before-launch.** |

LINDDUN surfaces the two things a pure-security model would miss: **Detectability**
(metadata, R-4) and **Unawareness** (the honesty obligation) — both first-class here.

---

## 13. Residual risk register

Risks we do **not** fully eliminate, with explicit acceptance.

| ID | Residual risk | Adversary | Likelihood | Impact | Mitigation | Status |
|----|---------------|-----------|-----------|--------|------------|--------|
| **R-1** | Offline dictionary attack on weak passwords via stolen `auth_verifier`/`AUTH_KEY` | DA-1, DA-2 | Med (weak pw) | Critical (→ AS1) | Strong-passphrase policy + high Argon2id cost (CRYPTO-SPEC §1.2, §7.1); **OPAQUE upgrade closes it** (§6.2) | **Accepted for MVP w/ mitigations; OPAQUE planned** |
| **R-2** | Operator ships key-exfiltrating client code (web: per load; native: via pushed update) | DA-2, DA-5, DA-7 | Web: Med · Native: Low | Critical | **Native-first** (one-time signed binary); reproducible builds; signed updates; CSP/SRI if web (BLUEPRINT §2.1/§6) | **Reduced by native; web residual disclosed** |
| **R-3** | Lose both password and recovery code → vault unrecoverable | (user error) | Med | High (to that user) | By design; aggressive onboarding disclosure (P14) | **Accepted (feature of ZK)** |
| **R-4** | Metadata leakage: existence, counts, sizes, sync timing | DA-1/2/5/6, DA-3(victim) | High | Low–Med | Disclose (P12); later: padding/bucketing/batched sync (CRYPTO-SPEC §12) | **Accepted for v1, disclosed** |
| **R-5** | Compromised unlocked device reads keys/PII | DA-8 | Low–Med | Critical | Out of scope; zeroization narrows window (P13) | **Accepted (out of scope)** |
| **R-6** | Build-pipeline / signing-key compromise (solo-operator custody) | DA-7 | Low | Critical | Reproducible builds, hardware-protected signing, minimal infra, native (BLUEPRINT §11) | **Accepted w/ operational controls** |
| **R-7** | Stalker abuses an account they control / coerce | DA-4 | Low | Med | No third-party lookup feature; optional 2FA; coercion out of scope | **Accepted w/ note** |
| **R-8** | Scan plaintext transits S-SCAN (web tier only) | DA-2 (web) | Med (if web built) | High | Memory-only, log-suppressed, persists nothing (CRYPTO-SPEC §5/§12, BLUEPRINT §7); **separate review obligation** | **Deferred — web tier only** |
| **R-9** | Third party (HIBP/broker) sees identifiers during a scan | EXT | High (inherent) | Low–Med | Necessary for the scan; minimize via HIBP k-anonymity range API (BLUEPRINT §7) | **Accepted (inherent, minimized)** |

---

## 14. Requirements traceability matrix (threat → property → control)

The reviewer's bridge: every property maps to a control and the threats it answers.

| Property | Answers adversary/threat | Control (CRYPTO-SPEC §) | Test/verification |
|----------|--------------------------|-------------------------|-------------------|
| P1 (no keys/PII to server) | DA-1, DA-2, DA-5 | §2, §3.3, §4.3, §8 | Inspect wire tables; assert no endpoint receives `ENC_KEY`/`MASTER_KEY`/PII |
| P2 (MASTER_KEY on-device, sole encryptor) | DA-1, DA-2 | §1.5, §2, §5 | Code review of key-gen + blob encrypt paths |
| P3 (AUTH⊥ENC) | DA-2 (RD-MEM/R-1) | §1.3, §3.3 | Confirm `crypto_kdf` independent subkeys; no path AUTH_KEY→ENC_KEY |
| P4 (wrapped keys opaque/non-swappable) | DA-1, DA-2 | §4.1 (AAD), §4.3 | AAD cross-slot/cross-user decrypt must fail |
| P5 (nonce uniqueness) | DA-1, DA-6 | §1.4 | Nonce-source review; statistical/fuzz test |
| P6 (context-authenticated ciphertext) | DA-1, DA-2, DA-6 | §4.1, §5, §11 | Tamper/downgrade tests fail closed |
| P7 (IDOR ⇒ ciphertext only) | DA-3 | §5, §6.3 | Cross-user fetch returns undecryptable blob; authz test |
| P8 (re-wrap, never re-encrypt) | DA-1 (key rotation) | §8.4, §8.5 | Verify blobs unchanged across pw change/recovery |
| P9 (recovery rotates code) | DA-2, reuse | §8.5.1 | Old code fails to unwrap after recovery |
| P10 (auth swappable, token-only) | DA-1/2, R-1 | §6 | Confirm token carries no key; envelope unchanged under OPAQUE swap |
| P11 (letter identifiers never persist) | DA-1, DA-2, DA-5 | §5.1 | Assert no identifier reaches server (mirrors CLI identifier-free test) |
| P12 (disclosed metadata only) | DA-1/2/5/6 (R-4) | §10, §12 | Enumerate stored fields; confirm against AS7 |
| P13 (memory-only keys, zeroized) | DA-8 (window) | §10 | Review zeroization on lock/logout |
| P14 (only documented unrecoverable state) | R-3 | §8.5, §12 | Onboarding-copy review; recovery test matrix |

---

## 15. Assumptions and dependencies

| ID | Assumption | If false → |
|----|-----------|-----------|
| ASM-1 | The user's device is trustworthy while unlocked (no malware/keylogger/coercion). | All client-side crypto is bypassable (R-5). Out of scope. |
| ASM-2 | libsodium and its CSPRNG are correct and unbroken. | Catastrophic; we accept the same trust as the rest of the ecosystem. |
| ASM-3 | TLS / the CA system is intact (no rogue cert for our domain). | DA-6 strengthens; tokens/credentials could be intercepted (blobs still E2E). |
| ASM-4 | Users choose a sufficiently strong password (enforced by policy in MVP). | R-1 likelihood rises; OPAQUE mitigates. |
| ASM-5 | The recovery code is stored by the user out-of-band and kept secret. | R-3 (loss) or AS4 compromise. |
| ASM-6 | Operator protects AS9 (build pipeline, signing keys). | R-6 / R-2 realized. |
| ASM-7 | Native delivery is the shipped model (per BLUEPRINT §6). | If web ships, re-open §3.3, R-2, R-8 as primary, not secondary. |
| ASM-8 | Third parties (HIBP/broker) are not colluding adversaries beyond seeing scan inputs. | R-9 broadens. |

---

## 16. Out of scope (explicit non-goals)

- **Compromised/unlocked-device malware** (DA-8 / R-5) — undefeatable client-side.
- **Coercion / rubber-hose** against the user (R-7).
- **Server availability/DoS** as a *confidentiality* concern (it isn't one here).
- **Web-tier S-SCAN hardening** (R-8) — real, but specified and reviewed separately
  when/if the web tier is built (BLUEPRINT §7).
- **Legal/compliance adjudication** (BLUEPRINT §10) — flagged, owned by a lawyer, not
  resolved here.
- **Side-channel/timing attacks on the device** beyond using constant-time library
  primitives — not analyzed at this phase; note for a later hardware/native review.

---

## 17. Phase 0 exit criteria (sign-off gate)

Phase 0 is complete — and Phase 1 (writing the crypto/auth core) may begin — **only**
when a security-literate reviewer confirms all of the following:

1. [ ] **Adversary completeness** — DA-1…DA-7 are the right in-scope set; DA-8 is
       correctly out of scope; the malicious-operator-as-primary stance is accepted.
2. [ ] **Property coverage** — P1…P14 each map to a control in CRYPTO-SPEC.md (§14
       matrix verified), and each is falsifiable/testable.
3. [ ] **Crown-jewel reduction holds** — §10's claim (every server-side path to AS1 is
       forced onto a human secret or device compromise) is sound.
4. [ ] **Residual register accepted** — R-1…R-9 are acknowledged with their stated
       mitigations and acceptance rationale; specifically R-1 (offline dict.), R-2
       (code delivery), R-3 (recovery loss) are accepted *with* the named conditions.
5. [ ] **STRIDE + LINDDUN** surfaces no unlisted threat to AS1.
6. [ ] **Honesty obligations** (LINDDUN-Unawareness, §12) are committed to in the
       user-facing copy — recovery loss, metadata, web-tier trust, MVP caveat.
7. [ ] **Argon2id parameters** (CRYPTO-SPEC §1.2/§6.1, the `[TUNE+REVIEW]` items) are
       benchmarked and approved — the single biggest lever on R-1.
8. [ ] **Open dependencies flagged for their owners** — legal items to a lawyer
       (BLUEPRINT §10); operational items (AS9/R-6) to the operator.

**Until every box is checked, the project does not write code that touches user PII.**
This document, BLUEPRINT.md, and CRYPTO-SPEC.md are revised together whenever the
architecture changes.
