# vanish — Phase 0 Review Packet (Reviewer Brief)

**Purpose:** Orient two external reviewers — a **cryptographer** and a **lawyer** — to
exactly what they are being asked to certify, so the Phase 0 blocking gate can close.
**This is a cover document.** It points at the design docs; it does not restate them.
**Deliverable:** ROADMAP.md item 0.4.
**Date:** 2026-06-16

**The packet (read in this order):**
1. [BLUEPRINT.md](./BLUEPRINT.md) — product & security design, delivery model, compliance flags (§10).
2. [THREAT-MODEL.md](./THREAT-MODEL.md) — adversaries, properties P1–P14, STRIDE/LINDDUN, residual register.
3. [CRYPTO-SPEC.md](./CRYPTO-SPEC.md) — the implementable mechanism; **the cryptographer's primary target.**
4. [ROADMAP.md](./ROADMAP.md) — sequencing; Phase 0 is a gate (this review *is* that gate).

---

## 1. What this product is, and the claim you're validating

**vanish** is evolving from a single-user CLI (data-broker registry + breach audit +
CCPA/GDPR letter generation + an identifier-free local tracker) into a paid, multi-user
**zero-knowledge footprint-monitoring** app (native-first, Tauri). Users monitor and
shrink their own digital footprint — breach exposure, data-broker presence, removal
progress — via a dashboard.

**The core security claim under review:** *the operator cannot read any user's PII.*
What sits server-side is ciphertext plus a login verifier and non-sensitive metadata —
nothing the operator can decrypt. A server breach, a malicious operator, or a subpoena
yields no readable user data. Per-user isolation is **cryptographic, not access-control**
(a successful IDOR yields only ciphertext under a key the attacker lacks).

**Your job:** confirm the mechanism in CRYPTO-SPEC.md actually delivers that claim
(cryptographer), and that the claim can be made lawfully and operated legally (lawyer).
**No key-handling, auth, or PII-touching code has been written**, and none will be until
you sign off — that is the gate (§4).

---

## 2. For the cryptographer

**Scope — review these, precisely:**
- **CRYPTO-SPEC §3–4** — key derivation and the **master-key envelope**: the
  password→`STRETCHED`→`ENC_KEY`/`AUTH_KEY` split (§3.3), the random `MASTER_KEY`, the
  `wrap`/`unwrap` construction, exact byte layout, and **AAD binding** (slot/user/
  param-version) in §4.1–§4.3.
- **CRYPTO-SPEC §8** — the **per-event wire tables** (signup, login, sync, password
  change, recovery): what crosses TB-NET, what the server stores, what it can/cannot
  derive.
- **CRYPTO-SPEC §13** — the **certification checklist**; your sign-off is essentially
  confirming each item holds given §1–§11.

Cross-reference THREAT-MODEL §6 (properties P1–P14) and §14 (traceability matrix) — each
property should map to a real control you can confirm in the spec.

**The exact questions you must be able to answer (from §13):**
- Can the server ever obtain `ENC_KEY` or `MASTER_KEY`? *(spec answer: no)*
- Is `AUTH_KEY` cryptographically independent of `ENC_KEY` — does learning one yield the other? *(no)*
- Are the two wrapped-key copies opaque to the server and **non-interchangeable** (slot/user/param-bound)? *(yes)*
- Is any AEAD nonce ever reused under a key; is the 24-byte random-nonce strategy collision-safe at scale? *(no reuse / yes safe)*
- Does every ciphertext authenticate its context, so blob-swap and param-downgrade are detectable? *(yes)*
- Does a successful IDOR yield only ciphertext for a key the attacker lacks? *(yes)*
- Does using the recovery code **rotate and invalidate** it; do password-change and recovery re-wrap `MASTER_KEY` **without re-encrypting the vault**? *(yes / yes)*
- Is the auth mechanism **token-only** (nothing key-bearing) and swappable MVP↔OPAQUE without touching the envelope? *(yes)*
- Is all randomness from a named CSPRNG, every primitive a direct libsodium call (no hand-rolled or novel composition)? *(yes)*

**Two design choices flagged for your second opinion** (we made a call; please confirm or challenge):
1. **AUTH/ENC split via a single Argon2id → BLAKE2b subkeys** (`crypto_kdf`,
   CRYPTO-SPEC §1.3, §3.3) — one expensive Argon2id, then cheap independent subkeys —
   rather than two separate Argon2id runs. Is the domain separation and independence
   sound as specified?
2. **XChaCha20-Poly1305 with random 24-byte nonces + AAD binding** (§1.4, §4.1, §5)
   chosen over `crypto_secretbox` specifically to get authenticated associated data.
   Is XChaCha + random-nonce the right call here over a counter scheme or AES-GCM?

**The one judgment call we most need ruled on:**
> **Does the MVP residual in CRYPTO-SPEC §7.1 (an offline dictionary attack on the
> password before the OPAQUE upgrade) undermine the zero-knowledge claim *as it will be
> marketed*?** In MVP, a malicious server / DB thief holding `auth_verifier` + salts can
> mount an offline dictionary attack bounded by Argon2id cost; for a weak password this
> recovers `ENC_KEY` → the vault. OPAQUE (a later upgrade, §6.2) closes it. **Rule on
> whether the MVP may honestly use "zero-knowledge" language, or whether that language
> must wait for OPAQUE** — and if MVP may use it, what caveat wording is required
> (this directly drives the lawyer's ToS-accuracy review and ROADMAP Phase 5 launch
> item #2). The mitigations we plan for MVP: enforced strong-passphrase policy +
> benchmarked high Argon2id cost (the §3 deliverable below).

**Also needed from you:** sign-off on the **Argon2id `[TUNE+REVIEW]` parameters**
(CRYPTO-SPEC §1.2, §6.1) once benchmarked — this is the single biggest lever on the
§7.1 residual (see §3 below). You approve the final `opslimit`/`memlimit`.

---

## 3. The Argon2id benchmark (parallel input you'll sign off on)

ROADMAP item 0.3: parameters are benchmarked on the lowest-end target device, choosing
the highest cost that keeps unlock under ~1 s, never below 64 MiB, recorded as
`kdf_params` v1. We will hand you the numbers; **your approval of them is part of the
gate.** Because they bound the §7.1 attack, they're not a detail — they're load-bearing.

---

## 4. For the lawyer

**Scope — the BLUEPRINT §10 questions, stated as decisions we need *before launch*:**

1. **Data-broker registration (CA / OR / TX / VT).** Does a tool that helps an
   individual file their *own* removals — and that **stores no readable personal data
   and sells nothing** — incur any data-broker registration obligation in these states?
   We believe we are an agent *for* the consumer, not a seller of personal data;
   **confirm or correct that characterization per state.**
2. **Breach-notification duties.** If *we* are breached, our store is **ciphertext with
   no operator-held key** (see THREAT-MODEL §5, CRYPTO-SPEC §4.3). Do encrypted-at-rest
   / no-key safe-harbor provisions exempt us from notification in the target
   jurisdictions, and under what conditions?
3. **ToS / privacy-policy accuracy.** Our public security claims must match the *actual*
   crypto guarantees — including the MVP caveat the cryptographer rules on in §2.
   **Review the claims for accuracy** (misstating the security model is itself exposure,
   e.g. FTC "deceptive practices"), and confirm the disclosures we must make: metadata
   the server *can* see (THREAT-MODEL AS7 / §12), and **recovery = possible permanent
   data loss** (lose both password and recovery code → unrecoverable, by design).
4. **Authorized-agent line (the one that scopes v1).** v1 is **tool, not agent**: the
   user sends their own removal letters; **the server never submits on a user's behalf**
   (CRYPTO-SPEC §5.1). Does this keep us clear of CCPA/GDPR **authorized-agent**
   obligations? And **specifically: what would trip those requirements** — i.e., what
   may we *not* add in v1 without crossing into agent territory? (This fences the
   deferred agent-submission feature; see §5.)

---

## 5. Out of scope for this review round

Do **not** spend time on these — they are deferred past Phase 0 and will get their own
review when/if they happen (ROADMAP "Post-v1"):
- **Agent-submission** of removals (the server filing for users) — fenced behind item 4 above.
- **OPAQUE implementation** — a later upgrade; here it matters only as the thing that
  *closes* the §7.1 residual (relevant to the §2 judgment call, not to be reviewed as code).
- **Dashboard / UX** (BLUEPRINT §8), scanning internals, the web tier, multi-device sync details.
- **Anything past Phase 0** — Phases 1–5 (ROADMAP) are downstream of your sign-off.

---

## 6. What your sign-off unblocks

This review **is** the Phase 0 gate. Per **ROADMAP Phase 0 exit criteria**, Phase 0
closes — and Phase 1 (writing the crypto/auth core) may begin — only when **all** of:

1. **Cryptographer sign-off** obtained on CRYPTO-SPEC §3–4, §8, §13 — in writing.
2. **Lawyer sign-off** obtained on BLUEPRINT §10; "tool not agent" v1 confirmed clear.
3. **Argon2id parameters** benchmarked, chosen, **reviewer-approved**, recorded as `kdf_params` v1.
4. THREAT-MODEL §17 checklist fully checked.
5. Any review-driven changes folded back into all three design docs (revised together).

> **Until 1–5 are done, no key-handling / auth / PII code exists.** If your review
> requires design changes, we loop back into Phase 0 rather than starting to code "the
> parts that won't change." Two specific outputs we need in writing: the cryptographer's
> **ruling on the §7.1 ZK-language judgment call** (§2) and the lawyer's **authorized-agent
> determination** (§4.4) — those two gate the public security copy and the v1 feature line.

**Thank you — we've tried to point you at exactly what matters and nothing more.**
