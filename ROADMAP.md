# vanish — Implementation Roadmap (Phase 0 → launchable v1)

**Status:** Planning document. Sequences the build from the three Phase 0 design
artifacts to a launchable v1. **It does not relax any gate those documents set.**
**Reads as prerequisite:** [BLUEPRINT.md](./BLUEPRINT.md),
[CRYPTO-SPEC.md](./CRYPTO-SPEC.md), [THREAT-MODEL.md](./THREAT-MODEL.md).
**Date:** 2026-06-16

> **The governing rule of this roadmap.** Phase 0 is a **blocking gate**, not a
> parallel track. Two external sign-offs (crypto review + legal review) and the
> Argon2id parameter benchmark must complete **before any key-handling, auth, or
> PII-touching code is written.** Every phase below is **sequential** — this is a
> solo-developer plan, not ten concurrent workstreams. Where a step needs an outside
> reviewer or a human decision, it is flagged, not assumed away.

---

## Legend

- 🚧 **GATE** — a hard stop. Downstream work may not begin until it clears.
- 📄 **Governs** — the Phase 0 document section that is the source of truth for the phase.
- 👤 **Human-in-loop** — needs an external reviewer or a decision only a person can make.
- ✅ **Exit criteria** — the checklist that closes the phase.

**v1 scope guardrails (true for the entire roadmap):**
- **Tool, not agent.** The server never submits removals on a user's behalf in v1
  (CRYPTO-SPEC §5.1). Agent-submission is **out of v1**, fenced behind the legal
  review as a *possible* later phase (see §Post-v1).
- **OPAQUE is a later upgrade, not a v1 blocker** — but the MVP residual (offline
  dictionary attack on the password, CRYPTO-SPEC §7.1 / THREAT-MODEL R-1) must be
  acknowledged in launch criteria, and **user-facing security copy must match the MVP
  reality, not the post-OPAQUE ideal** (Phase 5 checklist item).
- **Native-first (Tauri)** per BLUEPRINT §6. Web tier is explicitly out of v1.

---

## At-a-glance sequence

```
Phase 0 ──🚧GATE🚧──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4 ──► Phase 5 ──► v1 LAUNCH
(design &              (crypto/    (vault &    (on-device  (dashboard  (harden &
 external review)       auth core)  sync)       scanning)   /UX)        launch prep)

   No PII-touching code exists before the Phase 0 gate clears. ───────────────┘
```

Rough solo-dev effort (calendar, not a commitment — external reviews dominate the
critical path early): Phase 0 remaining ≈ blocked on reviewers; P1 ≈ 3–5 wks;
P2 ≈ 2–3 wks; P3 ≈ 2–3 wks (mostly porting existing CLI logic); P4 ≈ 3–4 wks;
P5 ≈ 2–4 wks + external test turnaround.

---

## Phase 0 — Design & Review  🚧 **BLOCKING GATE**

📄 **Governs:** BLUEPRINT §9, §10; CRYPTO-SPEC §1.2, §3–4, §8, §13; THREAT-MODEL §17.

The crypto envelope and threat model are designed; what remains is **independent
verification** and the one empirical input the spec deferred. **No implementation
phase starts until this closes.** This is a no-code-downstream rule.

### Already done (deliverables in hand)
- ✅ BLUEPRINT.md — product/security design, delivery recommendation, compliance flags.
- ✅ CRYPTO-SPEC.md — primitives, key hierarchy, envelope, recovery, wire tables, reviewer checklist.
- ✅ THREAT-MODEL.md — adversaries, properties P1–P14, STRIDE/LINDDUN, residual register, exit criteria.

### Remaining work (the gate itself)

| # | Deliverable | Owner | Notes |
|---|-------------|-------|-------|
| 0.1 👤 | **External cryptographer review** | Outside expert | Must cover **CRYPTO-SPEC §3–4 (envelope: derivation, wrap/unwrap, AAD binding), §8 (per-event wire tables), and the §13 certification checklist.** Reviewer confirms P1–P14 (THREAT-MODEL §6) each map to a real control. |
| 0.2 👤 | **External legal review** | Lawyer | Resolve **BLUEPRINT §10**: data-broker registration (CA/OR/TX/VT), breach-notification duties, ToS/privacy-policy accuracy, **authorized-agent** characterization. Confirms the "tool not agent" v1 stance keeps us clear; defines what would change if agent-submission is ever added. |
| 0.3 👤 | **Argon2id parameter benchmark** `[TUNE+REVIEW]` | Dev + reviewer | Benchmark `opslimit`/`memlimit` (CRYPTO-SPEC §1.2) on the **lowest-end target device**; pick highest cost keeping unlock < ~1 s; never below 64 MiB. Record as `kdf_params` v1. **This is the single biggest lever on R-1.** Reviewer approves final numbers. |
| 0.4 | **Reviewer brief / scope-of-work** | Dev | One page pointing 0.1 at exactly what to certify (envelope, wire tables, §13 + THREAT-MODEL §17 gate). Produce *before* engaging the reviewer. |
| 0.5 👤 | **Security-claims pre-draft** | Dev | Draft the public security wording now, matched to **MVP** crypto state (acknowledging R-1, recovery-loss, metadata). Locked/verified later in Phase 5; drafted here so reviewers can sanity-check honesty early. |

### ✅ Exit criteria (all required to open Phase 1)
1. [ ] Cryptographer sign-off obtained on CRYPTO-SPEC §3–4, §8, §13 — **in writing.**
2. [ ] Lawyer sign-off obtained on BLUEPRINT §10; "tool not agent" v1 confirmed clear.
3. [ ] Argon2id parameters benchmarked, chosen, reviewer-approved, recorded as `kdf_params` v1.
4. [ ] THREAT-MODEL §17 checklist fully checked (adversary completeness, property coverage, residual register accepted, honesty obligations committed).
5. [ ] Any review-driven spec changes folded back into all three docs (they are revised *together*).

🚧 **GATE:** Until 1–5 are done, **zero** key-handling/auth/PII code exists. If the
reviewer requires design changes, loop back into Phase 0 — do not start coding "the
parts that won't change."

---

## Phase 1 — Crypto/Auth Core (in isolation, no product features, no PII)

📄 **Governs:** CRYPTO-SPEC §1 (primitives), §3 (derivation), §4 (envelope), §6
(AuthModule), §8.4–§8.5 (change/recovery); THREAT-MODEL P1–P10, P13.
**Depends on:** Phase 0 gate fully closed.

Build and exhaustively test the cryptographic envelope **with no application data** —
test vectors only. This is the foundation everything else sits on; it ships nothing
user-facing.

### Deliverables
- **D1.1** libsodium integration in the native (Rust/Tauri) core; **all crypto in the
  native layer, never the webview** (THREAT-MODEL TB-PROC).
- **D1.2** KDF path: Argon2id → `STRETCHED` → `crypto_kdf` subkeys `ENC_KEY`/`AUTH_KEY`
  with the exact context/subkey-ids (CRYPTO-SPEC §1.3, §3.3); NFC password
  normalization (§9).
- **D1.3** Master-key envelope: `wrap`/`unwrap` with XChaCha20-Poly1305, the exact
  73-byte layout and AAD binding (slot/user/param-version) (CRYPTO-SPEC §4.1–§4.2).
- **D1.4** Recovery-code lifecycle: 160-bit generation/encoding (Crockford base32 +
  checksum), one-time display flow, **mandatory rotation on use** (CRYPTO-SPEC §3.4,
  §8.5.1).
- **D1.5** Swappable **AuthModule** interface with the **MVP mode** implemented
  (AUTH_KEY over TLS; server stores `crypto_pwhash_str` verifier); OPAQUE left as a
  documented seam, not built (CRYPTO-SPEC §6).
- **D1.6** Password-change and recovery flows: re-wrap `MASTER_KEY` only, **never
  re-encrypt the vault** (CRYPTO-SPEC §8.4–§8.5).
- **D1.7** Key-lifecycle hygiene: memory-only keys, `sodium_memzero`/`sodium_malloc`,
  zeroize on lock/logout (CRYPTO-SPEC §10).

### Test strategy (this is the proof the phase produces)
- **T1.a** Known-answer tests (KATs) for every crypto step against fixed vectors —
  derivation, wrap/unwrap, blob AEAD — so cross-platform determinism is locked
  (CRYPTO-SPEC §9). These become regression vectors forever.
- **T1.b** **Property test: the server never receives `ENC_KEY`/`MASTER_KEY`.** Model
  the AuthModule/sync boundary and assert no code path emits those bytes across
  TB-NET (THREAT-MODEL P1).
- **T1.c** **Opacity grep test** (mirrors the existing CLI's raw-DB-grep invariant):
  run a full wrap+encrypt cycle with known plaintext, then grep the *stored bytes* for
  the plaintext/keys — must be absent. Direct descendant of the CLI's
  "grep the .db for `jane@example.com`" test.
- **T1.d** Negative/integrity tests: tampered AAD, wrong slot, cross-user envelope,
  downgraded param-version → decrypt **fails closed** (THREAT-MODEL P4, P6).
- **T1.e** Recovery test matrix: forgot-password→recovery→new-password; **old recovery
  code invalid after use** (P9); blobs unchanged across change/recovery (P8).
- **T1.f** Nonce-uniqueness check across many encryptions (P5).

### ✅ Exit criteria
1. [ ] All KATs pass on every target platform (determinism proven).
2. [ ] T1.b and T1.c green — **demonstrated**, not asserted (R-1 aside, the ZK boundary holds for keys/PII).
3. [ ] Integrity/negative tests fail closed.
4. [ ] Recovery rotation verified; vault-immutability-on-rekey verified.
5. [ ] 👤 Crypto core reviewed (self + ideally a second pass from the Phase 0 reviewer) before anything is layered on it — THREAT-MODEL "gate the core" note.

🚧 **GATE:** the crypto core is frozen and reviewed before Phase 2 builds on it. No
product schema or PII flows until D1.* + T1.* are signed off.

---

## Phase 2 — Vault & Sync

📄 **Governs:** CRYPTO-SPEC §5 (blob layout + AAD), §8.3 (sync wire table);
BLUEPRINT §3 (data model); THREAT-MODEL P6, P7, P11, P12, R-4.
**Depends on:** Phase 1 frozen.

Encrypted vault storage + thin sync. The server stays an opaque blob store; reuse the
CLI's **identifier-free schema discipline** at the server layer.

### Deliverables
- **D2.1** Per-record AEAD encrypt-before-send under `MASTER_KEY`, with AAD binding
  `user_id`/`record_id`/schema-version (CRYPTO-SPEC §5).
- **D2.2** Canonical-JSON record serialization for determinism (CRYPTO-SPEC §9).
- **D2.3** Thin sync API: store/fetch opaque blobs by `record_id`; **no semantic
  columns** beyond the disclosed metadata set (AS7). Mirrors the CLI's "store the
  fact, never the identifier" server-side.
- **D2.4** Row-level authorization on every blob endpoint — **defense-in-depth**, not
  the boundary (THREAT-MODEL P7, DA-3).
- **D2.5** Session/refresh token handling; tokens are **not keys** (CRYPTO-SPEC §6.3).
- **D2.6** Conflict/versioning handling for multi-device sync (blob-format + schema
  versions, CRYPTO-SPEC §11).

### Test strategy
- **T2.a** Encrypt-before-send enforced: assert no endpoint accepts plaintext records.
- **T2.b** Server-side opacity: a DB dump greps clean (extends T1.c to real records).
- **T2.c** AAD record-binding: a blob cannot be replayed under a different `record_id`/user.
- **T2.d** Authz/IDOR unit tests: cross-user fetch denied **and**, if forced, returns
  only undecryptable ciphertext (P7). (Full adversarial IDOR pass is Phase 5.)
- **T2.e** Metadata audit: enumerate every stored field; confirm it matches AS7
  exactly — no accidental semantic leakage (P12, R-4).

### ✅ Exit criteria
1. [ ] Vault round-trips (encrypt→sync→fetch→decrypt) across two devices.
2. [ ] Opacity + AAD-binding + authz tests green.
3. [ ] Stored-field inventory matches THREAT-MODEL AS7; deviations documented or removed.
4. [ ] No plaintext-accepting endpoint exists.

---

## Phase 3 — Scanning (client-side / session-bound)

📄 **Governs:** BLUEPRINT §7; CRYPTO-SPEC §5, §5.1; THREAT-MODEL DA-4, R-9, TB-EXT.
**Depends on:** Phase 2 (results need the vault to land in).

Wrap the **existing vanish CLI core** as the on-device scan engine. **No server-side
plaintext scanning.** This phase is mostly *porting proven logic*, not new crypto.

### Deliverables
- **D3.1** Port CLI `audit` (HIBP) to run **on-device**; use the **k-anonymity range
  API** where possible to minimize what HIBP sees (BLUEPRINT §7, R-9).
- **D3.2** Port CLI broker `verify` + registry checks to run on-device against the
  bundled registry.
- **D3.3** Port CLI letter generation (CCPA/GDPR/generic) to render **in-memory,
  client-side**; identifiers **never** sent to or persisted by the server
  (CRYPTO-SPEC §5.1) — the CLI's identifier-free invariant, preserved.
- **D3.4** Scan results → vault: assemble in memory, encrypt under `MASTER_KEY`, store
  as blobs (Phase 2 path). Plaintext never crosses TB-NET.
- **D3.5** Exposure-history snapshots written as encrypted records (feeds the Phase 4
  graph).
- **D3.6** Honest "monitoring" semantics: scan-on-open + **opt-in local scheduled
  scan** (on-device); **no** server-side always-on monitoring claim (BLUEPRINT §7).
- **D3.7** 👤 **No "look up a person" feature** — only the account holder's own
  identifiers, entered on-device (THREAT-MODEL DA-4). Enforce as a product invariant.

### Test strategy
- **T3.a** Scan-to-vault: identifiers used in a scan/letter never appear in stored
  blobs or any request body (extend the grep invariant to the scan path; CRYPTO-SPEC §5.1).
- **T3.b** Reuse/port the CLI's existing audit/broker/letter tests as the engine's
  regression suite.
- **T3.c** Confirm no scanning endpoint exists server-side (native model — there is no
  S-SCAN in v1; THREAT-MODEL §3.3 web delta stays out of scope).

### ✅ Exit criteria
1. [ ] HIBP + broker scans run fully on-device; results encrypted before storage.
2. [ ] Letter identifiers provably never leave the device (T3.a green).
3. [ ] Ported CLI tests pass in the new engine.
4. [ ] "Monitoring" copy matches reality (scan-on-open / opt-in local schedule), not "24/7."

---

## Phase 4 — Dashboard / UX

📄 **Governs:** BLUEPRINT §8 (seven screens), §6 (Tauri/native-first); THREAT-MODEL
P12, P13, LINDDUN-Unawareness.
**Depends on:** Phase 3 (data to visualize).

The seven screens, **charts rendered from decrypted-in-memory data only** (server
ships ciphertext). Native-first (Tauri).

### Deliverables (BLUEPRINT §8)
- **D4.1** Footprint Overview (exposure score + headline counts).
- **D4.2** Exposure-over-time graph (from decrypted history snapshots).
- **D4.3** Breaches panel (reuse CLI severity classifier).
- **D4.4** Brokers panel (status lifecycle per registry category).
- **D4.5** Removal tracker (Kanban/timeline mirroring CLI `track`/`status`; letter
  rendered client-side, only the *fact* stored — CRYPTO-SPEC §5.1).
- **D4.6** Scan/refresh action (triggers Phase 3 scan, animates deltas).
- **D4.7** Security & recovery screen: ZK status in plain language, re-download/verify
  recovery code, change password, **and the honest-limitations disclosures**
  (recovery-loss, metadata, MVP caveat — LINDDUN-Unawareness, THREAT-MODEL §12).
- **D4.8** "Decrypted on your device" indicator on PII-bearing screens (BLUEPRINT §8 UX principle).

### Test strategy
- **T4.a** Charts/render derive from decrypted-in-memory data; no plaintext persisted
  to disk by the UI layer (P13 — webview holds display data only, transiently).
- **T4.b** Recovery/disclosure copy present and prominent (feeds Phase 5 launch check).
- **T4.c** UX walkthrough of full lifecycle: signup → scan → letter → track → recovery.

### ✅ Exit criteria
1. [ ] All seven screens functional against real (encrypted) data.
2. [ ] No PII written unencrypted by the UI layer.
3. [ ] Honest-limitation disclosures visible in-product (not buried).

---

## Phase 5 — Hardening & Launch Prep  🚧 **LAUNCH GATE**

📄 **Governs:** THREAT-MODEL §11 (STRIDE), §13 (residual register), §17 (exit gate);
BLUEPRINT §10 (legal), §11 (risks); CRYPTO-SPEC §7.1 (MVP caveat).
**Depends on:** Phases 1–4 complete.

Security testing, the launch checklist, and an **external** pre-launch test. Nothing
ships until this gate clears.

### Deliverables
- **D5.1** 👤 **External pre-launch security test** (penetration test / code audit of
  the implemented system, not just the design). Distinct from the Phase 0 design review.
- **D5.2** **IDOR / object-level-authorization pass (OWASP API #1)** — crypto isolation
  *defends* it (P7), but the **access layer must still be tested**: enumerate every
  object endpoint, attempt cross-user access, confirm both denial and ciphertext-only
  fallback (THREAT-MODEL DA-3).
- **D5.3** STRIDE walkthrough against the *built* system (THREAT-MODEL §11); confirm no
  unlisted threat to AS1.
- **D5.4** Residual-risk reconciliation: R-1…R-9 (THREAT-MODEL §13) each verified as
  *still* accepted-with-mitigations in the shipped product (esp. R-1 password policy +
  benchmarked Argon2id; R-4 metadata disclosed).
- **D5.5** Incident-response plan exists (breach handling, key-compromise comms,
  coordinated disclosure) — owns R-2/R-6 operationally.
- **D5.6** Supply-chain hardening: reproducible builds, code-signing with
  hardware-protected keys, minimal infra (THREAT-MODEL R-6; the solo-operator custody risk).
- **D5.7** Strong-passphrase policy enforced at signup (the primary R-1 mitigation,
  CRYPTO-SPEC §7.1).

### Launch checklist (all required) 👤
1. [ ] **Legal docs live & accurate** — ToS + privacy policy reflecting the ZK model,
       metadata visibility, recovery-loss; BLUEPRINT §10 questions resolved by counsel.
2. [ ] **Security copy matches actual crypto state** — public claims describe the
       **MVP** reality (acknowledge the R-1 offline-dictionary residual, CRYPTO-SPEC
       §7.1), **not** the post-OPAQUE ideal. No "even we can never attack your data"
       while shipping MVP. *(This is the explicit "copy reviewed against crypto state"
       item the brief requires.)*
3. [ ] **Recovery-loss warning prominent** — lose-both-secrets = unrecoverable, stated
       aggressively at signup and on the security screen (P14, R-3).
4. [ ] **Incident-response plan exists** (D5.5).
5. [ ] **External security test passed** (D5.1) with findings remediated or risk-accepted.
6. [ ] **IDOR/authz pass clean** (D5.2).
7. [ ] **Argon2id params shipped = the Phase 0 benchmarked values** (no last-minute downgrade).
8. [ ] **Metadata disclosure** present in privacy policy (R-4, P12).

### ✅ Exit criteria
- [ ] Every launch-checklist box checked. **Any unchecked box blocks launch.**

🚧 **GATE → v1 LAUNCH.**

---

## Post-v1 (explicitly out of the v1 roadmap)

Listed so they are *not* silently smuggled into v1. Each re-opens design/threat docs.

| Item | Why deferred | Gate to start |
|------|--------------|---------------|
| **OPAQUE auth upgrade** | Removes the R-1 offline-dictionary residual (CRYPTO-SPEC §6.2, §7.1). Not a v1 blocker because MVP mitigations bound the risk. **Use a vetted implementation — never hand-rolled.** | Swap behind the existing AuthModule seam; envelope untouched. Re-run Phase 1 auth tests. |
| **Agent-submission of removals** | v1 is **tool, not agent** (CRYPTO-SPEC §5.1). Submitting on a user's behalf likely triggers **authorized-agent** obligations (BLUEPRINT §10). | 👤 **Requires the legal review (0.2) to clear it first**, plus a new threat-model pass on the changed data flow. |
| **Web convenience tier** | Re-served crypto JS weakens the trust model (BLUEPRINT §2.1; THREAT-MODEL R-2, R-8). | Separate threat-model + review of S-SCAN transient-plaintext handling; disclosed weaker trust. |
| **Metadata-leak reduction** | R-4 accepted/disclosed for v1. | Padding/bucketing/batched sync; revisit THREAT-MODEL §12. |
| **Shamir social recovery** | Adds resilience but trustee attack surface (BLUEPRINT §4.4). | New crypto-spec section + review. |

---

## Cross-phase principles (true throughout)

1. **Sequential, solo-realistic.** One phase at a time; each gated by the prior. Early
   calendar time is dominated by *external reviewer turnaround* (Phase 0), not coding —
   plan for it.
2. **The three docs are living and revised together** whenever the architecture
   changes (THREAT-MODEL §17). A new endpoint/field/delivery-model re-opens the threat
   model before it ships.
3. **Honesty is a launch requirement, not polish.** Security copy tracks the *real*
   crypto state at all times (LINDDUN-Unawareness, THREAT-MODEL §12).
4. **No gate is the roadmap's to relax.** Phase 0's no-code rule, the tool-not-agent
   v1 boundary, and the launch checklist are inherited from the design docs and are
   non-negotiable here.
