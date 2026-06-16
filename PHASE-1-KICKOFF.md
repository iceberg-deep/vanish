# Phase 1 — Kickoff Checklist (Crypto/Auth Core)

**Use when:** the Phase 0 gate has cleared and Phase 1 (the crypto/auth core) is
starting. **Do not start any item below until §0 is fully checked.**
📄 **Governs:** CRYPTO-SPEC §1, §3, §4, §6, §8–§10; ROADMAP Phase 1; THREAT-MODEL
P1–P10, P13.
**Scope reminder:** Phase 1 ships **no product features and no PII** — test vectors
only. It builds and proves the envelope everything else sits on.

---

## §0 — Entry gate (verify the gate ACTUALLY cleared)

**Hard stop.** Every box here must be true before writing a line of crypto code.
These mirror ROADMAP Phase 0 exit criteria; this is the bouncer at the door.

- [ ] **Cryptographer sign-off in hand** (board #7) — written approval of CRYPTO-SPEC
      §3–4, §8, §13.
- [ ] **ZK-language ruling recorded** — the §7.1 judgment call is answered; if MVP may
      not use "zero-knowledge," SECURITY-CLAIMS.md and marketing are already reconciled
      to "end-to-end encrypted."
- [ ] **Legal sign-off in hand** (board #8) — BLUEPRINT §10 resolved; "tool not agent"
      v1 confirmed clear. *(Gates launch, not Phase 1 start — but confirm it's in flight.)*
- [ ] **Final Argon2id params approved** (board #9) — benchmarked on the lowest-end
      target device, reviewer-approved, and **KDF-PARAMS.md updated** with the binding
      `kdf_params` v1 (not the provisional MODERATE placeholder).
- [ ] **Spec deltas folded back** — any change the reviewer required is committed to
      CRYPTO-SPEC / THREAT-MODEL / BLUEPRINT (they are revised *together*) **before**
      coding, so the code targets the reviewed spec, not the pre-review draft.

> If the cryptographer required design changes, this checklist may itself need edits.
> Re-read CRYPTO-SPEC §3–4 and §8 against the sign-off before proceeding.

---

## §1 — Sprint setup (non-crypto scaffolding — safe to do first)

- [ ] Create the native crypto crate/module in the Tauri core (Rust). **All crypto
      lives here, never in the webview** (THREAT-MODEL TB-PROC).
- [ ] Pin the **libsodium** binding + version; record it. No other crypto dependency
      (CRYPTO-SPEC §1.1). Add a CI check that fails if a forbidden crypto lib is imported.
- [ ] Create a `crypto-constants` module from CRYPTO-SPEC §1 + KDF-PARAMS.md:
      `ALG_ARGON2ID13`, SALT/KEY/NONCE/TAG sizes, `crypto_kdf` context `"vanishKD"`,
      subkey ids (1=AUTH, 2=ENC), the approved `kdf_params` v1, AEAD AAD label strings
      (§4.1, §5). **Single source of truth — no magic numbers inline.**
- [ ] Stand up the test harness + a **KAT vector file format** (JSON: inputs →
      expected bytes) so known-answer tests are data-driven and portable (CRYPTO-SPEC §9).
- [ ] Add a `sodium_init()` guard at startup; fail closed if it errors.
- [ ] Wire CI to run the Phase 1 test suite on every target platform (determinism is
      cross-platform — CRYPTO-SPEC §9).

---

## §2 — Build order (each item cites the spec; implement in this sequence)

Dependencies flow downward; do not start an item until the one above is green.

1. [ ] **CSPRNG + encoding helpers** — `randombytes_buf`; Crockford base32 (+checksum);
       NFC password normalization; canonical-JSON serializer (CRYPTO-SPEC §1.5, §3.4, §9).
2. [ ] **Argon2id KDF** — `crypto_pwhash` → `STRETCHED` with approved params (§1.2, §3.3).
3. [ ] **Subkey split** — `crypto_kdf_derive_from_key` → `ENC_KEY` (id 2) and `AUTH_KEY`
       (id 1, MVP only); zeroize `STRETCHED` after (§1.3, §3.3, §10).
4. [ ] **AEAD primitive** — XChaCha20-Poly1305 encrypt/decrypt wrappers with random
       24-byte nonce + AAD, fail-closed on auth failure (§1.4).
5. [ ] **Master-key generation** — `MASTER_KEY = randombytes(32)` (§2, §4.2).
6. [ ] **Envelope wrap/unwrap** — exact 73-byte layout (`ver||nonce||ct+tag`) + AAD
       binding slot/user/param-version, for both password and recovery slots (§4.1–§4.3).
7. [ ] **Recovery-code lifecycle** — 160-bit generation, one-time display contract,
       derive `RECOVERY_KEY`, wrap; **mandatory rotation on use** (§3.4, §8.5.1).
8. [ ] **AuthModule (MVP mode)** — derive/verify path; server stores
       `crypto_pwhash_str` verifier; **outputs only a session token, nothing key-bearing**;
       OPAQUE left as a documented seam (§6). *Do not build OPAQUE.*
9. [ ] **Password-change + recovery flows** — re-wrap `MASTER_KEY` only; **never
       re-encrypt the vault** (§8.4–§8.5).
10. [ ] **Key-lifecycle hygiene** — `sodium_malloc`/`mlock` for long-lived keys;
        `sodium_memzero` on lock/logout; memory-only while unlocked (§10).

---

## §3 — Required test deliverables (the proof this phase produces)

These are not optional; they are the phase's output. Map to THREAT-MODEL properties.

- [ ] **KATs** for every step (derivation, subkeys, wrap/unwrap, AEAD) against fixed
      vectors; run on all platforms → cross-platform determinism locked (T1.a; P-determinism, §9).
- [ ] **Property test: server never receives `ENC_KEY`/`MASTER_KEY`** — model the
      AuthModule/sync boundary; assert no path emits those bytes (T1.b; **P1**).
- [ ] **Opacity grep test** — full wrap+encrypt with known plaintext, then grep the
      *stored bytes* for the plaintext/keys → absent. Direct descendant of the CLI's
      raw-DB-grep invariant (T1.c; **P1/P2**).
- [ ] **Negative/integrity tests** — tampered AAD, wrong slot, cross-user envelope,
      downgraded param-version → decrypt **fails closed** (T1.d; **P4, P6**).
- [ ] **Recovery matrix** — forgot→recover→new-password; **old recovery code invalid
      after use**; blobs unchanged across change/recovery (T1.e; **P8, P9**).
- [ ] **Nonce-uniqueness** check across many encryptions (T1.f; **P5**).
- [ ] **AUTH⊥ENC independence** test — confirm no derivation path links them (**P3**).

---

## §4 — Definition of Done (Phase 1 exit criteria)

Phase 1 closes — and Phase 2 (board #11) unblocks — only when:

- [ ] All KATs pass on every target platform.
- [ ] The property test + opacity grep are **green and demonstrated** (not asserted).
- [ ] All integrity/negative tests fail closed; recovery rotation + vault-immutability
      verified.
- [ ] No PII and no product features exist in this code (scope held).
- [ ] Every primitive is a **direct libsodium call** — no hand-rolled or novel
      composition (CRYPTO-SPEC §1; CI forbidden-import check green).
- [ ] 👤 **Crypto core reviewed and frozen** before Phase 2 builds on it (a second pass
      from the Phase 0 cryptographer is ideal) — ROADMAP "gate the core" rule.

---

## §5 — Standing guardrails (true for every commit in Phase 1)

- **No PII, ever** — test vectors and throwaway values only.
- **Native layer only** — keys never cross into the webview (TB-PROC).
- **No `Math.random`, no counters for nonces, no `localStorage` for keys** (§1.5, §10).
- **Constants come from the `crypto-constants` module** — never inline a size, label,
  or param.
- **Fail closed** — any decrypt/verify failure aborts; never return partial/garbage.
- **Don't build OPAQUE or agent-submission** — both are post-v1, behind their own gates.

---

## §6 — Board hand-off

On Phase 1 DoD: mark board **#10 completed**, confirm **#11 (Phase 2)** is unblocked,
and open the Phase 2 kickoff. Carry the KAT vectors forward as permanent regression
fixtures.
