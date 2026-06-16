# Phase 2 — Kickoff Checklist (Vault & Sync)

**Use when:** Phase 1 is frozen (board #10 done) and Phase 2 (board #11) has unblocked.
**Do not start any item below until §0 is fully checked.**
📄 **Governs:** CRYPTO-SPEC §5 (blob layout + AAD), §8.3 (sync wire table), §11
(versioning); BLUEPRINT §3 (data model); THREAT-MODEL P6, P7, P11, P12, R-4.
**Scope:** the server appears for the first time. It is an **opaque blob store** — it
stores ciphertext + the disclosed metadata set and nothing else. Still no PII in the
clear, still no product features beyond store/fetch.

> **The one idea this phase must not violate:** the server is untrusted for
> confidentiality (THREAT-MODEL DA-2). Everything it receives is already ciphertext;
> everything it stores is opaque; row-level authz is *defense-in-depth*, never the
> security boundary. If any item below would let the server see plaintext, it's wrong.

---

## §0 — Entry gate (Phase 1 must be truly done)

**Hard stop.** Phase 2 builds directly on the crypto core; a soft Phase 1 poisons it.

- [ ] **Phase 1 DoD met** (PHASE-1-KICKOFF §4) — KATs, the server-never-sees-`ENC_KEY`
      property test, and the opacity grep are all green and demonstrated.
- [ ] **Crypto core frozen + reviewed** — the envelope/AEAD/AuthModule API is stable;
      Phase 2 consumes it, does not modify it.
- [ ] **`MASTER_KEY` encrypt/decrypt + AEAD-with-AAD helpers exist and are stable** —
      Phase 2 calls them; it must not reach for raw libsodium itself.
- [ ] **AuthModule issues session tokens** (CRYPTO-SPEC §6.3) — Phase 2's endpoints
      authorize against those tokens; tokens are not keys.

> If Phase 1 changed anything in CRYPTO-SPEC §5/§8.3 during review, re-read those
> sections against the sign-off before starting.

---

## §1 — Sprint setup (server + client-sync scaffolding)

- [ ] Stand up the thin **sync API** service skeleton (no business logic yet).
- [ ] Define the **server schema** from CRYPTO-SPEC §5 + BLUEPRINT §3 — and **only**
      these columns. The `footprint_blobs` row is exactly:
      `{ record_id, user_id, blob, created_at, blob_format_version }`. **No semantic
      columns** (no breach name, broker id, type, dates). This is the CLI's
      identifier-free discipline, moved server-side.
- [ ] Wire **log hygiene from line one**: request/response bodies, blobs, and tokens
      are **never** logged; disable framework body-capture, APM payload capture, and
      error-tracker breadcrumbs that include bodies. (The "forgotten log sink" is the
      single most likely leak — treat every default as hostile.)
- [ ] Add a **stored-field allowlist test** that fails CI if any column outside the
      §5 schema (+ AS7 metadata) appears — locks the opacity guarantee into CI.
- [ ] Create the client **vault module** that sits on top of the Phase 1 crypto core:
      serialize → encrypt → send; receive → decrypt → deserialize.

---

## §2 — Build order (each item cites the spec; implement in sequence)

1. [ ] **Canonical-JSON record serialization** — deterministic (sorted keys, fixed
       number/UTF-8 conventions) so re-encrypts are byte-stable (CRYPTO-SPEC §9, §5).
2. [ ] **Record model + `record_id`** — client-generated UUIDv4 per record; opaque to
       the server (CRYPTO-SPEC §5).
3. [ ] **Per-record encrypt-before-send** — AEAD under `MASTER_KEY` with
       `AAD = "vanish.blob.v1" || user_id || record_id || schema_version`; the exact
       blob layout `ver||nonce||ct+tag` (CRYPTO-SPEC §5). **Encryption happens on the
       client; the server only ever receives the blob.**
4. [ ] **Sync write endpoint** — accepts `{record_id, blob, blob_format_version}` +
       session token; stores opaque; **rejects any plaintext-bearing payload** (§8.3).
5. [ ] **Sync read endpoint** — returns the user's blobs; client decrypts in memory.
6. [ ] **Row-level authorization** on every blob endpoint — scope strictly to the
       token's `user_id`; **defense-in-depth, not the boundary** (THREAT-MODEL P7, DA-3).
7. [ ] **Session/refresh token handling** — short-lived access + rotating refresh;
       tokens authorize fetch/write only, carry no key (CRYPTO-SPEC §6.3).
8. [ ] **Multi-device conflict + versioning** — handle two devices writing the same
       `record_id`; carry `blob_format_version` + record `schema_version` so future
       format changes are explicit migrations, never silent reinterpretation (§11).
9. [ ] **Metadata minimization pass** — confirm the only server-visible metadata is the
       disclosed AS7 set (existence, counts, sizes, sync timing); document anything
       extra or remove it (THREAT-MODEL P12, R-4).

---

## §3 — Required test deliverables (mapped to properties)

- [ ] **Encrypt-before-send enforced** — assert no endpoint accepts a plaintext record;
      a plaintext-bearing payload is rejected (T2.a; **P1**).
- [ ] **Server-side opacity grep** — write real records through the full path, dump the
      DB/store, grep for plaintext/identifiers → absent. Extends the Phase 1 opacity
      test to real records (T2.b; **P1/P2**).
- [ ] **AAD record-binding** — a blob cannot be decrypted/replayed under a different
      `record_id` or `user_id` → fails closed (T2.c; **P6**).
- [ ] **Authz / IDOR** — cross-user fetch is denied; and if forced, returns only
      undecryptable ciphertext (crypto isolation holds even if authz is bypassed)
      (T2.d; **P7**). *(Full adversarial IDOR sweep is Phase 5; this is the unit-level pass.)*
- [ ] **Metadata audit** — enumerate every stored field; assert it equals the AS7 set
      exactly; CI allowlist test green (T2.e; **P12, R-4**).
- [ ] **Round-trip across two simulated devices** — encrypt on A, sync, decrypt on B;
      conflict path exercised (DoD #1).
- [ ] **Letter-identifier non-persistence still holds** — the §5.1 invariant carries
      into the synced world: identifiers used to render a letter never reach the server
      (**P11**).

---

## §4 — Definition of Done (Phase 2 exit criteria)

Phase 2 closes — and Phase 3 (board #12) unblocks — only when:

- [ ] Vault round-trips (encrypt → sync → fetch → decrypt) across two devices.
- [ ] Opacity, AAD-binding, and authz tests are green.
- [ ] **Stored-field inventory matches THREAT-MODEL AS7 exactly** — deviations
      documented or removed; CI allowlist enforces it going forward.
- [ ] **No plaintext-accepting endpoint exists** anywhere in the sync surface.
- [ ] Log hygiene verified — no bodies/blobs/tokens in any log sink.

---

## §5 — Standing guardrails (every commit in Phase 2)

- **The server never sees plaintext or keys** — it receives blobs, stores blobs,
  returns blobs. If a feature seems to need server-side plaintext, it belongs on the
  client (or it's a Phase 3 on-device scan, not a sync feature).
- **No semantic columns** — the moment a breach name / broker id / record type lands
  in a server column, the opacity guarantee is broken. Keep it inside the ciphertext.
- **Authz is defense-in-depth, not the wall** — never rely on `user_id` filtering as
  the confidentiality boundary; the crypto is the wall (P7).
- **No logging of bodies, blobs, or tokens** — the highest-probability leak path.
- **Versioned formats only** — new `blob_format_version` / `schema_version`, never a
  reused number with new meaning (§11).
- **No scanning here** — HIBP/broker checks are Phase 3, on-device. Phase 2 is storage
  and transport of already-encrypted data only.

---

## §6 — Board hand-off

On Phase 2 DoD: mark board **#11 completed**, confirm **#12 (Phase 3 — on-device
scanning)** is unblocked, and open the Phase 3 kickoff. The opacity allowlist test and
the two-device round-trip become permanent regression fixtures.
