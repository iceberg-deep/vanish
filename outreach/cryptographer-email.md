# Cryptographer — Reviewer Engagement Email (draft)

Outreach draft to engage the external cryptographer for the Phase 0 review
(see [../REVIEW-PACKET.md](../REVIEW-PACKET.md) §2). Bracketed `[...]` fields are
placeholders to fill before sending. Attach or link the repo/packet under NDA as noted.

---

**Subject:** Paid crypto design review — zero-knowledge envelope, focused scope (Phase 0 gate)

Hi [Reviewer name],

I'm building **vanish**, a privacy-first, zero-knowledge footprint-monitoring app (native/Tauri; libsodium). It's the multi-user evolution of an existing single-user CLI. The core claim I need validated is the load-bearing one: **the operator cannot read any user's PII** — the server holds only ciphertext, a login verifier, and non-sensitive metadata, and per-user isolation is cryptographic rather than access-control.

I'd like to engage you for a **focused design review of the cryptographic spec — no implementation exists yet.** This review is a deliberate blocking gate: no key-handling, auth, or PII-touching code gets written until it clears, so your sign-off is what unblocks the build.

**Scope (bounded, design-only):**
- The master-key envelope — password→`STRETCHED`→`ENC_KEY`/`AUTH_KEY` split, the random `MASTER_KEY`, wrap/unwrap, byte layout, and AAD binding (CRYPTO-SPEC §3–4).
- The per-event wire tables — signup, login, sync, password change, recovery (§8).
- A certification checklist I've pre-written for you to confirm against (§13).

**Two choices I'd value a second opinion on:** (1) a single Argon2id → BLAKE2b (`crypto_kdf`) subkey split for AUTH/ENC rather than two Argon2id runs; (2) XChaCha20-Poly1305 with random 24-byte nonces + AAD, chosen over `crypto_secretbox` for the AAD.

**The one ruling I most need:** the MVP (pre-OPAQUE) leaves an offline dictionary attack on the password bounded by Argon2id cost. **Can the MVP honestly use "zero-knowledge" language, or must that wait for OPAQUE?** — and if it can, what caveat wording is required. There's also a short Argon2id parameter benchmark I'd ask you to approve.

I've written a **2-page reviewer brief (`REVIEW-PACKET.md`)** that orients you fast and points at exactly these sections — plus the full design docs (BLUEPRINT, THREAT-MODEL, CRYPTO-SPEC). Explicitly **out of scope:** OPAQUE implementation, agent-submission, dashboard/UX, anything downstream of this gate.

**Deliverable:** a short written sign-off (or required-changes list) covering §3–4, §8, §13, the two design choices, the ZK-language ruling, and the Argon2id params.

A few logistics:
- Would this kind of focused design review be a fit for you, and what's your **rate / how you prefer to scope it**? My budget is roughly [range].
- I'm hoping for a turnaround by **[target date]** — does that work?
- Happy to send the packet under NDA if you'd like one.

Thanks for considering it — I've tried to make the scope precise and respect your time. Glad to hop on a short call if that's easier.

Best,
[Your name]
[contact]
