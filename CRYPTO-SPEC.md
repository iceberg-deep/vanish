# vanish — Cryptographic Specification (Phase 0)

**Status:** Draft for cryptographer review. **No key-handling code may be written until this is signed off** (per BLUEPRINT.md §9, Phase 0 gate).
**Scope:** The exact cryptographic construction for the zero-knowledge footprint-monitoring product designed in [BLUEPRINT.md](./BLUEPRINT.md). Read the blueprint first for threat model (§2), data model (§3), and product framing.
**Audience:** A cryptography-literate reviewer who must be able to certify this design *without making any judgment calls that this document left open*.
**Date:** 2026-06-16

> **This is a design document, not code.** Its job is to remove every degree of
> freedom from the implementer. Where a value genuinely requires empirical tuning
> or reviewer sign-off (Argon2id cost parameters), it is marked **[TUNE+REVIEW]**
> and a default is given. Nothing else is left to implementer discretion.
>
> **Prime directive:** No hand-rolled crypto. Every operation below is a named call
> into a vetted library (libsodium). No novel cipher composition, no custom KDF, no
> "clever" nonce scheme. If a step here cannot be implemented as a direct library
> call, it is a bug in this spec — flag it, do not improvise.

---

## 0. Notation and conventions

- `||` — byte concatenation.
- `randombytes(n)` — `n` bytes from the platform CSPRNG (§1.4).
- `LE32(x)` / `LE64(x)` — little-endian fixed-width encoding of integer `x`.
- All multi-byte length fields are little-endian.
- All stored/transmitted binary is base64url (no padding) at the JSON boundary;
  raw bytes everywhere else. Encoding is **not** a security boundary.
- "Server" = the sync/account backend. "Client/device" = the user's app instance.
- **Vault** = the set of a user's encrypted footprint records (breach hits, broker
  matches, removal-request facts) plus the exposure-history series.
- A value is **"never leaves the device"** iff it is never written to disk
  unencrypted, never sent over any socket, and never passed to any logging/telemetry
  sink. This is an implementation obligation, not just a sentence.

---

## 1. Primitives and libraries

### 1.1 Library

**libsodium** is the single cryptographic dependency.

- **Client (native, recommended per BLUEPRINT.md §6):** the platform's native
  libsodium binding (e.g. `libsodium-sys`/`sodiumoxide` in the Rust/Tauri core, or
  the OS-packaged libsodium). Crypto runs in the native (Rust) layer, **not** in the
  webview JS, so keys never enter the webview heap.
- **Client (web tier, if ever built per BLUEPRINT.md §6/§7):** `libsodium.js`
  (the official WASM/asm.js build). Same primitives, same parameters.
- **Server:** the native libsodium binding for the backend language. The server uses
  libsodium **only** for the auth verifier (§4) and TLS is handled by the platform.
  The server performs **no** vault crypto — it cannot, having no keys.

**Forbidden:** any other crypto library for these operations; WebCrypto; Node
`crypto`; hand-written Argon2/ChaCha/Poly1305; OpenSSL EVP calls for the envelope.
**WebCrypto is explicitly not used anywhere in this spec.** (It lacks Argon2id and
its non-extractable-key model doesn't fit the wrap/unwrap envelope; mixing it in
would add a second, divergent crypto stack. One library, one set of test vectors.)

### 1.2 Password-based KDF — Argon2id

- **Primitive:** Argon2id via libsodium `crypto_pwhash`, algorithm constant
  `crypto_pwhash_ALG_ARGON2ID13`.
- **Salt:** 16 bytes (`crypto_pwhash_SALTBYTES`), random per user, per purpose
  (§3.1). Salts are **non-secret** and stored server-side.
- **Output length:** 32 bytes (a 256-bit stretched key).
- **Parallelism:** libsodium's `crypto_pwhash` fixes internal lanes; do **not**
  substitute a binding that exposes and changes `p`. If a non-libsodium Argon2 is
  ever used, set `p = 1` to match and document it. (Parameter portability is a
  correctness issue: the same password + salt must yield the same key on every
  platform, or recovery breaks.)
- **Cost parameters — [TUNE+REVIEW]:**
  - **Default:** `opslimit = 3`, `memlimit = 256 MiB` (268435456 bytes). These
    correspond to libsodium's `*_MODERATE` profile.
  - **Reasoning:** Argon2id's memory-hardness is the primary defense against the
    offline dictionary attack of §7.1. 256 MiB makes massively-parallel GPU/ASIC
    cracking expensive; `opslimit = 3` keeps single-derivation latency tolerable
    (~0.3–1.0 s on mid-range hardware).
  - **Obligation:** benchmark on the **lowest-end target device** and choose the
    highest cost that keeps unlock under ~1 s there. **Never** go below
    `memlimit = 64 MiB` (`*_INTERACTIVE`). The chosen values, plus a `kdf_params`
    version tag (§3.2), must be recorded per account so cost can be raised later
    without breaking existing users. **Reviewer must approve the final numbers.**

### 1.3 Subkey KDF — BLAKE2b (domain separation)

- **Primitive:** libsodium `crypto_kdf_derive_from_key` (keyed BLAKE2b).
- **Master input:** the 32-byte Argon2id output (`STRETCHED`, §3.3).
- **Context:** the 8-byte ASCII string `"vanishKD"` (`crypto_kdf_CONTEXTBYTES = 8`).
- **Subkey ids:** `1 → AUTH_KEY` (MVP auth module only, §6.1), `2 → ENC_KEY`.
- **Subkey length:** 32 bytes each.
- **Why this instead of two Argon2id runs:** one expensive Argon2id call, then cheap
  BLAKE2b subkey derivation. Subkeys are cryptographically independent — knowledge of
  subkey 1 reveals nothing about subkey 2 or about `STRETCHED` (BLAKE2b is one-way and
  the subkeys are keyed-independent outputs). This gives clean domain separation at a
  fraction of the cost of running Argon2id twice, and it is a single named library
  call (no manual HKDF construction).

### 1.4 Symmetric AEAD — XChaCha20-Poly1305 (IETF)

- **Primitive:** libsodium `crypto_aead_xchacha20poly1305_ietf_encrypt` /
  `_decrypt`.
- **Key:** 32 bytes. **Nonce:** 24 bytes. **Tag:** 16 bytes (Poly1305).
- **Nonce generation:** `randombytes(24)` — a **fresh random nonce for every
  encryption**, never reused under any key.
- **Why XChaCha (24-byte nonce) and not ChaCha20-Poly1305-IETF (12-byte) or
  AES-GCM:** the `MASTER_KEY` is long-lived and encrypts many vault records over the
  product's life. A 192-bit random nonce has a negligible birthday-collision
  probability across any realistic message count (safe well past 2⁴⁰ messages),
  which makes the **random-nonce** strategy safe *without* a stateful counter. A
  12-byte nonce would force a counter (fragile across devices/reinstalls) or risk
  collision; AES-GCM has the same 96-bit-nonce hazard and worse misuse failure modes.
  XChaCha + random nonce is the construction specifically chosen to make "just use a
  random nonce" provably safe here.
- **Associated data (AAD):** every AEAD call authenticates a context/AAD string
  (exact contents per use in §4 and §5). AAD binds each ciphertext to its role,
  version, and owner, preventing blob-swapping and downgrade attacks. AAD is
  authenticated, **not** encrypted.
- We use the AEAD directly rather than `crypto_secretbox` precisely because we need
  authenticated associated data; `crypto_secretbox` (XSalsa20-Poly1305) has no AAD
  parameter. Same Poly1305 authentication strength; AAD is the deciding factor.

### 1.5 CSPRNG

All random values (keys, nonces, salts, recovery codes) come from:

- **libsodium `randombytes_buf`** on every platform. Underneath: `getrandom(2)` /
  `/dev/urandom` (Linux), `arc4random` (BSD/macOS), `RtlGenRandom`/`BCryptGenRandom`
  (Windows); and in `libsodium.js`, `crypto.getRandomValues` (WebCrypto's RNG only).
- **Forbidden:** `Math.random`, any userland PRNG, time-seeded sources, "nonce = id"
  or counters for the AEAD nonce.

---

## 2. Key hierarchy (one picture)

```
            password (user secret, never leaves device)
                 │
                 │  Argon2id(salt_pw, MODERATE)         ← §1.2, the only slow step
                 ▼
            STRETCHED (32B, never stored, never sent)
                 │
        ┌────────┴───────────────┐  crypto_kdf, ctx="vanishKD"   ← §1.3
        ▼                        ▼
   AUTH_KEY (id=1)          ENC_KEY (id=2)
   MVP auth module only     wrapping key — NEVER leaves device, in any form
   (replaced by OPAQUE)          │
        │                        │  AEAD-wrap            ← §4.1
        │                        ▼
        │                 wrapped_key__password ──────────────┐
        │                                                     │  (both stored
   RECOVERY_CODE (160b, on-device, shown once)                │   server-side,
        │  Argon2id(salt_rec)                                 │   opaque)
        ▼                                                     │
   RECOVERY_KEY ──AEAD-wrap──▶ wrapped_key__recovery ─────────┤
                                                              ▼
                                   MASTER_KEY (32B, random, the ONLY key that
                                   encrypts vault data) ── §5 ──▶ footprint blobs
```

**Invariants the whole design rests on:**

1. `MASTER_KEY` is generated by `randombytes(32)` on-device at signup and is the
   **only** key that ever encrypts vault data.
2. `ENC_KEY` and `MASTER_KEY` **never leave the device** in any form — not to the
   server, not to disk unencrypted, not to logs.
3. The server only ever holds: the two *wrapped* copies of `MASTER_KEY`, the auth
   verifier, the public salts/params, and opaque ciphertext blobs. None of these
   let it derive `ENC_KEY`, `RECOVERY_KEY`, or `MASTER_KEY`.
4. **Authentication is a separate, swappable module (§6) that never touches the
   encryption envelope.** Changing how login works changes nothing in §4/§5.

---

## 3. Per-user secret and stored material

### 3.1 Salts (non-secret, stored server-side, generated at signup)

| Name | Bytes | Used for |
|---|---|---|
| `salt_pw` | 16 | Argon2id over the password → `STRETCHED` (§3.3) |
| `salt_rec` | 16 | Argon2id over the recovery code → `RECOVERY_KEY` (§3.4) |

Salts are random per user, never reused across users, and carry no secrecy
requirement (their job is to defeat precomputation/rainbow tables).

### 3.2 `kdf_params` (non-secret, versioned)

A small record: `{ version, alg: "argon2id13", opslimit, memlimit }`. Stored
server-side and returned to the client before any derivation so the client uses the
**exact** parameters this account was created with. The `version` integer lets us
introduce stronger parameters later: on next successful login the client can
re-derive under new params and re-upload the envelope (§8.4). Without storing these,
recovery and login would break the moment defaults change.

### 3.3 Derivation of `STRETCHED`, `ENC_KEY`, `AUTH_KEY`

```
STRETCHED = crypto_pwhash(
                outlen   = 32,
                passwd   = password_utf8_nfc,     # Unicode NFC-normalized (§9)
                salt     = salt_pw,
                opslimit = kdf_params.opslimit,
                memlimit = kdf_params.memlimit,
                alg      = crypto_pwhash_ALG_ARGON2ID13)

ENC_KEY  = crypto_kdf_derive_from_key(32, subkey_id=2, ctx="vanishKD", key=STRETCHED)
AUTH_KEY = crypto_kdf_derive_from_key(32, subkey_id=1, ctx="vanishKD", key=STRETCHED)   # MVP only
```

`STRETCHED` is zeroized (§8.2) immediately after both subkeys are derived. `AUTH_KEY`
is computed **only** by the MVP auth module (§6.1); under the OPAQUE upgrade (§6.2) it
is never computed and subkey id 1 is simply unused — **and the envelope is untouched.**

### 3.4 Recovery code and `RECOVERY_KEY`

```
RECOVERY_CODE = randombytes(20)            # 160 bits of CSPRNG entropy
display       = base32_crockford(RECOVERY_CODE)  # 32 chars, shown in 8 groups of 4
                                                 # + a 1-char checksum char (Crockford)
RECOVERY_KEY  = crypto_pwhash(32, recovery_code_normalized, salt_rec,
                              opslimit, memlimit, ARGON2ID13)
```

- **Entropy:** 160 bits — far beyond brute-force reach, so the Argon2id step over it
  is conservative defense-in-depth rather than the primary barrier (a high-entropy
  code does not *need* slow hashing). We still run Argon2id for uniformity and to be
  robust if the entropy estimate is ever wrong. (A reviewer may approve substituting
  a single `crypto_kdf`/BLAKE2b derivation here to make recovery fast; default is
  Argon2id.)
- **Encoding:** Crockford base32 (unambiguous: no I/L/O/U), upper-cased, grouped
  `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`, with a trailing checksum char so a
  mistyped code is rejected client-side before a doomed unwrap attempt. (Reviewer
  option: an EFF-wordlist / BIP39-style encoding instead, for transcribability — the
  underlying 160 bits are unchanged.)
- **Lifecycle:** generated on-device at signup, **displayed exactly once**, the user
  must confirm they stored it. The server **never** receives the code or any
  reversible form of it — only `wrapped_key__recovery` (§4.1). Input is
  whitespace-stripped and upper-cased ("recovery_code_normalized") before hashing so
  formatting/grouping never affects the derived key.
- **Sensitivity:** the recovery code is **password-equivalent** — anyone holding it
  can unwrap `MASTER_KEY` and decrypt the entire vault. UI must say so. It is rotated
  on every use (§8.5).

---

## 4. The master-key envelope (the part most likely to silently break ZK)

The envelope is the crux. Get the AAD and layout wrong and you get subtle breaks
(blob-swapping, slot-confusion, param downgrade) that still "work" in tests.

### 4.1 Wrap construction

Both wrapped copies use the **same** AEAD (§1.4), differing only in key and AAD:

```
nonce_p = randombytes(24)
wrapped_key__password =
    0x01                                   # 1-byte envelope-format version
 || nonce_p                                # 24 bytes
 || crypto_aead_xchacha20poly1305_ietf_encrypt(
        message = MASTER_KEY,              # 32 bytes plaintext
        ad      = AAD_pw,                  # authenticated, not encrypted (below)
        nonce   = nonce_p,
        key     = ENC_KEY)                 # → 48 bytes (32 ct + 16 tag)

nonce_r = randombytes(24)
wrapped_key__recovery =
    0x01
 || nonce_r
 || crypto_aead_xchacha20poly1305_ietf_encrypt(
        message = MASTER_KEY,
        ad      = AAD_rec,
        nonce   = nonce_r,
        key     = RECOVERY_KEY)
```

**Stored blob layout (both):** `version(1) || nonce(24) || ciphertext+tag(48)` =
**73 bytes**. Self-describing via the version byte; future formats bump it.

**AAD (authenticated context — pins role, owner, params):**

```
AAD_pw  = "vanish.envelope.v1" || 0x00 || user_id || 0x00 || "slot=password" || 0x00 || LE32(kdf_params.version)
AAD_rec = "vanish.envelope.v1" || 0x00 || user_id || 0x00 || "slot=recovery" || 0x00 || LE32(kdf_params.version)
```

The AAD makes the two slots **non-interchangeable** (a recovery-slot blob cannot be
verified/decrypted as a password-slot blob and vice versa), binds each envelope to
its `user_id` (a server can't graft user A's envelope onto user B), and binds the
KDF param version (prevents silent downgrade). AAD is reconstructed by the client at
unwrap time; if any bound value was tampered with, `_decrypt` returns an auth
failure and unwrap aborts.

### 4.2 Unwrap

```
MASTER_KEY = crypto_aead_xchacha20poly1305_ietf_decrypt(
                 ciphertext = blob[25:],          # after version(1)+nonce(24)
                 ad         = AAD_pw  (or AAD_rec),
                 nonce      = blob[1:25],
                 key        = ENC_KEY (or RECOVERY_KEY))
# Poly1305 verification fails ⇒ wrong key / tampering ⇒ abort, never return garbage.
```

### 4.3 Why the server cannot unwrap either copy

The server holds `wrapped_key__password`, `wrapped_key__recovery`, `salt_pw`,
`salt_rec`, `kdf_params`, and the auth verifier. To unwrap the password copy it needs
`ENC_KEY = KDF(Argon2id(password, salt_pw))`; to unwrap the recovery copy it needs
`RECOVERY_KEY = Argon2id(recovery_code, salt_rec)`. It possesses **neither the
password nor the recovery code**, and neither is derivable from anything it stores
(the verifier is a one-way hash; see §7.1 for the one residual offline-attack caveat).
Both wrapped blobs are AEAD ciphertext — indistinguishable from random without the
key. **The server's two copies are opaque to the server.**

---

## 5. Vault record encryption

Every footprint record (a breach hit, a broker match, a removal-request *fact*, an
exposure-history point) is serialized to canonical JSON and encrypted **only** under
`MASTER_KEY`:

```
record_pt   = utf8(canonical_json(record))         # see §9 for canonicalization
nonce_b     = randombytes(24)
AAD_b       = "vanish.blob.v1" || 0x00 || user_id || 0x00 || record_id || 0x00 || LE32(record_schema_version)
blob =
    0x01                                            # blob-format version
 || nonce_b                                         # 24 bytes
 || crypto_aead_xchacha20poly1305_ietf_encrypt(record_pt, AAD_b, nonce_b, MASTER_KEY)
```

- `record_id` is a client-generated random UUID (v4) so records can be addressed and
  updated without revealing content; it is bound into the AAD so the server cannot
  swap one record's ciphertext under another's id.
- **What the server stores per blob:** `{ record_id, user_id, blob, created_at,
  blob_format_version }`. Everything semantic (record type, breach name, broker id,
  dates, severity) is **inside** `record_pt` and therefore opaque. Per BLUEPRINT.md
  §3, prefer keeping even the record *type* inside the ciphertext; expose an outer
  `kind` enum **only** if a sync optimization genuinely requires it, and document the
  leak if so.
- The exposure-over-time graph (BLUEPRINT.md §8) is reconstructed entirely client-side
  by decrypting these blobs in memory; **no plaintext series exists server-side.**

### 5.1 Removal letters — tool-not-agent (v1)

Per the blueprint's "tool, not agent" stance, and consistent with the existing CLI's
**identifier-free invariant**:

- Removal letters (CCPA/GDPR/generic) are rendered **client-side, in memory**, from
  decrypted vault data plus the identifiers the user enters locally (name, email,
  phone, address).
- **Those identifiers never round-trip through the server and are never persisted —**
  not in plaintext, not encrypted. The server stores only the *fact* of a removal
  request (broker id, template, status, dates) as an ordinary vault blob (§5), exactly
  mirroring the CLI tracker's "store the fact, never the identifier" design.
- The user sends the letter themselves (their own email/web form). **The server never
  submits on the user's behalf in v1.**
- **Agent submission (the server filing on the user's behalf) is explicitly out of
  scope and fenced behind the legal review in BLUEPRINT.md §10** (authorized-agent
  obligations). It would change the data-flow and must not be built before that review.

---

## 6. Authentication boundary (swappable: MVP today, OPAQUE later)

**Design rule that makes the swap free:** authentication's *only* output is a
**session token** that authorizes fetching/writing this user's opaque blobs. It does
**not** produce, transport, or touch `ENC_KEY`/`MASTER_KEY`. The encryption envelope
(§4/§5) derives `ENC_KEY` from the password **independently**, on-device, with no
server involvement. Therefore the auth mechanism can be replaced without touching one
byte of the envelope. Both modules below satisfy the same interface:

```
AuthModule.register(user_id, password) -> { server_stores: <auth material> }
AuthModule.login(user_id, password)    -> session_token            # nothing key-bearing
```

### 6.1 MVP module — password-derived AUTH_KEY over TLS (default for launch)

- **Register:** client computes `AUTH_KEY` (§3.3), sends it once over TLS. Server
  stores `auth_verifier = crypto_pwhash_str(AUTH_KEY, opslimit_v, memlimit_v)` —
  libsodium's self-describing Argon2id string (its own embedded salt+params).
  - Verifier params **[TUNE+REVIEW]:** `*_INTERACTIVE` (opslimit 2, memlimit 64 MiB)
    is sufficient, because `AUTH_KEY` is already a 256-bit value produced by the
    expensive client-side Argon2id (§1.2); the server-side hash exists only so a DB
    leak doesn't reveal a directly-replayable `AUTH_KEY`. It does **not** add
    meaningful password-cracking resistance (that lives in the client KDF) — see §7.1.
- **Login:** client recomputes `AUTH_KEY`, sends it over TLS; server checks
  `crypto_pwhash_str_verify(auth_verifier, AUTH_KEY)`; on success issues a session
  token (§6.3).
- **Honest boundary:** in MVP the server *transiently* sees `AUTH_KEY` in process
  memory at login. `AUTH_KEY` is **independent of `ENC_KEY`** (§1.3), so this never
  reveals a key that decrypts the vault. The precise residual risk it leaves open is
  the **offline dictionary attack of §7.1**, which OPAQUE closes.

### 6.2 Upgrade path — OPAQUE (aPAKE). **Do not hand-roll.**

- OPAQUE is an asymmetric PAKE: the server learns **nothing** that enables an offline
  dictionary attack, and `AUTH_KEY` is never transmitted at all (subkey id 1 goes
  unused). This removes the §7.1 residual risk entirely.
- **Mandate:** if/when adopted, use a **vetted, audited OPAQUE implementation** (e.g.
  a maintained RFC 9380 / CFRG-aligned library). **Implementing OPAQUE by hand is
  forbidden** — it is exactly the kind of subtle primitive that fails silently.
- **Swap cost is zero for the envelope:** because §4/§5 derive `ENC_KEY` from the
  password independently of the auth module, switching MVP→OPAQUE changes only
  registration/login wire formats and the server's stored auth material. Vault blobs
  and wrapped keys are **untouched**; users do not re-encrypt anything. (OPAQUE also
  exposes an `export_key`; we deliberately **do not** repurpose it as `ENC_KEY`, to
  keep the envelope auth-agnostic and the swap clean.)
- Marked **upgrade path**, not a launch blocker — provided MVP enforces the §7.1
  mitigations (strong-passphrase policy + high Argon2id cost).

### 6.3 Session tokens

- On successful auth the server issues a **short-lived access token** (opaque random
  or signed, ≤15 min) plus a **rotating refresh token**. Tokens authorize blob
  fetch/write for that `user_id` only; they are **not** keys and cannot decrypt
  anything.
- Native: store tokens in the OS secure store (Keychain / Credential Manager /
  libsecret). Web (if built): access token in memory, refresh token in an HttpOnly,
  Secure, SameSite=Strict cookie.
- Row-level authorization on every blob endpoint (defense-in-depth against IDOR; per
  BLUEPRINT.md §2 a successful IDOR still only yields opaque ciphertext, but we
  enforce it anyway).

---

## 7. The residual offline-attack caveat (state it plainly)

### 7.1 What MVP leaves open, and exactly why

A malicious/compromised server, or anyone who steals the DB, holds `salt_pw`,
`kdf_params`, `auth_verifier`, and (if captured at a login) `AUTH_KEY`. With these
they can mount an **offline dictionary attack on the password**:

```
for each candidate pw in dictionary:
    AUTH_KEY' = KDF(Argon2id(pw, salt_pw, kdf_params))
    if crypto_pwhash_str_verify(auth_verifier, AUTH_KEY'):  # match → password found
        ENC_KEY' = KDF(Argon2id(pw, salt_pw))               # → unwrap MASTER_KEY → decrypt everything
```

- **Cost per guess = one Argon2id at our chosen parameters.** This is why §1.2's
  memory/time cost is the load-bearing defense, and why the parameters need real
  benchmarking and reviewer sign-off.
- **For a weak password this attack succeeds.** That is the honest limit of the MVP
  auth model against a *malicious server*. It does **not** affect confidentiality
  against an *external attacker who never obtains the password-derived material*, and
  it does **not** affect the recovery slot (160-bit code is out of dictionary reach).
- **Mitigations required for MVP launch:**
  1. **Strong passphrase policy** (e.g. enforce a passphrase / high estimated entropy;
     consider a zxcvbn-style strength gate). This is the single biggest lever.
  2. **High Argon2id cost** (§1.2), benchmarked and reviewer-approved.
  3. **Plan the OPAQUE upgrade (§6.2),** which removes the server's ability to run
     this attack at all.
- This caveat **must** be reflected in the user-facing security claims (don't claim
  "even we can't ever attack your data" while shipping MVP with weak-password
  acceptance). Reviewer must confirm the wording matches the model.

---

## 8. Per-event "what crosses the wire" — the reviewer's core checklist

Legend: **C→S** = client sends to server; **Stores** = what the server persists;
**Cannot derive** = what remains unreachable to the server.

### 8.1 Signup

| | |
|---|---|
| **Client computes** | `salt_pw`, `salt_rec` = `randombytes(16)`; `STRETCHED`, `ENC_KEY`, `AUTH_KEY` (§3.3); `MASTER_KEY = randombytes(32)`; `RECOVERY_CODE = randombytes(20)` → `RECOVERY_KEY`; `wrapped_key__password`, `wrapped_key__recovery` (§4.1); `auth_verifier` material per auth module |
| **C→S** | `user_id`, `salt_pw`, `salt_rec`, `kdf_params`, `wrapped_key__password`, `wrapped_key__recovery`, `auth_verifier` (MVP: from `AUTH_KEY`). **Empty vault.** |
| **Server stores** | exactly the received fields (all opaque/non-secret) |
| **Server can derive** | nothing about content; can authenticate future logins |
| **Cannot derive** | password, `STRETCHED`, `ENC_KEY`, `RECOVERY_CODE`, `RECOVERY_KEY`, `MASTER_KEY`, any future plaintext |
| **Never sent** | password, `STRETCHED`, `ENC_KEY`, `MASTER_KEY`, `RECOVERY_CODE`, `RECOVERY_KEY` |

### 8.2 Login (MVP module)

| | |
|---|---|
| **Client computes** | `STRETCHED` → `ENC_KEY`, `AUTH_KEY` (re-derived from typed password + fetched `salt_pw`/`kdf_params`) |
| **C→S** | `AUTH_KEY` (over TLS) |
| **Server stores** | nothing new (issues session token) |
| **Server sees transiently** | `AUTH_KEY` in memory (independent of `ENC_KEY`; see §7.1) |
| **Cannot derive** | `ENC_KEY`, `MASTER_KEY` (it never receives them; it only verifies `AUTH_KEY`) |
| **On device after login** | `ENC_KEY` → unwrap `wrapped_key__password` → `MASTER_KEY` held **in memory only** |

*(Under OPAQUE (§6.2): C→S carries the PAKE handshake messages, **not** `AUTH_KEY`; the
server sees nothing dictionary-attackable. Envelope unchanged.)*

### 8.3 Vault sync / write

| | |
|---|---|
| **Client computes** | encrypts each new/changed record under `MASTER_KEY` (§5) |
| **C→S** | `{ record_id, blob, blob_format_version }` per record; session token |
| **Server stores** | the opaque blobs + `created_at` + `user_id` |
| **Cannot derive** | record contents, types (if kept inside ciphertext), identifiers |
| **Leaks (metadata)** | blob count, sizes, timestamps (§10) |

### 8.4 Password change (user knows current password)

| | |
|---|---|
| **Client computes** | unwrap `MASTER_KEY` with current `ENC_KEY`; derive new `salt_pw'`, `STRETCHED'`, `ENC_KEY'`, `AUTH_KEY'`; **re-wrap the same `MASTER_KEY`** → new `wrapped_key__password`; new `auth_verifier` |
| **C→S** | new `salt_pw'`, `kdf_params` (if changed), new `wrapped_key__password`, new `auth_verifier` |
| **Server replaces** | `salt_pw`, `wrapped_key__password`, `auth_verifier` |
| **Unchanged server-side** | **all vault blobs and `wrapped_key__recovery`** — the `MASTER_KEY` did not change, so nothing is re-encrypted |
| **Cannot derive** | new or old password, `ENC_KEY`/`ENC_KEY'`, `MASTER_KEY` |

### 8.5 Recovery (forgot password, user has recovery code)

| | |
|---|---|
| **Client computes** | fetch `salt_rec`, `kdf_params`, `wrapped_key__recovery`; derive `RECOVERY_KEY`; **unwrap → `MASTER_KEY`**; set new password → new `salt_pw'`, `ENC_KEY'`, `AUTH_KEY'`; re-wrap `MASTER_KEY` → new `wrapped_key__password`; **rotate**: generate new `RECOVERY_CODE'` + `salt_rec'` → new `RECOVERY_KEY'` → new `wrapped_key__recovery`; new `auth_verifier` |
| **C→S** | new `salt_pw'`, new `salt_rec'`, new `wrapped_key__password`, **new `wrapped_key__recovery`**, new `auth_verifier` |
| **Server replaces** | `salt_pw`, `salt_rec`, both `wrapped_key__*`, `auth_verifier` |
| **Unchanged server-side** | **all vault blobs** — `MASTER_KEY` is unchanged |
| **Cannot derive** | old/new password, old/new recovery code, `MASTER_KEY` |
| **Mandatory** | the **old recovery code is invalidated** by overwriting `wrapped_key__recovery`; the new code is shown once. See §8.5.1 |

#### 8.5.1 Why recovery **must** rotate the code

Using the recovery code means it was just typed into the device (and possibly read off
paper, a screen, a password manager) — i.e. **exposed**. After recovery the old code's
`wrapped_key__recovery` is overwritten with one under a fresh `RECOVERY_KEY'`, so the
old code can no longer unwrap anything. This is **non-optional**: skipping rotation
leaves a used (and possibly observed) credential live. The new code is displayed once
with the same "store it now" flow as signup.

---

## 9. Encoding determinism (a quiet source of breakage)

Recovery and login depend on re-deriving the *exact same bytes* from the same secret.
Pin these down:

- **Password normalization:** Unicode **NFC** normalization of the password string
  before UTF-8 encoding, applied identically on every platform. (Without this, an
  accented character entered two different ways yields two different keys and login
  fails.)
- **Recovery code normalization:** strip all whitespace/hyphens, upper-case, validate
  the Crockford checksum, then UTF-8 encode before Argon2id.
- **Canonical JSON for records (§5):** deterministic serialization — sorted keys, no
  insignificant whitespace, UTF-8, a fixed number/encoding convention — so a record
  re-encrypted on another device is byte-stable where it must be. (Encryption itself
  tolerates non-canonical input, but canonicalization avoids diff/version churn and
  makes test vectors stable.)
- **Endianness:** all length/version integers little-endian (§0).

These are correctness, not secrecy, requirements — but a mismatch **locks users out**,
which for a ZK product is indistinguishable from data loss. Test-vector them.

---

## 10. Session and at-rest key handling on-device

- **While unlocked:** `MASTER_KEY` and `ENC_KEY` live **in process memory only**
  (native/Rust core, never the webview heap in the Tauri model). `STRETCHED` is
  zeroized immediately after subkey derivation (§3.3).
- **Zeroization:** wipe `STRETCHED`, `ENC_KEY`, `MASTER_KEY`, `RECOVERY_KEY`, and any
  derived buffers with `sodium_memzero` on lock, logout, and idle-timeout. Prefer
  `sodium_malloc`/`sodium_mlock`-backed buffers for long-lived key material to resist
  swap and core dumps. (Best-effort: a GC'd/relocating runtime can retain copies — do
  key handling in the native layer to keep this tractable.)
- **"Stay unlocked" (optional, native only):** never persist `MASTER_KEY` raw. Store
  the **wrapped** key plus a device-bound unlock key in the OS secure enclave/keychain;
  re-unwrap on resume. Reviewer must approve this flow if built.
- **Auto-lock on idle**; zeroize on lock. Re-unlock requires the password (re-derive)
  or the OS-keychain path above.
- **Honest limit:** a **compromised, unlocked device** is out of scope (BLUEPRINT.md
  §2). Malware that reads the unlocked process memory gets the keys. No client-side
  scheme defends against that; we do not pretend otherwise.

---

## 11. Versioning / crypto-agility

- **Format version bytes** lead every envelope (§4.1) and blob (§5); `kdf_params`
  carries a `version` (§3.2). This lets us: raise Argon2id cost, rotate the AEAD, or
  change the envelope layout, each as an explicit, detectable migration — never a
  silent reinterpretation of old bytes.
- **Migration rule:** a new version is *added*; old versions remain decryptable until
  every account has re-derived/re-wrapped. Never reuse a version number for a new
  meaning.

---

## 12. Explicit non-goals and known limitations

- **Metadata is visible to the server** (unavoidable): account existence, `user_id`,
  subscription status, blob count, blob sizes, and sync timestamps. Content is not.
  Mitigations (size-bucketing/padding, batched sync) are deferred; the leak is
  documented per BLUEPRINT.md §3.
- **Scan-vs-ZK plaintext transiency** (BLUEPRINT.md §7): footprint scans need plaintext
  identifiers. Native = on-device only (no server exposure). Web tier (if built) =
  a transient, memory-only, **log-suppressed** scan endpoint that persists nothing;
  this is a deliberate, audited weakening and **out of scope for this envelope spec** —
  it has its own review obligation.
- **Lose both password and recovery code ⇒ vault is unrecoverable, by design.** The
  operator holds no key and cannot help. This is the cost of real ZK and must be stated
  aggressively in onboarding.
- **MVP malicious-server offline dictionary attack (§7.1):** open until OPAQUE; bounded
  by Argon2id cost + password strength.
- **Compromised unlocked device (§10):** out of scope.
- **This spec does not cover:** TLS configuration, server authorization/rate-limiting
  details, billing-data handling (Stripe-tokenized per BLUEPRINT.md §3), agent-submission
  of removals (§5.1, fenced behind legal review). Those are specified elsewhere.

---

## 13. Reviewer's certification checklist

A cryptographer should be able to answer each of these **directly from this document**.
The bracketed answer is what a correct implementation of this spec yields; the reviewer
verifies the spec actually guarantees it.

**Key independence & server ignorance**
- [ ] Can the server ever obtain `ENC_KEY`? *(No — derived on-device, never sent; §2/§3.3/§4.3.)*
- [ ] Can the server ever obtain `MASTER_KEY`? *(No — generated on-device, only ever stored wrapped; §2/§4.3.)*
- [ ] Is `AUTH_KEY` cryptographically independent of `ENC_KEY` (does learning `AUTH_KEY` reveal `ENC_KEY`)? *(No leak — independent `crypto_kdf` subkeys of `STRETCHED`; §1.3/§3.3.)*
- [ ] Are the two wrapped-key copies opaque to the server, and non-interchangeable with each other? *(Yes — AEAD ciphertext; AAD binds slot+user+params; §4.1/§4.3.)*

**Nonces & AEAD**
- [ ] Is any nonce ever reused under the same key? *(No — every encryption draws a fresh `randombytes(24)`; §1.4.)*
- [ ] Is the 24-byte random-nonce strategy safe at expected message volume? *(Yes — 192-bit nonce, negligible birthday collision; §1.4.)*
- [ ] Does every AEAD call authenticate context (role/user/version/record_id) via AAD? *(Yes; §4.1/§5.)*
- [ ] Can a blob/envelope be swapped across slots, users, or records without detection? *(No — AAD binding; §4.1/§5.)*

**KDF**
- [ ] Is the password KDF memory-hard with reviewed parameters? *(Argon2id, [TUNE+REVIEW] §1.2.)*
- [ ] Are KDF salts unique per user and per purpose? *(Yes — `salt_pw`, `salt_rec`; §3.1.)*
- [ ] Are KDF parameters versioned and stored so login/recovery survive future changes? *(Yes; §3.2/§11.)*

**Recovery**
- [ ] Does the server ever receive the recovery code or a reversible form of it? *(No — only `wrapped_key__recovery`; §3.4/§4.3.)*
- [ ] Is the recovery code's entropy beyond dictionary reach? *(Yes — 160 bits; §3.4.)*
- [ ] Does using the recovery code rotate it and invalidate the old one? *(Yes — mandatory; §8.5/§8.5.1.)*
- [ ] Does recovery (and password change) avoid re-encrypting the vault? *(Yes — only the wrapper changes; `MASTER_KEY` constant; §8.4/§8.5.)*

**Auth boundary & swappability**
- [ ] Does authentication output anything key-bearing (anything that decrypts the vault)? *(No — only a session token; §6.)*
- [ ] Can the MVP auth module be replaced by OPAQUE without touching the encryption envelope? *(Yes — envelope derives `ENC_KEY` independently; §6.2.)*
- [ ] Is OPAQUE mandated to be a vetted implementation, never hand-rolled? *(Yes; §6.2.)*
- [ ] Is the MVP offline-dictionary residual risk stated, bounded, and mitigated? *(Yes; §7.1.)*

**PII / product invariants**
- [ ] Do removal-letter identifiers ever reach or persist on the server? *(No — rendered in-memory client-side, never sent/persisted; §5.1.)*
- [ ] Is agent-submission correctly fenced out of v1 pending legal review? *(Yes; §5.1.)*
- [ ] Is the server-visible metadata enumerated honestly? *(Yes; §10/§12.)*

**Hygiene**
- [ ] Is all randomness from a named CSPRNG, with `Math.random` and counters forbidden? *(Yes; §1.5.)*
- [ ] Are key buffers zeroized on lock/logout, memory-only while unlocked? *(Yes; §10.)*
- [ ] Is password/recovery-code/JSON encoding deterministic across platforms? *(Yes — NFC + canonical JSON; §9.)*
- [ ] Is every primitive a direct libsodium call, with no hand-rolled or novel composition? *(Yes; §1.)*

**Sign-off:** the design is certifiable when every box above is checked, the
**[TUNE+REVIEW]** Argon2id parameters (§1.2, §6.1) are benchmarked and approved, and
the §7.1 residual risk wording is reflected in the user-facing security claims. Only
then does Phase 1 (writing the crypto/auth core) begin.
