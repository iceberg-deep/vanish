# KDF Parameters — Benchmark Record (Phase 0 deliverable 0.3)

📄 **Governs:** CRYPTO-SPEC §1.2, §6.1 (`[TUNE+REVIEW]`); ROADMAP Phase 0 item 0.3.
**Status:** **Provisional — not yet reviewer-approved.** This is a starting data
point, not the final binding value. Phase 0 cannot close on this alone (see below).

## What this is

The Argon2id cost parameters (`opslimit`, `memlimit`) are the single biggest lever on
residual risk **R-1** (the MVP offline dictionary attack on the password,
CRYPTO-SPEC §7.1 / THREAT-MODEL §13). They were deferred in the spec as `[TUNE+REVIEW]`
precisely because they must be measured, not guessed. `tools/argon2_benchmark.py`
measures the exact primitive the spec mandates (libsodium `crypto_pwhash`,
`ALG_ARGON2ID13`) and hashes only a throwaway passphrase — no PII, nothing stored.

## Measurement (developer machine — NOT the target low-end device)

Linux, system libsodium.so.23, 3 runs/config:

| profile | opslimit | memlimit | median | < ~1 s? |
|---|---:|---:|---:|:--:|
| INTERACTIVE (floor) | 2 | 64 MiB | 0.075 s | yes |
| light | 3 | 64 MiB | 0.105 s | yes |
| **MODERATE (spec default)** | **3** | **256 MiB** | **0.465 s** | **yes** |
| moderate+ | 4 | 256 MiB | 0.614 s | yes |
| heavy | 3 | 512 MiB | 1.020 s | no |
| heavy+ | 4 | 512 MiB | 1.342 s | no |
| SENSITIVE | 4 | 1024 MiB | 3.875 s | no |

## Provisional candidate

**`kdf_params` v1 (candidate): Argon2id, opslimit = 3, memlimit = 256 MiB (MODERATE).**

Reasoning:
- Meets the spec rule (highest practical cost under ~1 s unlock; well above the
  64 MiB floor) with comfortable headroom on this machine (~0.47 s).
- A **low-end target device will be slower** than this dev box, so MODERATE is the
  conservative ceiling to validate there — 512 MiB already breaches ~1 s *here*, and
  would be worse on weaker hardware. The benchmark's "costliest-under-1s on this
  machine" pick (moderate+, 256 MiB / ops 4) is **not** recommended as the carry-
  forward value for exactly this reason: leave margin for slower devices.

## Why this does NOT close the gate yet

Per CRYPTO-SPEC §1.2 and ROADMAP Phase 0 exit criterion #3, the binding value must be:
1. **Benchmarked on the lowest-end target device** (this machine is not it), and
2. **Approved by the cryptographer** as part of the §13 sign-off.

Until both happen, this is a provisional candidate only. Re-run:
`python tools/argon2_benchmark.py` on representative low-end hardware and update this
record with the final, reviewer-approved pair before it is written into code as
`kdf_params` v1.
