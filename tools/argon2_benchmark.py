#!/usr/bin/env python3
"""Argon2id parameter benchmark — Phase 0 deliverable 0.3 (ROADMAP §Phase 0).

Measures the wall-clock cost of libsodium's `crypto_pwhash` (Argon2id, the exact
KDF pinned by CRYPTO-SPEC §1.2) across candidate (opslimit, memlimit) settings, so a
final parameter choice can be made and handed to the cryptographer for sign-off.

This is a *measurement tool*, not product code:
  * It hashes a fixed throwaway passphrase. No user PII, no secrets, nothing stored.
  * It calls the same primitive the spec mandates (ALG_ARGON2ID13), via the system
    libsodium, so the timings reflect the real construction.

IMPORTANT (the [TUNE+REVIEW] obligation, CRYPTO-SPEC §1.2):
  * Numbers here describe THIS machine. The binding decision must be benchmarked on
    the *lowest-end target device*, where the same params will be slower.
  * The rule: pick the highest cost that keeps unlock < ~1.0 s on that device, and
    NEVER drop memlimit below 64 MiB (the *_INTERACTIVE floor).
  * The chosen pair must be recorded as `kdf_params` v1 and approved by the reviewer.

Usage:
    python tools/argon2_benchmark.py            # full grid, 5 runs each
    python tools/argon2_benchmark.py --runs 3   # fewer samples (faster)
    python tools/argon2_benchmark.py --quick    # skip the 1 GiB rows
"""

import argparse
import ctypes
import ctypes.util
import statistics
import sys
import time

# libsodium constants (stable ABI). Argon2id13 = 2.
ALG_ARGON2ID13 = 2
SALTBYTES = 16
KEYBYTES = 32

MiB = 1024 * 1024

# Named reference profiles libsodium ships, plus a couple of in-between points.
# (label, opslimit, memlimit_bytes)
GRID = [
    ("INTERACTIVE (floor)", 2, 64 * MiB),
    ("light",               3, 64 * MiB),
    ("MODERATE (spec default)", 3, 256 * MiB),
    ("moderate+",           4, 256 * MiB),
    ("heavy",               3, 512 * MiB),
    ("heavy+",              4, 512 * MiB),
    ("SENSITIVE",           4, 1024 * MiB),
]


def load_sodium():
    name = ctypes.util.find_library("sodium") or "libsodium.so.23"
    try:
        lib = ctypes.CDLL(name)
    except OSError as exc:
        sys.exit("Could not load libsodium (%s): %s" % (name, exc))
    if lib.sodium_init() < 0:
        sys.exit("sodium_init() failed")
    # int crypto_pwhash(out, outlen, passwd, passwdlen, salt,
    #                   opslimit (u64), memlimit (size_t), alg (int))
    lib.crypto_pwhash.restype = ctypes.c_int
    lib.crypto_pwhash.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p,
        ctypes.c_ulonglong, ctypes.c_size_t, ctypes.c_int,
    ]
    lib.randombytes_buf.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    return lib


def derive_once(lib, password, salt, opslimit, memlimit):
    out = ctypes.create_string_buffer(KEYBYTES)
    rc = lib.crypto_pwhash(
        out, KEYBYTES,
        password, len(password),
        salt,
        opslimit, memlimit, ALG_ARGON2ID13,
    )
    if rc != 0:
        # Almost always: not enough memory for this memlimit on this box.
        raise MemoryError("crypto_pwhash rc=%d (likely OOM at %d MiB)"
                          % (rc, memlimit // MiB))
    return out.raw


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=5, help="samples per config (default 5)")
    ap.add_argument("--quick", action="store_true", help="skip the 1 GiB SENSITIVE row")
    args = ap.parse_args()

    lib = load_sodium()
    salt = ctypes.create_string_buffer(SALTBYTES)
    lib.randombytes_buf(salt, SALTBYTES)
    password = b"benchmark-throwaway-passphrase-not-a-secret"

    grid = [row for row in GRID if not (args.quick and row[2] >= 1024 * MiB)]

    print("Argon2id (crypto_pwhash, ALG_ARGON2ID13) — this machine, %d run(s)/config"
          % args.runs)
    print("NOTE: re-run on the lowest-end target device before deciding. [TUNE+REVIEW]\n")
    print("  %-26s %5s %9s   %9s  %s" % ("profile", "ops", "mem", "median", "under~1s?"))
    print("  " + "-" * 72)

    recommended = None
    for label, ops, mem in grid:
        times = []
        try:
            for _ in range(args.runs):
                t0 = time.perf_counter()
                derive_once(lib, password, salt, ops, mem)
                times.append(time.perf_counter() - t0)
        except MemoryError as exc:
            print("  %-26s %5d %6d MiB   %9s  %s" % (label, ops, mem // MiB, "—", exc))
            continue
        med = statistics.median(times)
        ok = med < 1.0
        flag = "yes" if ok else "NO (too slow)"
        print("  %-26s %5d %6d MiB   %8.3fs  %s" % (label, ops, mem // MiB, med, flag))
        # Track the costliest config that still meets the <1s rule and the 64MiB floor.
        if ok and mem >= 64 * MiB:
            if recommended is None or (mem, ops) > (recommended[2], recommended[1]):
                recommended = (label, ops, mem, med)

    print()
    if recommended:
        label, ops, mem, med = recommended
        print("Costliest config under ~1s on THIS machine: %s "
              "(opslimit=%d, memlimit=%d MiB, ~%.3fs)."
              % (label, ops, mem // MiB, med))
    else:
        print("No config met the <1s rule on this machine — investigate before deciding.")
    print("This is a starting data point only. The final pair MUST be benchmarked on")
    print("the lowest-end target device and approved by the reviewer (CRYPTO-SPEC §1.2).")


if __name__ == "__main__":
    main()
