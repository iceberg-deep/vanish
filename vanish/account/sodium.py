"""Thin ctypes binding to the system libsodium.

The single cryptographic dependency, per CRYPTO-SPEC.md §1.1 ("No hand-rolled
crypto"). Every primitive below is a direct libsodium call — no custom construction.
The library is loaded lazily on first use so that merely importing this package (e.g.
for linting) never requires libsodium to be present.

Exposes only the primitives the envelope needs:
  * Argon2id KDF            -> crypto_pwhash                       (§1.2)
  * subkey derivation       -> crypto_kdf_derive_from_key (BLAKE2b)(§1.3)
  * AEAD                    -> crypto_aead_xchacha20poly1305_ietf  (§1.4)
  * CSPRNG                  -> randombytes_buf                     (§1.5)
  * password-hash verifier  -> crypto_pwhash_str / _str_verify     (§6.1)
"""

import ctypes
import ctypes.util

# --- libsodium constants (stable ABI) ------------------------------------- #
SALTBYTES = 16
ALG_ARGON2ID13 = 2
KDF_CONTEXTBYTES = 8
KDF_KEYBYTES = 32
AEAD_KEYBYTES = 32
AEAD_NPUBBYTES = 24
AEAD_ABYTES = 16
PWHASH_STRBYTES = 128

# opslimit / memlimit presets (mirror libsodium's named profiles)
OPSLIMIT_INTERACTIVE = 2
MEMLIMIT_INTERACTIVE = 67108864      # 64 MiB
OPSLIMIT_MODERATE = 3
MEMLIMIT_MODERATE = 268435456        # 256 MiB

_lib = None


def _sodium():
    """Load + init libsodium once; cache the handle."""
    global _lib
    if _lib is not None:
        return _lib
    name = ctypes.util.find_library("sodium") or "libsodium.so.23"
    try:
        lib = ctypes.CDLL(name)
    except OSError as exc:  # pragma: no cover - environment-specific
        raise RuntimeError(
            "libsodium not found (%s); install it (e.g. `apt-get install "
            "libsodium23`)" % exc)
    if lib.sodium_init() < 0:  # pragma: no cover
        raise RuntimeError("sodium_init() failed")

    lib.randombytes_buf.argtypes = [ctypes.c_char_p, ctypes.c_size_t]

    lib.crypto_pwhash.restype = ctypes.c_int
    lib.crypto_pwhash.argtypes = [
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p,
        ctypes.c_ulonglong, ctypes.c_size_t, ctypes.c_int]

    lib.crypto_kdf_derive_from_key.restype = ctypes.c_int
    lib.crypto_kdf_derive_from_key.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_char_p]

    lib.crypto_aead_xchacha20poly1305_ietf_encrypt.restype = ctypes.c_int
    lib.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.crypto_aead_xchacha20poly1305_ietf_decrypt.restype = ctypes.c_int
    lib.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.c_char_p,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_char_p, ctypes.c_char_p]

    lib.crypto_pwhash_str.restype = ctypes.c_int
    lib.crypto_pwhash_str.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong,
        ctypes.c_ulonglong, ctypes.c_size_t]

    lib.crypto_pwhash_str_verify.restype = ctypes.c_int
    lib.crypto_pwhash_str_verify.argtypes = [
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulonglong]

    _lib = lib
    return _lib


def randombytes(n):
    """n bytes from the platform CSPRNG."""
    buf = ctypes.create_string_buffer(n)
    _sodium().randombytes_buf(buf, n)
    return buf.raw


def pwhash(outlen, password, salt, opslimit, memlimit):
    """Argon2id: derive an `outlen`-byte key from `password` + `salt`."""
    if len(salt) != SALTBYTES:
        raise ValueError("salt must be %d bytes" % SALTBYTES)
    out = ctypes.create_string_buffer(outlen)
    rc = _sodium().crypto_pwhash(
        out, outlen, password, len(password), salt,
        opslimit, memlimit, ALG_ARGON2ID13)
    if rc != 0:
        raise RuntimeError("crypto_pwhash failed (rc=%d, likely OOM)" % rc)
    return out.raw


def kdf_derive(subkey_len, subkey_id, context, key):
    """BLAKE2b subkey derivation (crypto_kdf_derive_from_key)."""
    if len(context) != KDF_CONTEXTBYTES:
        raise ValueError("context must be %d bytes" % KDF_CONTEXTBYTES)
    if len(key) != KDF_KEYBYTES:
        raise ValueError("key must be %d bytes" % KDF_KEYBYTES)
    out = ctypes.create_string_buffer(subkey_len)
    rc = _sodium().crypto_kdf_derive_from_key(
        out, subkey_len, subkey_id, context, key)
    if rc != 0:  # pragma: no cover
        raise RuntimeError("crypto_kdf_derive_from_key failed (rc=%d)" % rc)
    return out.raw


def aead_encrypt(message, ad, nonce, key):
    """XChaCha20-Poly1305 (IETF) encrypt. Returns ciphertext||tag."""
    if len(nonce) != AEAD_NPUBBYTES:
        raise ValueError("nonce must be %d bytes" % AEAD_NPUBBYTES)
    if len(key) != AEAD_KEYBYTES:
        raise ValueError("key must be %d bytes" % AEAD_KEYBYTES)
    out = ctypes.create_string_buffer(len(message) + AEAD_ABYTES)
    clen = ctypes.c_ulonglong(0)
    ad = ad or b""
    rc = _sodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
        out, ctypes.byref(clen), message, len(message),
        ad, len(ad), None, nonce, key)
    if rc != 0:  # pragma: no cover
        raise RuntimeError("aead encrypt failed (rc=%d)" % rc)
    return out.raw[:clen.value]


def aead_decrypt(ciphertext, ad, nonce, key):
    """XChaCha20-Poly1305 (IETF) decrypt. Raises on auth failure (fail closed)."""
    if len(nonce) != AEAD_NPUBBYTES:
        raise ValueError("nonce must be %d bytes" % AEAD_NPUBBYTES)
    if len(key) != AEAD_KEYBYTES:
        raise ValueError("key must be %d bytes" % AEAD_KEYBYTES)
    out = ctypes.create_string_buffer(max(len(ciphertext) - AEAD_ABYTES, 0))
    mlen = ctypes.c_ulonglong(0)
    ad = ad or b""
    rc = _sodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
        out, ctypes.byref(mlen), None, ciphertext, len(ciphertext),
        ad, len(ad), nonce, key)
    if rc != 0:
        raise ValueError("AEAD decryption failed (wrong key or tampered data)")
    return out.raw[:mlen.value]


def pwhash_str(password, opslimit, memlimit):
    """Argon2id password-hash string (self-describing salt+params)."""
    out = ctypes.create_string_buffer(PWHASH_STRBYTES)
    rc = _sodium().crypto_pwhash_str(
        out, password, len(password), opslimit, memlimit)
    if rc != 0:  # pragma: no cover
        raise RuntimeError("crypto_pwhash_str failed (rc=%d)" % rc)
    return out.value.decode("ascii")


def pwhash_str_verify(stored, password):
    """Verify a password against a stored crypto_pwhash_str hash."""
    buf = ctypes.create_string_buffer(stored.encode("ascii"), PWHASH_STRBYTES)
    return _sodium().crypto_pwhash_str_verify(buf, password, len(password)) == 0
