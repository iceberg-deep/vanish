"""The zero-knowledge auth envelope (CRYPTO-SPEC.md §2-§4).

High-level operations built on the libsodium primitives in `sodium.py`:
  * split key derivation  password -> STRETCHED -> ENC_KEY / AUTH_KEY  (§3.3)
  * master-key envelope   wrap/unwrap MASTER_KEY under ENC_KEY & RECOVERY_KEY (§4)
  * record AEAD           seal/open arbitrary data under MASTER_KEY      (§5)
  * recovery-code lifecycle                                             (§3.4)
  * MVP auth verifier                                                   (§6.1)

ENC_KEY and MASTER_KEY never leave the device in any form. Nothing here writes to
disk; persistence is the store layer's job and it only ever sees ciphertext.
"""

import base64
import struct
import unicodedata

from . import sodium

# Domain-separation context for the AUTH/ENC subkey split (exactly 8 bytes).
KDF_CONTEXT = b"vanishKD"
SUBKEY_AUTH = 1   # MVP auth module only; unused under OPAQUE
SUBKEY_ENC = 2

ENVELOPE_VERSION = 1
BLOB_VERSION = 1

# Provisional Argon2id cost. These are the MODERATE values from KDF-PARAMS.md and
# are **NOT yet reviewer-approved** — pending the low-end-device benchmark and the
# cryptographer sign-off (ROADMAP Phase 0 items 0.3/0.1). Do not ship as final.
DEFAULT_KDF_PARAMS = {
    "alg": "argon2id13",
    "opslimit": sodium.OPSLIMIT_MODERATE,
    "memlimit": sodium.MEMLIMIT_MODERATE,
    "version": 1,
    "reviewed": False,
}
# Light params for tests only (keeps Argon2id fast in CI). Never a production default.
FAST_KDF_PARAMS = {
    "alg": "argon2id13",
    "opslimit": sodium.OPSLIMIT_INTERACTIVE,
    "memlimit": sodium.MEMLIMIT_INTERACTIVE,
    "version": 1,
    "reviewed": False,
}

KEY_BYTES = 32


# --- normalization (determinism; CRYPTO-SPEC §9) -------------------------- #
def normalize_password(password):
    """NFC-normalize then UTF-8 encode, so the same password always re-derives."""
    return unicodedata.normalize("NFC", password).encode("utf-8")


# --- salts & keys --------------------------------------------------------- #
def new_salt():
    return sodium.randombytes(sodium.SALTBYTES)


def new_master_key():
    return sodium.randombytes(KEY_BYTES)


def derive_keys(password, salt_pw, params):
    """password -> (ENC_KEY, AUTH_KEY) via one Argon2id then BLAKE2b subkeys."""
    stretched = sodium.pwhash(
        sodium.KDF_KEYBYTES, normalize_password(password), salt_pw,
        params["opslimit"], params["memlimit"])
    enc_key = sodium.kdf_derive(KEY_BYTES, SUBKEY_ENC, KDF_CONTEXT, stretched)
    auth_key = sodium.kdf_derive(KEY_BYTES, SUBKEY_AUTH, KDF_CONTEXT, stretched)
    return enc_key, auth_key


# --- AEAD helpers --------------------------------------------------------- #
def _seal(version, plaintext, key, ad):
    nonce = sodium.randombytes(sodium.AEAD_NPUBBYTES)
    ct = sodium.aead_encrypt(plaintext, ad, nonce, key)
    return bytes([version]) + nonce + ct


def _open(version, blob, key, ad):
    if not blob or blob[0] != version:
        raise ValueError("unexpected blob format version")
    nonce = blob[1:1 + sodium.AEAD_NPUBBYTES]
    ct = blob[1 + sodium.AEAD_NPUBBYTES:]
    return sodium.aead_decrypt(ct, ad, nonce, key)


# --- master-key envelope (§4) --------------------------------------------- #
def envelope_aad(user_id, slot, kdf_version):
    return (b"vanish.envelope.v1\x00" + user_id.encode("utf-8")
            + b"\x00slot=" + slot.encode("ascii") + b"\x00"
            + struct.pack("<I", kdf_version))


def wrap_master_key(master_key, wrapping_key, user_id, slot, kdf_version):
    return _seal(ENVELOPE_VERSION, master_key, wrapping_key,
                 envelope_aad(user_id, slot, kdf_version))


def unwrap_master_key(blob, wrapping_key, user_id, slot, kdf_version):
    return _open(ENVELOPE_VERSION, blob, wrapping_key,
                 envelope_aad(user_id, slot, kdf_version))


# --- record AEAD under MASTER_KEY (§5) ------------------------------------ #
def seal_record(plaintext, master_key, ad):
    return _seal(BLOB_VERSION, plaintext, master_key, ad)


def open_record(blob, master_key, ad):
    return _open(BLOB_VERSION, blob, master_key, ad)


# --- recovery code (§3.4) ------------------------------------------------- #
def new_recovery_code():
    """160 bits of entropy, base32, shown once. Grouped for transcription."""
    raw = sodium.randombytes(20)
    code = base64.b32encode(raw).decode("ascii").rstrip("=")
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


def normalize_recovery_code(code):
    return "".join(ch for ch in code.upper() if ch.isalnum()).encode("ascii")


def derive_recovery_key(code, salt_rec, params):
    return sodium.pwhash(
        KEY_BYTES, normalize_recovery_code(code), salt_rec,
        params["opslimit"], params["memlimit"])


# --- MVP auth verifier (§6.1) --------------------------------------------- #
def make_auth_verifier(auth_key):
    """Server-side verifier: a slow hash of the high-entropy AUTH_KEY."""
    return sodium.pwhash_str(
        auth_key, sodium.OPSLIMIT_INTERACTIVE, sodium.MEMLIMIT_INTERACTIVE)


def verify_auth(verifier, auth_key):
    return sodium.pwhash_str_verify(verifier, auth_key)
