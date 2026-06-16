"""Envelope crypto: derivation independence, wrap/unwrap, record AEAD, recovery."""

import pytest

from vanish.account import crypto


def test_derive_keys_deterministic_and_independent():
    salt = crypto.new_salt()
    enc1, auth1 = crypto.derive_keys("pw", salt, crypto.FAST_KDF_PARAMS)
    enc2, auth2 = crypto.derive_keys("pw", salt, crypto.FAST_KDF_PARAMS)
    assert (enc1, auth1) == (enc2, auth2)          # deterministic
    assert enc1 != auth1                            # AUTH ⊥ ENC (independent subkeys)
    enc3, _ = crypto.derive_keys("pw", crypto.new_salt(), crypto.FAST_KDF_PARAMS)
    assert enc3 != enc1                             # salt actually matters


def test_envelope_wrap_unwrap_roundtrip():
    salt = crypto.new_salt()
    enc_key, _ = crypto.derive_keys("pw", salt, crypto.FAST_KDF_PARAMS)
    master = crypto.new_master_key()
    blob = crypto.wrap_master_key(master, enc_key, "uid", "password", 1)
    assert crypto.unwrap_master_key(blob, enc_key, "uid", "password", 1) == master


def test_envelope_rejects_wrong_key_and_wrong_slot():
    salt = crypto.new_salt()
    enc_key, _ = crypto.derive_keys("pw", salt, crypto.FAST_KDF_PARAMS)
    other, _ = crypto.derive_keys("other", crypto.new_salt(), crypto.FAST_KDF_PARAMS)
    master = crypto.new_master_key()
    blob = crypto.wrap_master_key(master, enc_key, "uid", "password", 1)
    with pytest.raises(ValueError):
        crypto.unwrap_master_key(blob, other, "uid", "password", 1)   # wrong key
    with pytest.raises(ValueError):
        crypto.unwrap_master_key(blob, enc_key, "uid", "recovery", 1)  # wrong slot
    with pytest.raises(ValueError):
        crypto.unwrap_master_key(blob, enc_key, "other-uid", "password", 1)  # user


def test_record_seal_open_and_tamper_fails():
    key = crypto.new_master_key()
    ad = b"vanish.identifier.v1\x00uid\x00email"
    blob = crypto.seal_record(b"jane@example.com", key, ad)
    assert crypto.open_record(blob, key, ad) == b"jane@example.com"
    tampered = blob[:-1] + bytes([blob[-1] ^ 0x01])
    with pytest.raises(ValueError):
        crypto.open_record(tampered, key, ad)


def test_recovery_code_has_entropy_and_normalizes():
    code = crypto.new_recovery_code()
    assert "-" in code                              # grouped for transcription
    a = crypto.normalize_recovery_code(code)
    b = crypto.normalize_recovery_code(code.lower().replace("-", "  "))
    assert a == b                                   # formatting-insensitive
    assert crypto.new_recovery_code() != crypto.new_recovery_code()


def test_default_params_are_provisional_and_unreviewed():
    # Guards against shipping with not-yet-reviewed Argon2id cost (CRYPTO-SPEC §1.2).
    assert crypto.DEFAULT_KDF_PARAMS["reviewed"] is False
    assert crypto.DEFAULT_KDF_PARAMS["memlimit"] >= 64 * 1024 * 1024
