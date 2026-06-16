"""Zero-knowledge proofs carried from the CLI's raw-store-grep discipline.

The storage layer holds only ciphertext + a verifier: never ENC_KEY, never MASTER_KEY,
and never the plaintext identifier value.
"""

from vanish.account import crypto, identity, store


def test_identifier_value_is_ciphertext_at_rest(registered):
    secret = "secret.person@example.com"
    sender = identity.RecordingSender()
    identity.request_email_verification(registered.session, secret, sender)
    identity.confirm_verification(registered.session, sender.last_token)

    blob = open(store.ACCOUNT_DB_PATH, "rb").read()
    assert secret.encode() not in blob, "plaintext identifier leaked into the store"
    # the encrypted column is genuinely present (and opaque)
    rows = store.list_identifiers(registered.user_id)
    assert rows and secret.encode() not in rows[0]["identifier_value_encrypted"]


def test_enc_key_and_master_key_never_in_store(registered):
    acct = store.get_account(registered.user_id)
    enc_key, auth_key = crypto.derive_keys(
        registered.password, acct["salt_pw"], acct["kdf_params"])
    master_key = registered.session.master_key

    blob = open(store.ACCOUNT_DB_PATH, "rb").read()
    assert enc_key not in blob, "ENC_KEY must never reach storage"
    assert master_key not in blob, "MASTER_KEY must never reach storage (only wrapped)"
    assert auth_key not in blob, "AUTH_KEY stored only as a one-way verifier"
