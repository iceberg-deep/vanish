"""Auth module (MVP) + unlocked Session — CRYPTO-SPEC.md §6.

`AuthModule` is the swappable seam: this MVP mode derives AUTH_KEY from the password
and stores a slow-hash verifier. OPAQUE (the aPAKE upgrade, §6.2) drops in behind the
same interface later WITHOUT touching the envelope, because the envelope derives
ENC_KEY independently of how authentication happens.

A successful login yields a `Session` holding MASTER_KEY in memory only. The session
is what the identity/scan layers operate against — there is no other way to reach the
vault key. Authentication's only output is this session; it is never key material that
the storage layer sees.
"""

import uuid

from . import crypto, store


class Session:
    """An unlocked account. Holds MASTER_KEY in memory for the active session."""

    def __init__(self, user_id, master_key):
        self.user_id = user_id
        self._master_key = master_key

    @property
    def master_key(self):
        if self._master_key is None:
            raise RuntimeError("session is locked")
        return self._master_key

    def lock(self):
        """Best-effort drop of the key. (Python bytes are immutable, so this
        cannot guarantee zeroization — see CRYPTO-SPEC §10 honest limits.)"""
        self._master_key = None


class MvpAuthModule:
    """Password-derived AUTH_KEY over the (future) wire; verifier stored locally."""

    def register(self, password, params=None):
        """Create an account. Returns (user_id, recovery_code) — code shown once."""
        params = params or crypto.DEFAULT_KDF_PARAMS
        user_id = uuid.uuid4().hex
        salt_pw = crypto.new_salt()
        salt_rec = crypto.new_salt()
        master_key = crypto.new_master_key()
        recovery_code = crypto.new_recovery_code()

        enc_key, auth_key = crypto.derive_keys(password, salt_pw, params)
        recovery_key = crypto.derive_recovery_key(recovery_code, salt_rec, params)

        wrapped_password = crypto.wrap_master_key(
            master_key, enc_key, user_id, "password", params["version"])
        wrapped_recovery = crypto.wrap_master_key(
            master_key, recovery_key, user_id, "recovery", params["version"])
        verifier = crypto.make_auth_verifier(auth_key)

        store.create_account(
            user_id, verifier, salt_pw, salt_rec, params,
            wrapped_password, wrapped_recovery)
        return user_id, recovery_code

    def login(self, user_id, password):
        """Verify the password and unwrap MASTER_KEY. Returns a Session or raises."""
        acct = store.get_account(user_id)
        if acct is None:
            raise ValueError("no such account")
        params = acct["kdf_params"]
        enc_key, auth_key = crypto.derive_keys(password, acct["salt_pw"], params)
        if not crypto.verify_auth(acct["auth_verifier"], auth_key):
            raise ValueError("invalid credentials")
        master_key = crypto.unwrap_master_key(
            acct["wrapped_password"], enc_key, user_id, "password",
            params["version"])
        return Session(user_id, master_key)

    def change_password(self, session, new_password, params=None):
        """Re-wrap MASTER_KEY under a new password. The vault is NOT re-encrypted."""
        params = params or crypto.DEFAULT_KDF_PARAMS
        salt_pw = crypto.new_salt()
        enc_key, auth_key = crypto.derive_keys(new_password, salt_pw, params)
        wrapped = crypto.wrap_master_key(
            session.master_key, enc_key, session.user_id, "password",
            params["version"])
        verifier = crypto.make_auth_verifier(auth_key)
        store.update_wrapped_password(
            session.user_id, salt_pw, verifier, wrapped)

    def recover(self, user_id, recovery_code, new_password, params=None):
        """Unwrap via the recovery code, set a new password, and ROTATE the code.

        Mandatory rotation (CRYPTO-SPEC §8.5.1): the used code was exposed, so it is
        invalidated and a fresh one is issued. Returns the new recovery code.
        """
        params = params or crypto.DEFAULT_KDF_PARAMS
        acct = store.get_account(user_id)
        if acct is None:
            raise ValueError("no such account")
        old_params = acct["kdf_params"]
        recovery_key = crypto.derive_recovery_key(
            recovery_code, acct["salt_rec"], old_params)
        master_key = crypto.unwrap_master_key(
            acct["wrapped_recovery"], recovery_key, user_id, "recovery",
            old_params["version"])

        # New password slot.
        session = Session(user_id, master_key)
        self.change_password(session, new_password, params)

        # Rotate the recovery slot with a brand-new code (invalidates the old one).
        new_code = crypto.new_recovery_code()
        salt_rec = crypto.new_salt()
        new_recovery_key = crypto.derive_recovery_key(new_code, salt_rec, params)
        wrapped_recovery = crypto.wrap_master_key(
            master_key, new_recovery_key, user_id, "recovery", params["version"])
        store.update_wrapped_recovery(user_id, salt_rec, wrapped_recovery)
        return new_code


# Default module instance (swap for an OpaqueAuthModule later, same interface).
default_module = MvpAuthModule()
