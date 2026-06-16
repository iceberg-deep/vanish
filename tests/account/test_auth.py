"""Auth module: register/login, password change, recovery + mandatory rotation."""

import pytest

from vanish.account import crypto


def test_register_then_login(registered):
    s = registered.mod.login(registered.user_id, registered.password)
    assert s.user_id == registered.user_id
    assert s.master_key == registered.session.master_key   # same key unwrapped


def test_login_wrong_password_fails(registered):
    with pytest.raises(ValueError):
        registered.mod.login(registered.user_id, "wrong password")


def test_change_password_preserves_master_key(registered):
    before = registered.session.master_key
    registered.mod.change_password(
        registered.session, "new passphrase here", params=crypto.FAST_KDF_PARAMS)
    # old password no longer works; new one does; key is unchanged (vault intact)
    with pytest.raises(ValueError):
        registered.mod.login(registered.user_id, registered.password)
    s = registered.mod.login(registered.user_id, "new passphrase here")
    assert s.master_key == before


def test_recover_rotates_code_and_invalidates_old(registered):
    new_code = registered.mod.recover(
        registered.user_id, registered.recovery, "reset passphrase",
        params=crypto.FAST_KDF_PARAMS)
    assert new_code != registered.recovery
    # new password works
    s = registered.mod.login(registered.user_id, "reset passphrase")
    assert s.master_key == registered.session.master_key
    # the OLD recovery code can no longer recover (it was rotated out)
    with pytest.raises(ValueError):
        registered.mod.recover(
            registered.user_id, registered.recovery, "another",
            params=crypto.FAST_KDF_PARAMS)
