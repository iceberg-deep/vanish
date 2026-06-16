"""Fixtures for the authenticated-user app tests.

Redirects the local account store into a tmp dir (mirrors the root conftest's
discipline for the CLI db) and provides a registered, logged-in session built with
fast Argon2id params so the suite stays quick.
"""

from types import SimpleNamespace

import pytest

from vanish.account import auth, crypto, store


@pytest.fixture(autouse=True)
def tmp_account_store(tmp_path, monkeypatch):
    vdir = tmp_path / ".vanish"
    monkeypatch.setattr(store, "VANISH_DIR", str(vdir))
    monkeypatch.setattr(store, "ACCOUNT_DB_PATH", str(vdir / "account.db"))
    store.init_db()
    yield


@pytest.fixture
def mod():
    return auth.MvpAuthModule()


@pytest.fixture
def registered(mod):
    """A registered + logged-in account using fast (test-only) KDF params."""
    password = "correct horse battery staple"
    user_id, recovery = mod.register(password, params=crypto.FAST_KDF_PARAMS)
    session = mod.login(user_id, password)
    return SimpleNamespace(
        mod=mod, user_id=user_id, recovery=recovery,
        password=password, session=session)
