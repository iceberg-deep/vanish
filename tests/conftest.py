"""Shared test fixtures.

Two hard rules for the suite, enforced here:
  * No test ever touches the real ~/.vanish store — `db` is redirected to a
    tmp dir for every test.
  * No test ever hits the network — `requests.get` is blocked by default; tests
    that exercise audit logic stub the specific audit function instead.
"""

import pytest

from vanish import db


@pytest.fixture(autouse=True)
def tmp_store(tmp_path, monkeypatch):
    """Redirect the SQLite store into a throwaway tmp directory."""
    vdir = tmp_path / ".vanish"
    monkeypatch.setattr(db, "VANISH_DIR", str(vdir))
    monkeypatch.setattr(db, "DB_PATH", str(vdir / "vanish.db"))
    db.init_db()
    yield
    return


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Fail loudly if any test makes a real HTTP request."""
    def _boom(*a, **k):
        raise AssertionError("network access attempted in a test")
    monkeypatch.setattr("requests.get", _boom)
    yield


class FakeResp:
    """Minimal stand-in for a requests.Response used by audit classifiers."""

    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


@pytest.fixture
def fake_resp():
    return FakeResp
