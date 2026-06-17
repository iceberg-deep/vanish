"""Single-operator runner proofs: the self-only gate holds end-to-end through the
CLI, single-operator is enforced, and no network/submit/multi-user path exists."""

import pathlib
import re

import pytest

from vanish.account import crypto, runner, scan, store

RUNNER_SRC = pathlib.Path("vanish/account/runner.py")
EXPORT_SRC = pathlib.Path("vanish/account/export_dashboard.py")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("VANISH_ACCOUNT_PASSWORD", "correct horse battery staple")
    monkeypatch.setenv("VANISH_ACCOUNT_FAST", "1")
    monkeypatch.delenv("HIBP_API_KEY", raising=False)   # keep scan offline


def run(argv, capsys):
    rc = runner.main(argv)
    return rc, capsys.readouterr().out


def test_scan_only_covers_verified_set_through_cli(capsys):
    run(["register"], capsys)
    uid = store.account_ids()[0]

    # Before verifying anything, a scan finds nothing — the gate yields no targets.
    run(["scan"], capsys)
    sess = runner._MODULE.login(uid, "correct horse battery staple")
    assert scan.load_findings(sess) == []

    # Verify an owned email, then scan -> findings appear (driven only by the
    # verified set).
    _, out = run(["verify-email", "owner@me.com"], capsys)
    token = re.search(r"VERIFICATION_TOKEN=(\S+)", out).group(1)
    run(["confirm-email", token], capsys)
    run(["scan"], capsys)
    assert scan.load_findings(sess)            # non-empty now


def test_cli_has_no_way_to_scan_a_third_party_identifier():
    # The `scan` subcommand accepts NO identifier argument — you cannot point it at
    # a stranger's email through the CLI.
    parser = runner.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["scan", "stranger@evil.com"])


def test_register_refuses_a_second_account(capsys):
    assert run(["register"], capsys)[0] == 0
    rc, _ = run(["register"], capsys)
    assert rc == 1                              # single operator: no second user


def test_sole_session_refuses_when_multiple_accounts(capsys):
    run(["register"], capsys)
    # Simulate a second account existing; the runner must refuse to choose.
    store.create_account("intruder", "v", b"0" * 16, b"0" * 16,
                         crypto.FAST_KDF_PARAMS, b"x", b"x")
    with pytest.raises(SystemExit):
        run(["whoami"], capsys)


def test_no_network_submit_or_multiuser_path():
    """Grep the runner + exporter source: no outbound client, no routable bind, no
    server, no multi-tenant surface. (The dashboard is a static file the operator
    serves themselves over loopback.)"""
    for src in (RUNNER_SRC, EXPORT_SRC):
        text = src.read_text().lower()
        for forbidden in ("urllib.request", "smtplib", "http.client", "ftplib",
                          ".post(", "sendmail", "0.0.0.0", "flask", "import socket",
                          "httpserver", "socketserver"):
            assert forbidden not in text, "%s has a forbidden path: %s" % (src, forbidden)
        assert not re.search(r"\brequests\b", text), "%s uses the requests lib" % src
