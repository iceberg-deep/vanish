"""End-to-end CLI behavior through main(), incl. the no-PII-persistence invariant."""

import pytest

from vanish import audit, cli, db


def run(argv, capsys):
    """Invoke the CLI and return (exit_code, stdout)."""
    rc = cli.main(argv)
    out = capsys.readouterr().out
    return rc, out


@pytest.fixture(autouse=True)
def non_interactive_and_offline(monkeypatch):
    """cleanse runs without a tty; browser/clipboard are no-ops in tests."""
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    monkeypatch.setattr(cli.automation, "open_url", lambda url: False)
    monkeypatch.setattr(cli.automation, "copy_clipboard", lambda text: (False, None))


# --- basic dispatch ------------------------------------------------------ #

def test_brokers_lists_registry(capsys):
    rc, out = run(["brokers", "--category", "people-search"], capsys)
    assert rc == 0
    assert "Spokeo" in out


def test_request_unknown_broker_errors(capsys):
    rc, _ = run(["request", "--broker", "nope", "--name", "X",
                 "--email", "x@e.com", "--template", "ccpa"], capsys)
    assert rc == 2


def test_request_renders_and_tracks(capsys):
    rc, out = run(["request", "--broker", "spokeo", "--name", "Jane Doe",
                   "--email", "jane@example.com", "--template", "ccpa",
                   "--track"], capsys)
    assert rc == 0
    assert "Jane Doe" in out                 # in the printed letter
    assert "Tracked as request" in out
    assert len(db.list_requests()) == 1      # but logged as a fact only


def test_track_shows_no_identifiers(capsys):
    run(["request", "--broker", "spokeo", "--name", "Jane Doe",
         "--email", "jane@example.com", "--template", "ccpa", "--track"], capsys)
    _, out = run(["track"], capsys)
    assert "jane@example.com" not in out
    assert "Jane Doe" not in out
    assert "Spokeo" in out


# --- the headline guarantee --------------------------------------------- #

def test_identifiers_never_reach_the_db_file(capsys):
    run(["request", "--broker", "spokeo", "--name", "Jane Doe",
         "--email", "jane@example.com", "--phone", "555-0100",
         "--template", "ccpa", "--track"], capsys)
    run(["cleanse", "--name", "Jane Doe", "--email", "jane@example.com",
         "--brokers", "spokeo,mylife", "--no-browser"], capsys)
    blob = open(db.DB_PATH, "rb").read()
    for needle in (b"Jane Doe", b"jane@example.com", b"555-0100"):
        assert needle not in blob, "identifier leaked into the DB file"


# --- status lifecycle ---------------------------------------------------- #

def test_status_update_via_cli(capsys):
    run(["request", "--broker", "spokeo", "--name", "X", "--email",
         "x@e.com", "--template", "ccpa", "--track"], capsys)
    rid = db.list_requests()[0]["id"]
    rc, out = run(["status", str(rid), "sent"], capsys)
    assert rc == 0
    assert db.status_counts().get("sent") == 1


# --- audit (network stubbed) -------------------------------------------- #

def test_audit_email_flags_sensitive(capsys, monkeypatch):
    monkeypatch.setattr(audit, "check_hibp", lambda email: {
        "ok": True, "breaches": [
            {"title": "MegaLeak", "name": "MegaLeak", "date": "2020-01-01",
             "data": ["Email addresses", "Passwords", "Social security numbers"]}]})
    rc, out = run(["audit", "--email", "me@example.com"], capsys)
    assert rc == 0
    assert "SENSITIVE" in out
    assert "High-risk data exposed" in out
    assert "credit freeze" in out  # SSN-specific guidance


def test_audit_username_reports_per_platform(capsys, monkeypatch):
    monkeypatch.setattr(audit, "check_username", lambda u, p=None: [
        {"platform": "github", "url": "https://github.com/x",
         "status": "found", "code": 200, "method": "status"},
        {"platform": "instagram", "url": "https://instagram.com/x",
         "status": "manual", "code": 200, "method": "manual"}])
    rc, out = run(["audit", "--username", "x"], capsys)
    assert rc == 0
    assert "github" in out and "instagram" in out


def test_audit_requires_something_to_check(capsys):
    rc, _ = run(["audit"], capsys)
    assert rc == 2


def test_audit_no_key_shows_safe_setup_guidance(capsys, monkeypatch):
    # Without a key: explain how to get one and how to use it for one session
    # only (export -> use -> unset), and disclose nothing is transmitted.
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    rc, out = run(["audit", "--email", "me@example.com"], capsys)
    assert rc == 0
    assert "No data is transmitted" in out
    assert "haveibeenpwned.com/API/Key" in out
    assert "export HIBP_API_KEY" in out
    assert "unset HIBP_API_KEY" in out


def test_audit_no_key_does_not_transmit(capsys, monkeypatch):
    # Belt-and-suspenders: with no key, the audit must not hit the network
    # (the conftest no_network fixture already raises on requests.get).
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    rc, _ = run(["audit", "--email", "me@example.com"], capsys)
    assert rc == 0


# --- cleanse walkthrough ------------------------------------------------- #

def test_cleanse_runs_all_three_phases(capsys):
    rc, out = run(["cleanse", "--name", "Jane", "--email", "jane@example.com",
                   "--brokers", "spokeo,mylife", "--no-browser"], capsys)
    assert rc == 0
    assert "FIND" in out and "CLEANSE" in out and "VALIDATE" in out
    assert "privacy@mylife.com" in out  # email broker draft target


def test_cleanse_requires_name_and_email(capsys):
    rc, _ = run(["cleanse", "--brokers", "spokeo", "--no-browser"], capsys)
    assert rc == 2


def test_cleanse_empty_selection_errors(capsys):
    rc, _ = run(["cleanse", "--name", "J", "--email", "j@e.com",
                 "--brokers", "does-not-exist", "--no-browser"], capsys)
    assert rc == 1


# --- guide --------------------------------------------------------------- #

def test_guide_stdout_prints_report(capsys):
    rc, out = run(["guide", "--stdout"], capsys)
    assert rc == 0
    assert "Removing Yourself From the Internet" in out


# --- regression: web-form steps must match the broker's match-method ----- #

def test_method_steps_adapt_to_profile_url(capsys):
    from vanish import brokers
    spokeo = brokers.get("spokeo")   # matches on a listing URL
    acxiom = brokers.get("acxiom")   # matches on name/address (no listing)
    spokeo_steps = " ".join(cli._method_steps(spokeo)).lower()
    acxiom_steps = " ".join(cli._method_steps(acxiom)).lower()
    assert "listing" in spokeo_steps
    assert "listing" not in acxiom_steps  # don't tell aggregator users to "find your listing"
    assert "name" in acxiom_steps
