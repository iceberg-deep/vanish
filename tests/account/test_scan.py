"""Scan-engine proofs: the gate is enforced, output is action-bound findings, the
field-drop holds end-to-end, and stored findings are ciphertext at rest."""

import pytest

from vanish.account import identity, scan, store


def _verify(reg, email):
    sender = identity.RecordingSender()
    identity.request_email_verification(reg.session, email, sender)
    identity.confirm_verification(reg.session, sender.last_token)


def _sources(breaches=None, brokers=None, accounts=None):
    return {
        "breach_exposure": lambda _e: breaches or [],
        "broker_listing": lambda _e: brokers or [],
        "discoverable_account": lambda _e: accounts or [],
    }


def test_scan_refuses_unverified_identifier(registered):
    # The gate (carried from Phase 1): a stranger's email cannot be scanned.
    with pytest.raises(PermissionError):
        scan.scan_target(registered.session, "email", "stranger@evil.com",
                         "run1", _sources())


def test_scan_only_covers_the_verified_set(registered):
    _verify(registered, "owner@me.com")
    brokers = [{"name": "Spokeo", "category": "people-search",
                "opt_out_url": "https://spokeo/optout"}]
    results = scan.scan(registered.session, sources=_sources(brokers=brokers),
                        persist=False)
    assert all(f.kind == "broker_listing" for f in results)
    assert results and results[0].remediation_action["target"] == "https://spokeo/optout"


def test_every_finding_is_action_bound(registered):
    _verify(registered, "owner@me.com")
    sources = _sources(
        breaches=[{"name": "MegaLeak", "data": ["Passwords"], "domain": "mega.example"}],
        brokers=[{"name": "Radaris", "category": "people-search",
                  "opt_out_url": "https://radaris/optout"}],
        accounts=[{"platform": "instagram", "exists": True}])
    results = scan.scan(registered.session, sources=sources, persist=False)
    assert {f.kind for f in results} == {
        "breach_exposure", "broker_listing", "discoverable_account"}
    for f in results:
        assert f.remediation_action.get("target")        # action-first, always


def test_field_drop_end_to_end(registered):
    """A discoverable-account source returning dossier noise yields existence-only."""
    _verify(registered, "owner@me.com")
    dirty_account = {
        "platform": "facebook", "exists": True,
        "recovery_email": "leak-recovery@gmail.com", "phone": "+1-555-0199",
        "linked_accounts": ["x:@owner"], "location": "Chicago",
        "last_seen": "2026-05-01", "risk_profile": "high"}
    results = scan.scan(registered.session,
                        sources=_sources(accounts=[dirty_account]), persist=False)
    f = next(f for f in results if f.kind == "discoverable_account")
    assert set(f.what_was_found) == {"platform"}
    assert f.what_was_found["platform"] == "facebook"


def test_stored_findings_are_ciphertext(registered):
    _verify(registered, "secret.owner@example.com")
    dirty_account = {"platform": "instagram", "exists": True,
                     "recovery_email": "hidden-recovery@example.com",
                     "phone": "+1-555-0123"}
    scan.scan(registered.session,
              sources=_sources(accounts=[dirty_account]), persist=True)

    raw = open(store.ACCOUNT_DB_PATH, "rb").read()
    # the verified identifier and the dropped dossier PII are absent from the store
    assert b"secret.owner@example.com" not in raw
    assert b"hidden-recovery@example.com" not in raw
    assert b"555-0123" not in raw
    # but findings round-trip when decrypted in-memory
    loaded = scan.load_findings(registered.session)
    assert loaded and loaded[0].kind == "discoverable_account"
    assert set(loaded[0].what_was_found) == {"platform"}


def test_status_flow_updates_finding_and_tracker(registered):
    _verify(registered, "owner@me.com")
    brokers = [{"name": "Spokeo", "category": "people-search",
                "opt_out_url": "https://spokeo/optout"}]
    scan.scan(registered.session, sources=_sources(brokers=brokers), persist=True)
    fid = scan.load_findings(registered.session)[0].finding_id

    assert scan.set_finding_status(registered.session, fid, "confirmed_removed")
    assert scan.load_findings(registered.session)[0].status == "confirmed_removed"
    # the identifier-free CLI tracker recorded the fact (kind + status only)
    from vanish import db as cli_db
    actions = [r["action"] for r in cli_db._connect().execute(
        "SELECT action FROM audit_log").fetchall()]
    assert "finding.status" in actions
