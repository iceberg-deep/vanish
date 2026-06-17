"""Action-layer proofs: identifier-non-persistence, action-correctness,
tool-not-agent, no-dossier-regression, status flow."""

import dataclasses
import pathlib
import re

from vanish import db as cli_db
from vanish.account import actions, findings, identity, scan, store

ACTIONS_SRC = pathlib.Path("vanish/account/actions.py")


def _verify(reg, email):
    sender = identity.RecordingSender()
    identity.request_email_verification(reg.session, email, sender)
    identity.confirm_verification(reg.session, sender.last_token)


def _seed(reg, **sources):
    base = {"breach_exposure": lambda e: [], "broker_listing": lambda e: [],
            "discoverable_account": lambda e: []}
    base.update(sources)
    _verify(reg, "owner@me.com")
    return scan.scan(reg.session, sources=base, persist=True)


def test_identifier_non_persistence_after_letter(registered):
    """Headline: rendering a letter with sentinel identifiers leaves no trace of
    them in any store."""
    _seed(registered, broker_listing=lambda e: [
        {"name": "Spokeo", "category": "people-search",
         "opt_out_url": "https://spokeo.com/optout"}])
    finding = scan.load_findings(registered.session)[0]

    sentinel_name = "Zxqvm Sentinelname"
    sentinel_email = "sentinel-zxqvm@nowhere.example"
    result = actions.generate_broker_letter(
        registered.session, finding, name=sentinel_name, email=sentinel_email)

    # the letter (for the user) DID render with the identifiers...
    assert sentinel_name in result.body and sentinel_email in result.body
    # ...but they evaporated: absent from the account store AND the CLI tracker.
    for path in (store.ACCOUNT_DB_PATH, cli_db.DB_PATH):
        raw = open(path, "rb").read()
        assert sentinel_name.encode() not in raw, "name leaked into %s" % path
        assert sentinel_email.encode() not in raw, "email leaked into %s" % path


def test_action_correctness_per_kind(registered):
    _seed(registered,
          breach_exposure=lambda e: [{"name": "MegaLeak", "data": ["Passwords"],
                                      "domain": "mega.example"}],
          broker_listing=lambda e: [{"name": "Radaris", "category": "people-search",
                                     "opt_out_url": "https://radaris.com/optout"}],
          discoverable_account=lambda e: [{"platform": "instagram", "exists": True}])
    by_kind = {f.kind: f for f in scan.load_findings(registered.session)}

    # broker -> a real letter naming the broker, with a valid template
    letter = actions.generate_broker_letter(
        registered.session, by_kind["broker_listing"], name="Jane Doe",
        email="jane@me.com", template="ccpa")
    assert letter.action_type == "letter" and letter.template == "ccpa"
    assert "Radaris" in letter.body and "CCPA" in letter.body
    assert letter.link == "https://radaris.com/optout"

    # discoverable account -> the official deletion link for that platform
    acct = actions.surface_account_deletion(
        registered.session, by_kind["discoverable_account"])
    assert acct.action_type == "link"
    assert acct.link == "https://www.instagram.com/accounts/remove/request/permanent/"

    # breach -> guidance, no letter, no submission
    breach = actions.surface_breach_guidance(
        registered.session, by_kind["breach_exposure"])
    assert breach.action_type == "guidance"
    assert "two-factor" in breach.body and "does not contact" in breach.body
    assert "To: Privacy" not in breach.body          # not a letter


def test_tool_not_agent_no_submit_path():
    """No code path submits/sends a removal to a third party."""
    text = ACTIONS_SRC.read_text().lower()
    for forbidden in ("smtplib", "urllib", "http.client", ".post(", ".send(",
                      "sendmail", "submit("):
        assert forbidden not in text, "action layer has a submit/send path: %s" % forbidden
    # the bare `requests` HTTP lib (but NOT the legitimate requests_gen letter core)
    assert not re.search(r"\brequests\b", text), "action layer uses the requests HTTP lib"


def test_no_dossier_regression():
    # no new identity-aggregating type in the action layer
    text = ACTIONS_SRC.read_text()
    for banned in ("class Profile", "class Person", "class Identity",
                   "class Subject", "class Dossier"):
        assert banned not in text
    # Finding gained no new field
    names = {f.name for f in dataclasses.fields(findings.Finding)}
    assert names == {"finding_id", "kind", "source", "severity", "what_was_found",
                     "remediation_action", "scan_run_id", "status"}
    # ActionResult is a per-finding result, not an identity aggregator
    ar = {f.name for f in dataclasses.fields(actions.ActionResult)}
    assert "finding_id" in ar and ar.isdisjoint(findings.FORBIDDEN_FIELDS)


def test_status_flow_through_action(registered):
    _seed(registered, broker_listing=lambda e: [
        {"name": "Spokeo", "category": "people-search",
         "opt_out_url": "https://spokeo.com/optout"}])
    finding = scan.load_findings(registered.session)[0]
    assert finding.status == "pending"

    actions.generate_broker_letter(registered.session, finding, name="Jane Doe",
                                   email="jane@me.com")
    assert scan.load_findings(registered.session)[0].status == "action_taken"

    actions.confirm_removed(registered.session, finding.finding_id)
    assert scan.load_findings(registered.session)[0].status == "confirmed_removed"

    # the identifier-free tracker recorded the transitions (kind + status only)
    actionset = [r["action"] for r in cli_db._connect().execute(
        "SELECT action FROM audit_log").fetchall()]
    assert actionset.count("finding.status") >= 2
