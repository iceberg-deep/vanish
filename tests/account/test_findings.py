"""Finding type proofs: dossier-impossibility, field-drop, action-binding."""

import dataclasses
import pathlib

import pytest

from vanish.account import findings

ACCOUNT_SRC = pathlib.Path("vanish/account")


def test_no_dossier_type_exists_anywhere():
    """No Profile / Person / Identity / Subject / Dossier type, no linked-account
    structure, anywhere in the account package."""
    banned = ("class Profile", "class Person", "class Identity", "class Subject",
              "class Dossier", "class LinkedAccount", "linked_accounts =",
              "class AccountGraph")
    for path in ACCOUNT_SRC.glob("*.py"):
        text = path.read_text()
        for token in banned:
            assert token not in text, "%s defines a dossier type: %s" % (path, token)


def test_finding_type_has_no_dossier_fields():
    field_names = {f.name for f in dataclasses.fields(findings.Finding)}
    # The type carries exactly the action-bound fields and nothing identity-shaped.
    assert field_names == {
        "finding_id", "kind", "source", "severity", "what_was_found",
        "remediation_action", "scan_run_id", "status"}
    assert field_names.isdisjoint(findings.FORBIDDEN_FIELDS)


def test_field_drop_at_ingestion():
    """A source that returns recovery email + phone + linked accounts (EmailOSINT
    style) yields a Finding with none of those fields."""
    dirty = {
        "platform": "instagram", "exists": True,
        "recovery_email": "secret-recovery@gmail.com",
        "phone": "+1-555-0100",
        "linked_accounts": ["twitter:@me", "facebook:/me"],
        "location": "Springfield, IL",
        "last_seen": "2026-06-01",
        "risk_score": 87,
        "display_name": "Jane Q.",
    }
    f = findings.build_finding(
        "discoverable_account", "mock", "low", dirty,
        {"action_type": "delete_or_lock", "target": "https://x/delete"}, "run1")
    keys = set(f.what_was_found)
    assert keys.isdisjoint(findings.FORBIDDEN_FIELDS)
    assert "recovery_email" not in keys and "phone" not in keys
    assert "linked_accounts" not in keys and "location" not in keys
    assert "platform" in keys                     # the one allowed, action-motivating field


def test_action_binding_required():
    with pytest.raises(ValueError):
        findings.build_finding("broker_listing", "registry", "medium",
                               {"broker_name": "X"}, {"action_type": "opt_out"},  # no target
                               "run1")
    with pytest.raises(ValueError):
        findings.build_finding("broker_listing", "registry", "medium",
                               {"broker_name": "X"}, None, "run1")
    # a concrete target makes it valid
    f = findings.build_finding("broker_listing", "registry", "medium",
                               {"broker_name": "X"},
                               {"action_type": "opt_out", "target": "https://x/optout"},
                               "run1")
    assert f.remediation_action["target"] == "https://x/optout"


def test_direct_construction_cannot_smuggle_dossier_field():
    with pytest.raises(ValueError):
        findings.Finding(
            finding_id="f1", kind="broker_listing", source="s", severity="low",
            what_was_found={"phone": "+1-555-0100"},
            remediation_action={"target": "https://x"}, scan_run_id="r")


def test_grouping_is_by_kind_only():
    fs = [
        findings.build_finding("breach_exposure", "hibp", "high", {"breach_name": "A"},
                               {"target": "https://a"}, "r"),
        findings.build_finding("broker_listing", "registry", "medium", {"broker_name": "B"},
                               {"target": "https://b"}, "r"),
        findings.build_finding("broker_listing", "registry", "medium", {"broker_name": "C"},
                               {"target": "https://c"}, "r"),
    ]
    grouped = findings.group_by_kind(fs)
    assert len(grouped["broker_listing"]) == 2
    assert len(grouped["breach_exposure"]) == 1
    assert findings.counts_by_kind(fs) == {
        "breach_exposure": 1, "broker_listing": 2, "discoverable_account": 0}
