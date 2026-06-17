"""Dashboard (view-layer) proofs: no dossier component, findings-only render,
grouping by kind only, action-presence, ZK in-memory render."""

import pathlib

from vanish.account import dashboard, findings, identity, scan

DASHBOARD_SRC = pathlib.Path("vanish/account/dashboard.py")


def _mk(kind, severity="medium", status="pending", **what):
    target = "https://example/%s" % kind
    return findings.build_finding(
        kind, "src", severity, what,
        {"action_type": "act", "label": "Do it", "target": target}, "run1", status)


def _sample():
    return [
        _mk("breach_exposure", "high", breach_name="MegaLeak",
            exposed_data=["Passwords"]),
        _mk("broker_listing", "medium", broker_name="Spokeo", category="people-search"),
        _mk("broker_listing", "low", broker_name="Radaris", category="people-search"),
        _mk("discoverable_account", "low", platform="instagram"),
    ]


def test_no_dossier_component_in_view_layer():
    """Grep the view source: no profile/identity/graph/timeline/location/photo view."""
    banned = ("profile_header", "identity_summary", "linked_account", "account_graph",
              "person_graph", "locations", "geomap", "map_view", "timeline",
              "activity_view", "profile_photo", "avatar", "risk_profile",
              "ai_summary", "dossier")
    text = DASHBOARD_SRC.read_text().lower()
    for token in banned:
        assert token not in text, "view layer references a dossier component: %s" % token


def test_view_layer_imports_no_data_sources():
    """The render path cannot fetch user attributes — it imports no store/scan/
    identity/network source."""
    text = DASHBOARD_SRC.read_text()
    for forbidden in ("import store", "import scan", "import identity",
                      "import audit", "import brokers", "import accounts",
                      "from . import store", "from .scan", "from .identity",
                      "from .store", "import requests"):
        assert forbidden not in text


def test_render_reads_only_finding_fields():
    view = dashboard.build_worklist(_sample())
    for group in view["groups"]:
        for row in group["rows"]:
            extra = set(row) - set(dashboard.ROW_FIELDS) - {"primary_action"}
            assert not extra, "row surfaced a non-Finding field: %s" % extra


def test_render_contains_no_identity_or_email():
    # Findings carry no identifier; the render never had access to one either.
    view = dashboard.build_worklist(_sample())
    out = dashboard.render_text(view).lower()
    assert "@" not in out                       # no email anywhere in the worklist
    assert "profile" not in out and "identity" not in out


def test_grouping_is_by_kind_and_sorted_by_severity():
    view = dashboard.build_worklist(_sample())
    kinds = [g["kind"] for g in view["groups"]]
    assert kinds == list(findings.KINDS)        # grouped strictly by kind
    brokers = next(g for g in view["groups"] if g["kind"] == "broker_listing")["rows"]
    assert [r["severity"] for r in brokers] == ["medium", "low"]   # severity-sorted
    # the only roll-ups are counts (not identities)
    assert view["counts"] == {"breach_exposure": 1, "broker_listing": 2,
                              "discoverable_account": 1, "total": 4}


def test_every_row_is_action_bound():
    view = dashboard.build_worklist(_sample())
    out = dashboard.render_text(view)
    for group in view["groups"]:
        for row in group["rows"]:
            assert row["remediation_action"].get("target")
            assert row["remediation_action"]["target"] in out   # action visible in render


def test_exposure_series_is_counts_only():
    series = dashboard.exposure_series([("w1", 12), ("w2", 7), ("w3", 3)])
    assert series == [{"t": "w1", "open": 12}, {"t": "w2", "open": 7},
                      {"t": "w3", "open": 3}]
    assert all(isinstance(p["open"], int) for p in series)


def test_render_is_in_memory_only_no_repersist(registered):
    """Rendering decrypted findings writes nothing back to the store (ZK carried)."""
    sender = identity.RecordingSender()
    identity.request_email_verification(registered.session, "owner@me.com", sender)
    identity.confirm_verification(registered.session, sender.last_token)
    scan.scan(registered.session, sources={
        "breach_exposure": lambda e: [],
        "broker_listing": lambda e: [{"name": "Spokeo", "category": "people-search",
                                      "opt_out_url": "https://spokeo/optout"}],
        "discoverable_account": lambda e: []}, persist=True)

    from vanish.account import store
    before = open(store.ACCOUNT_DB_PATH, "rb").read()
    view = dashboard.build_worklist(scan.load_findings(registered.session))
    dashboard.render_text(view)
    after = open(store.ACCOUNT_DB_PATH, "rb").read()
    assert before == after          # render persisted nothing
