"""Export proofs — the dossier-free guarantee, extended to the dashboard boundary.

The exported JSON carries only Finding fields projected to the dashboard's row shape:
no identifiers, no cross-finding links, no person object. This mirrors Phase 2's
field-drop discipline at the export edge.
"""

import json

from vanish.account import export_dashboard, identity, scan


def _seed(reg):
    identity.request_email_verification(
        reg.session, "owner@me.com", s := identity.RecordingSender())
    identity.confirm_verification(reg.session, s.last_token)
    scan.scan(reg.session, persist=True, sources={
        "breach_exposure": lambda e: [
            {"name": "MegaLeak", "data": ["Passwords"], "domain": "mega.example"}],
        "broker_listing": lambda e: [
            {"name": "Spokeo", "category": "people-search",
             "opt_out_url": "https://spokeo.com/optout"}],
        # dossier noise an OSINT-style source might return — must be dropped
        "discoverable_account": lambda e: [
            {"platform": "instagram", "exists": True,
             "recovery_email": "leak@x.com", "phone": "+1-555-0100",
             "linked_accounts": ["x:@me"]}]})


def test_export_has_no_identifier_fields(registered, tmp_path):
    _seed(registered)
    path = export_dashboard.write(registered.session, str(tmp_path / "f.json"))
    raw = open(path).read()
    # the verified identifier and any dossier PII the source leaked are absent
    for needle in ("owner@me.com", "leak@x.com", "555-0100", "linked_accounts",
                   "recovery_email", "\"email\"", "\"name\""):
        assert needle not in raw, "export leaked %r" % needle


def test_label_is_free_text_and_never_the_verified_email(registered, tmp_path):
    _seed(registered)            # verifies owner@me.com
    # default label is a placeholder, not the email
    default = json.loads(open(
        export_dashboard.write(registered.session, str(tmp_path / "a.json"))).read())
    assert default["operator"] == "you@local"
    assert "owner@me.com" not in open(str(tmp_path / "a.json")).read()
    # a custom label is shown verbatim; the verified email still never appears
    custom = json.loads(open(export_dashboard.write(
        registered.session, str(tmp_path / "b.json"), label="My Nickname")).read())
    assert custom["operator"] == "My Nickname"
    assert "owner@me.com" not in open(str(tmp_path / "b.json")).read()


def test_export_shape_is_dossier_free_and_action_bound(registered, tmp_path):
    _seed(registered)
    data = json.loads(open(
        export_dashboard.write(registered.session, str(tmp_path / "f.json"))).read())
    assert data["findings"]
    banned = export_dashboard._BANNED
    by_kind = {}
    for row in data["findings"]:
        assert set(map(str.lower, row["what_was_found"])).isdisjoint(banned)
        assert row["remediation"].get("url") or row["remediation"].get("text")
        by_kind.setdefault(row["kind"], row)

    # human-facing source names survive (the display name, not provenance)
    assert by_kind["broker_listing"]["source"] == "Spokeo"
    assert by_kind["discoverable_account"]["source"] == "instagram"
    assert by_kind["breach_exposure"]["source"] == "MegaLeak"
    # discoverable account is existence-only
    assert set(by_kind["discoverable_account"]["what_was_found"]) == {"platform"}
    # remediation kinds map correctly
    assert by_kind["broker_listing"]["remediation"]["type"] == "letter"
    assert by_kind["discoverable_account"]["remediation"]["type"] == "link"
    assert by_kind["breach_exposure"]["remediation"]["type"] == "guidance"


def test_dashboard_html_has_no_graph_or_identity_view():
    """The shipped dashboard is a worklist — no canvas, graph lib, or person view."""
    import pathlib
    html = pathlib.Path("vanish/account/dashboard.html").read_text().lower()
    # actual graph-rendering surfaces a Maltego-style view would need:
    for banned in ("<canvas", "<svg", "d3.", "cytoscape", "vis-network",
                   "force-graph", "sigma.js", "getcontext"):
        assert banned not in html, "dashboard contains a graph surface: %s" % banned
    # it explicitly groups by remediation category only
    assert "grouped by remediation category" in html
