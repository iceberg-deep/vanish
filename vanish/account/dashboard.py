"""Removal-worklist view layer (Phase 3).

Renders a flat ``list[Finding]`` (decrypted in-memory by the caller) as a prioritized
list of things to remove — nothing else. The emotional frame is "here's what to fix
and how," not "here's who you are."

This module is the view layer the native (Tauri) UI binds to; ``render_text`` is a
plain-text rendering that stands in for the on-screen worklist (and the render
snapshot in tests). It is deliberately a PURE function of the findings it is given:

  * It imports nothing that could fetch user attributes — no store, no scan engine, no
    identifiers table, no network source. Its only input is the findings list, and it
    reads only ``Finding`` fields.
  * It builds no person-level view of any kind: findings are grouped only by ``kind``
    (remediation category) and never assembled into one individual's profile, graph,
    map, or history. The forbidden person-view components are listed in the proof test.
  * Every row surfaces its ``remediation_action`` as the primary affordance. A row
    with no visible action is a bug.
  * The only roll-ups are aggregate counts (and a count-over-time series) — counts,
    never identities.
"""

from .findings import KINDS, counts_by_kind, group_by_kind

# Display order + phrasing for the three remediation categories.
_KIND_TITLE = {
    "breach_exposure": "Breaches — rotate these",
    "broker_listing": "Broker listings to remove",
    "discoverable_account": "Discoverable accounts to lock",
}
_HEADLINE = {
    "breach_exposure": "%d breaches — rotate these",
    "broker_listing": "%d broker listings to remove",
    "discoverable_account": "%d discoverable accounts to lock",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
# relisted = came back after removal: most urgent, sorts first.
_STATUS_ORDER = {"relisted": 0, "pending": 1, "action_taken": 2, "confirmed_removed": 3}

# The exact, complete set of Finding fields the view is allowed to surface.
ROW_FIELDS = ("kind", "source", "severity", "status",
              "what_was_found", "remediation_action")


def _row(finding):
    """A render row exposing ONLY Finding fields, action-first."""
    return {
        "kind": finding.kind,
        "source": finding.source,
        "severity": finding.severity,
        "status": finding.status,
        "what_was_found": finding.what_was_found,
        "remediation_action": finding.remediation_action,   # the primary affordance
        "primary_action": finding.remediation_action,        # alias: action-first
    }


def _sort_key(finding):
    return (_SEVERITY_ORDER.get(finding.severity, 99),
            _STATUS_ORDER.get(finding.status, 99))


def build_worklist(findings):
    """Group findings by kind and sort each group by severity then status.

    Returns a pure view-model: aggregate counts + per-kind groups of action-bound
    rows. There is no identity key, no cross-kind join, no person roll-up.
    """
    grouped = group_by_kind(findings)
    counts = counts_by_kind(findings)
    counts["total"] = sum(counts[k] for k in KINDS)
    groups = []
    for kind in KINDS:
        rows = [_row(f) for f in sorted(grouped[kind], key=_sort_key)]
        groups.append({"kind": kind, "title": _KIND_TITLE[kind], "rows": rows})
    headline = [_HEADLINE[k] % counts[k] for k in KINDS]
    return {"counts": counts, "headline": headline, "groups": groups}


def _summary(row):
    """One-line description from what_was_found ONLY (no identity)."""
    w = row["what_was_found"]
    if row["kind"] == "breach_exposure":
        exposed = ", ".join(w.get("exposed_data", []))
        return "%s%s" % (w.get("breach_name", "breach"),
                         " (%s)" % exposed if exposed else "")
    if row["kind"] == "broker_listing":
        return "%s — %s" % (w.get("broker_name", "broker"), w.get("category", ""))
    if row["kind"] == "discoverable_account":
        return "account on %s" % w.get("platform", "platform")
    return ""


def render_text(view):
    """Plain-text worklist render (stands in for the on-screen / Tauri view).

    Header is aggregate counts only — there is no identity/profile header.
    """
    lines = ["Removal worklist — %d items to fix" % view["counts"]["total"]]
    for line in view["headline"]:
        lines.append("  • " + line)
    for group in view["groups"]:
        if not group["rows"]:
            continue
        lines.append("")
        lines.append("== %s (%d) ==" % (group["title"], len(group["rows"])))
        for row in group["rows"]:
            action = row["remediation_action"]
            lines.append(
                "  [%-8s] %-46s  ->  %s: %s  [%s]" % (
                    row["severity"], _summary(row),
                    action.get("label", action.get("action_type", "action")),
                    action.get("target"), row["status"]))
    return "\n".join(lines)


def exposure_series(snapshots):
    """A count-over-time series for the line chart — counts, not identities.

    `snapshots` is an iterable of (label, open_count). Returns [{"t", "open"}], with
    open coerced to int so nothing finding-level can leak into the chart.
    """
    return [{"t": label, "open": int(open_count)} for label, open_count in snapshots]
