"""Export the logged-in operator's own findings to JSON for the local dashboard.

Single-operator, local-only. Writes a flat list of Finding records — the exact
dossier-free shape `dashboard.html` renders. It carries ONLY the fields a Finding
already exposes (projected onto the dashboard's row shape); it adds no identifier, no
cross-finding link, no person/identity object. The output is a worklist, not a profile.

Nothing is uploaded. The dashboard reads this file from disk (served over 127.0.0.1).

Usage (inside the account app, with an unlocked session):
    from vanish.account import export_dashboard
    export_dashboard.write(session, "vanish-findings.json")
"""

import json

from . import findings as findings_mod
from . import scan

# Identifier-ish keys that must NEVER appear in an exported row. The export is
# checked against these (belt-and-suspenders over Phase 2's field-drop).
_BANNED = {"email", "name", "full_name", "phone", "phone_number", "recovery_email",
           "alternate_email", "linked_accounts", "linked_account", "address",
           "location", "geo", "timeline", "profile", "display_name", "username"}


def _row(f):
    """Project a real Finding onto the dashboard's flat row shape.

    The display `source` is the human-facing name from what_was_found (broker /
    breach / platform) — NOT the engine provenance. `remediation_action` (a dict)
    maps onto the dashboard's `remediation` block. No identifier is read or written.
    """
    action = f.remediation_action or {}
    w = f.what_was_found or {}

    if f.kind == "broker_listing":
        source = w.get("broker_name") or f.source
        what = {"site": w.get("category", "people-search")}
        remediation = {"type": "letter", "url": action.get("target"),
                       "template": action.get("letter_template", "ccpa")}
    elif f.kind == "discoverable_account":
        source = w.get("platform") or f.source
        what = {"platform": w.get("platform")}
        remediation = {"type": "link", "url": action.get("target"),
                       "steps": action.get("steps", "")}
    else:  # breach_exposure
        source = w.get("breach_name") or f.source
        what = {"exposed": list(w.get("exposed_data", []))}
        remediation = {"type": "guidance",
                       "text": "Rotate this password everywhere it was reused, and "
                               "enable two-factor authentication.",
                       "url": action.get("target")}

    return {
        "finding_id": f.finding_id,
        "kind": f.kind,
        "source": source,
        "severity": f.severity,
        "what_was_found": what,    # already minimal + dossier-free (Phase 2)
        "remediation": remediation,
        "status": f.status,
    }


def build(session):
    """Return the dashboard payload (a plain dict) for the unlocked session."""
    rows = [_row(f) for f in scan.load_findings(session)]

    # belt-and-suspenders: no identifier/dossier field may ride along in any row.
    for r in rows:
        keys = set(map(str.lower, r["what_was_found"].keys()))
        leaked = (keys | {r["kind"]}) & _BANNED & keys
        if leaked:
            raise ValueError("export would leak identifier fields: %s" % sorted(leaked))
        # also guard against a forbidden Finding field sneaking in
        bad = findings_mod.FORBIDDEN_FIELDS & keys
        if bad:
            raise ValueError("export would leak dossier fields: %s" % sorted(bad))

    return {"operator": "you@local", "generated": True, "findings": rows}


def write(session, path="vanish-findings.json"):
    """Write the export JSON. Returns the path."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build(session), fh, indent=2)
    return path
