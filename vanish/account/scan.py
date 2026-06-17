"""The self-scan engine: turns a verified user's own identifiers into a worklist.

Reuses the existing vanish CLI core for the actual checks — HIBP breach lookup, the
data-broker registry, and (pluggably) per-platform account existence — and emits a
flat ``list[Finding]``. There is no profile, no person, no aggregation.

Two hard rules live here:
  * Every target passes through ``identity.assert_scannable`` first (carried from
    Phase 1). The engine reads ONLY the user's verified set; it accepts no externally
    supplied identifier. It physically cannot be pointed at a stranger.
  * Per the ZK model, the plaintext identifier exists in-memory only for the duration
    of the scan; findings are encrypted under MASTER_KEY before storage, and store
    only the minimal ``what_was_found`` needed to motivate the action.

Sources are injectable so real checks (network) and tests (mocks) share one path.
Whatever a source returns, ``findings.sanitize`` strips every dossier field at
ingestion (see ``findings.FORBIDDEN_FIELDS``).
"""

import json
import uuid

from .. import accounts as cli_accounts
from .. import audit as cli_audit
from .. import brokers as cli_brokers
from .. import db as cli_db
from . import crypto, findings, identity, store

_HIGH_RISK = {"passwords", "social security numbers", "credit cards",
              "bank account numbers"}
_BREACH_GUIDE = "https://vanish.local/guide/breach-credential-rotation"
_ACCOUNT_GUIDE = "https://vanish.local/guide/account-deletion"


def _finding_aad(user_id, finding_id):
    return (b"vanish.finding.v1\x00" + user_id.encode("utf-8") + b"\x00"
            + finding_id.encode("ascii"))


# --- default sources (reuse the CLI core) --------------------------------- #
def _breach_source(email):
    """HIBP breach lookup via the CLI's audit core. Network; mocked in tests."""
    result = cli_audit.check_hibp(email)
    return result.get("breaches", []) if result.get("ok") else []


def _broker_source(_email):
    """The data-broker registry as a removal worklist (local, no network)."""
    return cli_brokers.load_brokers()


def _account_source(_email):
    """Per-platform account existence. Existence-only; a real probe wires in here.

    Defaults to empty: we never fabricate existence. Tests inject a source that
    returns existence (plus dossier noise, to prove the noise is dropped).
    """
    return []


DEFAULT_SOURCES = {
    "breach_exposure": _breach_source,
    "broker_listing": _broker_source,
    "discoverable_account": _account_source,
}


# --- per-kind finding builders (set the concrete remediation action) ------ #
def _account_delete_url(platform):
    for a in cli_accounts.all_accounts():
        if platform and platform.lower() in (a["id"], a["name"].lower()):
            return a["url"]
    return _ACCOUNT_GUIDE


def _breach_finding(raw, run_id):
    classes = raw.get("data") or raw.get("exposed_data") or []
    severity = "high" if any(str(c).lower() in _HIGH_RISK for c in classes) else "medium"
    name = raw.get("name") or raw.get("title") or raw.get("breach_name") or "breach"
    domain = raw.get("domain")
    what = {"breach_name": name, "exposed_data": [str(c) for c in classes]}
    if raw.get("breach_date") or raw.get("date"):
        what["breach_date"] = raw.get("breach_date") or raw.get("date")
    action = {"action_type": "rotate_credentials",
              "label": "Change this password and enable 2FA",
              "target": ("https://%s" % domain) if domain else _BREACH_GUIDE}
    return findings.build_finding(
        "breach_exposure", "hibp", severity, what, action, run_id)


def _broker_finding(raw, run_id):
    what = {"broker_name": raw.get("name"), "category": raw.get("category")}
    action = {"action_type": "opt_out",
              "label": "File an opt-out / removal request",
              "target": raw.get("opt_out_url"),
              "letter_template": "ccpa"}
    return findings.build_finding(
        "broker_listing", "registry", "medium", what, action, run_id)


def _account_finding(raw, run_id):
    if not raw.get("exists"):
        return None
    platform = raw.get("platform")
    what = {"platform": platform}        # existence only — everything else dropped
    action = {"action_type": "delete_or_lock",
              "label": "Open the deletion / lock flow",
              "target": raw.get("remediation_url") or _account_delete_url(platform)}
    return findings.build_finding(
        "discoverable_account", "account-existence", "low", what, action, run_id)


_BUILDERS = {
    "breach_exposure": _breach_finding,
    "broker_listing": _broker_finding,
    "discoverable_account": _account_finding,
}


# --- the engine ----------------------------------------------------------- #
def scan_target(session, identifier_type, identifier_value, run_id, sources=None):
    """Scan ONE identifier — but only after the gate clears.

    Raises PermissionError if the identifier is not in the user's verified set. This
    is the enforcement chokepoint for the whole engine.
    """
    if not identity.assert_scannable(session, identifier_type, identifier_value):
        raise PermissionError(
            "refusing to scan an identifier the user has not verified")
    sources = sources or DEFAULT_SOURCES
    out = []
    for kind in findings.KINDS:
        source = sources.get(kind)
        if source is None:
            continue
        for raw in source(identifier_value):
            f = _BUILDERS[kind](raw, run_id)
            if f is not None:
                out.append(f)
    return out


# Sources whose output actually re-confirms PRESENCE (so a previously-removed item
# reappearing means the broker/account genuinely put you back -> relisted). The static
# broker registry is a worklist, NOT a presence probe, so "registry" is deliberately
# absent: re-scanning the registry must never spuriously relist a broker you removed.
# A breach is historical and never relists. Extend this only with real presence checks.
PRESENCE_CONFIRMING_SOURCES = frozenset({"account-existence"})


def collect(session, sources=None):
    """Build this run's findings WITHOUT persisting. Returns a flat list[Finding].

    Iterates ONLY identity.scannable_identifiers(session) — no external identifier can
    enter (every target passes the assert_scannable gate inside scan_target).
    """
    run_id = uuid.uuid4().hex
    results = []
    for identifier_type, value in identity.scannable_identifiers(session):
        results.extend(
            scan_target(session, identifier_type, value, run_id, sources))
    return results


def finding_key(f):
    """A stable cross-run key for ONE finding (the broker/breach/account it targets).

    This dedups a finding against its OWN prior versions across scans — it does NOT
    link different findings to each other or to a person. (broker_listing:spokeo is the
    same removal task this week as last week; that is all this encodes.)
    """
    w = f.what_was_found or {}
    if f.kind == "broker_listing":
        descriptor = w.get("broker_name", "")
    elif f.kind == "discoverable_account":
        descriptor = w.get("platform", "")
    elif f.kind == "breach_exposure":
        descriptor = w.get("breach_name", "")
    else:
        descriptor = ""
    return "%s:%s" % (f.kind, str(descriptor).strip().lower())


def reconcile(session, fresh):
    """Reconcile a fresh scan against stored findings. Returns a summary dict.

    Idempotent: a finding already on file is not duplicated. The relist rule:
      * fresh item matches a CONFIRMED_REMOVED stored item, AND the fresh item came
        from a presence-confirming source  -> the item came back: mark it `relisted`.
      * matches a confirmed-removed item from a non-presence source (e.g. the registry
        worklist) -> it stays removed (we cannot honestly claim a relist).
      * matches an open item -> kept as-is (no duplicate).
      * no match -> inserted (pending).
    """
    by_key = {}
    for sf in load_findings(session):
        by_key[finding_key(sf)] = sf
    summary = {"new": 0, "relisted": 0, "open": 0, "kept_removed": 0}
    for nf in fresh:
        key = finding_key(nf)
        sf = by_key.get(key)
        if sf is None:
            store_finding(session, nf)
            by_key[key] = nf          # dedup within this same batch too
            summary["new"] += 1
        elif sf.status == "confirmed_removed":
            if nf.source in PRESENCE_CONFIRMING_SOURCES:
                set_finding_status(session, sf.finding_id, "relisted")
                summary["relisted"] += 1
            else:
                summary["kept_removed"] += 1
        else:
            summary["open"] += 1
    return summary


def scan(session, sources=None, persist=True):
    """Scan the user's whole verified set. Returns the fresh list[Finding].

    When persist=True the run is reconciled into the stored set (idempotent +
    presence-gated relist); inspect the stored state with load_findings().
    """
    fresh = collect(session, sources)
    if persist:
        reconcile(session, fresh)
    return fresh


# --- encrypted-at-rest storage -------------------------------------------- #
def store_finding(session, finding):
    payload = json.dumps({
        "finding_id": finding.finding_id,
        "kind": finding.kind,
        "source": finding.source,
        "severity": finding.severity,
        "what_was_found": finding.what_was_found,
        "remediation_action": finding.remediation_action,
        "scan_run_id": finding.scan_run_id,
        "status": finding.status,
    }, sort_keys=True).encode("utf-8")
    ad = _finding_aad(session.user_id, finding.finding_id)
    blob = crypto.seal_record(payload, session.master_key, ad)
    store.insert_finding(session.user_id, finding.finding_id, blob)


def load_findings(session):
    """Decrypt the user's stored findings in-memory. Returns list[Finding]."""
    out = []
    for row in store.list_findings(session.user_id):
        ad = _finding_aad(session.user_id, row["finding_id"])
        data = json.loads(
            crypto.open_record(row["finding_encrypted"], session.master_key, ad))
        out.append(findings.Finding(
            finding_id=data["finding_id"], kind=data["kind"],
            source=data["source"], severity=data["severity"],
            what_was_found=data["what_was_found"],
            remediation_action=data["remediation_action"],
            scan_run_id=data["scan_run_id"], status=data["status"]))
    return out


def set_finding_status(session, finding_id, status):
    """Advance a finding's status and record an identifier-free fact in the tracker.

    The dashboard is the entry to the action layer; tapping a row's action moves it
    through pending -> action_taken -> confirmed_removed. The existing CLI tracker
    logs only the kind + new status — never any identifier.
    """
    if status not in findings.STATUSES:
        raise ValueError("invalid status: %r" % status)
    for f in load_findings(session):
        if f.finding_id == finding_id:
            updated = findings.Finding(
                finding_id=f.finding_id, kind=f.kind, source=f.source,
                severity=f.severity, what_was_found=f.what_was_found,
                remediation_action=f.remediation_action,
                scan_run_id=f.scan_run_id, status=status)
            payload = json.dumps({
                "finding_id": updated.finding_id, "kind": updated.kind,
                "source": updated.source, "severity": updated.severity,
                "what_was_found": updated.what_was_found,
                "remediation_action": updated.remediation_action,
                "scan_run_id": updated.scan_run_id, "status": updated.status,
            }, sort_keys=True).encode("utf-8")
            ad = _finding_aad(session.user_id, finding_id)
            blob = crypto.seal_record(payload, session.master_key, ad)
            store.update_finding(session.user_id, finding_id, blob)
            cli_db.log("finding.status", "kind=%s -> %s" % (f.kind, status))
            return True
    return False
