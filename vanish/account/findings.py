"""The Finding type — a flat, action-bound unit of exposure.

This module encodes, IN THE TYPE SYSTEM, the line the scan engine must not cross. It
surfaces a verified user's own exposure as a worklist of things to remove. It is NOT a
profile generator. The reference anti-pattern — a people-search / OSINT dossier
(aggregated identity, linked-account graph, recovery emails, activity timeline, AI
risk synthesis) — must be structurally *impossible* to produce here, not merely
discouraged.

How that's enforced:
  * There is NO Profile / Person / Identity / Subject type, anywhere. The scan returns
    a flat ``list[Finding]`` and nothing that wraps or groups findings by individual.
  * A ``Finding`` is independent and action-bound. It carries only the fields below;
    every one MUST have a concrete ``remediation_action`` or construction fails.
  * ``FORBIDDEN_FIELDS`` (recovery/linked emails, phone, photo, location, timeline,
    risk/AI synthesis, profile metadata) are dropped at ingestion and may never appear
    inside a Finding — enforced again in ``__post_init__`` so even direct construction
    can't smuggle them in.
  * Findings carry no join key tying them to a common identity beyond the scan run.
"""

import uuid
from dataclasses import dataclass

KINDS = ("breach_exposure", "broker_listing", "discoverable_account")
# relisted: a previously confirmed-removed item that a presence-confirming re-scan
# found again (the broker/account put you back). See scan.reconcile.
STATUSES = ("pending", "action_taken", "confirmed_removed", "relisted")

# Anything dossier-shaped. Keys matching these (case-insensitive) are stripped from
# any source payload at ingestion and rejected if found on a Finding.
FORBIDDEN_FIELDS = frozenset({
    "recovery_email", "recovery_emails", "alternate_email", "alternate_emails",
    "linked_email", "linked_emails", "linked_account", "linked_accounts",
    "account_links", "related_accounts", "cross_account", "join_key",
    "phone", "phone_number", "phonenumber", "mobile", "sms",
    "profile_photo", "photo", "avatar", "picture", "image",
    "location", "geo", "geolocation", "home_address", "address",
    "city", "state", "country", "latitude", "longitude", "lat", "lon",
    "first_seen", "last_seen", "last_active", "activity", "timeline", "history",
    "risk_profile", "risk_score", "risk", "ai_summary", "ai_synthesis",
    "synthesis", "dossier", "profile",
    # discoverable-account is existence-only: identity/profile metadata is dropped.
    "username", "user_id", "userid", "handle", "display_name", "displayname",
    "full_name", "name", "followers", "follower_count", "following", "bio",
})


def sanitize(payload):
    """Strip every forbidden key (recursively) from a raw source payload.

    This is the ingestion boundary: whatever an OSINT-style source returns, only
    non-dossier descriptive fields survive to motivate the remediation action.
    """
    if isinstance(payload, dict):
        return {k: sanitize(v) for k, v in payload.items()
                if k.lower() not in FORBIDDEN_FIELDS}
    if isinstance(payload, (list, tuple)):
        return [sanitize(v) for v in payload]
    return payload


@dataclass(frozen=True)
class Finding:
    """One independent, action-bound exposure. No identity aggregation, ever."""

    finding_id: str
    kind: str
    source: str
    severity: str
    what_was_found: dict
    remediation_action: dict
    scan_run_id: str
    status: str = "pending"

    def __post_init__(self):
        if self.kind not in KINDS:
            raise ValueError("invalid finding kind: %r" % self.kind)
        if self.status not in STATUSES:
            raise ValueError("invalid status: %r" % self.status)
        # Action-bound: a finding with no concrete action is invalid.
        ra = self.remediation_action
        if not ra or not isinstance(ra, dict) or not ra.get("target"):
            raise ValueError(
                "every finding must carry a concrete remediation_action.target")
        # Fail closed if any dossier field slipped through.
        bad = {k for k in _deep_keys(self.what_was_found)
               if k.lower() in FORBIDDEN_FIELDS}
        if bad:
            raise ValueError("forbidden dossier field(s) on finding: %s" % sorted(bad))


def _deep_keys(obj):
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(k)
            keys |= _deep_keys(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            keys |= _deep_keys(v)
    return keys


def build_finding(kind, source, severity, what_was_found, remediation_action,
                  scan_run_id, status="pending"):
    """Construct a Finding, sanitizing what_was_found at ingestion."""
    return Finding(
        finding_id=uuid.uuid4().hex,
        kind=kind,
        source=source,
        severity=severity,
        what_was_found=sanitize(what_was_found or {}),
        remediation_action=remediation_action,
        scan_run_id=scan_run_id,
        status=status,
    )


def group_by_kind(findings):
    """Group ONLY by remediation category — never by reconstructed identity."""
    out = {k: [] for k in KINDS}
    for f in findings:
        out[f.kind].append(f)
    return out


def counts_by_kind(findings):
    """Aggregate counts (the only allowed roll-up): N to remove per category."""
    return {k: len(v) for k, v in group_by_kind(findings).items()}


# Intentionally absent: any function that groups/links findings by a person key,
# assembles them into a graph, or returns a Profile/Identity object. See the
# dossier-impossibility test.
