"""Action layer — execute the removal from each worklist row.

Each Finding already carries a ``remediation_action``; this layer makes that action
*do* something. It introduces no new person-data and reveals nothing — it executes
removals:

  * broker_listing       -> render a CCPA/GDPR/generic removal letter (the existing
                            requests_gen core) for the user to send themselves, and
                            surface the opt-out URL.
  * discoverable_account -> surface the official deletion/lock flow from the accounts
                            registry for that platform.
  * breach_exposure      -> surface credential-rotation guidance for the affected
                            source. No letter, no third-party action.

Carried constraints:
  * TOOL, NOT AGENT (CRYPTO-SPEC §5.1). vanish never submits a removal on the user's
    behalf. There is no network/submit path here — it produces a letter/link for the
    user. Agent-submission stays fenced behind the legal review.
  * IDENTIFIER-EPHEMERALITY. The name/email/etc. needed to render a letter are used at
    render time and never persisted — not in the findings table, not in the tracker,
    not in any archive. Only the identifier-free fact of the action (finding_id, kind,
    status, timestamp) is stored, via the Phase 3 status flow. (Python strings can't be
    truly zeroized; these are held only as locals and never written down — see
    CRYPTO-SPEC §10 honest limits.)
  * NO DOSSIER REGRESSION. No new type aggregates findings by identity; no field is
    added to Finding. This consumes findings and produces letters/links + status
    transitions, nothing else.
"""

from dataclasses import dataclass, field

from .. import accounts as cli_accounts
from .. import requests_gen
from . import findings, identity, scan


@dataclass(frozen=True)
class ActionResult:
    """Per-finding action output for the user to act on. Never persisted."""

    finding_id: str
    kind: str
    action_type: str          # "letter" | "link" | "guidance"
    title: str
    body: str                 # the letter text / guidance / instructions
    link: str                 # opt-out URL / deletion link / affected source
    template: str = None      # broker letter template id, when action_type == letter
    steps: tuple = field(default_factory=tuple)


def _verified_email(session):
    for ident_type, value in identity.scannable_identifiers(session):
        if ident_type == "email":
            return value
    return None


def _account_steps(platform):
    for a in cli_accounts.all_accounts():
        if platform and platform.lower() in (a["id"], a["name"].lower()):
            return tuple(a.get("steps", ()))
    return ()


def generate_broker_letter(session, finding, name, email=None, phone=None,
                           address=None, template=None, as_agent=False,
                           advance=True):
    """Render a removal letter for a broker_listing finding (tool-not-agent).

    Identifiers are ephemeral: used to render the returned letter, never persisted.
    `email` defaults to a verified address from the session but may be supplied at
    call time; nothing here writes any of these down.
    """
    if finding.kind != "broker_listing":
        raise ValueError("not a broker_listing finding")
    broker_name = finding.what_was_found.get("broker_name") or "the data broker"
    template = (template or finding.remediation_action.get("letter_template")
                or "ccpa")
    contact_email = email or _verified_email(session)
    letter = requests_gen.render(
        template, broker_name, name, contact_email, phone, address, as_agent)
    if advance:
        scan.set_finding_status(session, finding.finding_id, "action_taken")
    return ActionResult(
        finding_id=finding.finding_id, kind=finding.kind, action_type="letter",
        title="Removal letter for %s" % broker_name, body=letter,
        link=finding.remediation_action.get("target"), template=template)


def surface_account_deletion(session, finding, advance=True):
    """Surface the official deletion/lock flow for a discoverable_account finding."""
    if finding.kind != "discoverable_account":
        raise ValueError("not a discoverable_account finding")
    platform = finding.what_was_found.get("platform")
    steps = _account_steps(platform)
    body = "\n".join("%d. %s" % (i + 1, s) for i, s in enumerate(steps)) or \
        "Open the link and follow the platform's account-deletion flow."
    if advance:
        scan.set_finding_status(session, finding.finding_id, "action_taken")
    return ActionResult(
        finding_id=finding.finding_id, kind=finding.kind, action_type="link",
        title="Delete or lock your %s account" % (platform or "account"),
        body=body, link=finding.remediation_action.get("target"), steps=steps)


def surface_breach_guidance(session, finding, advance=True):
    """Surface credential-rotation guidance for a breach_exposure finding."""
    if finding.kind != "breach_exposure":
        raise ValueError("not a breach_exposure finding")
    breach = finding.what_was_found.get("breach_name", "a breach")
    body = ("Your credentials were exposed in %s. Change your password on the "
            "affected service, turn on two-factor authentication, and update that "
            "password anywhere you reused it. vanish does not contact the service "
            "for you." % breach)
    if advance:
        scan.set_finding_status(session, finding.finding_id, "action_taken")
    return ActionResult(
        finding_id=finding.finding_id, kind=finding.kind, action_type="guidance",
        title="Secure your account after %s" % breach, body=body,
        link=finding.remediation_action.get("target"))


_DISPATCH = {
    "broker_listing": generate_broker_letter,
    "discoverable_account": surface_account_deletion,
    "breach_exposure": surface_breach_guidance,
}


def execute(session, finding, **kwargs):
    """Action a finding by kind. broker_listing requires a `name` kwarg."""
    if finding.kind not in findings.KINDS:
        raise ValueError("unknown finding kind: %r" % finding.kind)
    return _DISPATCH[finding.kind](session, finding, **kwargs)


def confirm_removed(session, finding_id):
    """User-confirmed removal: advance the finding to confirmed_removed."""
    return scan.set_finding_status(session, finding_id, "confirmed_removed")
