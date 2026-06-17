"""Single-operator, local-only runner for the vanish authenticated-user app.

   ┌──────────────────────────────────────────────────────────────────────────┐
   │  SINGLE_OPERATOR — NOT FOR DISTRIBUTION                                     │
   │  Personal use only, on this device, against your OWN verified footprint.   │
   │  • Crypto is PRE-EXTERNAL-REVIEW (crypto.DEFAULT_KDF_PARAMS reviewed=False).│
   │  • One local operator. There is no hosted server, no other users, no       │
   │    network sync, no public surface. Multi-user / hosted / public use is     │
   │    gated on the Phase 0 cryptographer + legal reviews (ROADMAP §Phase 0).   │
   └──────────────────────────────────────────────────────────────────────────┘

This wires the existing Phase 1-4 modules end-to-end for ONE local user. It adds no
new person-data type, no third-party submit path, and no lookup of anyone but the
authenticated operator's own verified identifiers — it only composes:
    auth (register/login) -> identity (verify) -> scan -> dashboard -> actions

Local-only is enforced, not just documented: this is a CLI with no network/server/
socket. Single-operator is enforced: register refuses a second account, and every
command operates on the sole account on the device.
"""

import argparse
import getpass
import os
import shutil
import sys

from . import (actions, auth, crypto, dashboard, export_dashboard, findings,
               identity, scan, store)

NOTICE = (
    "SINGLE_OPERATOR build — NOT FOR DISTRIBUTION. Personal use only, on this "
    "device, against your own verified footprint. Crypto is pre-external-review "
    "(reviewed=False); multi-user/hosted/public use is gated on the Phase 0 "
    "cryptographer + legal reviews."
)

_MODULE = auth.MvpAuthModule()


# --- helpers -------------------------------------------------------------- #
def _password(args):
    if getattr(args, "password", None):
        return args.password
    env = os.environ.get("VANISH_ACCOUNT_PASSWORD")
    if env:
        return env
    return getpass.getpass("Password: ")


def _params():
    # FAST is for local/dev convenience only; production default stays MODERATE.
    if os.environ.get("VANISH_ACCOUNT_FAST"):
        return crypto.FAST_KDF_PARAMS
    return crypto.DEFAULT_KDF_PARAMS


def _sole_session(args):
    """Log into THE single account on this device. Refuses if 0 or >1 exist."""
    ids = store.account_ids()
    if not ids:
        sys.exit("No account on this device yet. Run:  vanish-account register")
    if len(ids) > 1:
        sys.exit("Multiple accounts found — the single-operator runner refuses "
                 "to choose. This build holds one local user only.")
    return _MODULE.login(ids[0], _password(args))


# --- commands ------------------------------------------------------------- #
def cmd_register(args):
    if store.account_ids():
        print("An account already exists on this device. This is a single-operator "
              "build — it holds exactly one local user.", file=sys.stderr)
        return 1
    user_id, recovery = _MODULE.register(_password(args), params=_params())
    print(NOTICE + "\n")
    print("Account created (local, zero-knowledge).")
    print("  user_id        : %s" % user_id)
    print("  recovery code  : %s" % recovery)
    print("\nWrite the recovery code down now — it is shown ONCE. Losing both your "
          "password and this code means your data is unrecoverable, by design.")
    return 0


def cmd_verify_email(args):
    session = _sole_session(args)
    sender = identity.RecordingSender()
    identity.request_email_verification(session, args.email, sender)
    print("Added %s — pending verification. It is NOT scannable until confirmed."
          % identity.normalize_email(args.email))
    print("VERIFICATION_TOKEN=%s" % sender.last_token)
    print("(In production this token is emailed to that address to prove you own "
          "it; on this local build it is shown so you can confirm it yourself.)")
    return 0


def cmd_confirm_email(args):
    session = _sole_session(args)
    if identity.confirm_verification(session, args.token) is None:
        print("That token matched no pending verification.", file=sys.stderr)
        return 1
    print("Verified. This identifier is now scannable.")
    return 0


def cmd_scan(args):
    session = _sole_session(args)
    targets = identity.scannable_identifiers(session)
    if not targets:
        print("No verified identifiers yet. Add one:  vanish-account verify-email "
              "you@example.com")
        return 0
    fresh = scan.collect(session)
    summary = scan.reconcile(session, fresh)
    print("Scanned %d verified identifier(s). new=%d · relisted=%d · already-open=%d "
          "· stayed-removed=%d" % (len(targets), summary["new"], summary["relisted"],
                                   summary["open"], summary["kept_removed"]))
    if summary["relisted"]:
        print("  ! %d item(s) you'd removed have reappeared (relisted) — re-remove them."
              % summary["relisted"])
    print("View them:  vanish-account worklist")
    return 0


def cmd_worklist(args):
    session = _sole_session(args)
    view = dashboard.build_worklist(scan.load_findings(session))
    print(dashboard.render_text(view))
    return 0


def _find_one(session, prefix):
    matches = [f for f in scan.load_findings(session)
               if f.finding_id == prefix or f.finding_id.startswith(prefix)]
    if not matches:
        sys.exit("No finding matches id %r." % prefix)
    if len(matches) > 1:
        sys.exit("Ambiguous id %r — matches %d findings." % (prefix, len(matches)))
    return matches[0]


def cmd_action(args):
    session = _sole_session(args)
    finding = _find_one(session, args.finding_id)
    if finding.kind == "broker_listing":
        if not args.name:
            sys.exit("A broker removal letter needs your name:  --name 'Your Name'")
        result = actions.generate_broker_letter(
            session, finding, name=args.name, email=args.email, phone=args.phone,
            address=args.address, template=args.template, as_agent=args.as_agent)
    else:
        result = actions.execute(session, finding)
    print("== %s ==" % result.title)
    if result.link:
        print("Link: %s" % result.link)
    print()
    print(result.body)
    print("\n(status -> action_taken; vanish does not submit on your behalf — you "
          "send/act yourself.)")
    return 0


def cmd_confirm(args):
    session = _sole_session(args)
    finding = _find_one(session, args.finding_id)
    actions.confirm_removed(session, finding.finding_id)
    print("Marked confirmed_removed.")
    return 0


def cmd_export_dashboard(args):
    session = _sole_session(args)
    out_dir = args.out or os.path.join(os.path.expanduser("~"), "vanish-dashboard")
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    json_path = os.path.join(out_dir, "vanish-findings.json")
    export_dashboard.write(session, json_path, label=args.label)
    html_path = os.path.join(out_dir, "vanish-dashboard.html")
    shutil.copyfile(os.path.join(os.path.dirname(__file__), "dashboard.html"),
                    html_path)
    for p in (json_path, html_path):
        try:
            os.chmod(p, 0o600)         # owner-only, like the rest of the store
        except OSError:
            pass
    print("Wrote your dashboard to %s" % out_dir)
    print("  - vanish-dashboard.html")
    print("  - vanish-findings.json   (your real scan export, dossier-free)")
    print("\nBrowsers block file:// fetch, so serve the folder locally "
          "(still 127.0.0.1, single-operator):")
    print("  cd %s && python3 -m http.server 8000 --bind 127.0.0.1" % out_dir)
    print("  open http://127.0.0.1:8000/vanish-dashboard.html")
    return 0


def cmd_whoami(args):
    ids = store.account_ids()
    if not ids:
        print("No account on this device.")
        return 0
    session = _sole_session(args)
    counts = findings.counts_by_kind(scan.load_findings(session))
    print("user_id: %s" % session.user_id)
    print("verified identifiers: %d"
          % len(identity.scannable_identifiers(session)))
    print("findings: %s" % counts)
    return 0


# --- entry point ---------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="vanish-account",
        description="Single-operator, local-only runner for the vanish "
                    "authenticated-user app. NOT FOR DISTRIBUTION.")
    p.add_argument("--password", help="account password (else $VANISH_ACCOUNT_"
                   "PASSWORD or an interactive prompt)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("register", help="create the single local account")
    sub.add_parser("whoami", help="show the local account + finding counts")

    v = sub.add_parser("verify-email", help="add an email and start verification")
    v.add_argument("email")

    c = sub.add_parser("confirm-email", help="complete email verification")
    c.add_argument("token")

    # NOTE: `scan` takes NO identifier argument — there is deliberately no way to
    # point it at anything but the operator's own verified set (self-only gate).
    sub.add_parser("scan", help="scan your verified identifiers for exposure")
    sub.add_parser("worklist", help="show the removal worklist")

    a = sub.add_parser("action", help="action a finding (letter / link / guidance)")
    a.add_argument("finding_id")
    a.add_argument("--name", help="your name (broker removal letters)")
    a.add_argument("--email", help="your contact email for the letter (ephemeral)")
    a.add_argument("--phone", help="optional, ephemeral")
    a.add_argument("--address", help="optional, ephemeral")
    a.add_argument("--template", choices=("ccpa", "gdpr", "generic"), default=None)
    a.add_argument("--as-agent", action="store_true", dest="as_agent",
                   help=argparse.SUPPRESS)

    cf = sub.add_parser("confirm", help="mark a finding confirmed_removed")
    cf.add_argument("finding_id")

    e = sub.add_parser("export-dashboard",
                       help="write the local dashboard + your findings export")
    e.add_argument("--out", help="output folder (default ~/vanish-dashboard)")
    e.add_argument("--label", default="you@local",
                   help="free-text display nickname for the header (never your "
                        "verified email; shown verbatim). Default: you@local")
    return p


_COMMANDS = {
    "register": cmd_register, "whoami": cmd_whoami,
    "verify-email": cmd_verify_email, "confirm-email": cmd_confirm_email,
    "scan": cmd_scan, "worklist": cmd_worklist,
    "action": cmd_action, "confirm": cmd_confirm,
    "export-dashboard": cmd_export_dashboard,
}


def main(argv=None):
    print(NOTICE, file=sys.stderr)
    args = build_parser().parse_args(argv)
    return _COMMANDS[args.cmd](args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
