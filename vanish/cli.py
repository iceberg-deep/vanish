"""vanish command-line interface.

Single-operator footprint tool. vanish removes, it never discovers: it audits
identifiers you supply, files your own (or, statelessly, an authorized-agent)
opt-outs, and stores no record of any person. It deliberately contains NO
name->relatives/address/phone resolution and NO people-search aggregation.
Identifiers are passed at runtime, rendered into a letter, and never written to
disk — the tracker records only that a request was filed. All data stays local.
"""

import argparse
import os
import sys

from . import (
    __version__, accounts, audit, automation, brokers, db, guide,
    requests_gen, ui)
from .ui import C, paint


# --------------------------------------------------------------------------- #
# brokers
# --------------------------------------------------------------------------- #
def cmd_brokers(args):
    rows = brokers.query(args.category)
    if not rows:
        print(ui.warn("No brokers match category %r." % args.category))
        print(ui.info("Known categories: " + ", ".join(brokers.categories())))
        return 1

    title = "Data broker registry"
    if args.category:
        title += "  (" + ui.category_badge(args.category) + ")"
    print(ui.header(title))
    print("  " + paint("%d entries" % len(rows), C.GREY))

    for b in rows:
        bullet = paint("●", ui.CATEGORY_COLOR.get(b["category"], C.WHITE))
        name = paint(b["name"], C.BOLD, C.BRIGHT_WHITE)
        bid = paint("[" + b["id"] + "]", C.GREY)
        print("\n  " + bullet + " " + name + " " + bid)
        print("    " + ui.field("category", ui.category_badge(b["category"])))
        print("    " + ui.field("method", b["method"]))
        print("    " + ui.field("opt-out", paint(b["opt_out_url"], C.UNDERLINE, C.BRIGHT_BLUE)))
        print("    " + ui.field("needs", ", ".join(b["needs"])))
        print("    " + ui.field("notes", paint(b["notes"], C.DIM)))
    print()
    return 0


# --------------------------------------------------------------------------- #
# audit
# --------------------------------------------------------------------------- #
def cmd_audit(args):
    if not args.email and not args.username:
        print(ui.err("Provide --email and/or --username to audit."))
        return 2

    rc = 0
    if args.email:
        rc |= _audit_email(args.email)
    if args.username:
        rc |= _audit_username(args.username, args.platforms)
    return rc


def _audit_email(email):
    print(ui.header("Breach audit — Have I Been Pwned"))
    print("  " + ui.field("email", email))
    result = audit.check_hibp(email)

    if not result["ok"]:
        reason = result.get("reason")
        if reason == "no-api-key":
            print("  " + ui.warn(
                "HIBP_API_KEY not set — skipping breach lookup."))
            print("  " + paint(
                "Set it with: export HIBP_API_KEY=...  (key from "
                "https://haveibeenpwned.com/API/Key)", C.GREY))
        elif reason == "auth":
            print("  " + ui.err("HIBP rejected the API key (%s)." % result.get("detail", "")))
        elif reason == "rate-limited":
            print("  " + ui.warn("Rate limited by HIBP — try again shortly."))
        elif reason == "network":
            print("  " + ui.err("Network error reaching HIBP."))
        else:
            print("  " + ui.err("HIBP lookup failed (%s)." % result.get("detail", reason)))
        # Log the fact of the check only — never the email itself.
        db.log("audit.email", "result=%s" % reason)
        return 0  # graceful: not a hard failure

    breaches = result["breaches"]
    db.log("audit.email", "breaches=%d" % len(breaches))
    if not breaches:
        print("  " + ui.ok(paint("No breaches found. ", C.BRIGHT_GREEN) + ui.status_badge("clean")))
        return 0

    print("  " + ui.err("Found in %d breach(es) %s" % (len(breaches), ui.status_badge("pwned"))))
    all_critical = []
    for b in breaches:
        critical, other = audit.classify_exposure(b["data"])
        all_critical.extend(critical)
        print("\n    " + paint("‣ " + b["title"], C.BOLD, C.BRIGHT_RED)
              + paint("  (" + b["date"] + ")", C.GREY))
        if critical:
            # Sensitive exposures (passwords, SSN, financial) get their own
            # red line so they can't be missed in a long data-class list.
            print("      " + ui.field(
                "SENSITIVE", paint(", ".join(critical), C.BOLD, C.BRIGHT_RED), 9))
        if other:
            print("      " + ui.field("exposed", paint(", ".join(other), C.YELLOW), 9))

    # De-duplicate critical classes across breaches, preserving first-seen order.
    seen, uniq_critical = set(), []
    for dc in all_critical:
        key = dc.lower()
        if key not in seen:
            seen.add(key)
            uniq_critical.append(dc)

    if uniq_critical:
        print("\n  " + ui.err("⚠ High-risk data exposed: "
                              + paint(", ".join(uniq_critical), C.BOLD, C.BRIGHT_RED)))
        lower = " ".join(uniq_critical).lower()
        steps = []
        if "password" in lower:
            steps.append("change reused passwords now and turn on 2FA")
        if "social security" in lower or "ssn" in lower:
            steps.append("consider a credit freeze (Equifax/Experian/TransUnion)")
        if any(w in lower for w in ("credit card", "bank", "cvv", "pin")):
            steps.append("alert your bank and watch for fraudulent charges")
        for s in steps:
            print("    " + paint("• " + s, C.YELLOW))
    print()
    return 0


def _audit_username(username, platforms):
    platforms = platforms or list(audit.ALL_PLATFORMS)
    print(ui.header("Username audit — public profile probe"))
    print("  " + ui.field("handle", username))
    print("  " + paint("found = public profile  •  absent = no profile  •  "
                       "check = open it yourself (no reliable signal)",
                       C.GREY))

    results = audit.check_username(username, platforms)
    found = 0
    manual = 0
    for r in results:
        plat = paint(("{:<11}").format(r["platform"]), C.BRIGHT_WHITE)
        if r["status"] == "found":
            found += 1
            badge = ui.status_badge("found")
            line = paint(r["url"], C.UNDERLINE, C.BRIGHT_BLUE)
        elif r["status"] == "absent":
            badge = ui.status_badge("absent")
            line = paint("no public profile", C.GREY)
        elif r["status"] == "error":
            badge = paint(" ERR  ", C.BOLD, C.BRIGHT_RED)
            line = paint("request failed", C.GREY)
        elif r["status"] == "manual":
            manual += 1
            badge = paint(" CHECK", C.BOLD, C.YELLOW)
            # These platforms serve a 200 shell whether or not the handle
            # exists, so we can't decide — hand the user the URL to eyeball.
            line = paint(r["url"], C.UNDERLINE, C.BRIGHT_BLUE)
        else:
            badge = paint(" ?    ", C.BOLD, C.YELLOW)
            code = r["code"] if r["code"] is not None else "?"
            line = paint("inconclusive (HTTP %s)" % code, C.GREY)
        print("    " + badge + " " + plat + " " + line)

    summary = "%d confirmed public profile(s)" % found
    if manual:
        summary += "  •  %d need a manual check" % manual
    print("\n  " + ui.info(summary))
    # Log counts/results only — never the handle itself.
    db.log("audit.username",
           "found=%d manual=%d total=%d" % (found, manual, len(results)))
    print()
    return 0


# --------------------------------------------------------------------------- #
# request
# --------------------------------------------------------------------------- #
def cmd_request(args):
    broker = brokers.get(args.broker)
    if not broker:
        print(ui.err("Unknown broker id: %r" % args.broker))
        print(ui.info("List ids with:  vanish brokers"))
        return 2

    try:
        letter = requests_gen.render(
            args.template, broker, args.name, args.email,
            phone=args.phone, address=args.address, as_agent=args.as_agent,
        )
    except ValueError as exc:
        print(ui.err(str(exc)))
        return 2

    print(ui.header("Removal request — %s (%s template)"
                    % (broker["name"], args.template.upper())))
    print("  " + ui.field("filed as", "authorized agent" if args.as_agent else "self"))
    print("  " + ui.field("send to", paint(broker["opt_out_url"], C.UNDERLINE, C.BRIGHT_BLUE)))
    print("  " + ui.field("method", broker["method"]))
    print("\n" + ui.rule())
    print(paint(letter, C.BRIGHT_WHITE))
    print(ui.rule())

    if args.track:
        # Stores ONLY broker/template/status/dates — never the identifiers
        # above. They lived only long enough to render the letter.
        req_id = db.add_request(broker["id"], broker["name"], args.template)
        print("\n  " + ui.ok("Tracked as request " + paint("#%d" % req_id, C.BOLD)
                             + " " + ui.status_badge("pending")))
        print("  " + paint("Identifiers were used for the letter only and not stored.",
                           C.GREY))
        print("  " + paint("Update later with:  vanish status %d sent" % req_id, C.GREY))
    else:
        print("\n  " + ui.info("Not tracked. Re-run with --track to log this in the tracker."))
    print()
    return 0


# --------------------------------------------------------------------------- #
# track
# --------------------------------------------------------------------------- #
def cmd_track(args):
    rows = db.list_requests()
    print(ui.header("Tracked removal requests"))
    if not rows:
        print("  " + ui.info("No tracked requests yet. Use:  vanish request ... --track"))
        print()
        return 0

    for r in rows:
        print("\n  " + paint("#%d" % r["id"], C.BOLD, C.BRIGHT_WHITE)
              + " " + ui.status_badge(r["status"])
              + " " + paint(r["broker_name"], C.BRIGHT_CYAN))
        print("    " + ui.field("broker id", r["broker_id"]))
        print("    " + ui.field("template", r["template"].upper()))
        print("    " + ui.field("created", paint(r["created_at"], C.GREY)))
        print("    " + ui.field("updated", paint(r["updated_at"], C.GREY)))

    counts = db.status_counts()
    print("\n" + ui.rule())
    summary = "  ".join(
        ui.status_badge(s) + " " + paint(str(counts[s]), C.BOLD)
        for s in db.VALID_STATUSES if counts.get(s)
    )
    total = sum(counts.values())
    print("  " + paint("totals  ", C.GREY) + "%d request(s)   " % total + summary)
    print()
    return 0


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #
def cmd_status(args):
    try:
        changed = db.update_status(args.id, args.new_status)
    except ValueError as exc:
        print(ui.err(str(exc)))
        return 2
    if not changed:
        print(ui.err("No tracked request with id #%d." % args.id))
        print(ui.info("See all with:  vanish track"))
        return 1
    print(ui.ok("Request " + paint("#%d" % args.id, C.BOLD) + " set to "
                + ui.status_badge(args.new_status)))
    return 0


# --------------------------------------------------------------------------- #
# cleanse  (guided, max-automation: find -> cleanse -> validate)
# --------------------------------------------------------------------------- #
def _interactive():
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


def _ask(prompt_text, choices, default):
    """Prompt for one of `choices` (lower-cased first letters). Non-interactive
    runs return `default` so the walkthrough still prints end-to-end."""
    hint = "/".join(c.upper() if c == default else c for c in choices)
    if not _interactive():
        print("  " + paint("? %s [%s] -> %s (non-interactive)"
                           % (prompt_text, hint, default), C.GREY))
        return default
    while True:
        ans = input("  ? %s [%s]: " % (prompt_text, hint)).strip().lower()
        if not ans:
            return default
        for c in choices:
            if ans == c or ans == c[0]:
                return c
        print("    " + paint("Please answer one of: %s" % ", ".join(choices), C.GREY))


def _ask_value(prompt_text):
    """Free-text prompt (e.g. paste a listing URL). Empty -> None. Never stored."""
    if not _interactive():
        return None
    val = input("  ✎ %s (Enter to skip): " % prompt_text).strip()
    return val or None


def _automate_delivery(broker, letter, use_browser, page_already_open=False):
    """Do the automatable bits for one broker: open the page (unless FIND already
    did), and either draft a pre-filled email or copy the letter to the
    clipboard. Returns a label of what was auto-done."""
    did = []
    url = broker["opt_out_url"]
    opt_email = broker.get("opt_out_email")

    if opt_email:
        mailto = automation.build_mailto(
            opt_email, "CCPA/Privacy Removal Request", letter)
        opened = automation.open_url(mailto) if use_browser else False
        if opened:
            print("  " + ui.ok("Opened a pre-filled email to "
                               + paint(opt_email, C.BRIGHT_BLUE)))
            did.append("email drafted")
        else:
            print("  " + ui.info("Email this letter to "
                                 + paint(opt_email, C.BRIGHT_BLUE) + ":"))
    # Offer the web page (email brokers often have a form too), but don't open a
    # second tab if FIND already opened this exact URL.
    if page_already_open:
        print("  " + ui.field("opt-out", paint(url, C.UNDERLINE, C.BRIGHT_BLUE)
                              + paint("  (already open)", C.GREY)))
        did.append("page opened")
    else:
        opened_page = automation.open_url(url) if use_browser else False
        if opened_page:
            print("  " + ui.ok("Opened the opt-out page: "
                               + paint(url, C.UNDERLINE, C.BRIGHT_BLUE)))
            did.append("page opened")
        else:
            print("  " + ui.field("opt-out", paint(url, C.UNDERLINE, C.BRIGHT_BLUE)))

    copied, tool = automation.copy_clipboard(letter)
    if copied:
        print("  " + ui.ok("Letter copied to clipboard "
                           + paint("(via %s)" % tool, C.GREY) + " — paste it in."))
        did.append("letter on clipboard")
    else:
        print("  " + ui.info("Copy the letter below into the form/email:"))
        print(ui.rule())
        print(paint(letter, C.BRIGHT_WHITE))
        print(ui.rule())
    return ", ".join(did) if did else "manual"


# Remaining human-only steps by broker method (CAPTCHA/email/phone defenses).
_METHOD_STEPS = {
    "web-form": ["Find your listing, paste its URL into the form.",
                 "Solve the CAPTCHA and submit."],
    "web-form-phone": ["Submit the form.",
                       "Complete the phone verification call when prompted."],
    "web-form-account": ["Create/verify control of the listing as prompted.",
                         "Submit the suppression request."],
    "web-form-mail": ["Submit the form.",
                      "If asked, mail the identity verification they request."],
    "email-or-phone": ["Send the drafted email (or call the number in the notes)."],
    "email-or-form": ["Send the drafted email, or submit the consumer form."],
    "browser-optout": ["Use the on-page cookie/registry controls to opt out.",
                       "Clear ad cookies afterward."],
}


def cmd_cleanse(args):
    if args.validate:
        return _cleanse_validate(args)

    if not args.name or not args.email:
        print(ui.err("--name and --email are required to generate letters."))
        print(ui.info("(They render the letters only and are never stored.)"))
        return 2

    selected = brokers.query(args.category)
    if args.brokers:
        wanted = {b.strip() for b in args.brokers.split(",")}
        selected = [b for b in selected if b["id"] in wanted]
    if not selected:
        print(ui.err("No brokers match that selection."))
        return 1

    use_browser = not args.no_browser
    print(ui.header("Cleanse — guided removal across %d broker(s)" % len(selected)))
    print("  " + paint("Phases per broker:  ① find  ②  cleanse  ③ validate (later)",
                       C.GREY))
    print("  " + paint("I automate opening pages, drafting emails, and the letter. "
                       "CAPTCHAs / email confirmations / phone checks are yours.",
                       C.GREY))
    if not use_browser:
        print("  " + paint("(--no-browser: I'll print URLs instead of opening them)", C.GREY))
    if not automation.browser_available() and use_browser:
        print("  " + ui.warn("No browser/display detected — printing URLs to open yourself."))

    filed = 0
    for i, broker in enumerate(selected, 1):
        print("\n" + ui.rule())
        print(paint("[%d/%d] %s" % (i, len(selected), broker["name"]),
                    C.BOLD, C.BRIGHT_WHITE)
              + paint("  (%s · %s)" % (broker["category"], broker["method"]), C.GREY))

        # ① FIND
        print("\n  " + paint("① FIND", C.BOLD, C.BRIGHT_CYAN)
              + paint("  — locate your record", C.GREY))
        print("  " + ui.field("needs", ", ".join(broker["needs"])))
        if broker.get("notes"):
            print("  " + paint(broker["notes"], C.DIM))
        page_opened = False
        if "profile_url" in broker["needs"]:
            if use_browser and automation.open_url(broker["opt_out_url"]):
                page_opened = True
                print("  " + ui.ok("Opened the site — search your name and copy your listing URL."))
            else:
                print("  " + ui.info("Search your name at "
                                     + paint(broker["opt_out_url"], C.BRIGHT_BLUE)
                                     + " and copy your listing URL."))
            _ask_value("paste your listing URL")  # used in-session only, never stored

        # ② CLEANSE
        print("\n  " + paint("② CLEANSE", C.BOLD, C.BRIGHT_GREEN)
              + paint("  — submit the removal", C.GREY))
        letter = requests_gen.render(
            args.template, broker, args.name, args.email,
            phone=args.phone, address=args.address, as_agent=args.as_agent)
        auto = _automate_delivery(broker, letter, use_browser,
                                  page_already_open=page_opened)
        for n, step in enumerate(_METHOD_STEPS.get(broker["method"], []), 1):
            print("  " + paint("%d." % n, C.BRIGHT_CYAN) + " " + step)
        if "email" in str(broker["needs"]):
            print("  " + paint("→ watch for a confirmation email and click the link.", C.YELLOW))

        ans = _ask("Mark this submitted?", ["yes", "no", "skip"], "no")
        if ans == "yes":
            if args.track:
                req_id = db.add_request(broker["id"], broker["name"], args.template)
                db.update_status(req_id, "sent")
                print("  " + ui.ok("Tracked #%d as SENT (auto: %s)." % (req_id, auto)))
            filed += 1

    # ③ VALIDATE (next step)
    print("\n" + ui.rule())
    print("  " + paint("③ VALIDATE", C.BOLD, C.BRIGHT_MAGENTA)
          + paint("  — confirm removal took effect", C.GREY))
    print("  " + ui.info("Submitted %d removal(s)." % filed))
    print("  " + paint("Brokers take minutes to weeks (and some relist). "
                       "Re-check with:", C.GREY))
    print("    " + paint("vanish cleanse --validate", C.BRIGHT_WHITE)
          + paint("    # re-opens each tracked broker to confirm you're gone", C.GREY))
    print()
    return 0


def _cleanse_validate(args):
    """Validate phase: walk tracked requests, re-open each broker so you can
    confirm the listing is gone, and update status to confirmed/relisted."""
    rows = [r for r in db.list_requests() if r["status"] not in ("confirmed",)]
    print(ui.header("Cleanse — validate %d tracked removal(s)" % len(rows)))
    if not rows:
        print("  " + ui.info("Nothing to validate. File some with:  vanish cleanse ... --track"))
        print()
        return 0
    use_browser = not args.no_browser
    for r in rows:
        broker = brokers.get(r["broker_id"]) or {}
        url = broker.get("opt_out_url", "")
        print("\n  " + paint("#%d %s" % (r["id"], r["broker_name"]), C.BOLD, C.BRIGHT_WHITE)
              + " " + ui.status_badge(r["status"]))
        if url:
            if use_browser and automation.open_url(url):
                print("  " + ui.ok("Opened " + paint(url, C.BRIGHT_BLUE)
                                   + " — search your name to check."))
            else:
                print("  " + ui.info("Check " + paint(url, C.BRIGHT_BLUE)))
        ans = _ask("Still listed?", ["yes", "no", "unsure"], "unsure")
        if ans == "no":
            db.update_status(r["id"], "confirmed")
            print("  " + ui.ok("Marked CONFIRMED removed."))
        elif ans == "yes":
            db.update_status(r["id"], "relisted")
            print("  " + ui.warn("Marked RELISTED — re-file to remove again."))
    print()
    return 0


# --------------------------------------------------------------------------- #
# guide  (plain-English, printable removal report)
# --------------------------------------------------------------------------- #
def cmd_guide(args):
    report = guide.build_report(name=args.name, email=args.email)

    if args.stdout:
        print(report)
        return 0

    path = args.output or os.path.join(os.path.expanduser("~"),
                                       "vanish-removal-guide.md")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report)
    except OSError as exc:
        print(ui.err("Couldn't write the guide: %s" % exc))
        return 1

    lines = report.count("\n") + 1
    print(ui.header("Your removal guide is ready"))
    print("  " + ui.ok("Saved to " + paint(path, C.BRIGHT_WHITE)))
    print("  " + ui.field("length", "%d lines, plain English, with checkboxes" % lines))
    print("  " + paint("Open it in any text editor, or print it out and tick the "
                       "boxes as you go.", C.GREY))
    print("  " + paint("Prefer it on screen now?  vanish guide --stdout", C.GREY))
    print()
    return 0


# --------------------------------------------------------------------------- #
# accounts
# --------------------------------------------------------------------------- #
def cmd_accounts(args):
    print(ui.header("Account deletion / deactivation"))
    print("  " + paint("Official self-service flows. vanish never logs in for you.", C.GREY))
    for a in accounts.all_accounts():
        print("\n  " + paint("◆ " + a["name"], C.BOLD, C.BRIGHT_MAGENTA))
        print("    " + ui.field("link", paint(a["url"], C.UNDERLINE, C.BRIGHT_BLUE), 6))
        for i, step in enumerate(a["steps"], 1):
            print("    " + paint("%d." % i, C.BRIGHT_CYAN) + " " + step)
    print()
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser():
    parser = argparse.ArgumentParser(
        prog="vanish",
        description="Audit and scrub your own digital footprint (removal-only).",
        epilog="vanish removes, it never discovers. No lookups, no aggregation, "
               "no record of any person. Data stays local in ~/.vanish (0600).",
    )
    parser.add_argument(
        "--version", action="version",
        version=ui.banner(__version__) if ui.supports_color()
        else "vanish %s" % __version__,
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p_brokers = sub.add_parser("brokers", help="list known data brokers")
    p_brokers.add_argument(
        "--category", choices=brokers.categories(), help="filter by category")
    p_brokers.set_defaults(func=cmd_brokers)

    p_audit = sub.add_parser("audit", help="audit your own email / usernames")
    p_audit.add_argument("--email", help="email to check against Have I Been Pwned")
    p_audit.add_argument("--username", help="handle to probe across public profiles")
    p_audit.add_argument(
        "--platforms", nargs="+", choices=list(audit.ALL_PLATFORMS),
        help="restrict the username probe to these platforms")
    p_audit.set_defaults(func=cmd_audit)

    # request --------------------------------------------------------------- #
    p_req = sub.add_parser("request", help="generate a removal-request letter")
    p_req.add_argument("--broker", required=True, help="broker id (see: vanish brokers)")
    p_req.add_argument(
        "--name", required=True,
        help="name for the letter — used to render only, never stored")
    p_req.add_argument(
        "--email", required=True,
        help="contact email for the letter — used to render only, never stored")
    p_req.add_argument(
        "--phone", help="phone for the letter (optional) — never stored")
    p_req.add_argument(
        "--address", help="address for the letter (optional) — never stored")
    p_req.add_argument(
        "--template", required=True, choices=requests_gen.TEMPLATES,
        help="letter template")
    p_req.add_argument(
        "--as-agent", dest="as_agent", action="store_true",
        help="add authorized-agent language for filing on behalf of someone "
             "who asked (stateless — nothing about them is stored)")
    p_req.add_argument("--track", action="store_true", help="log this request to the tracker")
    p_req.set_defaults(func=cmd_request)

    # cleanse --------------------------------------------------------------- #
    p_clean = sub.add_parser(
        "cleanse", help="guided removal: find → cleanse → validate (max automation)")
    p_clean.add_argument("--name", help="name for the letters — render-only, never stored")
    p_clean.add_argument("--email", help="contact email for the letters — render-only, never stored")
    p_clean.add_argument("--phone", help="phone for the letters (optional) — never stored")
    p_clean.add_argument("--address", help="address for the letters (optional) — never stored")
    p_clean.add_argument(
        "--template", default="ccpa", choices=requests_gen.TEMPLATES,
        help="letter template (default: ccpa)")
    p_clean.add_argument("--category", choices=brokers.categories(),
                         help="limit to one broker category")
    p_clean.add_argument("--brokers", help="comma-separated broker ids to target")
    p_clean.add_argument(
        "--as-agent", dest="as_agent", action="store_true",
        help="authorized-agent language for filing on behalf of someone who asked (stateless)")
    p_clean.add_argument("--track", action="store_true",
                         help="log submitted removals to the tracker (no identifiers)")
    p_clean.add_argument("--no-browser", action="store_true",
                         help="print URLs instead of opening a browser")
    p_clean.add_argument("--validate", action="store_true",
                         help="validate phase: re-open tracked brokers and confirm removal")
    p_clean.set_defaults(func=cmd_cleanse)

    p_track = sub.add_parser("track", help="show tracked requests + status counts")
    p_track.set_defaults(func=cmd_track)

    p_status = sub.add_parser("status", help="update a tracked request's status")
    p_status.add_argument("id", type=int, help="request id")
    p_status.add_argument("new_status", choices=db.VALID_STATUSES, metavar="status",
                          help="one of: " + ", ".join(db.VALID_STATUSES))
    p_status.set_defaults(func=cmd_status)

    p_guide = sub.add_parser(
        "guide", help="write a plain-English, grandma-proof removal report")
    p_guide.add_argument("--name", help="personalize the guide (render-only, never stored)")
    p_guide.add_argument("--email", help="personalize the guide (render-only, never stored)")
    p_guide.add_argument("--output", help="where to save the .md file "
                                          "(default: ~/vanish-removal-guide.md)")
    p_guide.add_argument("--stdout", action="store_true",
                         help="print the guide to the screen instead of saving")
    p_guide.set_defaults(func=cmd_guide)

    p_acc = sub.add_parser("accounts", help="deletion/deactivation links + steps")
    p_acc.set_defaults(func=cmd_accounts)

    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        if ui.supports_color():
            print(ui.banner(__version__))
        parser.print_help()
        return 0

    db.init_db()
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n" + ui.warn("Interrupted."))
        return 130


if __name__ == "__main__":
    sys.exit(main())
