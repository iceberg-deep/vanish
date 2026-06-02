"""Build a plain-English, step-by-step removal report anyone can follow.

This turns the broker registry and account-deletion data into a printable
checklist written for a non-technical person — no command line, no jargon. The
optional name/email personalize the wording but are never stored.
"""

from . import accounts, brokers

# Per-method click-by-click steps, written for someone who has never done this.
# {broker}, {url}, {email}, {opt_out_email} are filled in per broker.
_METHOD_STEPS = {
    "web-form": [
        "Open your web browser (Chrome, Safari, or Edge) and go to this address: {url}",
        "Find the search box and type your full name, then press Enter.",
        "Look through the results for the entry that is really you — check the town and age.",
        "Click that entry to open it.",
        "Copy the web address shown at the very top of the page: click it once to highlight it, then hold Ctrl and press C (on a Mac, hold Command and press C).",
        "Go back to the removal page and click in the box that asks for the listing link, then paste it: hold Ctrl and press V (Mac: Command + V).",
        "Type your email address ({email}) where it asks.",
        "Tick the 'I'm not a robot' box and finish any little picture puzzle it shows.",
        "Click the Submit or Remove button.",
        "Open your email inbox, find the new message from {broker}, and click the confirmation link inside it. If you don't see it, look in your Spam or Junk folder.",
    ],
    "web-form-phone": [
        "Open your web browser and go to: {url}",
        "Type your full name in the search box and press Enter; find and open the entry that is you.",
        "Copy its web address (highlight it, then Ctrl+C / Command+C) and paste it into the removal box (Ctrl+V / Command+V).",
        "Enter your phone number when it asks.",
        "Click Submit. They will call or text you a short code.",
        "Type that code back into the page to prove it's you. You're done.",
    ],
    "web-form-account": [
        "Open your web browser and go to: {url}",
        "You'll need to make a quick free account so they know it's really you: enter your email ({email}) and create a password. Write the password down.",
        "Open your email and click the link they send to confirm your account.",
        "Sign in, find the listing that is you, and choose Remove / Suppress.",
        "Confirm. Note: this site often puts listings back after a while, so plan to check again in a few months.",
    ],
    "web-form-mail": [
        "Open your web browser and go to: {url}",
        "Fill in the removal form with your name, email ({email}), and address.",
        "Click Submit.",
        "If they ask you to prove who you are, they may send a letter or ask you to mail a copy of your ID. Follow those instructions to finish.",
    ],
    "email-or-phone": [
        "Open your email program (Gmail, Outlook, or your phone's Mail app).",
        "Start a new message to: {opt_out_email}",
        "For the subject, write: Please delete my personal information (CCPA request).",
        "Copy the ready-made letter below into the message.",
        "Send it. Keep the email — it's your proof you asked.",
    ],
    "email-or-form": [
        "Open your email program and start a new message to: {opt_out_email}",
        "Subject: Please delete my personal information (CCPA request).",
        "Paste the ready-made letter below into the message and send it.",
        "(If you'd rather use their website form instead, go to {url} and fill it in.)",
    ],
    "browser-optout": [
        "Open your web browser and go to: {url}",
        "Look for the 'opt out' or 'cookie choices' button and turn off data sharing.",
        "Afterward, clear your browser's cookies so old tracking is removed (in your browser menu: Settings → Privacy → Clear browsing data → Cookies).",
    ],
}

_GENERIC_STEPS = [
    "Open your web browser and go to: {url}",
    "Look for a link that says 'opt out', 'do not sell my info', or 'remove my listing', and follow it.",
    "Fill in your name and email ({email}) and submit the request.",
]


def _fill(step, broker, email):
    return step.format(
        broker=broker["name"],
        url=broker["opt_out_url"],
        email=email or "your email address",
        opt_out_email=broker.get("opt_out_email", "their privacy team"),
    )


def _letter_block(broker, name, email):
    """A short, paste-ready letter for email-method brokers."""
    return (
        "> To whom it may concern,\n>\n"
        "> Please delete all personal information you have about me and stop "
        "selling or sharing it. I am asking under my privacy rights (CCPA/CPRA).\n>\n"
        "> Name: %s\n> Email: %s\n>\n"
        "> Please confirm in writing when this is done. Thank you.\n"
        % (name or "(your full name)", email or "(your email)")
    )


def build_report(name=None, email=None):
    """Return the full grandma-friendly removal guide as Markdown."""
    who = name or "you"
    out = []
    A = out.append

    A("# Your Step-by-Step Guide to Removing Yourself From the Internet\n")
    A("This guide is written so **anyone** can follow it — no special computer "
      "skills needed. Take it one box at a time. You do **not** have to finish "
      "in one sitting; tick off each item as you go and come back later.\n")

    A("## Before you start\n")
    A("- Set aside about **an hour** (you can split it up).")
    A("- Have your **email inbox open** — many sites send you a link you must click.")
    A("- Keep this guide next to you and **tick each box** when it's done.")
    A("- It's normal for this to feel slow. Every site you finish is real progress.\n")
    A("> Tip: **Ctrl+C** means hold the *Ctrl* key and tap *C* (that copies). "
      "**Ctrl+V** pastes. On an Apple computer, use the *Command* key instead of *Ctrl*.\n")

    # Part 1 — data brokers, grouped by category.
    A("---\n")
    A("## Part 1 — Remove your listings from 'people-search' websites\n")
    A("These are websites that collect your name, address, and phone number and "
      "show them to anyone. We'll ask each one to take your information down.\n")

    rows = brokers.load_brokers()
    # people-search first (most important for safety), then the rest.
    order = ["people-search", "data-aggregator", "ad-tech"]
    rows = sorted(rows, key=lambda b: order.index(b["category"])
                  if b["category"] in order else 99)

    n = 0
    for b in rows:
        n += 1
        A("### %d. %s\n" % (n, b["name"]))
        A("- [ ] **Done with %s**\n" % b["name"])
        steps = _METHOD_STEPS.get(b["method"], _GENERIC_STEPS)
        for i, step in enumerate(steps, 1):
            A("%d. %s" % (i, _fill(step, b, email)))
        if b.get("opt_out_email"):
            A("\n**Ready-made letter to paste in:**\n")
            A(_letter_block(b, name, email))
        if b.get("notes"):
            A("\n*Good to know: %s*\n" % b["notes"])
        A("")

    # Part 2 — social accounts.
    A("---\n")
    A("## Part 2 — Delete or lock down old accounts\n")
    A("If you no longer use an account, deleting it removes another copy of your "
      "information. Only do the ones you want gone.\n")
    for a in accounts.all_accounts():
        A("### %s\n" % a["name"])
        A("- [ ] **Done with %s**\n" % a["name"])
        A("1. Go to: %s" % a["url"])
        for i, step in enumerate(a["steps"], 2):
            A("%d. %s" % (i, step))
        A("")

    # Part 3 — passwords & breaches.
    A("---\n")
    A("## Part 3 — Protect yourself from past leaks\n")
    A("Sometimes your email or password leaks in a company's data breach. Here's "
      "how to stay safe:\n")
    A("1. Go to **https://haveibeenpwned.com** and type in your email address. "
      "It will tell you, for free, if your information has been in a known leak.")
    A("2. If it says you were in a leak that exposed **passwords**, change that "
      "password right away — anywhere you used it.")
    A("3. Use a **different password for every important account** (especially "
      "email and banking). A password manager can remember them for you.")
    A("4. Turn on **two-step login** (also called 2FA) for your email and bank. "
      "It asks for a code from your phone so a stranger with your password still "
      "can't get in.")
    A("5. If a leak exposed your **Social Security number or bank details**, "
      "consider a free **credit freeze** with Equifax, Experian, and TransUnion "
      "so no one can open accounts in your name.\n")

    # Part 4 — keep it clean.
    A("---\n")
    A("## Part 4 — Check again every few months\n")
    A("Some of these websites quietly put your information back. Every **3 "
      "months**, search your own name on Google and re-do any site where you "
      "reappear. Twenty minutes now and then keeps you off the radar.\n")

    A("---\n")
    A("*You've got this, %s. Each box you tick is one less place a stranger can "
      "find you.*\n" % who)

    return "\n".join(out)
