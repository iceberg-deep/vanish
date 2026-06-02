"""Best-effort LOCAL automation for the guided cleanse.

We automate the parts a machine legitimately can — opening the right opt-out
page, putting the finished letter on your clipboard, drafting a pre-filled email
— and degrade gracefully (print exactly what to do by hand) when a capability is
missing (headless box, no clipboard tool, no mail client).

We deliberately do NOT auto-submit broker forms. CAPTCHAs, email-confirmation
links, and phone verification exist precisely to require a human; driving a
headless browser through them is brittle and against broker terms. Those steps
stay yours — vanish just removes every bit of friction around them.
"""

import os
import shutil
import subprocess
import sys
import webbrowser
from urllib.parse import quote


def browser_available():
    """Heuristic: can we plausibly open a real browser on this machine?"""
    if os.environ.get("BROWSER"):
        return True
    if sys.platform == "darwin" or sys.platform.startswith("win"):
        return True
    # Linux/BSD need a display server.
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def open_url(url):
    """Open `url` in the default browser. Returns True if it likely launched."""
    if not browser_available():
        return False
    try:
        return webbrowser.open(url, new=2)
    except Exception:
        return False


# (display name, argv) — first one whose binary exists wins.
_CLIPBOARD_TOOLS = (
    ("wl-copy", ["wl-copy"]),
    ("xclip", ["xclip", "-selection", "clipboard"]),
    ("xsel", ["xsel", "--clipboard", "--input"]),
    ("pbcopy", ["pbcopy"]),
    ("clip.exe", ["clip.exe"]),
)


def copy_clipboard(text):
    """Copy `text` to the system clipboard. Returns (ok, tool_name)."""
    for name, cmd in _CLIPBOARD_TOOLS:
        if shutil.which(cmd[0]):
            try:
                proc = subprocess.run(
                    cmd, input=text.encode("utf-8"), timeout=5)
                if proc.returncode == 0:
                    return True, name
            except Exception:
                continue
    return False, None


def build_mailto(to, subject, body):
    """Build a mailto: URL with a pre-filled subject and body."""
    return "mailto:%s?subject=%s&body=%s" % (
        quote(to or "", safe="@"), quote(subject), quote(body))
