"""Terminal color + ASCII-art helpers. All output is cosmetic; disable with NO_COLOR."""

import os
import sys

_ENABLED = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and os.environ.get(
    "TERM"
) != "dumb"


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GREY = "\033[90m"

    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"


def paint(text, *styles):
    """Wrap text in ANSI styles when color is enabled."""
    if not _ENABLED or not styles:
        return text
    return "".join(styles) + text + C.RESET


def supports_color():
    return _ENABLED


# Category accent colors.
CATEGORY_COLOR = {
    "people-search": C.BRIGHT_CYAN,
    "data-aggregator": C.BRIGHT_MAGENTA,
    "ad-tech": C.BRIGHT_YELLOW,
}

# Request/audit status colors.
STATUS_COLOR = {
    "pending": C.YELLOW,
    "sent": C.BRIGHT_BLUE,
    "confirmed": C.BRIGHT_GREEN,
    "relisted": C.BRIGHT_MAGENTA,
    "failed": C.BRIGHT_RED,
    "found": C.BRIGHT_GREEN,
    "verified": C.BRIGHT_GREEN,
    "absent": C.GREY,
    "pwned": C.BRIGHT_RED,
    "clean": C.BRIGHT_GREEN,
    "error": C.BRIGHT_RED,
}

LOGO = r"""
                    _      __
 _   ______ _____  (_)____/ /_
| | / / __ `/ __ \/ / ___/ __ \
| |/ / /_/ / / / / (__  ) / / /
|___/\__,_/_/ /_/_/____/_/ /_/
"""

_TAGLINE = "scrub your own digital footprint — locally, on your terms"


def banner(version=""):
    """Return the colorized logo + tagline block."""
    logo = paint(LOGO, C.BOLD, C.BRIGHT_CYAN)
    ver = paint("v" + version, C.DIM) if version else ""
    tag = paint("  " + _TAGLINE + ("  " + ver if ver else ""), C.GREY)
    return logo + "\n" + tag + "\n"


def rule(width=64, ch="─"):
    return paint(ch * width, C.GREY)


def header(text):
    """A section header with a leading marker."""
    marker = paint("▸", C.BRIGHT_CYAN)
    return "\n" + marker + " " + paint(text, C.BOLD, C.BRIGHT_WHITE)


def ok(text):
    return paint("✔", C.BRIGHT_GREEN) + " " + text


def warn(text):
    return paint("⚠", C.BRIGHT_YELLOW) + " " + text


def err(text):
    return paint("✗", C.BRIGHT_RED) + " " + text


def info(text):
    return paint("•", C.BRIGHT_BLUE) + " " + text


def field(label, value, label_w=12):
    return paint(("{:>%d}" % label_w).format(label) + " ", C.GREY) + str(value)


def status_badge(status):
    color = STATUS_COLOR.get(status, C.WHITE)
    return paint(" " + status.upper() + " ", C.BOLD, color)


def category_badge(category):
    color = CATEGORY_COLOR.get(category, C.WHITE)
    return paint(category, color)
