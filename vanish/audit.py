"""Self-audit helpers: Have I Been Pwned breach lookups + username probing.

Scope: probe-only. These check identifiers YOU supply about yourself against
breach data and public profile URLs. They do NOT resolve names to people,
relatives, addresses, or phone numbers, and never aggregate anything. The
identifiers are passed at call time and never persisted.
"""

import os

import requests

HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
USER_AGENT = "vanish-self-audit"

# Per-platform probe specs. Naively treating "HTTP 200" as "profile exists" is
# wrong for most large platforms: Instagram, X, Reddit, Twitch and friends serve
# a 200 JavaScript shell (or a bot wall) for handles that DON'T exist, so a 200
# is meaningless there. Each spec below declares how that platform actually
# signals absence, empirically verified against a known-nonexistent handle:
#
#   method "status"  -> the server returns a clean 404 for missing profiles.
#   method "content" -> always 200; absence is detectable by a marker in the body.
#   method "manual"  -> 200 JS shell / bot wall with no reliable signal over plain
#                       HTTP. We refuse to guess and ask the user to check the URL.
#
# Markers are matched against a lower-cased response body.
PLATFORMS = {
    "github": {"url": "https://github.com/{u}", "method": "status"},
    "youtube": {"url": "https://www.youtube.com/@{u}", "method": "status"},
    "tiktok": {
        "url": "https://www.tiktok.com/@{u}",
        "method": "content",
        "absent_markers": ["couldn't find this account", "page not available"],
    },
    "pinterest": {
        "url": "https://www.pinterest.com/{u}/",
        "method": "content",
        "absent_markers": ["user not found"],
    },
    "facebook": {
        "url": "https://www.facebook.com/{u}",
        "method": "content",
        "absent_markers": ["this content isn't available", "isn't available right now"],
    },
    "instagram": {"url": "https://www.instagram.com/{u}/", "method": "manual"},
    "x": {"url": "https://x.com/{u}", "method": "manual"},
    "reddit": {"url": "https://www.reddit.com/user/{u}", "method": "manual"},
    "twitch": {"url": "https://www.twitch.tv/{u}", "method": "manual"},
    "medium": {"url": "https://medium.com/@{u}", "method": "manual"},
}

ALL_PLATFORMS = tuple(PLATFORMS.keys())

# HIBP reports each breach's exposed "data classes" as free-text strings, e.g.
# "Passwords", "Social security numbers", "Credit cards". These substrings (case-
# insensitive) flag the classes that demand immediate action — a leaked password
# or SSN is a different order of harm than a leaked gender or IP address.
CRITICAL_DATA_MARKERS = (
    "password",
    "social security",
    "ssn",
    "credit card",
    "bank account",
    "bank number",
    "security question",
    "passport",
    "driver",          # driver's licence / license
    "tax",             # taxpayer / tax file numbers
    "pin",
    "cvv",
    "encrypted password",
    "historical password",
)


def classify_exposure(data_classes):
    """Split a breach's data classes into (critical, other), preserving order.

    `critical` are the high-harm exposures (passwords, SSNs, financial, etc.)
    matched against CRITICAL_DATA_MARKERS; `other` is everything else.
    """
    critical, other = [], []
    for dc in data_classes or []:
        low = dc.lower()
        if any(m in low for m in CRITICAL_DATA_MARKERS):
            critical.append(dc)
        else:
            other.append(dc)
    return critical, other


def has_hibp_key():
    """True if a HIBP API key is present in the environment."""
    return bool(os.environ.get("HIBP_API_KEY"))


def check_hibp(email, timeout=15):
    """Query Have I Been Pwned for breaches of `email`.

    The API key is read from the HIBP_API_KEY environment variable ONLY — there
    is deliberately no parameter or CLI flag for it, so it can't end up in shell
    history, argv, or a committed file. The key is used solely as a request
    header and is never logged, printed, or returned.

    Privacy note: this endpoint sends the FULL email address to HaveIBeenPwned
    (there is no k-anonymity for the email lookup, unlike the password API).
    Callers should disclose that to the user.

    Returns a dict:
      {"ok": True, "breaches": [...]}            on success
      {"ok": True, "breaches": []}               when not found (clean)
      {"ok": False, "reason": "no-api-key"|...}  on graceful degradation
    """
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        return {"ok": False, "reason": "no-api-key"}

    headers = {"hibp-api-key": api_key, "user-agent": USER_AGENT}
    url = HIBP_API.format(account=requests.utils.quote(email, safe=""))
    try:
        resp = requests.get(
            url, headers=headers, params={"truncateResponse": "false"}, timeout=timeout
        )
    except requests.RequestException as exc:
        return {"ok": False, "reason": "network", "detail": str(exc)}

    if resp.status_code == 200:
        try:
            data = resp.json()
        except ValueError:
            data = []
        breaches = [
            {
                "name": b.get("Name") or b.get("Title", "?"),
                "title": b.get("Title", b.get("Name", "?")),
                "date": b.get("BreachDate", "?"),
                "data": b.get("DataClasses", []),
            }
            for b in data
        ]
        return {"ok": True, "breaches": breaches}
    if resp.status_code == 404:
        return {"ok": True, "breaches": []}
    if resp.status_code in (401, 403):
        return {"ok": False, "reason": "auth", "detail": "HTTP %s" % resp.status_code}
    if resp.status_code == 429:
        return {"ok": False, "reason": "rate-limited"}
    return {"ok": False, "reason": "http", "detail": "HTTP %s" % resp.status_code}


def _classify(spec, resp):
    """Map an HTTP response to a status using the platform's detection method.

    Returns one of: found | absent | manual | unknown. `manual` means we cannot
    tell over plain HTTP and the user must open the URL themselves — we report
    that honestly rather than emitting a false "found".
    """
    code = resp.status_code
    method = spec["method"]

    if method == "status":
        if code == 200:
            return "found"
        if code == 404:
            return "absent"
        return "manual"

    if method == "content":
        body = resp.text.lower()
        if any(marker in body for marker in spec.get("absent_markers", [])):
            return "absent"
        if code == 404:
            return "absent"
        if code == 200:
            return "found"
        return "manual"

    # method == "manual": 200 JS shell / bot wall — never claim found/absent.
    return "manual"


def check_username(username, platforms=None, timeout=10):
    """Probe public profile URLs for `username` across `platforms`.

    Returns a list of dicts: {"platform", "url", "status", "code", "method"}
    where status is one of: found | absent | manual | unknown | error.
    """
    platforms = platforms or ALL_PLATFORMS
    results = []
    headers = {
        "user-agent": (
            "Mozilla/5.0 (compatible; vanish-self-audit/0.1; +local-only)"
        )
    }
    for platform in platforms:
        spec = PLATFORMS.get(platform)
        if not spec:
            results.append(
                {"platform": platform, "url": "", "status": "unknown",
                 "code": None, "method": None}
            )
            continue
        url = spec["url"].format(u=requests.utils.quote(username, safe=""))
        try:
            resp = requests.get(
                url, headers=headers, timeout=timeout, allow_redirects=True
            )
            code = resp.status_code
            status = _classify(spec, resp)
        except requests.RequestException:
            code, status = None, "error"
        results.append(
            {"platform": platform, "url": url, "status": status,
             "code": code, "method": spec["method"]}
        )
    return results
