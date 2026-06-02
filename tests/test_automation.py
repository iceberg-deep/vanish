"""Local automation helpers: mailto building, clipboard, browser heuristics."""

from urllib.parse import parse_qs, urlsplit

from vanish import automation


def test_build_mailto_encodes_subject_and_body():
    url = automation.build_mailto(
        "privacy@broker.com", "Delete me", "Line one\nLine two & more")
    assert url.startswith("mailto:privacy@broker.com?")
    q = parse_qs(urlsplit(url).query)
    assert q["subject"] == ["Delete me"]
    # newline and ampersand must survive a round-trip intact
    assert q["body"] == ["Line one\nLine two & more"]


def test_build_mailto_handles_missing_to():
    url = automation.build_mailto(None, "Subj", "Body")
    assert url.startswith("mailto:?")


def test_copy_clipboard_returns_false_when_no_tool(monkeypatch):
    # No clipboard binary available -> graceful (False, None), never raises.
    monkeypatch.setattr(automation.shutil, "which", lambda _name: None)
    ok, tool = automation.copy_clipboard("hello")
    assert ok is False and tool is None


def test_open_url_false_when_no_browser(monkeypatch):
    monkeypatch.setattr(automation, "browser_available", lambda: False)
    assert automation.open_url("https://example.com") is False


def test_browser_available_respects_env(monkeypatch):
    monkeypatch.setenv("BROWSER", "/usr/bin/firefox")
    assert automation.browser_available() is True
    monkeypatch.delenv("BROWSER", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(automation.sys, "platform", "linux")
    assert automation.browser_available() is False
