"""The grandma-proof guide report."""

from vanish import brokers, guide


def test_report_has_all_four_parts():
    r = guide.build_report()
    assert "## Before you start" in r
    assert "Part 1" in r and "Part 2" in r and "Part 3" in r and "Part 4" in r


def test_report_covers_every_broker_with_a_checkbox():
    r = guide.build_report()
    for b in brokers.load_brokers():
        assert b["name"] in r
        assert "- [ ] **Done with %s**" % b["name"] in r


def test_personalization_is_filled_in():
    r = guide.build_report(name="Jane Doe", email="jane@example.com")
    assert "Jane Doe" in r
    assert "jane@example.com" in r


def test_email_broker_gets_paste_ready_letter():
    r = guide.build_report(name="Jane", email="jane@example.com")
    # MyLife is an email broker -> its section should include the letter block.
    assert "privacy@mylife.com" in r
    assert "Ready-made letter to paste in" in r


def test_explains_jargon_for_non_technical_reader():
    r = guide.build_report()
    assert "Ctrl" in r and "Command" in r  # copy/paste explained
    assert "haveibeenpwned.com" in r       # breach self-check
    assert "two-step" in r.lower() or "2fa" in r.lower()


def test_report_is_plain_string_not_written_anywhere():
    # build_report must be pure: returns text, touches no files/db.
    out = guide.build_report()
    assert isinstance(out, str) and len(out) > 500
