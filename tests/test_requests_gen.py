"""Removal-letter rendering: templates, authorized-agent language, contents."""

import pytest

from vanish import requests_gen


BROKER = {"name": "Spokeo", "opt_out_url": "https://x", "method": "web-form"}


@pytest.mark.parametrize("template", ["ccpa", "gdpr", "generic"])
def test_each_template_renders_with_identity(template):
    letter = requests_gen.render(
        template, BROKER, "Jane Doe", "jane@example.com",
        phone="555-0100", address="1 Main St")
    assert "Spokeo" in letter
    assert "Jane Doe" in letter
    assert "jane@example.com" in letter
    assert "555-0100" in letter
    assert "1 Main St" in letter


def test_invalid_template_raises():
    with pytest.raises(ValueError):
        requests_gen.render("nope", BROKER, "Jane", "j@e.com")


@pytest.mark.parametrize("template", ["ccpa", "gdpr", "generic"])
def test_as_agent_injects_authorized_agent_language(template):
    plain = requests_gen.render(template, BROKER, "Jane", "j@e.com")
    agent = requests_gen.render(template, BROKER, "Jane", "j@e.com", as_agent=True)
    assert "designated authorized agent" not in plain
    assert "designated authorized agent" in agent
    assert "proof of authorization" in agent


def test_optional_fields_omitted_when_absent():
    letter = requests_gen.render("ccpa", BROKER, "Jane", "j@e.com")
    assert "Phone:" not in letter
    assert "Address:" not in letter


def test_ccpa_mentions_delete_and_optout():
    letter = requests_gen.render("ccpa", BROKER, "Jane", "j@e.com")
    assert "DELETE" in letter
    assert "OPT OUT" in letter
    assert "1798.100" in letter  # the CCPA citation


def test_gdpr_mentions_erasure_article():
    letter = requests_gen.render("gdpr", BROKER, "Jane", "j@e.com")
    assert "Article 17" in letter or "Art. 17" in letter
