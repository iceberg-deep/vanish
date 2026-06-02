"""Breach-severity classification and the honest username probe."""

from vanish import audit


# --- classify_exposure: the SSN/password/PII severity split -------------- #

def test_classify_flags_passwords_ssn_financial_as_critical():
    classes = ["Email addresses", "Passwords", "Social security numbers",
               "Credit cards", "Genders", "IP addresses"]
    critical, other = audit.classify_exposure(classes)
    assert "Passwords" in critical
    assert "Social security numbers" in critical
    assert "Credit cards" in critical
    assert "Genders" in other
    assert "Email addresses" in other
    assert "IP addresses" in other


def test_classify_is_case_insensitive_and_substring():
    critical, _ = audit.classify_exposure(
        ["historical passwords", "Bank account numbers", "Passport numbers"])
    assert set(critical) == {"historical passwords", "Bank account numbers",
                             "Passport numbers"}


def test_classify_handles_none_and_empty():
    assert audit.classify_exposure(None) == ([], [])
    assert audit.classify_exposure([]) == ([], [])


def test_classify_benign_only_has_no_critical():
    critical, other = audit.classify_exposure(["Usernames", "Job titles"])
    assert critical == []
    assert other == ["Usernames", "Job titles"]


# --- _classify: the per-platform username probe verdict ------------------ #

def test_status_method_uses_http_code(fake_resp):
    spec = {"method": "status"}
    assert audit._classify(spec, fake_resp(200)) == "found"
    assert audit._classify(spec, fake_resp(404)) == "absent"
    # anything else can't be trusted -> manual
    assert audit._classify(spec, fake_resp(403)) == "manual"


def test_content_method_detects_absence_marker(fake_resp):
    spec = {"method": "content", "absent_markers": ["user not found"]}
    # 200 but body says not found -> absent
    assert audit._classify(spec, fake_resp(200, "Sorry, USER NOT FOUND here")) == "absent"
    # 200 with no marker -> found
    assert audit._classify(spec, fake_resp(200, "real profile page")) == "found"
    # explicit 404 -> absent regardless of body
    assert audit._classify(spec, fake_resp(404, "")) == "absent"


def test_manual_method_never_guesses(fake_resp):
    spec = {"method": "manual"}
    assert audit._classify(spec, fake_resp(200, "anything")) == "manual"
    assert audit._classify(spec, fake_resp(403, "")) == "manual"


def test_registry_shape_is_sane():
    # Known-reliable 404 platforms must use the status method; JS-shell sites
    # must be 'manual' so we never emit a false "found".
    assert audit.PLATFORMS["github"]["method"] == "status"
    assert audit.PLATFORMS["instagram"]["method"] == "manual"
    assert audit.PLATFORMS["x"]["method"] == "manual"
    assert "absent_markers" in audit.PLATFORMS["pinterest"]
    assert set(audit.ALL_PLATFORMS) == set(audit.PLATFORMS)


def test_check_hibp_without_key_degrades(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    out = audit.check_hibp("me@example.com")
    assert out == {"ok": False, "reason": "no-api-key"}
