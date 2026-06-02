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


def test_check_hibp_without_key_degrades_without_network(monkeypatch):
    # Key absent -> graceful skip, and it must NOT touch the network.
    monkeypatch.delenv("HIBP_API_KEY", raising=False)

    def _no_call(*a, **k):
        raise AssertionError("must not call the network without a key")
    monkeypatch.setattr("requests.get", _no_call)

    out = audit.check_hibp("me@example.com")
    assert out == {"ok": False, "reason": "no-api-key"}


def test_check_hibp_with_env_key_attempts_call(monkeypatch):
    # Key present -> a request is attempted with the key as a header. We stub
    # the HTTP layer (no live call) and capture how it was invoked.
    monkeypatch.setenv("HIBP_API_KEY", "test-key-123")
    captured = {}

    class _Resp:
        status_code = 404  # "no breaches" — keeps the assertion simple

    def _fake_get(url, headers=None, params=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers or {}
        return _Resp()

    monkeypatch.setattr("requests.get", _fake_get)
    out = audit.check_hibp("me@example.com")

    assert out == {"ok": True, "breaches": []}
    assert "me%40example.com" in captured["url"] or "me@example.com" in captured["url"]
    # the key travels only as the documented header
    assert captured["headers"].get("hibp-api-key") == "test-key-123"


def test_check_hibp_key_is_never_returned(monkeypatch):
    # Defense in depth: the key must not leak into the result object.
    monkeypatch.setenv("HIBP_API_KEY", "super-secret-key")

    class _Resp:
        status_code = 200
        def json(self):
            return [{"Name": "X", "Title": "X", "BreachDate": "2020",
                     "DataClasses": ["Passwords"]}]

    monkeypatch.setattr("requests.get", lambda *a, **k: _Resp())
    out = audit.check_hibp("me@example.com")
    assert "super-secret-key" not in repr(out)


def test_has_hibp_key_reflects_environment(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    assert audit.has_hibp_key() is False
    monkeypatch.setenv("HIBP_API_KEY", "x")
    assert audit.has_hibp_key() is True
