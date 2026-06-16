"""The self-only-scan invariant — the point of Phase 1.

Proves assert_scannable refuses anything the user hasn't verified ownership of, that
an added-but-unconfirmed email is not scannable until the round-trip completes, and
that there is no path to mark an identifier verified without its token.
"""

from vanish.account import identity, store


def _verify(reg, email):
    sender = identity.RecordingSender()
    identity.request_email_verification(reg.session, email, sender)
    return identity.confirm_verification(reg.session, sender.last_token)


def test_assert_scannable_rejects_third_party(registered):
    _verify(registered, "owner@me.com")
    # The user's own, verified identifier is scannable...
    assert identity.assert_scannable(registered.session, "email", "owner@me.com")
    # ...a stranger's email the user never verified is refused.
    assert not identity.assert_scannable(
        registered.session, "email", "stranger@evil.com")
    # case/whitespace-folded, still the same owned identifier
    assert identity.assert_scannable(
        registered.session, "email", "  Owner@ME.com ")


def test_added_email_not_scannable_until_confirmed(registered):
    sender = identity.RecordingSender()
    identity.request_email_verification(registered.session, "new@me.com", sender)
    # added but unconfirmed -> NOT a valid scan target
    assert not identity.assert_scannable(registered.session, "email", "new@me.com")
    # complete the round-trip
    identity.confirm_verification(registered.session, sender.last_token)
    assert identity.assert_scannable(registered.session, "email", "new@me.com")


def test_no_path_to_verify_without_the_token(registered):
    sender = identity.RecordingSender()
    identity.request_email_verification(registered.session, "claim@me.com", sender)
    real = sender.last_token
    # A spread of wrong tokens never verifies and never makes it scannable.
    for i in range(50):
        bogus = ("0" * 63 + str(i % 10))
        assert bogus != real
        assert identity.confirm_verification(registered.session, bogus) is None
    assert not identity.assert_scannable(registered.session, "email", "claim@me.com")
    assert store.list_identifiers(registered.user_id) == []
    # Only the exact token promotes it.
    assert identity.confirm_verification(registered.session, real) is not None
    assert identity.assert_scannable(registered.session, "email", "claim@me.com")


def test_scannable_identifiers_is_the_only_target_source(registered):
    _verify(registered, "a@me.com")
    _verify(registered, "b@me.com")
    targets = identity.scannable_identifiers(registered.session)
    assert sorted(v for _, v in targets) == ["a@me.com", "b@me.com"]
    assert all(t == "email" for t, _ in targets)
