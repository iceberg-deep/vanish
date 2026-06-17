"""Re-scan / relist loop: idempotent re-scans, honest presence-gated relisting."""

from vanish.account import identity, scan


def _verify(reg, email):
    s = identity.RecordingSender()
    identity.request_email_verification(reg.session, email, s)
    identity.confirm_verification(reg.session, s.last_token)


def _sources(brokers=None, accounts=None):
    return {"breach_exposure": lambda e: [],
            "broker_listing": lambda e: brokers or [],
            "discoverable_account": lambda e: accounts or []}


def _by_key(session):
    return {scan.finding_key(f): f for f in scan.load_findings(session)}


def test_rescan_is_idempotent_no_duplicates(registered):
    _verify(registered, "owner@me.com")
    src = _sources(brokers=[{"name": "Spokeo", "category": "people-search",
                             "opt_out_url": "https://spokeo/optout"}])
    scan.scan(registered.session, sources=src)
    scan.scan(registered.session, sources=src)
    scan.scan(registered.session, sources=src)
    # three scans, still exactly one Spokeo finding
    assert len(scan.load_findings(registered.session)) == 1


def test_account_relists_after_removal_when_present_again(registered):
    _verify(registered, "owner@me.com")
    acct = _sources(accounts=[{"platform": "instagram", "exists": True}])
    scan.scan(registered.session, sources=acct)
    fid = _by_key(registered.session)["discoverable_account:instagram"].finding_id

    # user removes it
    scan.set_finding_status(registered.session, fid, "confirmed_removed")
    # later re-scan: the account-existence source (presence-confirming) sees it again
    summary = scan.reconcile(registered.session, scan.collect(registered.session, acct))

    assert summary["relisted"] == 1
    again = _by_key(registered.session)["discoverable_account:instagram"]
    assert again.status == "relisted"
    assert again.finding_id == fid                 # same finding, not a duplicate


def test_broker_does_not_spuriously_relist_from_registry(registered):
    """The static registry is a worklist, not a presence probe — a removed broker
    reappearing in the registry must NOT be reported as relisted."""
    _verify(registered, "owner@me.com")
    src = _sources(brokers=[{"name": "Spokeo", "category": "people-search",
                             "opt_out_url": "https://spokeo/optout"}])
    scan.scan(registered.session, sources=src)
    fid = _by_key(registered.session)["broker_listing:spokeo"].finding_id
    scan.set_finding_status(registered.session, fid, "confirmed_removed")

    summary = scan.reconcile(registered.session, scan.collect(registered.session, src))
    assert summary["relisted"] == 0
    assert summary["kept_removed"] == 1
    assert _by_key(registered.session)["broker_listing:spokeo"].status == "confirmed_removed"


def test_new_items_added_open_items_untouched(registered):
    _verify(registered, "owner@me.com")
    one = _sources(brokers=[{"name": "Spokeo", "category": "people-search",
                             "opt_out_url": "https://spokeo/optout"}])
    scan.scan(registered.session, sources=one)
    # next scan surfaces an additional broker; first stays as the same finding
    two = _sources(brokers=[
        {"name": "Spokeo", "category": "people-search", "opt_out_url": "https://spokeo/optout"},
        {"name": "Radaris", "category": "people-search", "opt_out_url": "https://radaris/optout"}])
    summary = scan.reconcile(registered.session, scan.collect(registered.session, two))
    assert summary["new"] == 1 and summary["open"] == 1
    keys = set(_by_key(registered.session))
    assert "broker_listing:spokeo" in keys and "broker_listing:radaris" in keys
