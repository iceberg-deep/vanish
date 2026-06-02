"""Broker registry loading and queries."""

from vanish import brokers


def test_registry_loads_and_has_expected_shape():
    rows = brokers.load_brokers()
    assert len(rows) >= 15
    for b in rows:
        assert {"id", "name", "category", "opt_out_url", "method", "needs"} <= set(b)
        assert b["opt_out_url"].startswith("http")


def test_categories_are_sorted_unique():
    cats = brokers.categories()
    assert cats == sorted(set(cats))
    assert "people-search" in cats


def test_query_filters_by_category():
    ps = brokers.query("people-search")
    assert ps and all(b["category"] == "people-search" for b in ps)


def test_get_known_and_unknown():
    assert brokers.get("spokeo")["name"] == "Spokeo"
    assert brokers.get("does-not-exist") is None


def test_email_brokers_expose_opt_out_email():
    # cleanse drafts a mailto from this field; it must be present + valid.
    mylife = brokers.get("mylife")
    assert mylife.get("opt_out_email") == "privacy@mylife.com"


def test_every_broker_has_provenance_fields():
    for b in brokers.load_brokers():
        assert isinstance(b["verified"], bool)
        assert b["last_verified"] is None or isinstance(b["last_verified"], str)
        assert isinstance(b["source"], str) and b["source"]


def test_verified_entries_carry_a_date():
    for b in brokers.load_brokers():
        if b["verified"]:
            assert b["last_verified"], "%s verified but no date" % b["id"]


def test_registry_path_points_at_a_real_file():
    import os
    assert os.path.isfile(brokers.registry_path())
