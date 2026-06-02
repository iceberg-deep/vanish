"""The store: identifier-free schema, request lifecycle, status counts."""

import os
import sqlite3

import pytest

from vanish import db


def _columns(table):
    conn = sqlite3.connect(db.DB_PATH)
    try:
        return {r[1] for r in conn.execute("PRAGMA table_info(%s)" % table)}
    finally:
        conn.close()


def _tables():
    conn = sqlite3.connect(db.DB_PATH)
    try:
        return {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


# --- the no-dossier guarantee -------------------------------------------- #

def test_requests_table_has_no_identifier_columns():
    cols = _columns("requests")
    forbidden = {"name", "email", "phone", "address", "dob",
                 "details", "subject_id", "relatives"}
    assert not (cols & forbidden), "identifier column leaked into requests"
    assert cols == {"id", "broker_id", "broker_name", "template",
                    "status", "created_at", "updated_at"}


def test_abandoned_subject_tables_do_not_exist():
    tables = _tables()
    assert "subjects" not in tables
    assert "audit_notes" not in tables


def test_add_request_stores_only_facts():
    rid = db.add_request("spokeo", "Spokeo", "ccpa")
    rows = db.list_requests()
    assert len(rows) == 1
    row = rows[0]
    assert row["id"] == rid
    assert row["broker_id"] == "spokeo"
    assert row["status"] == "pending"
    # the row dict must carry nothing resembling an identifier
    assert set(row.keys()) == {"id", "broker_id", "broker_name", "template",
                               "status", "created_at", "updated_at"}


def test_no_identifier_text_ever_lands_in_db_file():
    # Even after activity, grepping the raw db file finds no identifiers,
    # because none are ever passed to the store.
    db.add_request("spokeo", "Spokeo", "ccpa")
    db.add_request("mylife", "MyLife", "gdpr")
    blob = open(db.DB_PATH, "rb").read()
    for needle in (b"jane@example.com", b"Jane Doe", b"555"):
        assert needle not in blob


# --- lifecycle ----------------------------------------------------------- #

def test_status_update_and_counts():
    a = db.add_request("spokeo", "Spokeo", "ccpa")
    db.add_request("mylife", "MyLife", "gdpr")
    assert db.update_status(a, "sent") is True
    counts = db.status_counts()
    assert counts.get("sent") == 1
    assert counts.get("pending") == 1


def test_update_status_rejects_unknown_status():
    rid = db.add_request("spokeo", "Spokeo", "ccpa")
    with pytest.raises(ValueError):
        db.update_status(rid, "banana")


def test_update_status_missing_row_returns_false():
    assert db.update_status(9999, "sent") is False


# --- at-rest protection -------------------------------------------------- #

def test_db_file_is_owner_only():
    db.add_request("spokeo", "Spokeo", "ccpa")
    mode = oct(os.stat(db.DB_PATH).st_mode & 0o777)
    assert mode == "0o600"
