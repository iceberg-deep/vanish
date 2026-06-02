"""Local SQLite store for the single-operator request tracker + audit log.

vanish removes, it never discovers. This store records the *fact* that you
filed an opt-out — broker, template, status, dates — and nothing about any
person. There are no identifier columns: names, emails, addresses, and the like
are passed at letter-generation time, rendered, and never written here.

Everything lives under ~/.vanish/vanish.db (file mode 0600, in a 0700 dir).
Nothing is ever uploaded.
"""

import os
import sqlite3
from datetime import datetime, timezone

VANISH_DIR = os.path.join(os.path.expanduser("~"), ".vanish")
DB_PATH = os.path.join(VANISH_DIR, "vanish.db")

VALID_STATUSES = ("pending", "sent", "confirmed", "relisted", "failed")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _secure_perms():
    """Lock the store down to the owner only (0700 dir, 0600 db).

    Best-effort on filesystems without POSIX modes.
    """
    try:
        os.chmod(VANISH_DIR, 0o700)
        if os.path.exists(DB_PATH):
            os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


def _connect():
    os.makedirs(VANISH_DIR, mode=0o700, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _secure_perms()
    return conn


def _columns(conn, table):
    return {r["name"] for r in conn.execute("PRAGMA table_info(%s)" % table)}


def init_db():
    """Create/upgrade tables. Returns the db path.

    Drops the abandoned multi-subject scaffolding (`subjects`, `audit_notes`)
    and any `requests` table that still carried subject/identifier columns —
    that was scope drift toward a standing record of people, which vanish does
    not keep. Rebuilds `requests` identifier-free. Test data only; safe to drop.
    """
    conn = _connect()
    try:
        conn.execute("DROP TABLE IF EXISTS audit_notes")
        conn.execute("DROP TABLE IF EXISTS subjects")

        # Drop any legacy requests table that referenced a subject or stored PII.
        existing = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "requests" in existing:
            legacy = _columns(conn, "requests")
            if {"subject_id", "name", "email", "details"} & legacy:
                conn.execute("DROP TABLE requests")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS requests (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                broker_id   TEXT NOT NULL,
                broker_name TEXT NOT NULL,
                template    TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts     TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()
    return DB_PATH


def log(action, detail=""):
    """Append an entry to the audit log. Never log identifiers."""
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO audit_log (ts, action, detail) VALUES (?, ?, ?)",
            (_now(), action, detail),
        )
        conn.commit()
    finally:
        conn.close()


def add_request(broker_id, broker_name, template):
    """Record that an opt-out was filed. Returns the new id.

    Stores NO identifiers — only the fact of filing (broker, template, status,
    dates).
    """
    init_db()
    conn = _connect()
    try:
        now = _now()
        cur = conn.execute(
            """
            INSERT INTO requests
                (broker_id, broker_name, template, status, created_at, updated_at)
            VALUES (?, ?, ?, 'pending', ?, ?)
            """,
            (broker_id, broker_name, template, now, now),
        )
        conn.commit()
        req_id = cur.lastrowid
    finally:
        conn.close()
    log("request.created",
        "id=%s broker=%s template=%s" % (req_id, broker_id, template))
    return req_id


def list_requests():
    """Return all tracked requests, newest first. No identifiers to return."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM requests ORDER BY created_at DESC, id DESC"
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def status_counts():
    """Return {status: count} across all requests."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS n FROM requests GROUP BY status"
        ).fetchall()
    finally:
        conn.close()
    return {r["status"]: r["n"] for r in rows}


def update_status(req_id, status):
    """Update a request's status. Returns True if a row changed."""
    if status not in VALID_STATUSES:
        raise ValueError("invalid status: %s" % status)
    init_db()
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE requests SET status = ?, updated_at = ? WHERE id = ?",
            (status, _now(), req_id),
        )
        conn.commit()
        changed = cur.rowcount > 0
    finally:
        conn.close()
    if changed:
        log("request.status", "id=%s -> %s" % (req_id, status))
    return changed
