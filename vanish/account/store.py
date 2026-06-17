"""Local-first SQLite store for accounts + verified identifiers.

Local-first per BLUEPRINT.md §6: this lives on the user's own device
(~/.vanish/account.db, 0600 in a 0700 dir), NOT a hosted multi-tenant server. That
is deliberate — keeping data on-device keeps the data-broker-registration legal
question (BLUEPRINT §10) out of the critical path. The hosted-server sync variant is
DEFERRED pending the legal review (ROADMAP Phase 0 item 0.2).

This layer is the "untrusted storage" boundary of the ZK model: it only ever receives
the auth verifier, public salts/params, the ciphertext-wrapped master keys, and
ciphertext identifier values. It NEVER receives ENC_KEY or MASTER_KEY — there is no
function here that takes one. Verified identifiers carry their value only as
ciphertext (`identifier_value_encrypted`).
"""

import json
import os
import sqlite3
from datetime import datetime, timezone

VANISH_DIR = os.path.join(os.path.expanduser("~"), ".vanish")
ACCOUNT_DB_PATH = os.path.join(VANISH_DIR, "account.db")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _secure_perms():
    try:
        os.chmod(VANISH_DIR, 0o700)
        if os.path.exists(ACCOUNT_DB_PATH):
            os.chmod(ACCOUNT_DB_PATH, 0o600)
    except OSError:  # pragma: no cover - non-POSIX filesystems
        pass


def _connect():
    os.makedirs(VANISH_DIR, mode=0o700, exist_ok=True)
    conn = sqlite3.connect(ACCOUNT_DB_PATH)
    conn.row_factory = sqlite3.Row
    _secure_perms()
    return conn


def init_db():
    conn = _connect()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                user_id          TEXT PRIMARY KEY,
                auth_verifier    TEXT NOT NULL,
                salt_pw          BLOB NOT NULL,
                salt_rec         BLOB NOT NULL,
                kdf_params       TEXT NOT NULL,
                wrapped_password BLOB NOT NULL,
                wrapped_recovery BLOB NOT NULL,
                created_at       TEXT NOT NULL
            )
            """)
        # The scannable set: an identifier appears here ONLY after verification.
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS identifiers (
                id                         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id                    TEXT NOT NULL,
                identifier_type            TEXT NOT NULL,
                identifier_value_encrypted BLOB NOT NULL,
                verified_at                TEXT NOT NULL
            )
            """)
        # Added-but-unconfirmed identifiers wait here; never scannable. The raw
        # token is never stored — only its hash (token_hash).
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_verifications (
                id                         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id                    TEXT NOT NULL,
                identifier_type            TEXT NOT NULL,
                identifier_value_encrypted BLOB NOT NULL,
                token_hash                 TEXT NOT NULL,
                created_at                 TEXT NOT NULL
            )
            """)
        # Encrypted scan findings. The blob is the only semantic content; the
        # columns carry no exposure data (mirrors the CLI's identifier-free schema).
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id           TEXT NOT NULL,
                finding_id        TEXT NOT NULL,
                finding_encrypted BLOB NOT NULL,
                created_at        TEXT NOT NULL
            )
            """)
        conn.commit()
    finally:
        conn.close()
    return ACCOUNT_DB_PATH


def create_account(user_id, auth_verifier, salt_pw, salt_rec, kdf_params,
                   wrapped_password, wrapped_recovery):
    """Persist a new account. Inputs are verifier/salts/params/ciphertext only."""
    init_db()
    conn = _connect()
    try:
        conn.execute(
            """
            INSERT INTO accounts (user_id, auth_verifier, salt_pw, salt_rec,
                kdf_params, wrapped_password, wrapped_recovery, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, auth_verifier, salt_pw, salt_rec, json.dumps(kdf_params),
             wrapped_password, wrapped_recovery, now()))
        conn.commit()
    finally:
        conn.close()


def get_account(user_id):
    init_db()
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM accounts WHERE user_id = ?", (user_id,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    d = dict(row)
    d["kdf_params"] = json.loads(d["kdf_params"])
    return d


def account_ids():
    """All account ids on this device. Single-operator: expected to be 0 or 1."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT user_id FROM accounts ORDER BY created_at").fetchall()
    finally:
        conn.close()
    return [r["user_id"] for r in rows]


def update_wrapped_password(user_id, salt_pw, auth_verifier, wrapped_password):
    """Re-wrap after a password change: only the wrapper + verifier change."""
    conn = _connect()
    try:
        conn.execute(
            "UPDATE accounts SET salt_pw = ?, auth_verifier = ?, "
            "wrapped_password = ? WHERE user_id = ?",
            (salt_pw, auth_verifier, wrapped_password, user_id))
        conn.commit()
    finally:
        conn.close()


def update_wrapped_recovery(user_id, salt_rec, wrapped_recovery):
    conn = _connect()
    try:
        conn.execute(
            "UPDATE accounts SET salt_rec = ?, wrapped_recovery = ? "
            "WHERE user_id = ?", (salt_rec, wrapped_recovery, user_id))
        conn.commit()
    finally:
        conn.close()


# --- pending verifications ------------------------------------------------ #
def insert_pending(user_id, identifier_type, value_encrypted, token_hash):
    init_db()
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO pending_verifications (user_id, identifier_type, "
            "identifier_value_encrypted, token_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, identifier_type, value_encrypted, token_hash, now()))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_pending_by_token(user_id, token_hash):
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM pending_verifications WHERE user_id = ? AND "
            "token_hash = ?", (user_id, token_hash)).fetchone()
    finally:
        conn.close()
    return dict(row) if row else None


def delete_pending(pending_id):
    conn = _connect()
    try:
        conn.execute(
            "DELETE FROM pending_verifications WHERE id = ?", (pending_id,))
        conn.commit()
    finally:
        conn.close()


# --- verified identifiers ------------------------------------------------- #
def insert_identifier(user_id, identifier_type, value_encrypted, verified_at):
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO identifiers (user_id, identifier_type, "
            "identifier_value_encrypted, verified_at) VALUES (?, ?, ?, ?)",
            (user_id, identifier_type, value_encrypted, verified_at))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_identifiers(user_id):
    """Verified identifiers for a user, value still ciphertext."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM identifiers WHERE user_id = ? ORDER BY id",
            (user_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


# --- encrypted findings --------------------------------------------------- #
def insert_finding(user_id, finding_id, finding_encrypted):
    init_db()
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO findings (user_id, finding_id, finding_encrypted, "
            "created_at) VALUES (?, ?, ?, ?)",
            (user_id, finding_id, finding_encrypted, now()))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_findings(user_id):
    """Encrypted findings for a user (blob still ciphertext)."""
    init_db()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM findings WHERE user_id = ? ORDER BY id",
            (user_id,)).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def update_finding(user_id, finding_id, finding_encrypted):
    """Replace a finding's ciphertext (e.g. after a status change)."""
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE findings SET finding_encrypted = ? WHERE user_id = ? AND "
            "finding_id = ?", (finding_encrypted, user_id, finding_id))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()
