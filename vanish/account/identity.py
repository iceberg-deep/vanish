"""Identity-verification gate + the self-only-scan chokepoint.

THE INVARIANT (enforced in code, not convention): a scan may only ever target an
identifier the current authenticated user has *verified ownership of*. Every future
scan call MUST pass through `assert_scannable`, which returns True only for an
identifier in this user's verified set. There is deliberately no function here that
takes an arbitrary/third-party identifier and makes it scannable — ownership is proven
by the email round-trip, nothing else.

Flow:
  add email      -> request_email_verification  (staged in pending, NOT scannable)
  click the link -> confirm_verification         (promoted to verified + scannable)
  scan target?   -> assert_scannable             (the chokepoint)
"""

import hashlib

from . import crypto, store, sodium

SUPPORTED_TYPES = ("email",)


# --- normalization -------------------------------------------------------- #
def normalize_email(email):
    return email.strip().lower()


def normalize_identifier(identifier_type, value):
    if identifier_type == "email":
        return normalize_email(value)
    raise ValueError("unsupported identifier type: %r" % identifier_type)


# --- per-identifier encryption (under MASTER_KEY, §5) --------------------- #
def _identifier_aad(user_id, identifier_type):
    return (b"vanish.identifier.v1\x00" + user_id.encode("utf-8")
            + b"\x00" + identifier_type.encode("ascii"))


def _encrypt_value(session, identifier_type, value):
    ad = _identifier_aad(session.user_id, identifier_type)
    return crypto.seal_record(value.encode("utf-8"), session.master_key, ad)


def _decrypt_value(session, identifier_type, blob):
    ad = _identifier_aad(session.user_id, identifier_type)
    return crypto.open_record(blob, session.master_key, ad).decode("utf-8")


# --- email verification round-trip ---------------------------------------- #
class RecordingSender:
    """Dev/test sender: captures the token instead of emailing it.

    A real sender (SMTP / email API) delivers the token to the claimed address; the
    user's ability to read it there is the proof of ownership. Delivery is abstracted
    behind this interface; real delivery is a later deliverable.
    """

    def __init__(self):
        self.sent = []

    def send(self, email, token):
        self.sent.append((email, token))

    @property
    def last_token(self):
        return self.sent[-1][1]


def _hash_token(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def request_email_verification(session, email, sender):
    """Stage an email for verification and 'send' a confirmation token.

    The identifier is NOT scannable yet — it sits in pending until the token round-trip
    completes. Returns the pending id. The raw token is never stored (only its hash).
    """
    norm = normalize_email(email)
    token = sodium.randombytes(32).hex()
    blob = _encrypt_value(session, "email", norm)
    pending_id = store.insert_pending(
        session.user_id, "email", blob, _hash_token(token))
    sender.send(norm, token)
    return pending_id


def confirm_verification(session, token):
    """Complete the round-trip: promote the pending identifier to verified.

    Returns the new identifier id, or None if the token matches no pending record.
    This is the ONLY path that marks an identifier verified — and it requires the
    exact token. No token, no verification.
    """
    row = store.get_pending_by_token(session.user_id, _hash_token(token))
    if row is None:
        return None
    identifier_id = store.insert_identifier(
        session.user_id, row["identifier_type"],
        row["identifier_value_encrypted"], store.now())
    store.delete_pending(row["id"])
    return identifier_id


# --- the chokepoint ------------------------------------------------------- #
def assert_scannable(session, identifier_type, identifier_value):
    """True ONLY if this exact identifier is in the user's verified set.

    Every scan must call this before touching an identifier. It is the structural
    guarantee that the scan engine can never be pointed at a stranger's identifier.
    """
    if identifier_type not in SUPPORTED_TYPES:
        return False
    target = normalize_identifier(identifier_type, identifier_value)
    for ident_type, value in scannable_identifiers(session):
        if ident_type == identifier_type and value == target:
            return True
    return False


def scannable_identifiers(session):
    """The verified set, decrypted in-memory: the ONLY source of scan targets.

    The scan engine (a later phase) iterates this and nothing else; it accepts no
    externally-supplied identifier.
    """
    out = []
    for row in store.list_identifiers(session.user_id):
        value = _decrypt_value(
            session, row["identifier_type"], row["identifier_value_encrypted"])
        out.append((row["identifier_type"], value))
    return out
