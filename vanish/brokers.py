"""Load and query the bundled data-broker registry (data/brokers.json)."""

import json
import os

try:
    # Python 3.9+: read package data without unpacking the install.
    from importlib.resources import files as _res_files
except ImportError:  # pragma: no cover - Python 3.8 fallback
    _res_files = None

_DATA_FILENAME = "brokers.json"


def registry_path():
    """Filesystem path to the bundled brokers.json (for read/write)."""
    if _res_files is not None:
        try:
            return str(_res_files("vanish").joinpath("data", _DATA_FILENAME))
        except Exception:
            pass
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "data", _DATA_FILENAME)


def _load_raw():
    with open(registry_path(), encoding="utf-8") as fh:
        return json.load(fh)


def save_brokers(brokers):
    """Write the full broker list back to the registry file (maintainer use).

    Used by `vanish verify --write` to bake live-check results into the shipped
    registry. Raises OSError if the file isn't writable (e.g. a read-only
    site-packages install) — callers handle that gracefully.
    """
    with open(registry_path(), "w", encoding="utf-8") as fh:
        json.dump({"brokers": brokers}, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def load_brokers():
    """Return the list of broker dicts from the registry."""
    return _load_raw().get("brokers", [])


def categories():
    """Return the sorted set of distinct categories."""
    return sorted({b["category"] for b in load_brokers()})


def query(category=None):
    """Return brokers, optionally filtered by category."""
    brokers = load_brokers()
    if category:
        brokers = [b for b in brokers if b["category"] == category]
    return brokers


def get(broker_id):
    """Return a single broker by id, or None."""
    for b in load_brokers():
        if b["id"] == broker_id:
            return b
    return None
