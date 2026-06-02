"""Load and query the bundled data-broker registry (data/brokers.json)."""

import json
import os

try:
    # Python 3.9+: read package data without unpacking the install.
    from importlib.resources import files as _res_files
except ImportError:  # pragma: no cover - Python 3.8 fallback
    _res_files = None

_DATA_FILENAME = "brokers.json"


def _load_raw():
    if _res_files is not None:
        path = _res_files("vanish").joinpath("data", _DATA_FILENAME)
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    # Fallback: locate alongside this module.
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "data", _DATA_FILENAME), encoding="utf-8") as fh:
        return json.load(fh)


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
