#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# vanish — me.sh : scan -> export dashboard -> serve it locally
# ---------------------------------------------------------------------------
# SINGLE_OPERATOR · LOCAL ONLY · NOT FOR DISTRIBUTION
#   • Personal use, on this device, against YOUR OWN verified footprint.
#   • Crypto is pre-external-review (DEFAULT_KDF_PARAMS reviewed=False).
#   • The dashboard is served on the LOOPBACK interface (127.0.0.1) only —
#     never 0.0.0.0, never a routable address. Nothing is uploaded.
#   • This adds NO new capability; it just chains the existing
#     `vanish-account` commands so you don't retype them.
# ---------------------------------------------------------------------------
set -euo pipefail

PORT="${1:-8000}"
OUT_DIR="${VANISH_DASHBOARD_DIR:-$HOME/vanish-dashboard}"

echo "vanish · single-operator · local only (127.0.0.1)"

# 1. scan your verified identifiers
vanish-account scan

# 2. write the dashboard + your dossier-free findings export
vanish-account export-dashboard --out "$OUT_DIR"

# 3. serve the folder on loopback ONLY (browsers block file:// fetch)
URL="http://127.0.0.1:${PORT}/vanish-dashboard.html"
echo
echo "Serving your dashboard at:  ${URL}"
echo "(loopback only — Ctrl-C to stop)"
cd "$OUT_DIR"
exec python3 -m http.server "$PORT" --bind 127.0.0.1
