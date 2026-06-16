"""vanish authenticated-user app (local-first).

This subpackage is the multi-user evolution of the vanish CLI: per-user accounts,
a zero-knowledge auth envelope, and verified-identifier ownership — all stored on
the user's own device (local-first, per BLUEPRINT.md §6). Nothing here uploads.

SECURITY STATUS — read before relying on this:
  * The cryptographic design is specified in CRYPTO-SPEC.md. It is implemented here
    faithfully, but the external cryptographer review (ROADMAP Phase 0, item 0.1) has
    NOT yet completed. Do not treat this as security-certified.
  * The Argon2id cost parameters are the provisional MODERATE values from
    KDF-PARAMS.md, marked there as NOT-yet-reviewed and pending a low-end-device
    benchmark. See `crypto.DEFAULT_KDF_PARAMS`.
  * Auth is the MVP AuthModule from CRYPTO-SPEC §6 (a password-derived AUTH_KEY); the
    OPAQUE upgrade drops in behind the same seam later.

The core invariant this package exists to enforce (in code, not convention): a scan
may only ever target an identifier the current user has *verified ownership of*. See
`identity.assert_scannable` — the single chokepoint every future scan must pass.
"""

__all__ = ["crypto", "store", "auth", "identity"]
