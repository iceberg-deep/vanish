# Contributing to vanish

Thanks for your interest. vanish is small and deliberately narrow, and the bar
for changes is "does this help someone get their data *out*, without becoming a
tool that finds people?" Please read the scope boundary before opening a PR — it
is the one rule that gets PRs declined regardless of code quality.

## Scope — vanish removes, it never discovers

This is the organizing principle, and it is non-negotiable:

- **In scope:** anything that helps a person remove or suppress *their own*
  data — broker opt-out letters and flows, the audit probes for identifiers you
  supply about yourself, the tracker, the guide, account-deletion pathways.
- **Out of scope, and not accepted:** any feature that *finds, resolves, maps,
  or aggregates* information about people. No name → relatives / address / phone
  resolution, no people-search, no scraping of third parties, no standing
  "profile" or dossier of any subject. Same data, opposite direction — that
  direction is what a stalker needs, so it does not exist here.

If you're unsure which side of the line a feature is on, open an issue first.

## Privacy & data rules

- **No identifiers are persisted.** The tracker stores only the *fact* of a
  filing (broker, template, status, dates). Don't add columns or storage for
  names, emails, addresses, DOB, relatives, or any disambiguating PII.
- **Identifiers are ephemeral** — passed at letter-generation time, rendered,
  never written to disk.
- **Everything stays local.** The only network calls are the HIBP breach lookup
  (for an email you supply) and plain GETs to public profile URLs. No telemetry,
  no uploads.

## Secret-handling rule

- The HIBP key is read from the **`HIBP_API_KEY` environment variable only** —
  never a CLI flag (leaks into shell history), never a file the tool reads.
- **Never commit a key, token, or credential**, real or example. Use obvious
  fakes in tests (e.g. `test-key-123`) and `example.com` addresses in fixtures.
- Two guards enforce this: **GitHub push protection** (server-side, blocks
  recognized secrets at push) and a **gitleaks pre-commit hook** (local). Please
  enable the local hook:

  ```bash
  pip install pre-commit
  pre-commit install
  ```

  Copy `.env.example` to `.env` (gitignored) if you want to keep a local key;
  vanish does not read it — load it into your shell yourself.

## Development

```bash
pip install -e ".[dev]"
pytest            # 64+ tests; hermetic — no network, no ~/.vanish, no key needed
python -m pyflakes vanish tests
```

New behavior needs tests. Two invariants are asserted directly and must keep
passing: the `requests` table has **no identifier columns**, and identifiers
**never reach the DB file**.

## Pull request flow

`main` is protected: every change goes through a PR, and the **`ci-success`**
status check (the full test + lint matrix across Python 3.9–3.12) must pass
before merge. There are no direct pushes to `main`, including for maintainers.

1. Fork / branch off `main`.
2. Make your change with tests; run `pytest` and `pre-commit run --all-files`.
3. Open a PR. Keep the noreply or a non-personal commit identity if you care
   about email privacy.
4. Once CI is green, it merges through the gate (no admin override).

By contributing you agree your work is licensed under the project's
[MIT License](LICENSE).
