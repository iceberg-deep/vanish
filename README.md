# vanish

```
                    _      __
 _   ______ _____  (_)____/ /_
| | / / __ `/ __ \/ / ___/ __ \
| |/ / /_/ / / / / (__  ) / / /
|___/\__,_/_/ /_/_/____/_/ /_/
```

[![CI](https://github.com/iceberg-deep/vanish/actions/workflows/ci.yml/badge.svg)](https://github.com/iceberg-deep/vanish/actions/workflows/ci.yml)

**A single-operator CLI to audit and scrub your *own* digital footprint — locally, on your terms.**

vanish helps you:

1. **Audit** the identifiers you own (your email against breach databases, your usernames across public profiles).
2. **Generate** CCPA / GDPR / generic removal-request letters to data brokers — for yourself, or (statelessly) as an authorized agent for someone who asked.
3. **Track** your own opt-outs and find the official links to delete or deactivate accounts.

## Scope — vanish removes, it never discovers

The organizing principle: everything in vanish serves getting data *out*. Anything that finds, maps, or builds a standing record of people is out of scope — even when it sounds helpful. These limits are enforced in the code, not just promised:

- **No lookup capability, ever.** It does **not** resolve a name into relatives, addresses, or phone numbers, and performs **no** people-search or aggregation. It only *removes*, never *finds*. (Same data, opposite direction — that direction is what a stalker needs, so it does not exist here.)
- **No record of any person.** vanish keeps no profile, dossier, or roster of anyone. The tracker records only the *fact* that a request was filed — broker, template, status, dates — never who it was for.
- **Ephemeral identifiers.** The name/email/phone/address a letter needs are passed as CLI args **at generation time, rendered, and never written to disk.**
- **Stateless help for others.** You can generate an authorized-agent letter for someone who asked (`--as-agent`), at the moment they ask — vanish retains nothing about them. Managing many real subjects with verifiable consent is a different project with retention and privacy-law obligations, not a feature bolted on here.

All data is kept in a local SQLite database at `~/.vanish/vanish.db` (file mode `0600`, in a `0700` directory). **Nothing is ever uploaded.** The only network calls are: (a) the Have I Been Pwned breach API for an email you provide, and (b) plain `GET`s to public profile URLs to see whether a handle exists.

## Install

```bash
pip install -e .
# If your environment is externally managed and pip refuses:
pip install -e . --break-system-packages
```

Requires Python 3.8+ and `requests`.

## Usage

```bash
vanish --version
vanish                       # banner + help
```

### `brokers` — the registry

```bash
vanish brokers
vanish brokers --category people-search
vanish brokers --category data-aggregator
vanish brokers --category ad-tech
```

Lists ~20 known brokers — people-search sites plus high-impact aggregators that feed them (Acxiom, LexisNexis, Epsilon, Oracle, CoreLogic/Cotality, LiveRamp, Equifax, Experian, Data Axle) — with opt-out URL, method, what each needs, notes, and **provenance**: a `source`, a `verified` flag, and a `last_verified` date. Each entry shows a status badge: `VERIFIED` (link checked, with date), `CHECK` (anti-bot wall — the page likely exists but blocks automated checks), `DEAD` (link is gone), or `UNVERIFIED` (not checked yet).

Nothing in the registry asserts a URL works from memory — every link is either checked by `vanish verify` or clearly flagged. Aggregator entries are seeded from public sources (incl. California's CPPA DELETE Act registered-data-broker list) and marked with their `source`.

### `verify` — live-check the registry's own links

```bash
vanish verify                       # GET every opt-out URL, record status + date
vanish verify --broker spokeo       # just one
vanish verify --category data-aggregator
vanish verify --write               # bake results into the registry (maintainer use)
```

A plain GET to each `opt_out_url`. It **resolves nothing about people** — it only asks whether your registry's own links are alive today — and records the result to a local overlay (shown in `vanish brokers`). It honestly separates `blocked` (HTTP 401/403/429 anti-bot walls — *not* counted as dead) from genuinely `dead` (404/5xx) links, so a working-but-bot-protected opt-out page is never mistaken for a broken one. Only genuinely-dead links fail the run.

### `audit` — check your own identifiers

Probe-only: it checks a breach database and public profile URLs, resolves nothing, and **never stores the email or handle** (only outcome counts are logged).

```bash
# Breach check — see "Getting a HIBP API key" below. The key is read from the
# HIBP_API_KEY *environment variable* only (never a flag, never a file the tool
# reads), degrades gracefully if unset, transmits your full email to
# HaveIBeenPwned (no k-anonymity for the email lookup — the tool says so before
# it sends), and is never logged or printed.
export HIBP_API_KEY=your-key  # this session only — not in .bashrc
vanish audit --email me@example.com
unset HIBP_API_KEY            # clear it when done

# Public-profile probe (per-platform: found / absent / CHECK-manually)
vanish audit --username myhandle
vanish audit --username myhandle --platforms github reddit x
```

Breach results flag **high-risk exposures** — leaked passwords, Social Security numbers, and financial data are pulled onto their own `SENSITIVE` line per breach and summarized with next steps (rotate passwords + 2FA, credit freeze, alert your bank), so they don't get lost among benign data classes.

#### Getting a HIBP API key

The breach-by-email lookup uses the official [Have I Been Pwned API](https://haveibeenpwned.com/API/Key), which requires a low-cost API key (HIBP charges a small fee to fund the service; there is no free tier for the email endpoint). To get and use one:

1. Go to **https://haveibeenpwned.com/API/Key**, verify your email, and subscribe.
2. Use the key for a **single session only** — keep it out of `~/.bashrc` and other startup files so it isn't persisted:

   ```bash
   export HIBP_API_KEY=your-key      # this terminal only
   vanish audit --email you@example.com
   unset HIBP_API_KEY                # clear it when done
   ```

3. **Most private** (the key is never shown on screen or saved in shell history):

   ```bash
   read -rs HIBP_API_KEY && export HIBP_API_KEY   # type the key at the silent prompt
   vanish audit --email you@example.com
   unset HIBP_API_KEY
   ```

The username probe and everything else in vanish need **no key** and make no such transmission — only the email breach check does.

The key comes from the environment, or from an untracked local `.env` you source yourself (see [`.env.example`](.env.example)) — **never a CLI flag, and never committed**. `.env` is gitignored, GitHub push protection is enabled, and a [gitleaks pre-commit hook](.pre-commit-config.yaml) guards against accidental commits locally.

Platforms probed: github, instagram, x, tiktok, reddit, pinterest, twitch, medium, youtube, facebook. (Instagram/X/Reddit/Twitch/Medium serve a 200 shell for missing handles, so those are honestly flagged `CHECK` rather than guessed.)

### `request` — generate a removal letter

```bash
vanish request --broker spokeo \
  --name "Jane Doe" --email jane@example.com \
  --phone "+1 555 0100" --address "123 Main St, Springfield" \
  --template ccpa --track

# Filing for someone who asked you to — stateless, nothing about them is stored:
vanish request --broker spokeo --name "A Friend" --email friend@example.com \
  --template ccpa --as-agent
```

- The `--name/--email/--phone/--address` identifiers render the letter **only** and are **never written to disk**.
- `--as-agent` adds authorized-agent language ("I am the designated authorized agent for the consumer named below, acting with their permission, and can provide proof of authorization on request") for filing on behalf of someone who asked — vanish keeps no record of them.
- Templates: `ccpa`, `gdpr`, `generic`. Add `--track` to log the *fact of filing* (broker, template, status, dates — no identifiers).

### `cleanse` — guided removal (max automation): find → cleanse → validate

The flagship workflow. It walks each broker through three phases and automates
everything a machine legitimately can, then hands you the steps it can't.

```bash
# Walk every people-search broker, tracking what you submit:
vanish cleanse --name "Jane Doe" --email jane@example.com \
  --category people-search --template ccpa --track

# Target specific brokers, or file as an authorized agent for someone who asked:
vanish cleanse --name "A Friend" --email friend@example.com \
  --brokers spokeo,mylife --as-agent --track

# Later: confirm the removals actually took effect
vanish cleanse --validate
```

Per broker:

- **① find** — auto-opens the broker so you can locate your listing (people-search sites need your record URL).
- **② cleanse** — renders the letter and **automates delivery**: opens the opt-out page, copies the letter to your clipboard (`wl-copy`/`xclip`/`pbcopy`/`clip.exe`), and for email brokers opens a **pre-filled `mailto:`** draft. Then it prints the steps only you can do.
- **③ validate** — `--validate` re-opens each tracked broker so you can confirm you're gone, marking each `confirmed` or `relisted`.

**What it can't do autonomously, and why:** CAPTCHAs, email-confirmation links, and phone verification are deliberate broker defenses against automation — those stay yours. vanish removes all the friction around them (right page, right letter, one paste) but never auto-submits a form. On a headless box or without a clipboard tool it degrades cleanly to printing the URLs and letter. Identifiers render the letters only and are **never stored**; `--track` logs just broker/template/status/dates.

### `track` / `status` — follow up

```bash
vanish track                   # all tracked requests (broker / template / status / dates)
vanish status 1 sent           # update request #1
```

`track` shows what *you* filed, not who for — there are no identifiers in it. Statuses: `pending`, `sent`, `confirmed`, `relisted`, `failed`.

### `guide` — a plain-English, grandma-proof removal report

Generates a printable, no-jargon checklist that **anyone** can follow in a browser — no command line needed. It's built from the live broker + account data, so it stays in sync. Each broker gets numbered click-by-click steps (web-form sites get search/copy/paste instructions; email sites get a ready-to-paste letter), plus a checkbox to track progress.

```bash
vanish guide                                   # saves ~/vanish-removal-guide.md
vanish guide --name "Jane Doe" --email jane@example.com   # personalized
vanish guide --stdout                          # print to screen instead
vanish guide --output ~/Desktop/cleanup.md     # choose where to save
```

The report covers four parts: ① people-search & aggregator removals, ② deleting old social accounts, ③ checking breaches + password safety (in plain words), and ④ re-checking every few months. The saved file contains the name/email you pass (it's *your* copy to follow), so keep it private; it is **not** written to vanish's database.

### `accounts` — delete/deactivate your own accounts

```bash
vanish accounts
```

Official links and steps for Instagram, Facebook, X, TikTok, LinkedIn, Reddit, Snapchat, your Google account, and Google's "Results about you" tool.

## How it works

vanish is a small, dependency-light Python CLI (`requests` is the only runtime dependency). It runs entirely on your machine and is built around one rule — **it removes, it never discovers** — so every part either acts on data you supply about yourself or points you at an official removal flow. Nothing crawls, resolves, or aggregates information about people.

### The flow

The headline workflow (`cleanse`) is a three-phase loop you drive, with the machine doing everything it legitimately can:

```
 ┌─ ① FIND ──────────┐   ┌─ ② CLEANSE ─────────────┐   ┌─ ③ VALIDATE ────────┐
 │ open each broker, │   │ render the opt-out      │   │ re-open the broker, │
 │ locate your       │ → │ letter, auto-open page, │ → │ confirm you're gone,│
 │ listing           │   │ clipboard / mailto      │   │ mark confirmed /    │
 │                   │   │ draft, show the steps   │   │ relisted            │
 └───────────────────┘   └─────────────────────────┘   └─────────────────────┘
```

What it automates: opening the right page, copying the finished letter to your clipboard, drafting a pre-filled email. What it **won't** automate: submitting forms, solving CAPTCHAs, clicking email-confirmation links, phone verification — those are deliberate broker defenses against bots, so they stay with you. On a headless box (no browser/clipboard) it degrades cleanly to printing the URLs and letter.

### The pieces

| Module | Responsibility |
|---|---|
| `brokers.py` + `data/brokers.json` | Static registry: each broker's opt-out URL, method, what it needs, and (for email brokers) a contact address. Pure reference data. |
| `audit.py` | Two probes: a HaveIBeenPwned breach lookup (your email) and a public-profile check (your username). The profile check classifies each platform as `found` / `absent` / `manual` based on how that site actually behaves (see below). |
| `requests_gen.py` | Renders CCPA / GDPR / generic removal letters from identifiers passed at call time. Adds authorized-agent language on request. Returns text; persists nothing. |
| `automation.py` | Best-effort local actions: open a URL, copy to clipboard (`wl-copy`/`xclip`/`pbcopy`/`clip.exe`), build a `mailto:`. Every action degrades gracefully if unavailable. |
| `cli.py` | Argument parsing and the command flows (`brokers`, `audit`, `request`, `cleanse`, `track`, `status`, `guide`, `accounts`). |
| `db.py` | A local SQLite tracker that records only the *fact* of a filing — broker, template, status, dates. It has no columns for names, emails, or any identifier. |
| `guide.py` | Generates the plain-English `guide` report from the live broker/account data. |
| `accounts.py` | Static deletion/deactivation links and steps for major platforms. |

### Why the username probe is honest

Naively, "HTTP 200 = profile exists" — but Instagram, X, Reddit, Twitch and others return a `200` JavaScript shell even for handles that don't exist, so a 200 is meaningless there. Each platform is therefore classified by how it *actually* signals absence:

- **status** (e.g. GitHub, YouTube) — a clean `404` for missing profiles, so the HTTP code is trustworthy.
- **content** (e.g. TikTok, Pinterest, Facebook) — always `200`, but a known marker in the body reveals absence.
- **manual** (e.g. Instagram, X, Reddit) — a `200` shell with no reliable signal, so vanish refuses to guess and flags it `CHECK` with the URL for you to eyeball.

The result is no false "found" hits — which, for a footprint tool, is the difference between useful and misleading.

### What crosses the network

Only two things ever leave your machine, and only when you ask: (a) your email address to **HaveIBeenPwned** during a breach check (requires a key; the tool discloses this before sending), and (b) plain `GET`s to public profile URLs during a username probe. Letter generation, the tracker, the guide, and everything else are entirely offline.

## Data & privacy

- Local store: `~/.vanish/vanish.db` (SQLite, `0600`, in a `0700` dir) — `requests`, `audit_log`, and `verifications` (your local link-check results; broker id + HTTP status only, no PII).
- `requests` holds only `broker / template / status / created / updated`. **No name, email, address, or any identifier is stored anywhere** — inspect the schema and you'll find no such columns.
- Identifiers exist only in memory during letter generation.
- Set `NO_COLOR=1` to disable colored output.
- No telemetry. No uploads. No people-search. No lookups. No record of any person.

## Development & tests

```bash
pip install -e ".[dev]"
pytest
```

The suite (`tests/`) covers the breach-severity classifier, the honest username
probe, letter generation + authorized-agent language, the broker registry, the
guide report, the automation helpers, and full CLI flows. Two invariants are
asserted directly: the `requests` table has **no identifier columns**, and
identifiers **never reach the database file** even after a tracked request +
cleanse run. Every test is isolated — the store is redirected to a tmp dir and
network access is blocked — so it never touches `~/.vanish` or the internet.

## License

MIT.
