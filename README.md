# vanish

```
                    _      __
 _   ______ _____  (_)____/ /_
| | / / __ `/ __ \/ / ___/ __ \
| |/ / /_/ / / / / (__  ) / / /
|___/\__,_/_/ /_/_/____/_/ /_/
```

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

Lists ~15 known brokers (Spokeo, Whitepages, BeenVerified, Radaris, MyLife, PeopleFinders, Intelius, TruePeopleSearch, FastPeopleSearch, Instant Checkmate, TruthFinder, Acxiom, LexisNexis, Oracle BlueKai, Epsilon) with opt-out URL, method, what each needs from you, and notes.

### `audit` — check your own identifiers

Probe-only: it checks a breach database and public profile URLs, resolves nothing, and **never stores the email or handle** (only outcome counts are logged).

```bash
# Breach check (needs a HIBP API key; degrades gracefully if unset)
export HIBP_API_KEY=...        # from https://haveibeenpwned.com/API/Key
vanish audit --email me@example.com

# Public-profile probe (per-platform: found / absent / CHECK-manually)
vanish audit --username myhandle
vanish audit --username myhandle --platforms github reddit x
```

Breach results flag **high-risk exposures** — leaked passwords, Social Security numbers, and financial data are pulled onto their own `SENSITIVE` line per breach and summarized with next steps (rotate passwords + 2FA, credit freeze, alert your bank), so they don't get lost among benign data classes.

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

## Data & privacy

- Local store: `~/.vanish/vanish.db` (SQLite, `0600`, in a `0700` dir) — just `requests` and `audit_log` tables.
- `requests` holds only `broker / template / status / created / updated`. **No name, email, address, or any identifier is stored anywhere** — inspect the schema and you'll find no such columns.
- Identifiers exist only in memory during letter generation.
- Set `NO_COLOR=1` to disable colored output.
- No telemetry. No uploads. No people-search. No lookups. No record of any person.

## License

MIT.
