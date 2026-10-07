# SentryFeed

A self-hosted threat-intel dashboard running on a Raspberry Pi 3B. Every 30 minutes it pulls security and tech news, looks up the CVEs each story mentions, checks whether CISA has confirmed they're being exploited, and colours every story by how much it matters.

| Colour | Meaning |
|---|---|
| Red | Confirmed exploitation, a zero-day, or CVSS 9.0+ |
| Orange | CVSS 7.0 to 8.9, or a serious incident (breach, ransomware, takeover) |
| Yellow | Everything else that happened |
| Green | Tech and AI news, not an incident |

## How it works

```
RSS feeds ──> collect.py ──> SQLite ──> Flask dashboard ──> browser
               │
               ├─ fetch.py    download and normalise 9 feeds
               ├─ enrich.py   pull CVE IDs, look up CVSS and CISA KEV status in NVD
               └─ score.py    assign a colour and record why
```

- **Sources:** The Hacker News, BleepingComputer, Dark Reading, Krebs on Security, Schneier on Security, Microsoft MSRC, TechCrunch, The Verge (AI), MIT Technology Review. The list lives in `feeds.py`.
- **Storage:** one SQLite file. Links are unique, so re-running the collector never creates duplicates. Only the last 14 days are kept per run, and each source is capped at 100 items (MSRC publishes its whole history in one feed).
- **CVE lookups:** each CVE is looked up in the NVD API once and cached. Unscored CVEs are rechecked after 24 hours, since NVD often scores new CVEs a few days after publication.

## Password check

`/password` tells you whether a password has appeared in a data breach, using [Have I Been Pwned's Pwned Passwords](https://haveibeenpwned.com/Passwords), without the password leaving the browser:

1. The browser hashes the password with SHA-1.
2. Only the first 5 of the hash's 40 characters go to SentryFeed, which relays them to Pwned Passwords and gets back every leaked hash starting with them (a few hundred, padded with fake entries so the response size gives nothing away).
3. The browser looks for its own full hash in that list.

SentryFeed relays the request instead of the browser calling Pwned Passwords directly, so visitors' IP addresses never reach HIBP and the page's security policy can forbid connections to any other site. Browsers only provide built-in hashing on HTTPS pages, so `templates/_sha1.js` is a small fallback for the Pi's plain-HTTP setup, tested against Node's SHA-1 on 5,000+ inputs.

## Scoring rules

Signals are trusted in this order:

1. **CISA KEV.** If NVD says CISA has added the CVE to its Known Exploited Vulnerabilities catalog, the story is red. This is the strongest signal available.
2. **CVSS.** 9.0+ red, 7.0 to 8.9 orange, below 7 yellow. Exploitation language ("exploited in the wild", "zero-day") still lifts a scored item to red, because a medium bug under active attack matters more than its score.
3. **Keywords.** Used only when there's no score. The lists are at the top of `score.py`.

Every item stores the reason for its colour (`CVSS 9.8`, `CISA: actively exploited`, `mentions 'zero-day'`), and the dashboard shows it. Everything is rescored on every run, so a score that arrives later or a keyword change applies to old items too.

## Design decisions

- **CISA's RSS feeds were discontinued.** Instead of a separate CISA source, KEV status comes from the `cisaExploitAdd` field in NVD's CVE records, the same API call that returns the score.
- **Feed content is treated as untrusted input.** Jinja escapes everything in the list, the detail panel only writes text with `textContent`, and any link that isn't `http` or `https` is dropped, so a compromised feed can't inject script or a `javascript:` link. Tested with a planted `<script>` headline.
- **The Pi 3B has 1 GB of RAM**, so there is no framework beyond Flask, no JavaScript build step, and the collector runs as a one-shot job instead of a resident process.
- **A strict Content Security Policy.** Every page gets a fresh random nonce, and only scripts and styles carrying it may run. Pages may only connect back to this server, so the password page physically can't send anything elsewhere.
- **systemd over cron.** It keeps the dashboard alive, restarts it on failure, starts it on boot, and logs every collector run to the journal. Both units are sandboxed (`ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges`) so they can only write inside the project folder.

## Setup

On Raspberry Pi OS Lite (64-bit), as a user named `kaido` (change the paths in `deploy/` if yours differs):

```bash
git clone https://github.com/<you>/sentryfeed.git ~/sentryfeed
cd ~/sentryfeed
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Optional but recommended: a free NVD API key raises the rate limit 10x
echo 'YOUR-KEY' > .nvd_api_key && chmod 600 .nvd_api_key

python collect.py          # first run
python app.py              # dashboard on port 5000, Ctrl+C to stop
```

To run it permanently:

```bash
sudo cp deploy/sentryfeed-* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentryfeed-web.service sentryfeed-collect.timer
```

## Known limitations

- Keyword matching can't read context: "not a zero-day" still matches "zero-day".
- The same story from two outlets appears twice, since deduplication is by URL.
- Non-incident posts in the security feeds (events, opinion pieces) land in yellow.

## Planned

- A file and link checker. The file's fingerprint is calculated in the browser and checked against VirusTotal; the file itself is never uploaded.
- A world map that places incidents geographically.
- Share-price impact for public companies named in a breach.
- Deduplicating the same story across outlets by title similarity.
- Later: email breach checks and opt-in alerts via HIBP, with a confirmation link before any email is stored.
