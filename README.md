# SentryFeed

A self-hosted threat-intel dashboard running on a Raspberry Pi 3B. Every 30 minutes it pulls security and tech news, looks up the CVEs each story mentions, checks whether CISA has confirmed they're being exploited, and colours every story by how much it matters.

![SentryFeed dashboard: severity tiles, the story list and a story's detail panel](docs/dashboard.png)

| Colour | Meaning |
|---|---|
| Red | Confirmed exploitation, a zero-day, or CVSS 9.0+ |
| Orange | CVSS 7.0 to 8.9, or a serious incident (breach, ransomware, takeover) |
| Yellow | Everything else that happened |
| Green | Tech and AI news, not an incident |
| Blue | Events: webinars, virtual events, guides and similar posts. Kept because they can be worth reading, but never counted as incidents |

The same story from several outlets is shown once, with the other outlets listed under it.

## How it works

```
RSS feeds ──> collect.py ──> SQLite ──> Flask dashboard ──> browser
               │
               ├─ fetch.py    download and normalise 9 feeds
               ├─ enrich.py   pull CVE IDs, look up CVSS and CISA KEV status in NVD
               └─ score.py    assign a colour and record why

app.py ──> dedupe.py   group the same story from different outlets
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

## File & link check

`/scan` builds links to [VirusTotal](https://www.virustotal.com) reports:

- **Files** are fingerprinted (SHA-256) in the browser and never uploaded. Hashing streams the file in 4 MB chunks through `templates/_sha256.js`, so any size works without loading it all into memory; it's tested against Node's SHA-256 on 3,000+ inputs with random chunk splits.
- **Links, domains, IPs and hashes** are recognised and sent to the matching report page. Anything that isn't `http` or `https` (such as `javascript:` or `file:`) is rejected.

SentryFeed never calls the VirusTotal API itself: the free API is limited to 4 lookups a minute and can't be used in commercial products, while linking to VirusTotal's own pages has neither limit. The page warns that VirusTotal adds anything looked up through its website to its dataset, and that uploaded files are shared with its community.

## Scoring rules

Signals are trusted in this order:

1. **CISA KEV.** If NVD says CISA has added the CVE to its Known Exploited Vulnerabilities catalog, the story is red. This is the strongest signal available.
2. **CVSS.** 9.0+ red, 7.0 to 8.9 orange, below 7 yellow. Exploitation language ("exploited in the wild", "zero-day") still lifts a scored item to red, because a medium bug under active attack matters more than its score.
3. **Keywords.** Used only when there's no score. The lists are at the top of `score.py`.

**Events** are spotted by their titles (`[Virtual Event] ...`, `Webinar: ...`, Schneier's Friday squid post) and turn blue before any other rule runs, so a webinar called "Defending against zero-days" isn't counted as a zero-day.

**Negation.** A keyword doesn't count when it's being denied: "not a zero-day", "hasn't been exploited in the wild" and "no evidence it has been exploited in the wild" don't turn red. Only short filler words may sit between the negation and the keyword, so "Microsoft has not patched a zero-day" still does.

Every item stores the reason for its colour (`CVSS 9.8`, `CISA: actively exploited`, `mentions 'zero-day'`), and the dashboard shows it. Everything is rescored on every run, so a score that arrives later or a keyword change applies to old items too.

## Merging duplicate stories

`dedupe.py` groups articles from different outlets that cover the same story. Two articles match when they come from different sources, were published within 72 hours of each other, and either mention the same CVE or have similar titles.

Title similarity weights each word by how rare it is across everything in the window, so sharing "Kiteworks" counts for far more than sharing "flaw" or "attack". The threshold (0.35) was set on ~65 real headlines: the true pairs scored 0.37 to 0.72 and the closest unrelated pair 0.32. Each article is only compared with the first article of each group, so one loose match can't chain unrelated stories together, and an event post is never merged with news about the same topic.

The highest-ranked article leads, so the story takes its colour; the tiles count stories, not articles; and the CVEs of every article in the group are shown. Run `python dedupe.py` to print the groups it would make from your database.

## Design decisions

- **CISA's RSS feeds were discontinued.** Instead of a separate CISA source, KEV status comes from the `cisaExploitAdd` field in NVD's CVE records, the same API call that returns the score.
- **Feed content is treated as untrusted input.** Jinja escapes everything in the list, the detail panel only writes text with `textContent`, and any link that isn't `http` or `https` is dropped, so a compromised feed can't inject script or a `javascript:` link. Tested with a planted `<script>` headline.
- **The Pi 3B has 1 GB of RAM**, so there is no framework beyond Flask, no JavaScript build step, and the collector runs as a one-shot job instead of a resident process.
- **A strict Content Security Policy.** Every page gets a fresh random nonce, and only scripts and styles carrying it may run. Pages may only connect back to this server, so the password page physically can't send anything elsewhere.
- **systemd over cron.** It keeps the dashboard alive, restarts it on failure, starts it on boot, and logs every collector run to the journal. Both units are sandboxed (`ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges`) so they can only write inside the project folder.

## Setup

On Raspberry Pi OS Lite (64-bit), as a user named `kaido` (change the paths in `deploy/` if yours differs):

```bash
git clone https://github.com/kaid0x/sentryfeed.git ~/sentryfeed
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

- Keyword matching only understands simple negation; sarcasm or "could become a zero-day" still matches.
- Story merging compares titles only, so two very differently worded headlines about the same story stay separate.
- Events are spotted by title patterns; one worded like a normal headline lands in yellow, and opinion pieces still do.

## Planned

- A world map that places incidents geographically.
- Share-price impact for public companies named in a breach.
- Later: email breach checks and opt-in alerts via HIBP, with a confirmation link before any email is stored.
