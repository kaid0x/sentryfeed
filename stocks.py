"""Share prices around breaches of US-listed companies, and their SEC breach filings.

When a headline names a US-listed company as the victim of a breach ("AT&T
confirms data breach", "Hackers breach Snowflake customers"), SentryFeed records
the company and, once a day:

- fetches its daily closing prices, plus the S&P 500 (through the SPY fund) for
  comparison, from Alpha Vantage. Needs a free key in .alphavantage_key.
- checks the SEC for an 8-K filing under Item 1.05, which US-listed companies have
  had to file within four business days of deciding a cyber incident is material
  since December 2023. Needs a contact in .sec_contact (see README).

Prices move for many reasons, so the dashboard shows the move around the story
next to the market's, never a claim that the breach caused it.

Run `python stocks.py` to update and print what it found.
"""
import re
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import requests

HERE = Path(__file__).parent
AV_KEY_FILE = HERE / ".alphavantage_key"
SEC_CONTACT_FILE = HERE / ".sec_contact"

COMPANIES_URL = "https://www.sec.gov/files/company_tickers.json"
SUBMISSIONS_URL = "https://data.sec.gov/submissions/CIK{cik:010d}.json"
FILING_URL = "https://www.sec.gov/Archives/edgar/data/{cik}/{accession}/{document}"
AV_URL = "https://www.alphavantage.co/query"

MARKET = "SPY"                 # tracks the S&P 500
LOOKBACK_DAYS = 90             # stories older than this aren't followed
FOLLOW_DAYS = 21               # keep refreshing prices this long after a story
TRADING_DAYS = 10              # shown before and after the story
REFRESH_COMPANIES_DAYS = 7
SAME_STORY = timedelta(hours=72)   # same company within this gap = one incident

# Alpha Vantage's free key allows 25 requests a day. Leave headroom for running
# `python stocks.py` by hand, and space requests out in case of a per-minute limit.
AV_DAILY_BUDGET = 20
AV_PER_RUN = 4
AV_GAP_SECONDS = 13
SEC_PER_RUN = 20
SEC_GAP_SECONDS = 0.2          # the SEC allows up to 10 requests a second

SECURITY_SEVERITIES = ("red", "orange", "yellow")

# Brands and short names headlines use, mapped to the listed company's ticker.
ALIASES = {
    "Google": "GOOGL", "Gmail": "GOOGL", "YouTube": "GOOGL", "Mandiant": "GOOGL", "Alphabet": "GOOGL",
    "Meta": "META", "Facebook": "META", "Instagram": "META", "WhatsApp": "META",
    "Amazon": "AMZN", "AWS": "AMZN", "Amazon Web Services": "AMZN",
    "Microsoft": "MSFT", "GitHub": "MSFT", "LinkedIn": "MSFT", "Xbox": "MSFT",
    "Apple": "AAPL", "iCloud": "AAPL",
    "Cisco": "CSCO", "Splunk": "CSCO", "Palo Alto Networks": "PANW", "CrowdStrike": "CRWD",
    "Fortinet": "FTNT", "Okta": "OKTA", "Cloudflare": "NET", "Zscaler": "ZS", "SentinelOne": "S",
    "Akamai": "AKAM", "F5": "FFIV", "Check Point": "CHKP", "Broadcom": "AVGO", "VMware": "AVGO",
    "Dell": "DELL", "HP": "HPQ", "HPE": "HPE", "Hewlett Packard Enterprise": "HPE", "Juniper": "HPE",
    "Oracle": "ORCL", "Salesforce": "CRM", "Snowflake": "SNOW", "Atlassian": "TEAM",
    "Progress Software": "PRGS", "MOVEit": "PRGS", "Adobe": "ADBE", "Intel": "INTC", "AMD": "AMD",
    "Nvidia": "NVDA", "NVIDIA": "NVDA", "Qualcomm": "QCOM", "IBM": "IBM", "Accenture": "ACN",
    "Workday": "WDAY", "ServiceNow": "NOW", "Zoom": "ZM", "Dropbox": "DBX", "Twilio": "TWLO",
    "Coinbase": "COIN", "Robinhood": "HOOD", "PayPal": "PYPL",
    "AT&T": "T", "Verizon": "VZ", "T-Mobile": "TMUS", "Comcast": "CMCSA", "Xfinity": "CMCSA",
    "UnitedHealth": "UNH", "Change Healthcare": "UNH", "Optum": "UNH", "CVS": "CVS",
    "Elevance": "ELV", "Anthem": "ELV", "Cigna": "CI",
    "Walmart": "WMT", "Target": "TGT", "Home Depot": "HD", "Costco": "COST", "Nike": "NKE",
    "Starbucks": "SBUX", "McDonald's": "MCD", "Ticketmaster": "LYV", "Live Nation": "LYV",
    "MGM Resorts": "MGM", "Caesars": "CZR", "Clorox": "CLX", "Marriott": "MAR", "Hilton": "HLT",
    "Uber": "UBER", "Lyft": "LYFT", "Disney": "DIS", "Netflix": "NFLX", "Electronic Arts": "EA",
    "Roblox": "RBLX", "Krispy Kreme": "DNUT", "Hertz": "HTZ", "Boeing": "BA",
    "Lockheed Martin": "LMT", "Johnson Controls": "JCI", "Halliburton": "HAL",
    "JPMorgan": "JPM", "JPMorgan Chase": "JPM", "Bank of America": "BAC", "Wells Fargo": "WFC",
    "Citigroup": "C", "Citi": "C", "Capital One": "COF", "American Express": "AXP", "Visa": "V",
    "Mastercard": "MA", "Charles Schwab": "SCHW", "Equifax": "EFX", "TransUnion": "TRU",
}

# The name shown for a ticker: the first alias listed for it ("UnitedHealth", not "Optum").
DISPLAY = {}
for _alias, _ticker in ALIASES.items():
    DISPLAY.setdefault(_ticker, _alias)

# Shortened SEC names that are too common as ordinary headline words to trust.
NOT_COMPANIES = {
    "global", "national", "american", "united", "first", "general", "international", "universal",
    "central", "major", "data", "security", "federal", "new", "one", "live", "five", "us", "the",
    "hackers", "breach", "cyber", "digital", "network", "cloud", "online", "hack", "people",
}

# Endings stripped from the SEC's legal names: "CLOROX CO /DE/" -> "Clorox".
_SUFFIX_RE = re.compile(
    r"(?:\s*/[A-Z]{2,3}/?|[,.]?\s+(?:inc|incorporated|corp|corporation|co|company|companies|ltd|limited|"
    r"plc|llc|l\.?p|n\.?v|s\.?a|ag|se|holdings?|group|the|class [a-z])\.?)$",
    re.IGNORECASE,
)

# What makes a named company the victim rather than the vendor of a flawed product.
# "Cisco patches flaw" doesn't count; "Cisco confirms breach" does.
_INCIDENT = (
    r"(?i:data breach(?:es)?|breach(?:es|ed)?|hack(?:s|ed)?|cyber ?attacks?|attacks?|security incident|"
    r"cybersecurity incident|intrusions?|compromise[ds]?|ransomware|leak(?:s|ed)?|stolen|stole|steal|theft|"
    r"accessed|exposed|outage|extortion)"
)
_SAYS = r"(?i:confirms?|discloses?|reports?|says?|admits?|notifies|investigates?|acknowledges?|reveals?)"
_HIT = (
    r"(?i:hit by|hit with|struck by|suffers?|hacked|breached|compromised|data breach|breach|cyber ?attack|"
    r"ransomware attack|security incident|cybersecurity incident|data leak|outage)"
)
_ASSETS = (
    r"(?i:customers?|users?|employees?|patients?|data|systems?|networks?|servers?|accounts?|"
    r"source code|databases?|email)"
)
_ATTACKERS = r"(?:(?i:hackers?|attackers?|ransomware(?: gangs?)?|threat actors?)|[A-Z][\w-]+ (?i:hackers|gang|ransomware))"
_ATTACKER_VERBS = r"(?i:breach(?:ed|es)?|hit|hack(?:ed|s)?|target(?:ed|s)?|attack(?:ed|s)?|compromise[ds]?|steal from|stole from|extort(?:ed|s)?)"


def _victim_patterns(name):
    c = re.escape(name)
    possessive = r"(?:['’]s?)?"
    return [
        rf"\b{c}{possessive}\s+{_SAYS}\s+(?:[^\s]+\s+){{0,6}}?{_INCIDENT}\b",
        rf"\b{c}{possessive}\s+{_HIT}\b",
        rf"\b{c}{possessive}\s+{_ASSETS}\s+(?:[^\s]+\s+){{0,4}}?{_INCIDENT}\b",
        rf"\b(?i:breach|hack|cyber ?attack|attack|ransomware attack|intrusion|outage|incident)\s+(?i:at|on|of|against|hits?)\s+(?i:the\s+)?{c}\b",
        rf"\b{_ATTACKERS}\s+{_ATTACKER_VERBS}\s+(?i:the\s+)?{c}\b",
    ]


def short_name(legal_name):
    """'CLOROX CO /DE/' -> 'Clorox', 'Cisco Systems, Inc.' -> 'Cisco Systems'."""
    name = legal_name.strip()
    while True:
        trimmed = _SUFFIX_RE.sub("", name).strip(" ,.")
        if trimmed == name:
            break
        name = trimmed
    if not re.search(r"[a-z]", name):   # ALL CAPS legal names: title-case the long words
        name = " ".join(w.capitalize() if len(w) > 4 and w.isalpha() else w for w in name.split())
    return name


# ---------- outside lookups ----------

def av_key():
    return AV_KEY_FILE.read_text().strip() if AV_KEY_FILE.exists() else None


def sec_contact():
    return SEC_CONTACT_FILE.read_text().strip() if SEC_CONTACT_FILE.exists() else None


def _today():
    return datetime.now(timezone.utc).date().isoformat()


def _looked_up_today(conn, kind, key):
    row = conn.execute("SELECT day FROM lookups WHERE kind = ? AND key = ?", (kind, str(key))).fetchone()
    return bool(row) and row["day"] == _today()


def _mark_looked_up(conn, kind, key, day=None):
    conn.execute("INSERT OR REPLACE INTO lookups (kind, key, day) VALUES (?, ?, ?)",
                 (kind, str(key), day or _today()))
    conn.commit()


def refresh_companies(conn, contact):
    """The SEC's list of every US-listed company and its ticker, refreshed weekly."""
    row = conn.execute("SELECT day FROM lookups WHERE kind = 'companies'").fetchone()
    if row and date.fromisoformat(row["day"]) > date.today() - timedelta(days=REFRESH_COMPANIES_DAYS):
        return "up to date"
    resp = requests.get(COMPANIES_URL, headers={"User-Agent": contact}, timeout=30)
    resp.raise_for_status()
    rows, seen = [], set()
    for entry in resp.json().values():   # listed largest first; keep each company's first ticker
        cik = int(entry["cik_str"])
        if cik in seen:
            continue
        seen.add(cik)
        rows.append((cik, entry["ticker"].upper(), entry["title"]))
    conn.execute("DELETE FROM companies")
    conn.executemany("INSERT INTO companies (cik, ticker, name) VALUES (?, ?, ?)", rows)
    _mark_looked_up(conn, "companies", "all")
    return f"{len(rows)} companies"


def fetch_prices(conn, ticker, key):
    """Last ~100 trading days of closes. Returns None, or an error message."""
    symbol = ticker.replace("-", ".")   # SEC writes BRK-B, Alpha Vantage BRK.B
    resp = requests.get(AV_URL, params={"function": "TIME_SERIES_DAILY", "symbol": symbol,
                                        "outputsize": "compact", "apikey": key}, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    # Any answer from the API counts as today's lookup, errors included, so a bad
    # ticker isn't retried every 30 minutes. Only network failures are retried.
    _mark_looked_up(conn, "prices", ticker)
    series = data.get("Time Series (Daily)")
    if not series:
        return data.get("Note") or data.get("Information") or data.get("Error Message") or "no data"
    conn.executemany(
        "INSERT OR REPLACE INTO prices (ticker, day, close) VALUES (?, ?, ?)",
        [(ticker, day, float(values["4. close"])) for day, values in series.items()],
    )
    conn.commit()
    return None


def fetch_filings(conn, cik, contact):
    """Record the company's 8-K filings under Item 1.05 (material cybersecurity incident)."""
    resp = requests.get(SUBMISSIONS_URL.format(cik=cik), headers={"User-Agent": contact}, timeout=20)
    resp.raise_for_status()
    recent = resp.json()["filings"]["recent"]
    found = 0
    for i, form in enumerate(recent["form"]):
        if form not in ("8-K", "8-K/A"):
            continue
        items = (recent.get("items") or [""] * len(recent["form"]))[i] or ""
        if "1.05" not in items.split(","):
            continue
        accession = recent["accessionNumber"][i]
        url = FILING_URL.format(cik=cik, accession=accession.replace("-", ""), document=recent["primaryDocument"][i])
        conn.execute(
            "INSERT OR REPLACE INTO sec_filings (accession, cik, form, filed, url) VALUES (?, ?, ?, ?, ?)",
            (accession, cik, form, recent["filingDate"][i], url),
        )
        found += 1
    _mark_looked_up(conn, "sec", cik)
    return found


# ---------- spotting breached companies ----------

def load_names(conn):
    """lowercased name -> (cik, ticker, display name)."""
    by_ticker = {}
    names = {}
    for row in conn.execute("SELECT cik, ticker, name FROM companies"):
        display = short_name(row["name"])
        by_ticker[row["ticker"]] = (row["cik"], row["ticker"], display)
        key = display.lower()
        if len(key) >= 3 and key not in NOT_COMPANIES and key not in names:
            names[key] = (row["cik"], row["ticker"], display)
    for alias, ticker in ALIASES.items():
        if ticker in by_ticker:
            cik = by_ticker[ticker][0]
            # Headlines are split into words with "'s" removed, so "McDonald's" is looked up as "McDonald".
            names[re.sub(r"['’]s$", "", alias).lower()] = (cik, ticker, DISPLAY.get(ticker, alias))
    return names


_WORD_RE = re.compile(r"[A-Za-z0-9][\w&'’.\-]*")


def victims(title, names):
    """US-listed companies a headline names as the victim: [(cik, ticker, name, matched)]."""
    words = []
    for m in _WORD_RE.finditer(title):
        word = m.group(0).rstrip(".,'’")
        word = re.sub(r"['’]s$", "", word)
        words.append(word)
    found, used = {}, set()
    for size in (5, 4, 3, 2, 1):                       # longest names first
        for i in range(len(words) - size + 1):
            if any(j in used for j in range(i, i + size)):
                continue
            phrase = " ".join(words[i:i + size])
            hit = names.get(phrase.lower())
            if not hit or not phrase[0].isupper():
                continue
            if not any(re.search(p, title) for p in _victim_patterns(phrase)):
                continue
            used.update(range(i, i + size))
            cik, ticker, display = hit
            found.setdefault(cik, (cik, ticker, display, phrase))
    return list(found.values())


def find_events(conn):
    """Rebuild stock_events from the last LOOKBACK_DAYS of security stories."""
    names = load_names(conn)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).isoformat()
    rows = conn.execute(
        f"""SELECT id, title FROM items
            WHERE severity IN ({",".join("?" * len(SECURITY_SEVERITIES))})
              AND published >= ?""",
        (*SECURITY_SEVERITIES, cutoff),
    ).fetchall()
    events = [(row["id"], cik, matched) for row in rows for cik, _, _, matched in victims(row["title"], names)]
    conn.execute("DELETE FROM stock_events")
    conn.executemany("INSERT INTO stock_events (item_id, cik, matched) VALUES (?, ?, ?)", events)
    conn.commit()
    return len(events)


def update(conn, log=print):
    """One collector step. Never raises: a failed lookup is retried next run."""
    contact, key = sec_contact(), av_key()
    if not contact:
        log("Stocks: skipped. Add a contact to .sec_contact to turn on (see README).")
        return
    try:
        log(f"Stocks: SEC company list {refresh_companies(conn, contact)}")
    except (requests.RequestException, ValueError, KeyError) as e:
        log(f"Stocks: couldn't fetch the SEC company list ({e.__class__.__name__}); trying next run")
        if not conn.execute("SELECT 1 FROM companies LIMIT 1").fetchone():
            return
    log(f"Stocks: {find_events(conn)} breach mentions of US-listed companies")

    # Newest stories first, so a backlog never starves today's news.
    follow_from = (datetime.now(timezone.utc) - timedelta(days=FOLLOW_DAYS)).isoformat()
    recent = conn.execute(
        """SELECT DISTINCT c.cik, c.ticker,
                  MAX(i.published) AS latest,
                  (SELECT COUNT(*) FROM prices p WHERE p.ticker = c.ticker) AS have
           FROM stock_events e JOIN items i ON i.id = e.item_id JOIN companies c ON c.cik = e.cik
           GROUP BY c.cik ORDER BY latest DESC"""
    ).fetchall()

    sec_done = 0
    for row in recent:
        if sec_done >= SEC_PER_RUN or _looked_up_today(conn, "sec", row["cik"]):
            continue
        try:
            fetch_filings(conn, row["cik"], contact)
        except (requests.RequestException, ValueError, KeyError) as e:
            log(f"Stocks: SEC lookup for {row['ticker']} failed ({e.__class__.__name__})")
        sec_done += 1
        time.sleep(SEC_GAP_SECONDS)

    if not key:
        log("Stocks: no Alpha Vantage key in .alphavantage_key, so no prices")
        return
    wanted = [MARKET] + [r["ticker"] for r in recent if r["latest"] >= follow_from or not r["have"]]
    used_today = conn.execute(
        "SELECT COUNT(*) FROM lookups WHERE kind = 'prices' AND day = ?", (_today(),)
    ).fetchone()[0]
    if _looked_up_today(conn, "prices-limit", "all"):
        log("Stocks: Alpha Vantage's daily limit was reached earlier today; prices resume tomorrow")
        return
    fetched = 0
    for ticker in dict.fromkeys(wanted):
        if fetched >= AV_PER_RUN or used_today >= AV_DAILY_BUDGET:
            break
        if _looked_up_today(conn, "prices", ticker):
            continue
        if fetched:
            time.sleep(AV_GAP_SECONDS)
        try:
            error = fetch_prices(conn, ticker, key)
        except (requests.RequestException, ValueError, KeyError) as e:
            error = e.__class__.__name__
        fetched += 1
        used_today += 1
        if error:
            log(f"Stocks: prices for {ticker} failed: {error[:120]}")
            if "rate limit" in error.lower() or "requests per day" in error.lower():
                _mark_looked_up(conn, "prices-limit", "all")
                break
    log(f"Stocks: prices fetched for {fetched} tickers ({used_today}/{AV_DAILY_BUDGET} today)")


# ---------- what the dashboard shows ----------

def _series(conn, ticker, start, end):
    return {r["day"]: r["close"] for r in conn.execute(
        "SELECT day, close FROM prices WHERE ticker = ? AND day BETWEEN ? AND ? ORDER BY day",
        (ticker, start, end))}


def incidents(conn):
    """One entry per company per incident, newest first, with price data ready to chart."""
    rows = conn.execute(
        """SELECT e.item_id, e.cik, c.ticker, c.name, i.title, i.link, i.source, i.published, i.severity
           FROM stock_events e JOIN items i ON i.id = e.item_id JOIN companies c ON c.cik = e.cik
           ORDER BY i.published"""
    ).fetchall()

    grouped = []
    for row in rows:
        published = datetime.fromisoformat(row["published"])
        for g in grouped:
            if g["cik"] == row["cik"] and published - g["_first"] <= SAME_STORY:
                g["stories"].append(dict(row))
                break
        else:
            grouped.append({"cik": row["cik"], "ticker": row["ticker"],
                            "company": DISPLAY.get(row["ticker"]) or short_name(row["name"]),
                            "_first": published, "stories": [dict(row)]})

    for g in grouped:
        story_day = g.pop("_first").date()
        g["date"] = story_day.isoformat()
        start = (story_day - timedelta(days=TRADING_DAYS * 2 + 6)).isoformat()
        end = (story_day + timedelta(days=TRADING_DAYS * 2 + 6)).isoformat()
        stock, market = _series(conn, g["ticker"], start, end), _series(conn, MARKET, start, end)
        days = sorted(set(stock) & set(market))
        before = [d for d in days if d < g["date"]][-(TRADING_DAYS + 1):]
        after = [d for d in days if d >= g["date"]][:TRADING_DAYS]
        g["points"] = [{"day": d, "close": stock[d], "market": market[d]} for d in before + after]
        g["base_day"] = before[-1] if before else None
        if before and after:
            base, last = before[-1], after[-1]
            g["change"] = stock[last] / stock[base] - 1
            g["market_change"] = market[last] / market[base] - 1
            g["through"] = last
        else:
            g["change"] = g["market_change"] = g["through"] = None
        lo = (story_day - timedelta(days=30)).isoformat()
        hi = (story_day + timedelta(days=60)).isoformat()
        g["filings"] = [dict(r) for r in conn.execute(
            "SELECT form, filed, url FROM sec_filings WHERE cik = ? AND filed BETWEEN ? AND ? ORDER BY filed",
            (g["cik"], lo, hi))]
        g["sec_checked"] = bool(conn.execute(
            "SELECT 1 FROM lookups WHERE kind = 'sec' AND key = ?", (str(g["cik"]),)).fetchone())
    grouped.sort(key=lambda g: g["date"], reverse=True)
    return grouped


def main():
    from db import connect

    conn = connect()
    update(conn)
    found = incidents(conn)
    print(f"\n{len(found)} incidents involving US-listed companies:\n")
    for g in found:
        s = g["stories"][0]
        print(f"{g['date']}  {g['company']} ({g['ticker']})  [{s['source']}] {s['title']}")
        if g["change"] is not None:
            print(f"    {g['change']:+.1%} through {g['through']}, S&P 500 {g['market_change']:+.1%}")
        else:
            print("    no price data around the story yet")
        for f in g["filings"]:
            print(f"    SEC {f['form']} Item 1.05 filed {f['filed']}: {f['url']}")
    conn.close()


if __name__ == "__main__":
    main()
