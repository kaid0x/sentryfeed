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
import zlib
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import requests

HERE = Path(__file__).parent
AV_KEY_FILE = HERE / ".alphavantage_key"
SEC_CONTACT_FILE = HERE / ".sec_contact"

COMPANIES_URL = "https://www.sec.gov/files/company_tickers_exchange.json"   # includes each exchange
COMPANIES_FALLBACK_URL = "https://www.sec.gov/files/company_tickers.json"
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

# Security vendor watch: big cybersecurity companies, and the names of their own
# products, so a story about a flaw in FortiGate is marked on Fortinet's chart.
WATCHLIST = [
    ("CRWD", "CrowdStrike", r"CrowdStrike|Falcon sensor"),
    ("PANW", "Palo Alto Networks", r"Palo Alto(?: Networks)?|PAN-OS|GlobalProtect|Cortex XDR|Prisma (?:Access|Cloud)"),
    ("FTNT", "Fortinet", r"Fortinet|Forti[A-Z][A-Za-z]+"),
    ("ZS", "Zscaler", r"Zscaler"),
    ("NET", "Cloudflare", r"Cloudflare"),
    ("OKTA", "Okta", r"Okta"),
    ("S", "SentinelOne", r"SentinelOne"),
    ("CHKP", "Check Point", r"Check Point"),
]
SECTOR = ("CIBR", "Cybersecurity sector fund")   # an ETF holding the sector's biggest companies
WATCH_TRADING_DAYS = 30
WATCH_SEVERITIES = ("red", "orange")
# A story marks a vendor when it pairs the vendor's name with one of these...
_FLAW = (
    r"(?i:flaws?|vulnerabilit(?:y|ies)|vulnerable|zero[- ]days?|0[- ]days?|CVE-\d{4}-\d+|exploit\w*|bugs?|"
    r"patch\w*|breach\w*|hack(?:ed|s)?|outage|crash(?:es|ed)?|bypass|RCE|backdoor\w*|compromise[ds]?|"
    r"targeted|attacks?|stole|stolen|leak\w*|credentials)"
)
# ...unless the vendor is the researcher, or its brand is only being faked.
_NOT_ITS_PRODUCT = (
    r"(?i:\b(?:fake|spoofed|bogus|counterfeit)\s+(?:\w+\s+)?(?:{name})|(?:{name})[- ]themed|impersonat\w*\s+(?:{name})|"
    r"(?:{name})(?:['’]s)?\s+(?:Research|researchers?|finds|found|discovers|uncovers|spots|tracks|links|report|threat intelligence))"
)

# Companies listed outside the US, matched by name in headlines. The SEC's list only
# covers US listings, so these are hand-picked: London's biggest and most-breached
# names, and the large Dubai and Abu Dhabi companies. (ticker, name shown, pattern).
# London tickers are Alpha Vantage symbols. Dubai and Abu Dhabi symbols are as the
# exchanges show them; no free price source covers those exchanges, so their cards
# have no chart (ADX's own data service has a free tier worth checking later).
INTERNATIONAL = {
    "LSE": {
        "label": "London Stock Exchange", "benchmark": ("ISF.LON", "FTSE 100"), "currency": "GBX",
        "listings": [
            ("MKS.LON", "Marks & Spencer", r"Marks (?:&|and) Spencer|\bM&S\b"),
            ("CPI.LON", "Capita", r"\bCapita\b"),
            ("TSCO.LON", "Tesco", r"\bTesco\b"),
            ("SBRY.LON", "Sainsbury's", r"Sainsbury['’]?s?|\bArgos\b"),
            ("BARC.LON", "Barclays", r"Barclays"),
            ("LLOY.LON", "Lloyds Banking Group", r"Lloyds(?: Bank(?:ing Group)?)?|\bHalifax\b|Bank of Scotland"),
            ("HSBA.LON", "HSBC", r"\bHSBC\b"),
            ("NWG.LON", "NatWest", r"NatWest|Royal Bank of Scotland|\bRBS\b"),
            ("STAN.LON", "Standard Chartered", r"Standard Chartered"),
            ("VOD.LON", "Vodafone", r"Vodafone"),
            ("BT-A.LON", "BT Group", r"\bBT Group\b|\bBT\b(?= customers| broadband| says| confirms)|Openreach"),
            ("BP.LON", "BP", r"\bBP\b"),
            ("SHEL.LON", "Shell", r"\bShell\b(?! [Cc]ompan)"),
            ("ULVR.LON", "Unilever", r"Unilever"),
            ("AZN.LON", "AstraZeneca", r"AstraZeneca"),
            ("GSK.LON", "GSK", r"\bGSK\b|GlaxoSmithKline"),
            ("RR.LON", "Rolls-Royce", r"Rolls-Royce"),
            ("BA.LON", "BAE Systems", r"BAE Systems"),
            ("EXPN.LON", "Experian", r"Experian"),
            ("SGE.LON", "Sage Group", r"Sage Group"),
            ("JD.LON", "JD Sports", r"JD Sports"),
            ("KGF.LON", "Kingfisher", r"Kingfisher plc|\bB&Q\b|Screwfix"),
            ("WPP.LON", "WPP", r"\bWPP\b"),
            ("PSON.LON", "Pearson", r"\bPearson\b"),
            ("BRBY.LON", "Burberry", r"Burberry"),
            ("EZJ.LON", "easyJet", r"easyJet"),
            ("IAG.LON", "IAG (British Airways)", r"British Airways|\bIAG\b|Aer Lingus|Vueling"),
            ("AV.LON", "Aviva", r"\bAviva\b"),
            ("LGEN.LON", "Legal & General", r"Legal (?:&|and) General"),
            ("DGE.LON", "Diageo", r"Diageo"),
            ("RIO.LON", "Rio Tinto", r"Rio Tinto"),
            ("GLEN.LON", "Glencore", r"Glencore"),
            ("NG.LON", "National Grid", r"National Grid"),
            ("CNA.LON", "Centrica (British Gas)", r"Centrica|British Gas"),
            ("SVT.LON", "Severn Trent", r"Severn Trent"),
            ("UU.LON", "United Utilities", r"United Utilities"),
            ("PNN.LON", "Pennon (South West Water)", r"Pennon|South West Water"),
            ("ITV.LON", "ITV", r"\bITV\b"),
            ("OCDO.LON", "Ocado", r"\bOcado\b"),
            ("FRAS.LON", "Frasers Group", r"Frasers Group|Sports Direct|House of Fraser"),
            ("LSEG.LON", "London Stock Exchange Group", r"London Stock Exchange Group|\bLSEG\b"),
            ("REL.LON", "RELX", r"\bRELX\b|LexisNexis"),
            ("WTB.LON", "Whitbread (Premier Inn)", r"Whitbread|Premier Inn"),
            ("IHG.LON", "IHG Hotels", r"\bIHG\b|InterContinental Hotels|Holiday Inn"),
            ("MNG.LON", "M&G", r"\bM&G\b"),
            ("ADM.LON", "Admiral Group", r"Admiral Group"),
            ("AUTO.LON", "Auto Trader", r"Auto Trader"),
        ],
    },
    "DFM": {
        "label": "Dubai Financial Market", "benchmark": None,
        "disclosures": "https://www.dfm.ae/the-exchange/news-disclosures/disclosures",
        "listings": [
            ("EMAAR", "Emaar Properties", r"\bEmaar\b(?! Development)"),
            ("EMAARDEV", "Emaar Development", r"Emaar Development"),
            ("EMIRATESNBD", "Emirates NBD", r"Emirates NBD|\bENBD\b"),
            ("DIB", "Dubai Islamic Bank", r"Dubai Islamic Bank"),
            ("CBD", "Commercial Bank of Dubai", r"Commercial Bank of Dubai"),
            ("MASQ", "Mashreq", r"\bMashreq(?:bank)?\b"),
            ("DU", "du (Emirates Integrated Telecommunications)",
             r"Emirates Integrated Telecommunications|\bEITC\b|(?<=telco )du\b|(?<=operator )du\b|\bdu(?= telecom| customers| subscribers)"),
            ("DEWA", "Dubai Electricity and Water Authority", r"\bDEWA\b|Dubai Electricity (?:and|&) Water"),
            ("SALIK", "Salik", r"\bSalik\b"),
            ("PARKIN", "Parkin", r"\bParkin\b"),
            ("AIRARABIA", "Air Arabia", r"Air Arabia"),
            ("ARMX", "Aramex", r"Aramex"),
            ("TALABAT", "Talabat", r"Talabat"),
            ("TECOM", "TECOM Group", r"\bTECOM\b"),
            ("DTC", "Dubai Taxi Company", r"Dubai Taxi"),
            ("DFM", "Dubai Financial Market", r"Dubai Financial Market"),
            ("SPINNEYS", "Spinneys", r"Spinneys"),
            ("ALANSARI", "Al Ansari Financial Services", r"Al Ansari (?:Exchange|Financial)"),
        ],
    },
    "ADX": {
        "label": "Abu Dhabi Securities Exchange", "benchmark": None,
        "disclosures": "https://www.adx.ae/en/issuers/issuers-information/listed-companies-disclosures",
        "listings": [
            ("FAB", "First Abu Dhabi Bank", r"First Abu Dhabi Bank"),
            ("ADCB", "Abu Dhabi Commercial Bank", r"Abu Dhabi Commercial Bank|\bADCB\b"),
            ("ADIB", "Abu Dhabi Islamic Bank", r"Abu Dhabi Islamic Bank|\bADIB\b"),
            ("EAND", "e& (Etisalat)", r"(?<![\w&])e&(?![\w&])|Etisalat"),
            ("ADNOCDIST", "ADNOC Distribution", r"ADNOC Distribution"),
            ("ADNOCGAS", "ADNOC Gas", r"ADNOC Gas"),
            ("ADNOCDRILL", "ADNOC Drilling", r"ADNOC Drilling"),
            ("ADNOCLS", "ADNOC Logistics & Services", r"ADNOC Logistics"),
            ("ADPORTS", "AD Ports Group", r"AD Ports|Abu Dhabi Ports"),
            ("ALDAR", "Aldar Properties", r"\bAldar\b"),
            ("IHC", "International Holding Company", r"International Holding Company"),
            ("TAQA", "TAQA", r"\bTAQA\b"),
            ("BOROUGE", "Borouge", r"Borouge"),
            ("PUREHEALTH", "PureHealth", r"PureHealth|Pure Health"),
            ("LULU", "Lulu Retail", r"Lulu (?:Hypermarket|Retail|Group)"),
            ("MULTIPLY", "Multiply Group", r"Multiply Group"),
            ("PRESIGHT", "Presight AI", r"Presight"),
            ("SPACE42", "Space42 (Yahsat, Bayanat)", r"Space42|Yahsat|Bayanat"),
            ("NMDC", "NMDC Group", r"\bNMDC\b"),
            ("AGTHIA", "Agthia", r"Agthia"),
            ("ALPHADHABI", "Alpha Dhabi", r"Alpha Dhabi"),
            ("RAKBANK", "RAKBANK", r"RAKBANK|RAK Bank"),
            ("ADNIC", "Abu Dhabi National Insurance", r"\bADNIC\b"),
            ("DANA", "Dana Gas", r"Dana Gas"),
            ("FERTIGLB", "Fertiglobe", r"Fertiglobe"),
        ],
    },
}
US_BENCHMARK = (MARKET, "S&P 500")


def synthetic_cik(exchange, ticker):
    """Non-US companies have no SEC number, so they get a stable negative one."""
    return -(zlib.crc32(f"{exchange}:{ticker}".encode()) & 0x7FFFFFFF) - 1


_INTERNATIONAL = [
    (synthetic_cik(ex, ticker), ex, ticker, name, re.compile(pattern))
    for ex, cfg in INTERNATIONAL.items() for ticker, name, pattern in cfg["listings"]
]


def ensure_international(conn):
    conn.executemany(
        """INSERT INTO companies (cik, ticker, name, exchange) VALUES (?, ?, ?, ?)
           ON CONFLICT(cik) DO UPDATE SET ticker = excluded.ticker, name = excluded.name, exchange = excluded.exchange""",
        [(cik, ticker, name, ex) for cik, ex, ticker, name, _ in _INTERNATIONAL],
    )
    conn.commit()


def display_ticker(ticker):
    return ticker[:-4] if ticker.endswith(".LON") else ticker


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
        rf"\b{c}{possessive}\s+{_ASSETS}['’]?\s+(?:[^\s]+\s+){{0,4}}?{_INCIDENT}\b",
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


def _company_rows(contact):
    """[(cik, ticker, name, exchange)], largest companies first. Uses the list with
    exchanges, or the plain list (no exchanges) if that one fails."""
    try:
        resp = requests.get(COMPANIES_URL, headers={"User-Agent": contact}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        col = {name: i for i, name in enumerate(data["fields"])}
        return [(int(r[col["cik"]]), r[col["ticker"]], r[col["name"]], r[col["exchange"]]) for r in data["data"]]
    except (requests.RequestException, ValueError, KeyError, TypeError, IndexError):
        resp = requests.get(COMPANIES_FALLBACK_URL, headers={"User-Agent": contact}, timeout=30)
        resp.raise_for_status()
        return [(int(e["cik_str"]), e["ticker"], e["title"], None) for e in resp.json().values()]


def refresh_companies(conn, contact):
    """The SEC's list of every US-listed company and its ticker, refreshed weekly."""
    row = conn.execute("SELECT day FROM lookups WHERE kind = 'companies' AND key = 'with-exchange'").fetchone()
    if row and date.fromisoformat(row["day"]) > date.today() - timedelta(days=REFRESH_COMPANIES_DAYS):
        return "up to date"
    rows, seen = [], set()
    for cik, ticker, name, exchange in _company_rows(contact):
        if cik in seen:          # keep each company's first (main) ticker
            continue
        seen.add(cik)
        rows.append((cik, ticker.upper(), name, exchange))
    # Update in place so what fetch_filings learned (foreign_filer) survives the refresh.
    conn.executemany(
        """INSERT INTO companies (cik, ticker, name, exchange) VALUES (?, ?, ?, ?)
           ON CONFLICT(cik) DO UPDATE SET ticker = excluded.ticker, name = excluded.name,
                                          exchange = excluded.exchange""",
        rows,
    )
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS listed (cik INTEGER PRIMARY KEY)")
    conn.execute("DELETE FROM listed")
    conn.executemany("INSERT INTO listed (cik) VALUES (?)", [(c,) for c in seen])
    conn.execute("DELETE FROM companies WHERE cik > 0 AND cik NOT IN (SELECT cik FROM listed)")
    _mark_looked_up(conn, "companies", "with-exchange")
    return f"{len(rows)} companies"


def fetch_prices(conn, ticker, key):
    """Last ~100 trading days of closes. Returns None, or an error message."""
    # SEC writes BRK-B, Alpha Vantage BRK.B. London symbols are already Alpha Vantage's.
    symbol = ticker if ticker.endswith(".LON") else ticker.replace("-", ".")
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


DOMESTIC_FORMS = {"10-K", "10-K/A", "10-Q", "10-Q/A", "8-K", "8-K/A"}
FOREIGN_FORMS = {"20-F", "20-F/A", "40-F", "40-F/A", "6-K", "6-K/A"}


def is_foreign_filer(submissions):
    """True for companies that report to the SEC as foreign companies (annual 20-F,
    news on 6-K). The Item 1.05 breach rule is for 8-K filers, so it doesn't apply
    to them. A foreign-based company filing 10-Ks and 8-Ks is treated as domestic."""
    forms = set(submissions.get("filings", {}).get("recent", {}).get("form", []))
    if forms & DOMESTIC_FORMS:
        return False
    if forms & FOREIGN_FORMS:
        return True
    addresses = submissions.get("addresses") or {}
    return any((a or {}).get("isForeignLocation") == 1 for a in addresses.values())


def fetch_filings(conn, cik, contact):
    """Record the company's 8-K filings under Item 1.05 (material cybersecurity incident)."""
    resp = requests.get(SUBMISSIONS_URL.format(cik=cik), headers={"User-Agent": contact}, timeout=20)
    resp.raise_for_status()
    data = resp.json()
    recent = data["filings"]["recent"]
    conn.execute("UPDATE companies SET foreign_filer = ? WHERE cik = ?", (int(is_foreign_filer(data)), cik))
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
    for row in conn.execute("SELECT cik, ticker, name FROM companies WHERE cik > 0"):
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
    """Listed companies a headline names as the victim: [(cik, ticker, name, matched)].
    London, Dubai and Abu Dhabi names are checked first, so a UK company that also has
    US-traded shares (BP, HSBC, Vodafone) is shown against its home market."""
    found, taken = {}, set()
    for cik, _, ticker, name, regex in _INTERNATIONAL:
        for m in regex.finditer(title):
            if any(re.search(p, title) for p in _victim_patterns(m.group(0))):
                found.setdefault(cik, (cik, ticker, name, m.group(0)))
                taken.add(m.group(0).lower())
                taken.add(name.lower())
                break
    us = _us_victims(title, names, taken)
    return list(found.values()) + [v for v in us if v[0] not in found]


def _us_victims(title, names, taken):
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
            if not hit or not phrase[0].isupper() or phrase.lower() in taken:
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


def _update_breaches(conn, contact, log):
    """Companies, breach mentions and SEC filings. Returns the breached companies,
    newest story first. Without an SEC contact only London, Dubai and Abu Dhabi
    companies can be spotted."""
    ensure_international(conn)
    if contact:
        try:
            log(f"Stocks: SEC company list {refresh_companies(conn, contact)}")
        except (requests.RequestException, ValueError, KeyError) as e:
            log(f"Stocks: couldn't fetch the SEC company list ({e.__class__.__name__}); trying next run")
    else:
        log("Stocks: no .sec_contact, so only London, Dubai and Abu Dhabi companies are tracked (see README)")
    log(f"Stocks: {find_events(conn)} breach mentions of listed companies")

    recent = conn.execute(
        """SELECT c.cik, c.ticker, c.exchange,
                  MAX(i.published) AS latest,
                  (SELECT COUNT(*) FROM prices p WHERE p.ticker = c.ticker) AS have
           FROM stock_events e JOIN items i ON i.id = e.item_id JOIN companies c ON c.cik = e.cik
           GROUP BY c.cik ORDER BY latest DESC"""
    ).fetchall()

    sec_done = 0
    for row in recent:
        if not contact or row["cik"] < 0 or sec_done >= SEC_PER_RUN or _looked_up_today(conn, "sec", row["cik"]):
            continue
        try:
            fetch_filings(conn, row["cik"], contact)
        except (requests.RequestException, ValueError, KeyError) as e:
            log(f"Stocks: SEC lookup for {row['ticker']} failed ({e.__class__.__name__})")
        sec_done += 1
        time.sleep(SEC_GAP_SECONDS)
    return recent


def benchmark_for(exchange):
    """(ticker, name) of the market to compare with, or None when there are no prices."""
    if exchange in INTERNATIONAL:
        return INTERNATIONAL[exchange]["benchmark"]
    return US_BENCHMARK


def update(conn, log=print):
    """One collector step. Never raises: a failed lookup is retried next run."""
    contact, key = sec_contact(), av_key()
    recent = _update_breaches(conn, contact, log)

    if not key:
        log("Stocks: no Alpha Vantage key in .alphavantage_key, so no prices")
        return
    if _looked_up_today(conn, "prices-limit", "all"):
        log("Stocks: Alpha Vantage's daily limit was reached earlier today; prices resume tomorrow")
        return

    # The market first (every chart needs it), then breach victims, newest story
    # first, then the vendor watch.
    follow_from = (datetime.now(timezone.utc) - timedelta(days=FOLLOW_DAYS)).isoformat()
    wanted = [MARKET]
    for r in recent:
        bench = benchmark_for(r["exchange"])
        if bench and (r["latest"] >= follow_from or not r["have"]):
            wanted += [bench[0], r["ticker"]]      # a London company also needs the FTSE 100
    wanted += [ticker for ticker, _, _ in WATCHLIST] + [SECTOR[0]]
    used_today = conn.execute(
        "SELECT COUNT(*) FROM lookups WHERE kind = 'prices' AND day = ?", (_today(),)
    ).fetchone()[0]
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
        """SELECT e.item_id, e.cik, c.ticker, c.name, c.exchange, c.foreign_filer,
                  i.title, i.link, i.source, i.published, i.severity
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
            exchange = row["exchange"]
            intl = INTERNATIONAL.get(exchange)
            grouped.append({"cik": row["cik"], "ticker": row["ticker"], "display_ticker": display_ticker(row["ticker"]),
                            "exchange": exchange, "exchange_label": intl["label"] if intl else exchange,
                            "otc": exchange == "OTC", "foreign": bool(row["foreign_filer"]),
                            "us": row["cik"] > 0,
                            "currency": intl.get("currency", "USD") if intl else "USD",
                            "disclosures": intl.get("disclosures") if intl else None,
                            "company": (row["name"] if intl else DISPLAY.get(row["ticker"]) or short_name(row["name"])),
                            "_first": published, "stories": [dict(row)]})

    for g in grouped:
        story_day = g.pop("_first").date()
        g["date"] = story_day.isoformat()
        start = (story_day - timedelta(days=TRADING_DAYS * 2 + 6)).isoformat()
        end = (story_day + timedelta(days=TRADING_DAYS * 2 + 6)).isoformat()
        bench = benchmark_for(g["exchange"])
        g["no_prices"] = bench is None          # Dubai and Abu Dhabi: no free price source
        g["market_name"] = bench[1] if bench else None
        stock = _series(conn, g["ticker"], start, end) if bench else {}
        market = _series(conn, bench[0], start, end) if bench else {}
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


def product_stories(conn, since):
    """Major and Medium stories about a flaw or breach in each vendor's own products:
    {ticker: [story, ...]}, oldest first."""
    rows = conn.execute(
        f"""SELECT id, title, link, source, published, severity FROM items
            WHERE severity IN ({",".join("?" * len(WATCH_SEVERITIES))}) AND published >= ?
            ORDER BY published""",
        (*WATCH_SEVERITIES, since),
    ).fetchall()
    found = {ticker: [] for ticker, _, _ in WATCHLIST}
    for ticker, _, names in WATCHLIST:
        mention = re.compile(rf"\b(?:{names})\b")
        not_its = re.compile(_NOT_ITS_PRODUCT.format(name=names))
        for row in rows:
            title = row["title"]
            if mention.search(title) and re.search(rf"\b{_FLAW}\b", title) and not not_its.search(title):
                found[ticker].append(dict(row))
    return found


def vendor_watch(conn):
    """The watchlist's last WATCH_TRADING_DAYS against the market, with product stories
    pinned to the trading day they landed on. All charts share one scale."""
    market = {r["day"]: r["close"] for r in conn.execute(
        "SELECT day, close FROM prices WHERE ticker = ? ORDER BY day DESC LIMIT ?", (MARKET, WATCH_TRADING_DAYS + 1))}
    days = sorted(market)
    if len(days) < 2:
        return {"vendors": [], "sector": None, "range": None}
    stories = product_stories(conn, days[0] + "T00:00:00+00:00")

    def one(ticker, name):
        closes = _series(conn, ticker, days[0], days[-1])
        shared = [d for d in days if d in closes]
        if len(shared) < 2:
            return {"ticker": ticker, "company": name, "points": [], "change": None, "market_change": None}
        first, last = shared[0], shared[-1]
        return {
            "ticker": ticker, "company": name,
            "points": [{"day": d, "close": closes[d], "market": market[d]} for d in shared],
            "change": closes[last] / closes[first] - 1,
            "market_change": market[last] / market[first] - 1,
            "from": first, "through": last,
        }

    vendors = []
    for ticker, name, _ in WATCHLIST:
        v = one(ticker, name)
        marks = []
        for s in stories[ticker]:
            day = s["published"][:10]
            # Weekend and after-hours stories land on the next trading day on the chart.
            landed = next((d for d in (p["day"] for p in v["points"]) if d >= day), None)
            marks.append({**s, "day": landed or (v["points"][-1]["day"] if v["points"] else day)})
        v["stories"] = marks
        vendors.append(v)

    moves = [p["close"] / v["points"][0]["close"] - 1 for v in vendors for p in v["points"]]
    moves += [p["market"] / v["points"][0]["market"] - 1 for v in vendors for p in v["points"]]
    return {
        "vendors": vendors,
        "sector": one(*SECTOR),
        "range": [min(moves + [0]), max(moves + [0])] if moves else None,
    }


def main():
    from db import connect

    conn = connect()
    update(conn)
    found = incidents(conn)
    print(f"\n{len(found)} incidents involving US-listed companies:\n")
    for g in found:
        s = g["stories"][0]
        notes = [n for n, on in (("over the counter", g["otc"]), ("foreign filer", g["foreign"])) if on]
        print(f"{g['date']}  {g['company']} ({g['exchange'] or 'US'}: {g['display_ticker']}"
              f"{', ' + ', '.join(notes) if notes else ''})  [{s['source']}] {s['title']}")
        if g["no_prices"]:
            print(f"    no free price source for {g['exchange_label']}")
        elif g["change"] is not None:
            print(f"    {g['change']:+.1%} through {g['through']}, {g['market_name']} {g['market_change']:+.1%}")
        else:
            print("    no price data around the story yet")
        for f in g["filings"]:
            print(f"    SEC {f['form']} Item 1.05 filed {f['filed']}: {f['url']}")
    watch = vendor_watch(conn)
    print(f"\nSecurity vendor watch (last {WATCH_TRADING_DAYS} trading days):\n")
    for v in watch["vendors"] + ([watch["sector"]] if watch["sector"] else []):
        move = "no prices yet" if v["change"] is None else f"{v['change']:+.1%} (S&P 500 {v['market_change']:+.1%})"
        print(f"  {v['company']:<26} {v['ticker']:<5} {move}")
        for s in v.get("stories", []):
            print(f"      {s['day']}  [{s['severity']}] {s['title']}")
    conn.close()


if __name__ == "__main__":
    main()
