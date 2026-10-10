import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).with_name("sentryfeed.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id          INTEGER PRIMARY KEY,
    link        TEXT NOT NULL UNIQUE,
    category    TEXT NOT NULL,
    source      TEXT NOT NULL,
    title       TEXT NOT NULL,
    summary     TEXT,
    published   TEXT,
    fetched_at  TEXT NOT NULL,
    cves        TEXT,              -- NULL = not checked yet, '' = checked and none found
    cvss        REAL,              -- highest score among the item's CVEs
    kev         INTEGER NOT NULL DEFAULT 0,  -- 1 if any of its CVEs is in CISA's exploited list
    severity    TEXT,              -- red / orange / yellow / green / blue
    severity_reason TEXT           -- why it got that colour, shown on the dashboard
);
CREATE INDEX IF NOT EXISTS idx_items_published ON items(published);

-- One row per CVE ever looked up, so each CVE hits the NVD API once, not once per article.
CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id      TEXT PRIMARY KEY,
    cvss        REAL,
    kev         INTEGER NOT NULL DEFAULT 0,
    checked_at  TEXT NOT NULL
);

-- Stock impact (stocks.py). Public data only: the SEC's list of listed companies,
-- their breach filings, and daily closing prices.
CREATE TABLE IF NOT EXISTS companies (
    cik         INTEGER PRIMARY KEY,   -- the SEC's company ID
    ticker      TEXT NOT NULL,
    name        TEXT NOT NULL,
    exchange    TEXT,                  -- Nasdaq, NYSE, OTC, CBOE
    foreign_filer INTEGER NOT NULL DEFAULT 0   -- files as a foreign company (20-F/6-K), so no Item 1.05
);
CREATE INDEX IF NOT EXISTS idx_companies_ticker ON companies(ticker);
CREATE TABLE IF NOT EXISTS stock_events (   -- a story naming a company as a breach victim
    item_id     INTEGER NOT NULL,
    cik         INTEGER NOT NULL,
    matched     TEXT NOT NULL,          -- the words in the headline that named it
    PRIMARY KEY (item_id, cik)
);
CREATE TABLE IF NOT EXISTS prices (
    ticker      TEXT NOT NULL,
    day         TEXT NOT NULL,          -- trading day, YYYY-MM-DD
    close       REAL NOT NULL,
    PRIMARY KEY (ticker, day)
);
CREATE TABLE IF NOT EXISTS sec_filings (    -- 8-Ks reporting a material cyber incident (Item 1.05)
    accession   TEXT PRIMARY KEY,
    cik         INTEGER NOT NULL,
    form        TEXT NOT NULL,
    filed       TEXT NOT NULL,
    url         TEXT NOT NULL
);
-- Events people submit (events.py). Nothing shows on the site until it's approved
-- from the Pi's command line.
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY,
    title        TEXT NOT NULL,
    kind         TEXT NOT NULL,         -- ctf, webinar, conference, meetup, workshop, training, other
    starts_at    TEXT NOT NULL,         -- UTC
    ends_at      TEXT,                  -- UTC, optional
    tz           TEXT NOT NULL,         -- the submitter's time zone, for showing the original time
    online       INTEGER NOT NULL,
    location     TEXT,
    url          TEXT NOT NULL,
    organiser    TEXT NOT NULL,
    description  TEXT,
    contact      TEXT,                  -- optional, never shown on the site
    status       TEXT NOT NULL DEFAULT 'pending',   -- pending, approved, rejected
    submitted_at TEXT NOT NULL,
    reviewed_at  TEXT,
    submitter    TEXT                   -- keyed hash of the visitor's IP, for rate limiting only
);
CREATE INDEX IF NOT EXISTS idx_events_status ON events(status, starts_at);

-- When each outside lookup last ran, so each one happens at most once a day.
-- Vulnerability centre (vulns.py).
CREATE TABLE IF NOT EXISTS kev (            -- CISA's Known Exploited Vulnerabilities catalogue, refreshed daily
    cve_id          TEXT PRIMARY KEY,
    vendor          TEXT NOT NULL,
    product         TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT,
    date_added      TEXT NOT NULL,          -- YYYY-MM-DD
    due_date        TEXT,                   -- deadline for US federal agencies to fix it
    required_action TEXT,
    ransomware      INTEGER NOT NULL DEFAULT 0,  -- CISA knows of ransomware campaigns using it
    notes           TEXT
);
CREATE INDEX IF NOT EXISTS idx_kev_added ON kev(date_added);
CREATE TABLE IF NOT EXISTS epss (           -- FIRST's daily estimate of exploitation in the next 30 days
    cve_id      TEXT PRIMARY KEY,
    score       REAL NOT NULL,              -- probability, 0 to 1
    percentile  REAL NOT NULL,              -- share of all scored CVEs at or below this one
    day         TEXT NOT NULL               -- the date FIRST scored it
);
CREATE TABLE IF NOT EXISTS cve_details (    -- NVD's description and fix links, for the CVE pages
    cve_id      TEXT PRIMARY KEY,
    found       INTEGER NOT NULL,           -- 0 = NVD has no record (yet)
    description TEXT,
    cvss        REAL,
    published   TEXT,
    refs        TEXT,                       -- JSON list of {url, tags}: patches and vendor advisories
    checked_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cve_lookups (    -- live lookups from the CVE page, kept two days for rate limits
    visitor     TEXT NOT NULL,              -- keyed hash of the IP, as for events; never the IP itself
    at          TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (           -- small facts about the database, like when the collector last ran
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lookups (
    kind        TEXT NOT NULL,          -- 'prices', 'sec', 'companies'
    key         TEXT NOT NULL,          -- ticker, CIK, or 'all'
    day         TEXT NOT NULL,          -- UTC date of the lookup
    PRIMARY KEY (kind, key)
);
"""


# Columns added after a table was first created. Older databases get them on connect.
ADDED_COLUMNS = {
    "items": {
        "kev": "INTEGER NOT NULL DEFAULT 0",
        "severity_reason": "TEXT",
    },
    "companies": {
        "exchange": "TEXT",
        "foreign_filer": "INTEGER NOT NULL DEFAULT 0",
    },
}


def _migrate(conn):
    for table, columns in ADDED_COLUMNS.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, definition in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
    conn.commit()


def get_meta(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
    conn.commit()


def mark_collected(conn):
    """Record the end of a collector run. Pages use it for "Updated 12:41" and to know when
    their cached stories are stale. (Not the file's modification time: CVE lookups and event
    submissions write to the database too.)"""
    set_meta(conn, "collected_at", datetime.now(timezone.utc).isoformat())


def last_collected(conn):
    """When the collector last finished, or the file's modification time for a database
    from before this was recorded. None if there's no database yet."""
    value = get_meta(conn, "collected_at")
    if value:
        return datetime.fromisoformat(value)
    if DB_PATH.exists():
        return datetime.fromtimestamp(DB_PATH.stat().st_mtime, timezone.utc)
    return None


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    _migrate(conn)
    return conn


def save_items(conn, items):
    """Insert items, silently skipping any link already stored.
    Returns how many were actually new."""
    now = datetime.now(timezone.utc).isoformat()
    before = conn.total_changes
    conn.executemany(
        """INSERT OR IGNORE INTO items
               (link, category, source, title, summary, published, fetched_at)
           VALUES
               (:link, :category, :source, :title, :summary, :published, :fetched_at)""",
        [{**item, "fetched_at": now} for item in items if item["link"]],
    )
    conn.commit()
    return conn.total_changes - before


def count_by_category(conn):
    rows = conn.execute(
        "SELECT category, COUNT(*) AS n FROM items GROUP BY category ORDER BY category"
    )
    return {row["category"]: row["n"] for row in rows}


def cve_stats(conn):
    row = conn.execute(
        """SELECT
               SUM(cves != '')          AS with_cves,
               SUM(cvss IS NOT NULL)    AS scored,
               SUM(kev = 1)             AS kev
           FROM items"""
    ).fetchone()
    return {k: row[k] or 0 for k in ("with_cves", "scored", "kev")}
