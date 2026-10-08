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
-- When each outside lookup last ran, so each one happens at most once a day.
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
