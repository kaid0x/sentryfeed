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
    severity    TEXT,              -- red / orange / yellow / green
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
"""


# Columns added after Stage 2. Older databases get them added on connect.
ADDED_COLUMNS = {
    "kev": "INTEGER NOT NULL DEFAULT 0",
    "severity_reason": "TEXT",
}


def _migrate(conn):
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(items)")}
    for name, definition in ADDED_COLUMNS.items():
        if name not in cols:
            conn.execute(f"ALTER TABLE items ADD COLUMN {name} {definition}")
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
