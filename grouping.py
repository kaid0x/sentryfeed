"""Stories for the pages: one entry per story, with every outlet's article about it grouped.

Grouping takes a few seconds on the Pi, mostly finding the countries and products in each
article. So the collector groups every window the pages use once per run (save_all) and keeps
the result in the story_groups table, and pages read it back (saved). A window that wasn't
saved, like an old digest week, is grouped on the spot instead.
"""
import json
import zlib
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import briefing
import stack
from dedupe import group_stories
from geo import locate

# Order matters: this is the sort order and the order of the filter tiles.
SEVERITIES = [
    ("red", "Major"),
    ("orange", "Medium"),
    ("yellow", "Low"),
    ("green", "Tech & AI"),
    ("blue", "Events"),
]
RANK = {key: i for i, (key, _) in enumerate(SEVERITIES)}

# Every window a page asks for: the feed and map choices (24h to 14 days), which the fixed
# windows in app.py, rss.py and vulns.py all reuse. A page asking for any other window has
# it grouped on the spot after every collector run (and logs a warning), so add it here.
SAVED_DAYS = (1, 3, 7, 14)
PULSE_MAX_DAYS = 365        # /gulf covers everything since the first story, up to a year
SAVED_WEEKS = 3             # this week, last week (the digest's default) and the week before it

# Bump when the shape of a grouped story changes, so pages ignore what older code saved.
FORMAT = 1

# What the page needs about each other outlet covering a story.
ALSO_FIELDS = ("id", "source", "title", "link", "age", "published", "match")


def safe_link(url):
    """Feed content is untrusted input. Only allow http(s) links, so a poisoned
    feed can't slip a javascript: URL into the page."""
    return url if urlparse(url or "").scheme in ("http", "https") else None


def ago(iso, now):
    if not iso:
        return ""
    minutes = int((now - datetime.fromisoformat(iso)).total_seconds() // 60)
    if minutes < 60:
        return f"{max(minutes, 1)}m ago"
    if minutes < 48 * 60:
        return f"{minutes // 60}h ago"
    return f"{minutes // 1440}d ago"


def ungrouped(conn, days=None, start=None, end=None):
    """Every item in the window, one per article: the last `days` days, or from `start`
    up to (not including) `end`, both timezone-aware datetimes."""
    now = datetime.now(timezone.utc)
    columns = """SELECT id, category, source, title, summary, link, published,
                        cves, cvss, kev, severity, severity_reason FROM items"""
    if start is not None:
        rows = conn.execute(
            columns + " WHERE severity IS NOT NULL AND published >= ? AND published < ?",
            (start.astimezone(timezone.utc).isoformat(), end.astimezone(timezone.utc).isoformat()),
        ).fetchall()
    else:
        rows = conn.execute(
            columns + " WHERE severity IS NOT NULL AND (published IS NULL OR published >= ?)",
            ((now - timedelta(days=days)).isoformat(),),
        ).fetchall()

    items = []
    for row in rows:
        item = dict(row)
        item["link"] = safe_link(item["link"])
        item["age"] = ago(item["published"], now)
        item["cves"] = [c for c in (item["cves"] or "").split(",") if c]
        items.append(item)

    # Two stable sorts: newest first, then by severity. Result: red block on top,
    # newest-first within each colour.
    items.sort(key=lambda i: i["published"] or "", reverse=True)
    items.sort(key=lambda i: RANK.get(i["severity"], len(RANK)))
    return items


def group(conn, days=None, start=None, end=None):
    """One entry per story. When several outlets covered it, the highest-ranked
    article leads (so the story takes its colour), and the rest are listed under
    "also" with their CVEs and countries added to the lead's."""
    stories = group_stories(ungrouped(conn, days, start, end), RANK)
    for story in stories:
        others = story["also"]
        members = [story, *others]
        story["cves"] = sorted(set(story["cves"]).union(*(m["cves"] for m in others)))
        story["kev"] = int(any(m["kev"] for m in members))
        where, blamed, products = set(), set(), set()
        for m in members:
            w, b = locate(m)
            where.update(w)
            blamed.update(b)
            if story["severity"] in stack.SECURITY_SEVERITIES:
                products.update(stack.match(m))
        story["where"], story["blamed"] = sorted(where), sorted(blamed)
        story["products"] = sorted(products)
        story["also"] = [{k: m.get(k) for k in ALSO_FIELDS} for m in others]
    return stories


def first_published(conn):
    """When SentryFeed's first story was published, or None with no stories yet."""
    first = conn.execute("SELECT MIN(published) FROM items WHERE severity IS NOT NULL").fetchone()[0]
    return datetime.fromisoformat(first) if first else None


def gulf_days(first, now):
    """/gulf's window: every day since the first story, up to PULSE_MAX_DAYS."""
    return min(PULSE_MAX_DAYS, (now - first).days + 1) if first else 1


def days_key(days):
    return f"days:{days}"


def week_key(start):
    return f"week:{start.isoformat()}"


def saved(conn, key):
    """The collector's grouping for this window, or None if it hasn't saved one."""
    row = conn.execute("SELECT stories FROM story_groups WHERE key = ? AND format = ?", (key, FORMAT)).fetchone()
    return json.loads(zlib.decompress(row[0])) if row else None


def save_all(conn):
    """Group every window the pages use and save the results, replacing the last run's.
    Run by the collector after scoring. Returns how many windows were saved."""
    now = datetime.now(timezone.utc)
    windows = {days_key(d): {"days": d} for d in (*SAVED_DAYS, gulf_days(first_published(conn), now))}
    current = briefing.week_start(briefing.week_id(now))
    for back in range(SAVED_WEEKS):
        start = current - timedelta(days=7 * back)
        windows[week_key(start)] = {"start": start, "end": start + timedelta(days=7)}

    made_at = now.isoformat()
    # Compressed: about 4.5 times smaller, which matters once every run is copied to Turso.
    rows = [(key, FORMAT, zlib.compress(json.dumps(group(conn, **window)).encode()), made_at)
            for key, window in windows.items()]
    with conn:      # one transaction: pages see the old set or the new one, never half
        conn.execute("DELETE FROM story_groups")
        conn.executemany("INSERT INTO story_groups (key, format, stories, made_at) VALUES (?, ?, ?, ?)", rows)
    return len(rows)
