"""Stories for the pages: one entry per story, with every outlet's article about it grouped.

Two things keep this cheap as the database grows:
- Each article's countries and products are worked out once, when it arrives (tag_articles),
  and kept in the items table. That was most of the time grouping took.
- The collector groups every window the pages use once per run (save_all) and keeps the result
  in the story_groups table, and pages read it back (saved). A window that wasn't saved, like
  an old digest week, is grouped on the spot instead.
"""
import hashlib
import json
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import briefing
import stack
from db import get_meta, set_meta
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
GULF_KEY = "gulf"           # /gulf's saved window; it grows by a day each day, so it isn't keyed by length

# The files whose rules decide an article's countries and products. When either changes,
# every article is tagged again.
RULE_FILES = ("geo.py", "stack.py")

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


def tags_for(item):
    """(where, blamed, products) for one article, worked out from its title and summary."""
    where, blamed = locate(item)
    return where, blamed, stack.match(item)


def is_gulf(item, where, blamed):
    """From a Gulf outlet or naming a GCC country: the articles /gulf is about."""
    return int(item["category"] == "regional" or bool(briefing.GCC & set(where + blamed)))


def _split(text):
    return [part for part in text.split(",") if part]


def rules_fingerprint():
    """Changes whenever geo.py or stack.py does."""
    digest = hashlib.sha256()
    for name in RULE_FILES:
        digest.update(Path(__file__).with_name(name).read_bytes())
    return digest.hexdigest()[:16]


def tag_articles(conn):
    """Work out each new article's countries and products and keep them in the items table,
    so grouping doesn't redo it on every run. When geo.py or stack.py change, every article
    is tagged again. Returns how many articles were tagged."""
    fingerprint = rules_fingerprint()
    retag = get_meta(conn, "tag_rules") != fingerprint
    rows = conn.execute("SELECT id, category, title, summary FROM items"
                        + ("" if retag else " WHERE where_cc IS NULL")).fetchall()
    updates = []
    for row in rows:
        item = dict(row)
        where, blamed, products = tags_for(item)
        updates.append((",".join(where), ",".join(blamed), ",".join(products),
                        is_gulf(item, where, blamed), item["id"]))
    conn.executemany("UPDATE items SET where_cc = ?, blamed_cc = ?, products = ?, gulf = ? WHERE id = ?", updates)
    set_meta(conn, "tag_rules", fingerprint)     # commits the updates too
    return len(updates)


def ungrouped(conn, days=None, start=None, end=None, gulf_only=False):
    """Every item in the window, one per article: the last `days` days, or from `start`
    up to (not including) `end`, both timezone-aware datetimes. With gulf_only, only
    articles from Gulf outlets or naming a GCC country."""
    now = datetime.now(timezone.utc)
    columns = """SELECT id, category, source, title, summary, link, published, cves, cvss, kev,
                        severity, severity_reason, where_cc, blamed_cc, products AS tagged, gulf FROM items"""
    gulf = " AND (gulf = 1 OR gulf IS NULL)" if gulf_only else ""
    if start is not None:
        rows = conn.execute(
            columns + " WHERE severity IS NOT NULL AND published >= ? AND published < ?" + gulf,
            (start.astimezone(timezone.utc).isoformat(), end.astimezone(timezone.utc).isoformat()),
        ).fetchall()
    else:
        rows = conn.execute(
            columns + " WHERE severity IS NOT NULL AND (published IS NULL OR published >= ?)" + gulf,
            ((now - timedelta(days=days)).isoformat(),),
        ).fetchall()

    items = []
    for row in rows:
        item = dict(row)
        where_cc, blamed_cc, tagged, in_gulf = (item.pop(k) for k in ("where_cc", "blamed_cc", "tagged", "gulf"))
        if where_cc is None:        # arrived since the collector last tagged articles
            item["_tags"] = tags_for(item)
            in_gulf = is_gulf(item, *item["_tags"][:2])
        else:
            item["_tags"] = (_split(where_cc), _split(blamed_cc), _split(tagged or ""))
        if gulf_only and not in_gulf:
            continue
        item["link"] = safe_link(item["link"])
        item["age"] = ago(item["published"], now)
        item["cves"] = [c for c in (item["cves"] or "").split(",") if c]
        items.append(item)

    # Two stable sorts: newest first, then by severity. Result: red block on top,
    # newest-first within each colour.
    items.sort(key=lambda i: i["published"] or "", reverse=True)
    items.sort(key=lambda i: RANK.get(i["severity"], len(RANK)))
    return items


def group(conn, days=None, start=None, end=None, gulf_only=False):
    """One entry per story. When several outlets covered it, the highest-ranked
    article leads (so the story takes its colour), and the rest are listed under
    "also" with their CVEs and countries added to the lead's."""
    stories = group_stories(ungrouped(conn, days, start, end, gulf_only), RANK)
    for story in stories:
        others = story["also"]
        members = [story, *others]
        story["cves"] = sorted(set(story["cves"]).union(*(m["cves"] for m in others)))
        story["kev"] = int(any(m["kev"] for m in members))
        where, blamed, products = set(), set(), set()
        for m in members:
            w, b, p = m["_tags"]
            where.update(w)
            blamed.update(b)
            if story["severity"] in stack.SECURITY_SEVERITIES:
                products.update(p)
        story["where"], story["blamed"] = sorted(where), sorted(blamed)
        story["products"] = sorted(products)
        del story["_tags"]
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


def _packed(stories):
    """A window's stories as saved: compressed JSON, about 4.5 times smaller, which matters
    once every run is copied to Turso. Without the "5m ago" ages, which pages work out on
    each visit anyway, so a window that hasn't changed packs to the same bytes."""
    for story in stories:
        for s in (story, *story["also"]):
            s["age"] = ""
    return zlib.compress(json.dumps(stories).encode())


def save_all(conn):
    """Group every window the pages use and save the ones that changed since the last run.
    Run by the collector after scoring. Returns (windows changed, windows in all)."""
    now = datetime.now(timezone.utc)
    windows = {days_key(d): {"days": d} for d in SAVED_DAYS}
    windows[GULF_KEY] = {"days": gulf_days(first_published(conn), now), "gulf_only": True}
    current = briefing.week_start(briefing.week_id(now))
    for back in range(SAVED_WEEKS):
        start = current - timedelta(days=7 * back)
        windows[week_key(start)] = {"start": start, "end": start + timedelta(days=7)}

    stored = {key: (fmt, blob) for key, fmt, blob in conn.execute("SELECT key, format, stories FROM story_groups")}
    changed = []
    for key, window in windows.items():
        packed = _packed(group(conn, **window))
        if stored.get(key) != (FORMAT, packed):
            changed.append((key, FORMAT, packed, now.isoformat()))
    with conn:      # one transaction: pages see the old set or the new one, never half
        conn.executemany("DELETE FROM story_groups WHERE key = ?", [(k,) for k in stored if k not in windows])
        conn.executemany("INSERT OR REPLACE INTO story_groups (key, format, stories, made_at) VALUES (?, ?, ?, ?)",
                         changed)
    return len(changed), len(windows)
