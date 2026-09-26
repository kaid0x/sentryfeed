from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request

from db import DB_PATH, connect

app = Flask(__name__)

# Order matters: this is the sort order and the order of the filter tiles.
SEVERITIES = [
    ("red", "Major"),
    ("orange", "Medium"),
    ("yellow", "Low"),
    ("green", "Tech & AI"),
]
RANK = {key: i for i, (key, _) in enumerate(SEVERITIES)}
WINDOWS = [(1, "24h"), (3, "3 days"), (7, "7 days"), (14, "14 days")]
DEFAULT_DAYS = 3


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


def load_items(days):
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=days)).isoformat()
    conn = connect()
    rows = conn.execute(
        """SELECT id, category, source, title, summary, link, published,
                  cves, cvss, kev, severity, severity_reason
           FROM items
           WHERE severity IS NOT NULL AND (published IS NULL OR published >= ?)""",
        (cutoff,),
    ).fetchall()
    conn.close()

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


def last_updated():
    """Every collector run rewrites severities, so the database file's
    modification time is the time of the last run."""
    if not DB_PATH.exists():
        return None
    mtime = datetime.fromtimestamp(DB_PATH.stat().st_mtime, timezone.utc)
    return ago(mtime.isoformat(), datetime.now(timezone.utc))


def window_days():
    days = request.args.get("days", DEFAULT_DAYS, type=int)
    return days if days in dict(WINDOWS) else DEFAULT_DAYS


@app.route("/")
def index():
    days = window_days()
    items = load_items(days)
    return render_template(
        "index.html",
        items=items,
        counts=Counter(i["severity"] for i in items),
        kev_count=sum(1 for i in items if i["kev"]),
        severities=SEVERITIES,
        windows=WINDOWS,
        days=days,
        updated=last_updated(),
    )


@app.route("/api/items")
def api_items():
    """Same data as JSON. The world map will read from here later."""
    return jsonify(load_items(window_days()))


if __name__ == "__main__":
    # 0.0.0.0 = reachable from other devices on your network, not just the Pi itself.
    app.run(host="0.0.0.0", port=5000)
