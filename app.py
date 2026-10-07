import re
import secrets
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, Response, g, jsonify, render_template, request

from db import DB_PATH, connect
from dedupe import group_stories

app = Flask(__name__)

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
HASH_PREFIX_RE = re.compile(r"^[0-9A-F]{5}$")

# Order matters: this is the sort order and the order of the filter tiles.
SEVERITIES = [
    ("red", "Major"),
    ("orange", "Medium"),
    ("yellow", "Low"),
    ("green", "Tech & AI"),
    ("blue", "Events"),
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


def load_items_ungrouped(days):
    """Every item in the window, one per article."""
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


# What the page needs about each other outlet covering a story.
ALSO_FIELDS = ("source", "title", "link", "age", "match")


def load_items(days):
    """One entry per story. When several outlets covered it, the highest-ranked
    article leads (so the story takes its colour), and the rest are listed under
    "also" with their CVEs added to the lead's."""
    stories = group_stories(load_items_ungrouped(days), RANK)
    for story in stories:
        others = story["also"]
        story["cves"] = sorted(set(story["cves"]).union(*(m["cves"] for m in others)))
        story["kev"] = int(any(m["kev"] for m in [story, *others]))
        story["also"] = [{k: m.get(k) for k in ALSO_FIELDS} for m in others]
    return stories


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


@app.before_request
def make_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def inject_csp_nonce():
    return {"csp_nonce": g.get("csp_nonce", "")}


@app.after_request
def security_headers(resp):
    """Only scripts and styles carrying this request's nonce may run, and pages may
    only talk to this server. So even if feed content slipped past escaping, it
    couldn't run script, and the password page can't send anything anywhere else."""
    nonce = g.get("csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
        "img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


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


@app.route("/password")
def password():
    return render_template("password.html")


@app.route("/scan")
def scan():
    return render_template("scan.html")


@app.route("/api/pwned/<prefix>")
def pwned_range(prefix):
    """Relay a 5-character hash prefix to Pwned Passwords. The browser never sends
    anything more, so this server can't learn the password either. Relaying (rather
    than the browser calling HIBP directly) keeps visitors' IPs away from HIBP and
    lets the page's security policy forbid connections to any other site."""
    prefix = prefix.upper()
    if not HASH_PREFIX_RE.match(prefix):
        return jsonify(error="expected 5 hex characters"), 400
    try:
        upstream = requests.get(
            PWNED_RANGE_URL.format(prefix),
            # Padding adds fake entries so the response size doesn't hint at the prefix.
            headers={"Add-Padding": "true", "User-Agent": "SentryFeed"},
            timeout=10,
        )
        upstream.raise_for_status()
    except requests.RequestException:
        return jsonify(error="breach database unreachable"), 502
    resp = Response(upstream.text, mimetype="text/plain")
    resp.headers["Cache-Control"] = "no-store"
    return resp


if __name__ == "__main__":
    # 0.0.0.0 = reachable from other devices on your network, not just the Pi itself.
    app.run(host="0.0.0.0", port=5000)
