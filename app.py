import os
import re
import secrets
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import Flask, Response, g, jsonify, redirect, render_template, request, url_for
from itsdangerous import BadSignature, URLSafeTimedSerializer

from db import DB_PATH, connect
from dedupe import group_stories
from geo import NAMES as COUNTRY_NAMES, locate
import events
import stocks

SECRET_FILE = Path(__file__).with_name(".flask_secret")


def load_secret():
    """A random key made on first run and kept in .flask_secret (never committed).
    O_EXCL means two gunicorn workers starting at once can't each make a different key."""
    try:
        fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        for _ in range(50):        # the other worker may still be writing it
            key = SECRET_FILE.read_text().strip()
            if key:
                return key
            time.sleep(0.05)
        raise RuntimeError(".flask_secret is empty; delete it and restart")
    key = secrets.token_hex(32)
    with os.fdopen(fd, "w") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.config["SECRET_KEY"] = load_secret()
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024     # forms only; nothing big is ever posted
FORM_SIGNER = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="event-form")
FORM_MAX_AGE = 2 * 3600       # a form left open longer than this has to be reloaded
FORM_MIN_SECONDS = 3          # people take longer than this to fill it in; bots often don't

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
# Events are rare, so their tile only appears when there's at least one to show.
OPTIONAL_TILES = {"blue"}
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
ALSO_FIELDS = ("id", "source", "title", "link", "age", "match")


def load_items(days):
    """One entry per story. When several outlets covered it, the highest-ranked
    article leads (so the story takes its colour), and the rest are listed under
    "also" with their CVEs and countries added to the lead's."""
    stories = group_stories(load_items_ungrouped(days), RANK)
    for story in stories:
        others = story["also"]
        members = [story, *others]
        story["cves"] = sorted(set(story["cves"]).union(*(m["cves"] for m in others)))
        story["kev"] = int(any(m["kev"] for m in members))
        where, blamed = set(), set()
        for m in members:
            w, b = locate(m)
            where.update(w)
            blamed.update(b)
        story["where"], story["blamed"] = sorted(where), sorted(blamed)
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
    attach_stock_summaries(items)
    # Listed events starting soon join the event posts under the Events tile, first.
    conn = connect()
    try:
        listed = events.as_feed_items(events.upcoming(conn, within=events.SHOW_ON_FEED))
    finally:
        conn.close()
    for item in listed:
        item["link"] = safe_link(item["link"])
    first_blue = next((i for i, item in enumerate(items) if item["severity"] == "blue"), len(items))
    items[first_blue:first_blue] = listed
    counts = Counter(i["severity"] for i in items)
    return render_template(
        "index.html",
        items=items,
        counts=counts,
        tiles=[(k, label) for k, label in SEVERITIES if counts[k] or k not in OPTIONAL_TILES],
        country_names=COUNTRY_NAMES,
        kev_count=sum(1 for i in items if i["kev"]),
        severities=SEVERITIES,
        windows=WINDOWS,
        days=days,
        updated=last_updated(),
    )


def load_incidents():
    conn = connect()
    try:
        return stocks.incidents(conn)
    finally:
        conn.close()


def attach_stock_summaries(items):
    """Give each feed story that names a breached US-listed company a one-line stock summary."""
    by_item = {}
    for inc in load_incidents():
        summary = {k: inc[k] for k in ("company", "ticker", "change", "market_change")}
        summary["sec"] = bool(inc["filings"])
        for story in inc["stories"]:
            by_item.setdefault(story["item_id"], summary)
    for item in items:
        for member_id in [item["id"], *(m["id"] for m in item["also"])]:
            if member_id in by_item:
                item["stock"] = by_item[member_id]
                break


@app.route("/stocks")
def stock_impact():
    conn = connect()
    try:
        incidents = stocks.incidents(conn)
        watch = stocks.vendor_watch(conn)
    finally:
        conn.close()
    for story in [s for inc in incidents for s in inc["stories"]] + [s for v in watch["vendors"] for s in v["stories"]]:
        story["link"] = safe_link(story["link"])
    return render_template(
        "stocks.html",
        incidents=incidents,
        watch=watch,
        watch_days=stocks.WATCH_TRADING_DAYS,
        has_prices_key=bool(stocks.av_key()),
        has_sec_contact=bool(stocks.sec_contact()),
        lookback=stocks.LOOKBACK_DAYS,
        updated=last_updated(),
    )


# Stories on the map: incidents only, not tech news or events.
MAP_SEVERITIES = ("red", "orange", "yellow")
MAP_FIELDS = ("title", "link", "source", "age", "severity", "where", "blamed")


@app.route("/map")
def world_map():
    days = window_days()
    stories = [s for s in load_items(days) if s["severity"] in MAP_SEVERITIES]
    placed = [s for s in stories if s["where"] or s["blamed"]]
    return render_template(
        "map.html",
        stories=[{**{k: s[k] for k in MAP_FIELDS}, "sources": 1 + len(s["also"])} for s in placed],
        unplaced=len(stories) - len(placed),
        country_names=COUNTRY_NAMES,
        severities=SEVERITIES,
        windows=WINDOWS,
        days=days,
        updated=last_updated(),
    )


@app.route("/events")
def events_page():
    conn = connect()
    try:
        upcoming = events.upcoming(conn)
    finally:
        conn.close()
    for e in upcoming:
        e["url"] = safe_link(e["url"])
    return render_template("events.html", events=upcoming, kinds=events.KINDS)


def visitor_address():
    # Behind a reverse proxy (Vercel later) this becomes the proxy's address; see README.
    return request.remote_addr or ""


@app.route("/events/submit", methods=["GET", "POST"])
def submit_event():
    if request.method == "GET":
        return render_template("event_submit.html", kinds=events.KINDS, form={}, errors={},
                               token=FORM_SIGNER.dumps(int(time.time())),
                               sent=request.args.get("sent") == "1", default_tz=events.DEFAULT_TZ)

    form = request.form
    def again(errors, problem=None):
        return render_template("event_submit.html", kinds=events.KINDS, form=form, errors=errors,
                               problem=problem, token=FORM_SIGNER.dumps(int(time.time())),
                               sent=False, default_tz=events.DEFAULT_TZ), 400

    # Bots: a hidden field people never see, and a form filled in impossibly fast.
    # Both get the normal "thanks" page so they learn nothing, and nothing is saved.
    try:
        issued = FORM_SIGNER.loads(form.get("token", ""), max_age=FORM_MAX_AGE)
    except BadSignature:
        return again({}, "This form expired. Please check the details and submit again.")
    if form.get("website") or time.time() - issued < FORM_MIN_SECONDS:
        return redirect(url_for("submit_event", sent=1), code=303)

    data, errors = events.validate(form)
    if errors:
        return again(errors)
    conn = connect()
    try:
        submitter = events.visitor_key(app.config["SECRET_KEY"], visitor_address())
        refusal = events.can_submit(conn, submitter)
        if refusal:
            return again({}, refusal)
        events.save(conn, data, submitter)
    finally:
        conn.close()
    # Redirect after posting, so refreshing the thanks page doesn't submit it twice.
    return redirect(url_for("submit_event", sent=1), code=303)


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
