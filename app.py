import copy
import gzip
import os
import re
import secrets
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import sqlite3

import requests
from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, url_for
from itsdangerous import BadSignature, URLSafeTimedSerializer

from db import connect, last_collected
from dedupe import group_stories
from geo import locate
import briefing
import events
import stack
import stocks
import vulns

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
app.jinja_env.filters["country"] = lambda cc: briefing.NAMES.get(cc, cc)   # "AE" -> "United Arab Emirates"
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
ALSO_FIELDS = ("id", "source", "title", "link", "age", "published", "match")

# Grouped stories per window, kept until the collector runs again. Grouping takes a few
# seconds on the Pi, and the stories only change when the collector runs.
_STORY_CACHE = {}


def load_items(days):
    """One entry per story, ready for the pages (see _group_items). Each call gets its
    own copy, with ages worked out afresh and anything older than the window dropped."""
    stamp = collected_time()
    cached = _STORY_CACHE.get(days)
    if cached is None or cached[0] != stamp:
        cached = (stamp, _group_items(days))
        _STORY_CACHE[days] = cached
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=days)).isoformat()
    stories = copy.deepcopy([s for s in cached[1] if not s["published"] or s["published"] >= cutoff])
    for story in stories:
        story["age"] = ago(story["published"], now)
        for other in story["also"]:
            other["age"] = ago(other["published"], now)
    return briefing.prepare(stories)


def _group_items(days):
    """One entry per story. When several outlets covered it, the highest-ranked
    article leads (so the story takes its colour), and the rest are listed under
    "also" with their CVEs and countries added to the lead's."""
    stories = group_stories(load_items_ungrouped(days), RANK)
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


def collected_time():
    """When the collector last finished (db.last_collected), read once per request."""
    if "collected" not in g:
        conn = connect()
        try:
            g.collected = last_collected(conn)
        finally:
            conn.close()
    return g.collected


def last_updated():
    """ "12m ago" since the collector last finished, or None before the first run."""
    when = collected_time()
    return ago(when.isoformat(), datetime.now(timezone.utc)) if when else None


def window_days(default=DEFAULT_DAYS):
    days = request.args.get("days", default, type=int)
    return days if days in dict(WINDOWS) else default


@app.before_request
def make_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def inject_page_basics():
    """What every page's masthead, menus and footer need."""
    when = collected_time()
    collected = when.astimezone(briefing.DUBAI) if when else None
    return {
        "csp_nonce": g.get("csp_nonce", ""),
        "site_nav": briefing.NAV,
        "site_footer": briefing.FOOTER,
        "site_today": datetime.now(briefing.DUBAI),
        "site_collected": collected,
        "site_updated": last_updated(),
    }


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
    return compress(resp)


# Pages that echo back what a visitor typed, next to a token. Compressing those could let an
# attacker guess the token from response sizes (the BREACH attack), so they go uncompressed.
NO_COMPRESS = {"/events/submit"}


def compress(resp):
    """Gzip HTML pages. The map's shapes shrink to about a third, which matters on the Pi."""
    if (resp.mimetype == "text/html" and resp.status_code in (200, 400, 503) and not resp.direct_passthrough
            and request.path not in NO_COMPRESS and "Content-Encoding" not in resp.headers
            and "gzip" in request.headers.get("Accept-Encoding", "")):
        body = resp.get_data()
        if len(body) > 1024:
            resp.set_data(gzip.compress(body, compresslevel=6))
            resp.headers["Content-Encoding"] = "gzip"
            resp.headers["Vary"] = "Accept-Encoding"
    return resp


def page_or_unavailable(template, build, **context):
    """Render a page from build(), or the same template in its error state if the
    database can't be read (the collector may be part-way through a run)."""
    try:
        data, error = build(), None
    except (sqlite3.Error, OSError) as exc:
        data, error = None, type(exc).__name__
    page = render_template(template, data=data, error=error, **context)
    return (page, 503) if error else page


@app.route("/")
def home():
    # Old bookmarks of the feed, like /?days=3, still land on the feed.
    if "days" in request.args:
        return redirect(url_for("feed", days=window_days()), code=301)

    def build():
        stories = load_items(14)
        attach_stock_summaries(stories)
        incidents = load_incidents()
        for inc in incidents:
            for story in inc["stories"]:
                story["link"] = safe_link(story["link"])
        conn = connect()
        try:
            upcoming = events.upcoming(conn)[:3]
        finally:
            conn.close()
        for e in upcoming:
            e["url"] = safe_link(e["url"])
        return briefing.front_page(stories, incidents, upcoming)

    return page_or_unavailable("home.html", build, active="home", gulf_view=" ".join(map(str, briefing.GULF_VIEW)),
                               gulf_shapes=briefing.GULF_SHAPES, world_lite=briefing.WORLD_LITE,
                               centres=briefing.CENTRES, has_sec_contact=bool(stocks.sec_contact()))


@app.route("/feed")
def feed():
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
        "feed.html",
        active="feed",
        items=items,
        counts=counts,
        tiles=[(k, label) for k, label in SEVERITIES if counts[k] or k not in OPTIONAL_TILES],
        country_names=briefing.NAMES,
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
        summary = {k: inc[k] for k in ("company", "display_ticker", "change", "market_change",
                                         "market_name", "no_prices", "exchange", "us")}
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


MAP_DAYS = 7     # a week gives the map enough countries to be worth reading


@app.route("/map")
def world_map():
    days = window_days(MAP_DAYS)
    return page_or_unavailable("map.html", lambda: briefing.map_page(load_items(days)), active="map",
                               days=days, windows=WINDOWS, world=briefing.WORLD_SHAPES,
                               gulf_view=" ".join(map(str, briefing.GULF_VIEW)))


STACK_DAYS = 14
STACK_FIELDS = ("title", "link", "source", "age", "severity", "severity_reason", "kev", "products")


@app.route("/stack")
def my_stack():
    stories = [s for s in load_items(STACK_DAYS) if s["products"]]
    return render_template(
        "stack.html",
        catalog=stack.catalog(),
        names=stack.NAMES,
        stories=[{**{k: s[k] for k in STACK_FIELDS}, "title": s["headline"], "severity_reason": s["reason"],
                  "sources": 1 + len(s["also"])} for s in stories],
        days=STACK_DAYS,
        severities=SEVERITIES,
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


VULN_NEWS_DAYS = 7


@app.route("/vulns")
def vulnerabilities():
    # The lookup form sends ?cve=...; a valid ID goes to its own page, anything else is explained here.
    asked = request.args.get("cve")
    if asked is not None:
        cve_id = vulns.normalise(asked)
        if cve_id:
            return redirect(url_for("vulnerability", cve_id=cve_id), code=303)

    def build():
        conn = connect()
        try:
            recent = vulns.recent_kev(conn)
            for row in recent:
                row["due"] = vulns.due_words(row["due_date"])
                row["epss_text"] = vulns.epss_words(row["epss"])
                row["products"] = stack.match({"title": f"{row['vendor']} {row['product']}", "summary": row["name"]})
                row["stories"] = len(vulns.stories_mentioning(conn, row["cve_id"]))
            stories = [s for s in load_items(VULN_NEWS_DAYS) if s["severity"] in briefing.SECURITY]
            news = vulns.news_by_likelihood(conn, stories)
            for row in news:
                row["epss_text"] = vulns.epss_words(row["epss"])
            return {"recent": recent, "kev_total": vulns.kev_total(conn), "news": news}
        finally:
            conn.close()

    page = page_or_unavailable("vulns.html", build, active="vulns", news_days=VULN_NEWS_DAYS,
                               asked=asked, stack_names=stack.NAMES)
    return (page, 400) if asked is not None and isinstance(page, str) else page


@app.route("/vulns/<cve_id>")
def vulnerability(cve_id):
    normal = vulns.normalise(cve_id)
    if not normal:
        abort(404)
    if normal != cve_id:
        return redirect(url_for("vulnerability", cve_id=normal), code=301)
    conn = connect()
    try:
        kev = conn.execute("SELECT * FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
        details, score, note = vulns.look_up(conn, cve_id, events.visitor_key(app.config["SECRET_KEY"], visitor_address()))
        stories = vulns.stories_mentioning(conn, cve_id)
    finally:
        conn.close()
    for s in stories:
        s["link"] = safe_link(s["link"])
        s["headline"] = briefing.clean_title(s)
    if details:
        details["refs"] = [r for r in details["refs"] if safe_link(r["url"])]
    kev = dict(kev) if kev else None
    if kev:
        kev["due"] = vulns.due_words(kev["due_date"])
        kev["notes_links"] = [u for u in (n.strip() for n in (kev["notes"] or "").split(";")) if safe_link(u)]
    # A heading in words: CISA's name for the flaw, or Microsoft's (one advisory per CVE, so its
    # title names this flaw; other outlets' headlines can cover several and aren't used).
    title = kev["name"] if kev else next((s["headline"] for s in stories if s["source"] == "Microsoft MSRC"), None)
    return render_template("vuln.html", active="vulns", cve_id=cve_id, kev=kev, details=details, score=score, title=title,
                           note=note, stories=stories, epss_text=vulns.epss_words(score["score"]) if score else None,
                           percentile_text=vulns.percentile_words(score["percentile"]) if score else None)


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
