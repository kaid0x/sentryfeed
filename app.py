import copy
import gzip
import os
import re
import secrets
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from flask import (Flask, Response, abort, g, has_request_context, jsonify, make_response, redirect,
                   render_template, request, url_for)
from itsdangerous import BadSignature, URLSafeTimedSerializer

from db import DATABASE_ERRORS, ERRORS as DB_ERRORS, connect as open_database, last_collected
from grouping import RANK, SEVERITIES, ago, safe_link
import briefing
import domaincheck
import events
import grouping
import ics
import learn
import ransomware
import rss
import stack
import stocks
import trigger
import vulns

SECRET_FILE = Path(__file__).with_name(".flask_secret")


def load_secret():
    """FLASK_SECRET_KEY from the environment (Vercel), or a random key made on first run and
    kept in .flask_secret (never committed). O_EXCL means two gunicorn workers starting at
    once can't each make a different key."""
    if os.environ.get("FLASK_SECRET_KEY", "").strip():
        return os.environ["FLASK_SECRET_KEY"].strip()
    if os.environ.get("VERCEL"):
        # Vercel's files are read-only, and a key made per instance would differ between them.
        raise RuntimeError("Set FLASK_SECRET_KEY in the Vercel project's environment variables")
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
app.jinja_env.filters["glossed"] = briefing.glossed                         # marks a reason's term
FORM_SIGNER = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="event-form")
FORM_MAX_AGE = 2 * 3600       # a form left open longer than this has to be reloaded
FORM_MIN_SECONDS = 3          # people take longer than this to fill it in; bots often don't

PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/{}"
HASH_PREFIX_RE = re.compile(r"^[0-9A-F]{5}$")

# Events are rare, so their tile only appears when there's at least one to show.
OPTIONAL_TILES = {"blue"}
WINDOWS = [(1, "24h"), (3, "3 days"), (7, "7 days"), (14, "14 days")]
DEFAULT_DAYS = 3


# Grouped stories per window, kept until the collector runs again. The collector saves them
# (grouping.save_all), so this only saves re-reading them from the database on every visit.
_STORY_CACHE = {}


def _grouped(key, **window):
    """The collector's saved grouping for this window, or grouped now if it has none."""
    conn = connect()
    try:
        stories = grouping.saved(conn, key)
        if stories is None:
            if key.startswith("days:"):
                app.logger.warning("No saved grouping for the %s-day window, so grouping it now",
                                   window["days"])
            stories = grouping.group(conn, **window)
    finally:
        conn.close()
    return stories


def load_items(days, gulf_only=False):
    """One entry per story, ready for the pages (see grouping.group). Each call gets its
    own copy, with ages worked out afresh and anything older than the window dropped.
    With gulf_only, only stories from Gulf outlets or naming a GCC country (for /gulf)."""
    stamp = collected_time()
    key = grouping.GULF_KEY if gulf_only else grouping.days_key(days)
    cached = _STORY_CACHE.get(key)
    if cached is None or cached[0] != stamp:
        cached = (stamp, _grouped(key, days=days, gulf_only=gulf_only))
        _STORY_CACHE[key] = cached
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=days)).isoformat()
    stories = copy.deepcopy([s for s in cached[1] if not s["published"] or s["published"] >= cutoff])
    for story in stories:
        story["age"] = ago(story["published"], now)
        for other in story["also"]:
            other["age"] = ago(other["published"], now)
    return briefing.prepare(stories)


def load_week(start, end):
    """One entry per story published in [start, end), e.g. a digest's week. Cached like load_items."""
    key = ("week", start.isoformat())
    stamp = collected_time()
    cached = _STORY_CACHE.get(key)
    if cached is None or cached[0] != stamp:
        cached = (stamp, _grouped(grouping.week_key(start), start=start, end=end))
        _STORY_CACHE[key] = cached
    now = datetime.now(timezone.utc)
    stories = copy.deepcopy(cached[1])
    for story in stories:
        story["age"] = ago(story["published"], now)
        for other in story["also"]:
            other["age"] = ago(other["published"], now)
    return briefing.prepare(stories)


def connect():
    """A database connection. Once the database has failed during a request, later attempts
    in the same request fail straight away instead of waiting out the timeout again."""
    if has_request_context() and g.get("db_error"):
        raise g.db_error
    return open_database()


def collected_time():
    """When the collector last finished (db.last_collected), read once per request. None if
    the database can't be read (then g.db_error), so pages that don't need it, like the tools, still load."""
    if "collected" not in g:
        g.collected = None
        try:
            conn = connect()
            try:
                g.collected = last_collected(conn)
            finally:
                conn.close()
        except DB_ERRORS as exc:
            g.db_error = exc
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
        "site_glossary": briefing.GLOSSARY,
        "site_today": datetime.now(briefing.DUBAI),
        "site_collected": collected,
        "site_updated": last_updated(),
        "site_db_down": "db_error" in g,
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


# Pages that echo back what a visitor typed, next to a form token: the setup the BREACH attack
# uses to guess a secret from response sizes, so SentryFeed doesn't compress them. (Vercel's CDN
# compresses them anyway and has no switch for one page. That's safe here: the token is a signed
# timestamp anyone gets by opening the form, and with no logins there's no secret to guess.)
NO_COMPRESS = {"/events/submit"}


def compress(resp):
    """Gzip HTML pages and feeds. The map's shapes shrink to about a third, which matters on the Pi."""
    if request.path in NO_COMPRESS:
        resp.headers["Cache-Control"] = "no-store"     # a page with a fresh token stays out of caches
        return resp
    if (resp.mimetype in ("text/html", "application/rss+xml") and resp.status_code in (200, 400, 503) and not resp.direct_passthrough
            and "Content-Encoding" not in resp.headers
            and "gzip" in request.headers.get("Accept-Encoding", "")):
        body = resp.get_data()
        if len(body) > 1024:
            resp.set_data(gzip.compress(body, compresslevel=6))
            resp.headers["Content-Encoding"] = "gzip"
            resp.headers["Vary"] = "Accept-Encoding"
    return resp


@app.errorhandler(DATABASE_ERRORS[0])
def database_unavailable(exc):
    """A page without its own error state (see page_or_unavailable) couldn't read the
    database: say so plainly, with 503 so feed readers and crawlers try again later."""
    g.db_error = exc
    error = type(exc).__name__
    if request.path.startswith("/api/"):
        return jsonify(error=f"database unavailable ({error})"), 503
    if request.path.startswith("/feeds/"):
        return Response(f"SentryFeed couldn't read its database ({error}). Try again in a few minutes.\n",
                        503, mimetype="text/plain")
    return render_template("unavailable.html", error=error, active=None), 503


if len(DATABASE_ERRORS) > 1:        # turso-serverless's errors, when it's installed
    app.register_error_handler(DATABASE_ERRORS[1], database_unavailable)


def page_or_unavailable(template, build, **context):
    """Render a page from build(), or the same template in its error state if the
    database can't be read (the collector may be part-way through a run)."""
    try:
        data, error = build(), None
    except DB_ERRORS as exc:
        data, error = None, type(exc).__name__
        g.db_error = exc
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
WATCH_TEXT_CHARS = 400      # the start of a summary watch words are matched in, as for products (stack.match)


def stack_entry(s):
    return {**{k: s[k] for k in STACK_FIELDS}, "title": s["headline"], "severity_reason": s["reason"],
            "sources": 1 + len(s["also"])}


@app.route("/stack")
def my_stack():
    stories = [s for s in load_items(STACK_DAYS) if s["products"]]
    return render_template(
        "stack.html",
        catalog=stack.catalog(),
        names=stack.NAMES,
        stories=[stack_entry(s) for s in stories],
        days=STACK_DAYS,
        severities=SEVERITIES,
    )


@app.route("/api/watch")
def api_watch():
    """Every security story of the last STACK_DAYS days, with the start of its summary, for watch
    words. My stack and the front page fetch it only when the visitor has saved watch words, so
    other visitors don't download it; the request carries no words, which stay in the browser."""
    stories = [s for s in load_items(STACK_DAYS) if s["severity"] in stack.SECURITY_SEVERITIES]
    resp = jsonify([{**stack_entry(s), "link": safe_link(s["link"]),
                     "text": (s.get("summary") or "")[:WATCH_TEXT_CHARS]} for s in stories])
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp


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
            mentions = vulns.mention_counts(conn, (row["cve_id"] for row in recent))
            for row in recent:
                row["due"] = vulns.due_words(row["due_date"])
                row["epss_text"] = vulns.epss_words(row["epss"])
                row["products"] = stack.match({"title": f"{row['vendor']} {row['product']}", "summary": row["name"]})
                row["stories"] = mentions.get(row["cve_id"], 0)
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
        kev["vendor_slug"] = vulns.vendor_slug(kev["vendor"])
        kev["notes_links"] = [u for u in (n.strip() for n in (kev["notes"] or "").split(";")) if safe_link(u)]
    # A heading in words: CISA's name for the flaw, or Microsoft's (one advisory per CVE, so its
    # title names this flaw; other outlets' headlines can cover several and aren't used).
    title = kev["name"] if kev else next((s["headline"] for s in stories if s["source"] == "Microsoft MSRC"), None)
    return render_template("vuln.html", active="vulns", cve_id=cve_id, kev=kev, details=details, score=score, title=title,
                           note=note, stories=stories, learning=learn.for_cve(details, kev), epss_text=vulns.epss_words(score["score"]) if score else None,
                           percentile_text=vulns.percentile_words(score["percentile"]) if score else None)


def first_story_time():
    """When SentryFeed's first story was published, or None with no stories yet."""
    conn = connect()
    try:
        return grouping.first_published(conn)
    finally:
        conn.close()


def first_week_start():
    """Monday of the week SentryFeed's first story was published, or None with no stories yet."""
    first = first_story_time()
    return briefing.week_start(briefing.week_id(first)) if first else None


@app.route("/digest")
def digest_latest():
    """The latest finished week, or this week so far if SentryFeed is younger than that."""
    now = datetime.now(timezone.utc)
    first = first_week_start()
    latest = briefing.week_start(briefing.week_id(now - timedelta(days=7)))
    if first is None or latest < first:
        latest = briefing.week_start(briefing.week_id(now))
    return redirect(url_for("digest_week", week=briefing.week_id(latest)), code=302)


@app.route("/digest/<week>")
def digest_week(week):
    start = briefing.week_start(week)
    if start is None:
        abort(404)
    canonical = briefing.week_id(start)
    if week != canonical:
        return redirect(url_for("digest_week", week=canonical), code=301)
    now = datetime.now(timezone.utc)
    current = briefing.week_start(briefing.week_id(now))
    first = first_week_start()
    if first is None or start < first or start > current:
        abort(404)
    end, prev_start = start + timedelta(days=7), start - timedelta(days=7)
    # Only compare two whole weeks: not the first week (collection started part-way through),
    # and not this week, which isn't over yet.
    first_story = first_story_time()
    compare = prev_start >= first_story and start != current

    def week_incidents(incidents, a, b):
        return [i for i in incidents if a.date().isoformat() <= i["date"] < b.date().isoformat()]

    def build():
        stories = load_week(start, end)
        attach_stock_summaries(stories)
        incidents = load_incidents()
        for inc in incidents:
            for story in inc["stories"]:
                story["link"] = safe_link(story["link"])
        conn = connect()
        try:
            new_kev = vulns.kev_between(conn, start.date(), (end - timedelta(days=1)).date())
            prev = None
            if compare:
                prev_kev = vulns.kev_between(conn, prev_start.date(), (start - timedelta(days=1)).date())
                prev = (load_week(prev_start, start), len(prev_kev), len(week_incidents(incidents, prev_start, start)))
            # Events listed for the week after: from the week's end, or from now if it hasn't ended.
            upcoming = events.upcoming(conn, within=timedelta(days=7), now=max(end, now))
        finally:
            conn.close()
        for e in upcoming:
            e["url"] = safe_link(e["url"])
        for row in new_kev:
            row["epss_text"] = vulns.epss_words(row["epss"])
        return briefing.digest(stories, new_kev, week_incidents(incidents, start, end), upcoming, prev)

    weeks = []
    w = current
    while w >= first:
        weeks.append((briefing.week_id(w), briefing.week_label(w), w == current))
        w -= timedelta(days=7)
    return page_or_unavailable(
        "digest.html", build, active="digest", week=canonical, label=briefing.week_label(start),
        number=int(canonical[-2:]), in_progress=start == current, first_partial=start < first_story,
        compared_with_partial=not compare and prev_start >= first and start != current,
        prev_week=briefing.week_id(prev_start) if prev_start >= first else None,
        next_week=briefing.week_id(end) if end <= current else None, weeks=weeks,
        world_lite=briefing.WORLD_LITE, has_sec_contact=bool(stocks.sec_contact()),
    )


def stack_products(vendor, product, name):
    """My stack product ids a CISA entry is about, using the same matching as stories."""
    return stack.match({"title": f"{vendor} {product}", "summary": name})


def build_patch_queue():
    stories = [s for s in load_items(vulns.QUEUE_NEWS_DAYS) if s["severity"] in briefing.SECURITY]
    conn = connect()
    try:
        return vulns.patch_queue(conn, stories, stack_products)
    finally:
        conn.close()


@app.route("/patch")
def patch_first():
    def build():
        queue = build_patch_queue()
        for row in queue:
            row["fix_link"] = safe_link(row["fix_link"])
            if row["story"]:
                row["story"]["link"] = safe_link(row["story"]["link"])
        return {"queue": queue}

    return page_or_unavailable("patch.html", build, active="patch", stack_names=stack.NAMES,
                               news_days=vulns.QUEUE_NEWS_DAYS, kev_days=vulns.QUEUE_KEV_DAYS,
                               points={"kev": vulns.POINTS_KEV, "ransomware": vulns.POINTS_RANSOMWARE,
                                       "epss": vulns.POINTS_EPSS, "cvss": vulns.POINTS_CVSS_MAX,
                                       "article": vulns.POINTS_PER_ARTICLE, "news": vulns.POINTS_NEWS_MAX,
                                       "due": vulns.POINTS_DUE_SOON, "due_days": vulns.DUE_SOON_DAYS})


VENDOR_NEWS_DAYS = 14
TIMING_MIN_FLAWS = 5     # below this many dated flaws, a median would mislead


_VENDOR_CACHE = {}


@app.route("/vendors")
def vendors():
    def build():
        # Only changes when CISA's list does, so it's kept until the collector runs again.
        stamp = collected_time()
        if "rows" not in _VENDOR_CACHE or _VENDOR_CACHE["stamp"] != stamp:
            conn = connect()
            try:
                rows = vulns.vendor_index(conn)
            finally:
                conn.close()
            for v in rows:
                v["stack"] = sorted(set().union(*(stack_products(v["vendor"], p, "") for p in v["product_names"])))
            _VENDOR_CACHE.update(stamp=stamp, rows=rows)
        return {"vendors": _VENDOR_CACHE["rows"]}

    return page_or_unavailable("vendors.html", build, active="vendors", stack_names=stack.NAMES)


@app.route("/vendors/<slug>")
def vendor(slug):
    if slug != vulns.vendor_slug(slug):
        canonical = vulns.vendor_slug(slug)
        if not canonical:
            abort(404)
        return redirect(url_for("vendor", slug=canonical), code=301)
    conn = connect()
    try:
        record = vulns.vendor_detail(conn, slug)
    finally:
        conn.close()
    if record is None:
        abort(404)
    pattern = re.compile(rf"\b{re.escape(record['vendor'])}\b", re.I)
    news = [s for s in load_items(VENDOR_NEWS_DAYS)
            if s["severity"] in briefing.SECURITY and pattern.search(s["headline"] or "")][:8]
    return render_template("vendor.html", active="vendors", r=record, news=news, news_days=VENDOR_NEWS_DAYS,
                           timing_min=TIMING_MIN_FLAWS, soon_days=vulns.LISTED_SOON_DAYS, launch=vulns.KEV_LAUNCH_DAY)


SEVERITY_LABEL = dict(SEVERITIES)
MAX_STACK_PRODUCTS = 60


def stack_from_link():
    """Valid product ids from ?stack=a,b,c (unknown ones ignored), in catalogue order."""
    asked = set((request.args.get("stack") or "").lower().split(","))
    return [pid for pid in stack.NAMES if pid in asked][:MAX_STACK_PRODUCTS]


@app.route("/feeds")
def feeds_page():
    feeds = [(name, title, desc, url_for("feed_xml", name=name, _external=True))
             for name, (title, desc) in rss.FEEDS.items()]
    return render_template("feeds.html", active="feeds", feeds=feeds, stack_names=stack.NAMES,
                           stack_base=url_for("feed_xml", name="stack", _external=True), days=rss.FEED_DAYS,
                           cal_url=url_for("deadline_calendar", _external=True), cal_past_days=ics.PAST_DAYS,
                           on_vercel=bool(os.environ.get("VERCEL")))


@app.route("/feeds/<name>.xml")
def feed_xml(name):
    if name != "stack" and name not in rss.FEEDS:
        abort(404)
    page_url = url_for("feeds_page", _external=True)
    feed_url = request.url
    if name == "patch":
        title, desc = rss.FEEDS[name]
        items = [rss.patch_item(row, rank, url_for("vulnerability", cve_id=row["cve_id"], _external=True))
                 for rank, row in enumerate(build_patch_queue(), 1)]
        body = rss.build(title, desc, url_for("patch_first", _external=True), feed_url, items)
    elif name == "events":
        conn = connect()
        try:
            listed = events.upcoming(conn)
        finally:
            conn.close()
        for e in listed:
            e["url"] = safe_link(e["url"])
        title, desc = rss.FEEDS[name]
        body = rss.build(title, desc, page_url, feed_url, [rss.event_item(e) for e in listed])
    else:
        stories = load_items(rss.FEED_DAYS)
        if name == "stack":
            products = stack_from_link()
            if not products:
                return Response("This feed needs ?stack= with product ids from SentryFeed's My stack page, "
                                "e.g. /feeds/stack.xml?stack=fortinet,exchange\n", status=400,
                                mimetype="text/plain")
            mine = set(products)
            chosen = [s for s in stories if s["severity"] in briefing.SECURITY and mine & set(s["products"])]
            names = [stack.NAMES[p] for p in products]
            title = "Your stack: " + (", ".join(names) if len(names) <= 4 else ", ".join(names[:4]) + f" and {len(names) - 4} more")
            desc = "Stories about the products in this link, from SentryFeed's My stack."
        else:
            title, desc = rss.FEEDS[name]
            if name == "major":
                chosen = [s for s in stories if s["severity"] == "red"]
            elif name == "major-medium":
                chosen = [s for s in stories if s["severity"] in ("red", "orange")]
            else:
                chosen = briefing.gulf_stories(stories)[0]
        body = rss.build(title, desc, page_url, feed_url,
                         [rss.story_item(s, SEVERITY_LABEL[s["severity"]]) for s in chosen])
    resp = Response(body, mimetype="application/rss+xml")
    resp.headers["Cache-Control"] = "public, max-age=900"    # readers needn't ask more than every 15 minutes
    return resp


@app.route("/feeds/patch-deadlines.ics")
def deadline_calendar():
    """CISA's fix-by dates as a calendar to subscribe to (ics.py). ?stack= keeps only the flaws
    in those My stack products, matched as on the Patch page."""
    products = stack_from_link()
    if "stack" in request.args and not products:
        return Response("?stack= needs product ids from SentryFeed's My stack page, "
                        "e.g. /feeds/patch-deadlines.ics?stack=fortinet,exchange\n", status=400,
                        mimetype="text/plain")
    since = (vulns.today() - timedelta(days=ics.PAST_DAYS)).isoformat()
    conn = connect()
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT cve_id, vendor, product, name, date_added, due_date, ransomware "
            "FROM kev WHERE due_date >= ?", (since,))]
    finally:
        conn.close()
    if products:
        mine = set(products)
        rows = [r for r in rows if mine & set(stack_products(r["vendor"], r["product"], r["name"]))]
    name = "SentryFeed: CISA deadlines for your stack" if products else "SentryFeed: CISA patch deadlines"
    body = ics.build(rows, name, request.url,
                     lambda cve_id: url_for("vulnerability", cve_id=cve_id, _external=True),
                     url_for("patch_first", _external=True))
    resp = Response(body, mimetype="text/calendar")
    resp.headers["Cache-Control"] = "public, max-age=3600"   # CISA's list changes once a day
    return resp


def visitor_address():
    """The visitor's IP, for rate limits (only ever stored as a keyed hash). On Vercel every
    request arrives through its proxy, which overwrites x-vercel-forwarded-for with the real
    client address, so a visitor can't fake it. Elsewhere (the Pi) that header could be sent
    by anyone, so the connection's own address is used."""
    if os.environ.get("VERCEL"):
        forwarded = request.headers.get("x-vercel-forwarded-for") or request.headers.get("x-forwarded-for") or ""
        return forwarded.split(",")[0].strip()
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


@app.route("/tasks/collect", methods=["GET", "POST"])
def collect_if_due():
    """Visited every 5 minutes by an outside service: starts the collector on GitHub Actions
    when the data is stale (see trigger.py). Plain text, never cached, not for search engines."""
    try:
        status, message = trigger.check(connect)
    except DB_ERRORS as exc:
        status, message = 503, f"Couldn't read the database ({type(exc).__name__})."
    resp = Response(message + "\n", status, mimetype="text/plain")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex"
    return resp


@app.route("/password")
def password():
    return render_template("password.html")


@app.route("/ransomware")
def ransomware_stats():
    def build():
        conn = connect()
        try:
            return ransomware.stats(conn, briefing.GCC)
        finally:
            conn.close()

    return page_or_unavailable("ransomware.html", build, active="ransomware", months_wanted=ransomware.MONTHS)


@app.route("/gulf")
def gulf_pulse():
    first = first_story_time()

    def build():
        days = grouping.gulf_days(first, datetime.now(timezone.utc))
        news = briefing.gulf_pulse(load_items(days, gulf_only=True))
        for s in news["latest"]:
            s["link"] = safe_link(s["link"])
        conn = connect()
        try:
            claims = ransomware.gulf(conn)
        finally:
            conn.close()
        return {"news": news, "claims": claims}

    return page_or_unavailable("gulf.html", build, active="gulf", since=first.astimezone(briefing.DUBAI) if first else None,
                               gcc=briefing.GCC_ORDER, months_wanted=ransomware.MONTHS)


@app.route("/headers")
def headers():
    return render_template("headers.html", active="headers")


@app.route("/domain")
def domain_check():
    """The domain security check (domaincheck.py). ?d= makes a result shareable; a domain
    checked in the last hour shows its saved result, and new checks are rate-limited."""
    raw, raw_selector = request.args.get("d", ""), request.args.get("s", "")
    page = {"active": "domain", "raw": raw, "raw_selector": raw_selector, "verdicts": domaincheck.VERDICTS,
            "groups": domaincheck.GROUPS, "per_hour": domaincheck.CHECKS_PER_VISITOR_HOUR,
            "selector_count": len(domaincheck.DKIM_SELECTORS)}
    if not raw.strip():
        return render_template("domain.html", **page)
    try:
        domain, shown, note = domaincheck.normalize(raw)
        selector = domaincheck.normalize_selector(raw_selector)
    except ValueError as e:
        return render_template("domain.html", problem=str(e), **page), 400
    key = domaincheck.cache_key(domain, selector)
    page.update(domain=domain, shown=shown, note=note, selector=selector,
                share=url_for("domain_check", d=domain, s=selector, _external=True) if selector
                else url_for("domain_check", d=domain, _external=True))
    try:
        conn = connect()
        try:
            result = domaincheck.cached(conn, key)
            if result is None:
                refusal = domaincheck.can_check(conn, events.visitor_key(app.config["SECRET_KEY"], visitor_address()))
                if refusal:
                    resp = make_response(render_template("domain.html", refusal=refusal, **page), 429)
                    resp.headers["X-Robots-Tag"] = "noindex"
                    return resp
                domaincheck.record_check(conn, events.visitor_key(app.config["SECRET_KEY"], visitor_address()))
                result = domaincheck.run(domain, selector=selector)
                if result["checks"]:            # a domain that doesn't exist or a DNS outage isn't saved
                    domaincheck.save(conn, key, result)
        finally:
            conn.close()
    except DB_ERRORS as exc:
        g.db_error = exc
        setting_up = "no such table" in str(exc).lower()
        resp = make_response(render_template("domain.html", db_problem=True, setting_up=setting_up, **page), 503)
        resp.headers["X-Robots-Tag"] = "noindex"
        return resp
    checked = datetime.fromisoformat(result["checked_at"])
    page.update(result=result, score=domaincheck.score(result),
                checked_ago=ago(result["checked_at"], datetime.now(timezone.utc)),
                checked_dubai=checked.astimezone(briefing.DUBAI))
    resp = make_response(render_template("domain.html", **page))
    resp.headers["X-Robots-Tag"] = "noindex"     # results are for whoever asked, not for search engines
    return resp


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
