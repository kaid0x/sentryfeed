"""Redesign prototypes (branch `redesign` only, not linked from the live site).

Three directions built on the same real data so they can be compared side by side:
A, an operations dashboard; B, an intelligence briefing; C, a map-first situation room.
Each has a home page and the password check as its tool page, at /proto/<a|b|c>.
"""
import json
import re
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import abort, render_template
from markupsafe import Markup

import events
import stack
import stocks
from db import DB_PATH, connect
from geo import NAMES as COUNTRY_NAMES

DIRECTIONS = {"a": "Watch floor", "b": "The Briefing", "c": "Situation room"}
SECURITY = ("red", "orange", "yellow")
RANK = {"red": 0, "orange": 1, "yellow": 2, "green": 3, "blue": 4}
GCC = {"AE", "SA", "QA", "KW", "BH", "OM"}
DUBAI = ZoneInfo("Asia/Dubai")
HOME_STORIES = 5
MARKET_DAYS = 30
# Titles that say a flaw is already being used, for stories CISA hasn't listed (yet).
EXPLOITED_RE = re.compile(r"\b(?:exploited|exploiting|exploitation|zero-days?|0-days?|in the wild)\b", re.I)

_TEMPLATES = Path(__file__).with_name("templates")
# The map's shapes without the outer <svg> tag, so each prototype can crop it with its own viewBox.
# The file is built offline by tools/build_world.mjs from Natural Earth, never from feed content.
WORLD_SHAPES = Markup((_TEMPLATES / "_world.svg").read_text().split("\n", 1)[1].rsplit("</svg>", 1)[0])
_POINTS = json.loads((_TEMPLATES / "_world_points.json").read_text())
CENTRES = _POINTS["points"]
NAMES = {**_POINTS["names"], **COUNTRY_NAMES}

FOOTER = [
    ("How it works", "https://github.com/kaid0x/sentryfeed#how-it-works"),
    ("Sources", "https://github.com/kaid0x/sentryfeed/blob/main/feeds.py"),
    ("Code", "https://github.com/kaid0x/sentryfeed"),
    ("Built by Haseeb", "https://mhaseebashfaq.com"),
]


def nav(d):
    """The grouped navigation being tested. A None link is a planned page, shown but not linked."""
    return [
        ("Intel", [("Feed", "/"), ("Map", "/map"), ("Stocks", "/stocks"), ("My stack", "/stack"),
                   ("Vulnerabilities", None), ("Ransomware stats", None),
                   ("Weekly digest", None), ("Gulf pulse", None)]),
        ("Tools", [("Password check", f"/proto/{d}/password"), ("File & link check", "/scan"),
                   ("Email header analyser", None), ("Domain check", None)]),
        ("Community", [("Events", "/events"), ("Submit an event", "/events/submit")]),
    ]


def by_importance(stories):
    """Most important first: severity, then CISA-listed, then how many outlets covered it, then newest."""
    ordered = sorted(stories, key=lambda s: s["published"] or "", reverse=True)
    return sorted(ordered, key=lambda s: (RANK.get(s["severity"], 9), -s["kev"], -len(s["also"])))


def collected_at():
    if not DB_PATH.exists():
        return None
    return datetime.fromtimestamp(DB_PATH.stat().st_mtime, timezone.utc).astimezone(DUBAI)


def hour_strip(day, now):
    """The last 24 hours, oldest first: per hour, security stories by severity and the worst one."""
    hours = [Counter() for _ in range(24)]
    for s in day:
        if s["published"] and s["severity"] in SECURITY:
            ago = int((now - datetime.fromisoformat(s["published"])).total_seconds() // 3600)
            hours[23 - min(max(ago, 0), 23)][s["severity"]] += 1
    strip = []
    for i, counts in enumerate(hours):
        start = (now - timedelta(hours=23 - i)).astimezone(DUBAI)
        worst = next((sev for sev in SECURITY if counts[sev]), None)
        strip.append({"label": start.strftime("%H:00"), "worst": worst, "total": sum(counts.values()),
                      **{sev: counts[sev] for sev in SECURITY}})
    return strip


def daily(stories, now, days=14):
    """Security stories per Dubai calendar day, oldest first."""
    today = now.astimezone(DUBAI).date()
    dates = [today - timedelta(days=n) for n in range(days - 1, -1, -1)]
    counts = {d: Counter() for d in dates}
    for s in stories:
        if s["published"] and s["severity"] in SECURITY:
            d = datetime.fromisoformat(s["published"]).astimezone(DUBAI).date()
            if d in counts:
                counts[d][s["severity"]] += 1
    return [{"label": d.strftime("%a %d %b"), "short": d.strftime("%d"), "today": d == today,
             **{sev: counts[d][sev] for sev in SECURITY}, "total": sum(counts[d].values())} for d in dates]


def country_map(stories):
    """Per country the worst severity and story count (where it happened), who is blamed, and blame lines."""
    hit, blamed, lines = {}, Counter(), Counter()
    for s in stories:
        for cc in s["where"]:
            entry = hit.setdefault(cc, {"cc": cc, "name": NAMES.get(cc, cc), "count": 0, "worst": s["severity"]})
            entry["count"] += 1
            if RANK[s["severity"]] < RANK[entry["worst"]]:
                entry["worst"] = s["severity"]
        for cc in s["blamed"]:
            blamed[cc] += 1
            for target in s["where"]:
                if target != cc and cc in CENTRES and target in CENTRES:
                    lines[(cc, target)] += 1
    countries = sorted(hit.values(), key=lambda c: (-c["count"], RANK[c["worst"]], c["name"]))
    # Every country on the map, whether it was hit, blamed, or both, for the situation room's list.
    index = [{**c, "blamed": blamed.get(c["cc"], 0)} for c in countries]
    index += [{"cc": cc, "name": NAMES.get(cc, cc), "count": 0, "worst": None, "blamed": n}
              for cc, n in blamed.most_common() if cc not in hit]
    return {
        "countries": countries,
        "index": index,
        "blamed": [{"cc": cc, "name": NAMES.get(cc, cc), "count": n} for cc, n in blamed.most_common()],
        "lines": [{"from": a, "to": b, "count": n, "path": arc(CENTRES[a], CENTRES[b])} for (a, b), n in lines.items()],
    }


def arc(a, b):
    """A gentle curve from a to b, bowed upwards so lines that share a country stay apart."""
    (x1, y1), (x2, y2) = a, b
    mx, my = (x1 + x2) / 2, (y1 + y2) / 2 - abs(x2 - x1) * 0.18 - 6
    return f"M{x1:.1f},{y1:.1f} Q{mx:.1f},{my:.1f} {x2:.1f},{y2:.1f}"


def home_data(app_mod):
    now = datetime.now(timezone.utc)
    stories = app_mod.load_items(14)
    app_mod.attach_stock_summaries(stories)

    def within(hours):
        cutoff = (now - timedelta(hours=hours)).isoformat()
        return [s for s in stories if not s["published"] or s["published"] >= cutoff]

    day, week = within(24), within(24 * 7)
    security_day = [s for s in day if s["severity"] in SECURITY]
    security_week = [s for s in week if s["severity"] in SECURITY]
    placed_week = [s for s in security_week if s["where"] or s["blamed"]]

    conn = connect()
    try:
        upcoming = events.upcoming(conn)[:3]
    finally:
        conn.close()
    for e in upcoming:
        e["url"] = app_mod.safe_link(e["url"])

    month_ago = (now - timedelta(days=MARKET_DAYS)).date().isoformat()
    markets = [i for i in app_mod.load_incidents() if i["date"] >= month_ago][:4]
    for inc in markets:
        inc["story"] = inc["stories"][-1]
        inc["story"]["link"] = app_mod.safe_link(inc["story"]["link"])

    when = collected_at()
    return {
        "now": now.astimezone(DUBAI),
        "collected": when,
        "updated": app_mod.last_updated(),
        "counts": {
            "major": sum(1 for s in day if s["severity"] == "red"),
            "exploited": sum(1 for s in security_day if s["kev"]),
            "companies": len({s["stock"]["company"] for s in day if s.get("stock")}),
            "day": len(day),
            "security_day": len(security_day),
            "week": len(security_week),
            "placed_week": len(placed_week),
        },
        "top": by_importance(security_day)[:HOME_STORIES],
        "exploited": by_importance([s for s in security_week
                                    if s["kev"] or EXPLOITED_RE.search(s["title"] or "")])[:5],
        "gulf": by_importance([s for s in week if s["severity"] != "blue" and
                               (s.get("category") == "regional" or GCC & set(s["where"] + s["blamed"]))])[:5],
        "unplaced": by_importance([s for s in security_week if not (s["where"] or s["blamed"])])[:5],
        "placed": by_importance(placed_week),
        "map": country_map(placed_week),
        "hours": hour_strip(day, now),
        "days": daily(stories, now),
        "events": upcoming,
        "markets": markets,
        "has_sec_contact": bool(stocks.sec_contact()),
        "has_prices_key": bool(stocks.av_key()),
        "stack_stories": [{"title": s["title"], "link": s["link"], "severity": s["severity"], "age": s["age"],
                           "products": s["products"]} for s in stories if s["products"]],
        "stack_names": stack.NAMES,
    }


def register(app, app_mod):
    """Add the prototype routes. app_mod is app.py itself, passed in to avoid a circular import."""
    app.jinja_env.filters["country"] = lambda cc: NAMES.get(cc, cc)
    app.jinja_env.filters["product"] = lambda pid: stack.NAMES.get(pid, pid)

    def common(d):
        if d not in DIRECTIONS:
            abort(404)
        return {"d": d, "direction": DIRECTIONS[d], "nav": nav(d), "footer": FOOTER, "severities": dict(app_mod.SEVERITIES),
                "names": NAMES, "world": WORLD_SHAPES, "centres": CENTRES}

    @app.route("/proto")
    def proto_index():
        return render_template("proto/index.html", directions=DIRECTIONS)

    @app.route("/proto/<d>")
    def proto_home(d):
        ctx = common(d)
        try:
            data, error = home_data(app_mod), None
        except (sqlite3.Error, OSError) as exc:
            data, error = None, type(exc).__name__
        page = render_template(f"proto/{d}_home.html", **ctx, data=data, error=error, page="home")
        return (page, 503) if error else page

    @app.route("/proto/<d>/password")
    def proto_password(d):
        ctx = common(d)
        return render_template(f"proto/{d}_password.html", **ctx, collected=collected_at(), page="password")
