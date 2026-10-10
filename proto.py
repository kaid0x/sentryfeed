"""Redesign prototypes (branch `redesign` only, not linked from the live site).

Three directions built on the same real data so they can be compared side by side:
A, an operations dashboard; B, an intelligence briefing; C, a map-first situation room.
Each has a home page and the password check as its tool page, at /proto/<a|b|c>.
"""
import gzip
import json
import re
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import abort, render_template, request
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
_WORLD_TEXT = (_TEMPLATES / "_world.svg").read_text().split("\n", 1)[1].rsplit("</svg>", 1)[0]
WORLD_SHAPES = Markup(_WORLD_TEXT)
_NUMBER = re.compile(r"-?\d+\.\d+")
_PATH_D = re.compile(r' d="([^"]+)"')


def _lite_path(d):
    """Whole-number coordinates, specks of islands dropped: plenty for a map a few hundred pixels wide."""
    d = _NUMBER.sub(lambda n: str(round(float(n.group()))), d)
    keep = []
    for sub in re.findall(r"M[^M]+", d):
        pts = [(int(x), int(y)) for x, y in re.findall(r"(-?\d+),(-?\d+)", sub)]
        xs, ys = [x for x, _ in pts], [y for _, y in pts]
        if (max(xs) - min(xs)) * (max(ys) - min(ys)) >= 6:
            keep.append(re.sub(r"L(-?\d+,-?\d+)(?:L\1)+", r"L\1", sub))
    return "".join(keep)


def _lite_world():
    lines = []
    for line in _WORLD_TEXT.splitlines():
        m = _PATH_D.search(line)
        if m:
            d = _lite_path(m.group(1))
            if not d:
                continue
            line = line.replace(m.group(1), d)
        lines.append(line)
    return "\n".join(lines)


def _region(x0, y0, x1, y1):
    """Only the countries that reach into a box, at full detail, for a zoomed-in crop."""
    lines = []
    for line in _WORLD_TEXT.splitlines():
        m = _PATH_D.search(line)
        if not m:
            continue
        xs = [float(v) for v in re.findall(r"(-?[\d.]+),", m.group(1))]
        ys = [float(v) for v in re.findall(r",(-?[\d.]+)", m.group(1))]
        if max(xs) >= x0 and min(xs) <= x1 and max(ys) >= y0 and min(ys) <= y1:
            lines.append(line)
    return "\n".join(lines)


WORLD_LITE = Markup(_lite_world())          # about 30% smaller than the full map
GULF_VIEW = (548, 112, 150, 100)            # x, y, width, height of the Gulf crop
GULF_SHAPES = Markup(_region(GULF_VIEW[0] - 10, GULF_VIEW[1] - 10,
                             GULF_VIEW[0] + GULF_VIEW[2] + 10, GULF_VIEW[1] + GULF_VIEW[3] + 10))
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
        ("Intel", [("Feed", "/"), ("Map", "/proto/b/map" if d == "b" else "/map"), ("Stocks", "/stocks"), ("My stack", "/stack"),
                   ("Vulnerabilities", None), ("Ransomware stats", None),
                   ("Weekly digest", None), ("Gulf pulse", None)]),
        ("Tools", [("Password check", f"/proto/{d}/password"), ("File & link check", "/scan"),
                   ("Email header analyser", None), ("Domain check", None)]),
        ("Community", [("Events", "/events"), ("Submit an event", "/events/submit")]),
    ]


# ---------- Plainer words (display only; score.py and the live site are unchanged) ----------

MS_KINDS = ("Remote Code Execution", "Elevation of Privilege", "Information Disclosure",
            "Security Feature Bypass", "Denial of Service", "Spoofing", "Tampering")
_MS_TITLE = re.compile(rf"^(?:CVE-\d{{4}}-\d+\s+)?(.+?)\s+({'|'.join(MS_KINDS)})\s+Vulnerability$")
_CHROMIUM = re.compile(r"^Chromium:\s*CVE-\d{4}-\d+\s+(.+)$")


def clean_title(story):
    """Microsoft's advisory titles, "CVE-2026-72979 Windows DHCP Server Remote Code Execution
    Vulnerability", read as "Windows DHCP Server: remote code execution flaw". Others are untouched."""
    title = story["title"] or ""
    if story["source"] != "Microsoft MSRC":
        return title
    m = _MS_TITLE.match(title)
    if m:
        return f"{m.group(1)}: {m.group(2).lower()} flaw"
    m = _CHROMIUM.match(title)
    if m:
        return f"Chrome and Edge: {m.group(1)[0].lower()}{m.group(1)[1:]}"
    return re.sub(r"^CVE-\d{4}-\d+\s+", "", title)


# The scorer's matched keyword, in words a reader would use.
KEYWORD_WORDS = {
    "actively exploited": "Reported as actively exploited", "actively exploiting": "Reported as actively exploited",
    "under active exploitation": "Reported as actively exploited", "mass exploitation": "Mass exploitation reported",
    "exploited in the wild": "Exploited in the wild", "exploitation in the wild": "Exploited in the wild",
    "zero-day": "Zero-day", "zero-days": "Zero-days", "zero day": "Zero-day", "0-day": "Zero-day", "0-days": "Zero-days",
    "critical": "Described as critical", "remote code execution": "Remote code execution", "rce": "Remote code execution",
    "ransomware": "Ransomware", "data breach": "Data breach", "data breaches": "Data breach",
    "breach": "Breach", "breached": "Breach", "breaches": "Breach",
    "backdoor": "Backdoor", "backdoored": "Backdoor", "backdoors": "Backdoor",
    "nation-state": "State-backed hackers", "nation state": "State-backed hackers",
    "malware": "Malware", "hacked": "Hack", "compromise": "Systems compromised", "compromised": "Systems compromised",
    "stolen": "Data stolen", "leak": "Data leak", "leaked": "Data leak", "leaks": "Data leak",
    "exploit": "Exploit", "exploits": "Exploit", "exploited": "Exploited",
    "data theft": "Data theft", "credential theft": "Credential theft", "extortion": "Extortion",
    "wiper": "Wiper malware", "wipers": "Wiper malware", "worm": "Worm", "worms": "Worm", "spyware": "Spyware",
    "stealer": "Info-stealer", "stealers": "Info-stealer", "infostealer": "Info-stealer", "infostealers": "Info-stealer",
    "botnet": "Botnet", "botnets": "Botnet", "ddos": "DDoS attack", "sql injection": "SQL injection",
    "auth bypass": "Login bypass", "authentication bypass": "Login bypass", "privilege escalation": "Privilege escalation",
}


def _keyword(word):
    word = word.lower()
    if word in KEYWORD_WORDS:
        return KEYWORD_WORDS[word]
    if word.startswith(("supply-chain", "supply chain")):
        return "Supply-chain attack"
    if word.startswith(("take", "takeover")):
        return "Takeover"
    if word.startswith("malicious"):
        return word.capitalize()
    return word.capitalize()


def plain_reason(reason):
    """ "mentions 'rce'" becomes "Remote code execution"; "CVSS 9.8" becomes "Rated 9.8 out of 10"."""
    if not reason or reason.startswith("no severity"):
        return ""
    head, _, tail = reason.partition(", ")
    tail = f", {tail}" if tail else ""
    if head == "CISA: actively exploited":
        return "CISA says it's being exploited" + tail
    m = re.fullmatch(r"CVSS ([\d.]+)(?: \+ mentions '(.+)')?", head)
    if m:
        if m.group(2):
            return f"{_keyword(m.group(2))}, rated {m.group(1)} out of 10{tail}"
        return f"Rated {m.group(1)} out of 10{tail}"
    m = re.fullmatch(r"mentions '(.+)'", head)
    if m:
        return _keyword(m.group(1)) + tail
    return reason[0].upper() + reason[1:]


def group_advisories(stories):
    """Microsoft publishes one advisory per flaw, often several a day. On the front page they
    become one item, so three CVE titles don't push the day's real news off the top."""
    ms = [s for s in stories if s["source"] == "Microsoft MSRC"]
    if len(ms) < 2:
        return stories
    ms = by_importance(ms)
    major = sum(1 for s in ms if s["severity"] == "red")
    lead = ms[0]
    group = {
        **lead,
        "title": f"Microsoft: {len(ms)} security advisories in the last 24 hours",
        "headline": f"Microsoft: {len(ms)} security advisories in the last 24 hours",
        "link": "https://msrc.microsoft.com/update-guide",
        "summary": "",
        "also": [],
        "cves": sorted({c for s in ms for c in s["cves"]}),
        "kev": int(any(s["kev"] for s in ms)),
        "where": [], "blamed": [],
        "severity_reason": "",
        "reason": f"{major} rated Major" if major else "",
        "items": [{"title": s["headline"], "link": s["link"], "severity": s["severity"],
                   "cves": s["cves"], "reason": s["reason"]} for s in ms],
    }
    return [s for s in stories if s["source"] != "Microsoft MSRC"] + [group]


# The regional feeds carry a lot of vendor news, which often names the UAE or Saudi Arabia as a
# market. Their stories stay only if serious or about an incident, a flaw or the authorities.
# Stories from the international outlets that name a GCC country are news by definition.
GULF_NEWS_RE = re.compile(
    r"\b(?:attacks?|attacked|breach\w*|hack\w*|ransomware|leak\w*|vulnerab\w*|flaws?|exploit\w*|"
    r"phishing|scam\w*|fraud\w*|malware|outage|arrest\w*|fined?|law|regulat\w*|ministry|authority|"
    r"council|government|national|CERT|TDRA|NCA|police)\b", re.I)


def gulf_split(stories):
    kept, dropped = [], 0
    for s in stories:
        regional = s.get("category") == "regional"
        if (s["severity"] in ("red", "orange") or GULF_NEWS_RE.search(s["title"] or "")
                or (not regional and GCC & set(s["where"] + s["blamed"]))):
            kept.append(s)
        else:
            dropped += 1
    return kept, dropped


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

    for s in stories:
        s["headline"] = clean_title(s)
        s["reason"] = plain_reason(s["severity_reason"])

    def within(hours):
        cutoff = (now - timedelta(hours=hours)).isoformat()
        return [s for s in stories if not s["published"] or s["published"] >= cutoff]

    day, week = within(24), within(24 * 7)
    security_day = [s for s in day if s["severity"] in SECURITY]
    security_week = [s for s in week if s["severity"] in SECURITY]
    placed_week = [s for s in security_week if s["where"] or s["blamed"]]

    gulf = gulf_split([s for s in week if s["severity"] != "blue" and
                       (s.get("category") == "regional" or GCC & set(s["where"] + s["blamed"]))])

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
        "top": by_importance(group_advisories(security_day))[:HOME_STORIES],
        "exploited": by_importance([s for s in security_week
                                    if s["kev"] or EXPLOITED_RE.search(s["title"] or "")])[:5],
        "gulf": by_importance(gulf[0])[:5],
        "gulf_dropped": gulf[1],
        "unplaced": by_importance([s for s in security_week if not (s["where"] or s["blamed"])])[:5],
        "placed": by_importance(placed_week),
        "all_unplaced": len(security_week) - len(placed_week),
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
                "names": NAMES, "world": WORLD_SHAPES, "world_lite": WORLD_LITE, "gulf_shapes": GULF_SHAPES,
                "gulf_view": " ".join(map(str, GULF_VIEW)), "centres": CENTRES}

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

    @app.route("/proto/<d>/map")
    def proto_map(d):
        if d != "b":
            abort(404)      # only B has its own map page; C is a map already
        ctx = common(d)
        try:
            data, error = home_data(app_mod), None
        except (sqlite3.Error, OSError) as exc:
            data, error = None, type(exc).__name__
        page = render_template("proto/b_map.html", **ctx, data=data, error=error, page="map")
        return (page, 503) if error else page

    @app.after_request
    def compress(resp):
        """Gzip prototype pages: the map's SVG shrinks to about a third. Only /proto pages, which hold
        no secrets and reflect no form input, so compression can't leak anything (the BREACH attack)."""
        if (request.path.startswith("/proto") and resp.status_code in (200, 503) and resp.mimetype == "text/html"
                and not resp.direct_passthrough and "gzip" in request.headers.get("Accept-Encoding", "")
                and "Content-Encoding" not in resp.headers):
            body = resp.get_data()
            if len(body) > 1024:
                resp.set_data(gzip.compress(body, compresslevel=6))
                resp.headers["Content-Encoding"] = "gzip"
                resp.headers["Vary"] = "Accept-Encoding"
        return resp

    @app.route("/proto/<d>/password")
    def proto_password(d):
        ctx = common(d)
        return render_template(f"proto/{d}_password.html", **ctx, collected=collected_at(), page="password")
