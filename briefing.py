"""What the front page and the map page show, worked out from the stories app.py loads.

Also the plainer wording used across the site: Microsoft's advisory titles made readable,
and the scorer's reasons ("mentions 'rce'") put in words a reader would use. score.py keeps
its own wording, which stays exact for debugging the scoring rules.
"""
import json
import re
from collections import Counter
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from markupsafe import Markup

import stack
from geo import NAMES as COUNTRY_NAMES

SECURITY = ("red", "orange", "yellow")
RANK = {"red": 0, "orange": 1, "yellow": 2, "green": 3, "blue": 4}
GCC = {"AE", "SA", "QA", "KW", "BH", "OM"}
DUBAI = ZoneInfo("Asia/Dubai")
HOME_STORIES = 5
MARKET_DAYS = 30
# Titles that say a flaw is already being used, for stories CISA hasn't listed (yet).
EXPLOITED_RE = re.compile(r"\b(?:exploited|exploiting|exploitation|zero-days?|0-days?|in the wild)\b", re.I)

_TEMPLATES = Path(__file__).with_name("templates")
# The map's shapes without the outer <svg> tag, so each map can crop it with its own viewBox.
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
    ("RSS feeds", "/feeds"),
    ("Built by Haseeb", "https://mhaseebashfaq.com"),
]


# Grouped navigation: (group, [(label, link, page key)]). A None link is a planned page,
# named in the menu but not linked, so nothing in the menu leads nowhere.
NAV = [
    ("Intel", [("Feed", "/feed", "feed"), ("Map", "/map", "map"), ("Stocks", "/stocks", "stocks"),
               ("My stack", "/stack", "stack"), ("Vulnerabilities", "/vulns", "vulns"),
               ("Patch this first", "/patch", "patch"),
               ("Ransomware stats", None, None), ("Weekly digest", "/digest", "digest"), ("Gulf pulse", None, None)]),
    ("Tools", [("Password check", "/password", "password"), ("File & link check", "/scan", "scan"),
               ("Email header analyser", None, None), ("Domain check", None, None)]),
    ("Community", [("Events", "/events", "events"), ("Submit an event", "/events/submit", "submit")]),
]


# ---------- Glossary ----------

# One line each, shown when someone clicks a dotted-underlined term (templates: ui.term).
GLOSSARY = {
    "cve": ("CVE", "a public ID for one security flaw, like CVE-2021-44228, so everyone can refer to the same bug."),
    "cvss": ("CVSS", "a score out of 10 for how much damage a flaw could do if it's used. It says nothing about "
                     "whether anyone is using it."),
    "epss": ("EPSS", "FIRST's daily estimate of the chance a flaw is exploited in the next 30 days, worked out from "
                     "real attack data."),
    "kev": ("KEV", "CISA's Known Exploited Vulnerabilities list: flaws the US cyber agency has confirmed are being "
                   "used in real attacks. If you run one, patch it first."),
    "zero-day": ("Zero-day", "a flaw attackers use before a fix exists, so defenders have had zero days to patch."),
    "rce": ("Remote code execution", "a flaw that lets an attacker run their own code on a machine over the network. "
                                     "Usually the most serious kind."),
    "ransomware": ("Ransomware", "malware that locks or steals an organisation's data and demands payment to unlock "
                                 "it or not leak it."),
    "rss": ("RSS", "a feed of new posts that apps like Feedly, NetNewsWire, Outlook or Slack's RSS app can follow, "
                   "so new stories come to you without visiting the site."),
    "hash": ("Hash", "a fixed-length fingerprint worked out from data. The same input always gives the same hash, "
                     "but the hash can't be turned back into the input."),
    "sec-8k": ("Form 8-K, Item 1.05", "since December 2023, a US-listed company must report a material cyber "
                                      "incident to the SEC within four business days of deciding it's material."),
}
# Plain-word reasons (see plain_reason) that start with a glossary term.
_REASON_TERMS = [
    (re.compile(r"^(Zero-days?)"), "zero-day"),
    (re.compile(r"^(Remote code execution)"), "rce"),
    (re.compile(r"^(Ransomware)"), "ransomware"),
    (re.compile(r"^(Rated [\d.]+ out of 10)"), "cvss"),
    (re.compile(r"^(CISA says it's being exploited)"), "kev"),
]


def glossed(reason):
    """A reason with its leading term marked for the glossary, e.g. <span class="term" ...>Zero-day</span>."""
    for pattern, key in _REASON_TERMS:
        m = pattern.match(reason or "")
        if m:
            return Markup('<span class="term" data-term="{}">{}</span>').format(key, m.group(1)) + reason[m.end():]
    return reason or ""


# ---------- Plainer words ----------

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


def group_advisories(stories, span="in the last 24 hours"):
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
        "title": f"Microsoft: {len(ms)} security advisories {span}",
        "headline": f"Microsoft: {len(ms)} security advisories {span}",
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


def gulf_stories(stories):
    """Stories for "In the Gulf": from the regional outlets or naming a GCC country, without vendor news.
    Returns (stories, how many vendor announcements were left out)."""
    return gulf_split([s for s in stories if s["severity"] != "blue" and
                       (s.get("category") == "regional" or GCC & set(s["where"] + s["blamed"]))])


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


def prepare(stories):
    """Add the readable headline and reason every page shows."""
    for s in stories:
        s["headline"] = clean_title(s)
        s["reason"] = plain_reason(s["severity_reason"])
    return stories


def _within(stories, now, hours):
    cutoff = (now - timedelta(hours=hours)).isoformat()
    return [s for s in stories if not s["published"] or s["published"] >= cutoff]


def front_page(stories, incidents, upcoming):
    """Everything the home page needs. stories: the last 14 days, prepared, with stock summaries."""
    now = datetime.now(timezone.utc)
    day, week = _within(stories, now, 24), _within(stories, now, 24 * 7)
    security_day = [s for s in day if s["severity"] in SECURITY]
    security_week = [s for s in week if s["severity"] in SECURITY]
    placed_week = [s for s in security_week if s["where"] or s["blamed"]]
    gulf, gulf_dropped = gulf_split([s for s in week if s["severity"] != "blue" and
                                     (s.get("category") == "regional" or GCC & set(s["where"] + s["blamed"]))])
    month_ago = (now - timedelta(days=MARKET_DAYS)).date().isoformat()
    markets = [i for i in incidents if i["date"] >= month_ago][:4]
    for inc in markets:
        inc["story"] = inc["stories"][-1]
    return {
        "counts": {
            "major": sum(1 for s in day if s["severity"] == "red"),
            "exploited": sum(1 for s in security_day if s["kev"]),
            "companies": len({s["stock"]["company"] for s in day if s.get("stock")}),
            "day": len(day),
            "week": len(security_week),
            "placed_week": len(placed_week),
        },
        "top": by_importance(group_advisories(security_day))[:HOME_STORIES],
        "exploited": by_importance([s for s in security_week
                                    if s["kev"] or EXPLOITED_RE.search(s["title"] or "")])[:5],
        "gulf": by_importance(gulf)[:5],
        "gulf_dropped": gulf_dropped,
        "map": country_map(placed_week),
        "events": upcoming[:3],
        "markets": markets,
        "stack_stories": [{"title": s["headline"], "link": s["link"], "severity": s["severity"], "age": s["age"],
                           "products": s["products"]} for s in stories if s["products"]],
        "stack_names": stack.NAMES,
    }


def map_page(stories):
    """The map page: stories in the chosen window, those with a country and those without."""
    security = [s for s in stories if s["severity"] in SECURITY]
    placed = [s for s in security if s["where"] or s["blamed"]]
    return {
        "total": len(security),
        "placed": by_importance(placed),
        "unplaced": by_importance([s for s in security if not (s["where"] or s["blamed"])])[:6],
        "unplaced_count": len(security) - len(placed),
        "map": country_map(placed),
    }


# ---------- Weekly digest ----------

# Weeks run Monday to Sunday, in Dubai time, named the ISO way: 2026-W41.
WEEK_RE = re.compile(r"^(\d{4})-W(\d{2})$", re.I)
DIGEST_STORIES = 8


def week_id(when):
    d = when.astimezone(DUBAI).date() if isinstance(when, datetime) else when
    year, week, _ = d.isocalendar()
    return f"{year}-W{week:02d}"


def week_start(wid):
    """Midnight on the Monday of "2026-W41", Dubai time, or None if it isn't a real week."""
    m = WEEK_RE.match(wid or "")
    if not m:
        return None
    try:
        monday = date.fromisocalendar(int(m.group(1)), int(m.group(2)), 1)
    except ValueError:
        return None
    return datetime.combine(monday, time(0), DUBAI)


def week_label(start):
    """ "6 to 12 October 2026", "29 September to 5 October 2026", "29 December 2025 to 4 January 2026"."""
    first, last = start.date(), (start + timedelta(days=6)).date()
    if first.year != last.year:
        return f"{first.day} {first:%B %Y} to {last.day} {last:%B %Y}"
    if first.month != last.month:
        return f"{first.day} {first:%B} to {last.day} {last:%B %Y}"
    return f"{first.day} to {last.day} {last:%B %Y}"


def compared(now, before):
    """ "3 more than the week before", "2 fewer", "same as the week before", or "" with nothing to compare."""
    if before is None:
        return ""
    if now == before:
        return "same as the week before"
    diff = abs(now - before)
    return f"{diff} {'more' if now > before else 'fewer'} than the week before"


def _week_numbers(stories, new_kev, companies):
    security = [s for s in stories if s["severity"] in SECURITY]
    placed = [s for s in security if s["where"] or s["blamed"]]
    return {
        "major": sum(1 for s in stories if s["severity"] == "red"),
        "medium": sum(1 for s in stories if s["severity"] == "orange"),
        "exploited": sum(1 for s in security if s["kev"]),
        "new_kev": new_kev,
        "countries": len(country_map(placed)["countries"]),
        "companies": companies,
    }


NUMBER_LABELS = [
    ("major", "Major story", "Major stories"),
    ("medium", "Medium story", "Medium stories"),
    ("exploited", "story about a flaw on CISA's list", "stories about flaws on CISA's list"),
    ("new_kev", "flaw added to CISA's list", "flaws added to CISA's list"),
    ("countries", "country named in incidents", "countries named in incidents"),
    ("companies", "breached listed company", "breached listed companies"),
]


def digest(stories, new_kev, incidents, upcoming, prev=None):
    """One week's digest. stories: the week's stories, prepared, with stock summaries; new_kev: CISA
    additions that week; incidents: listed companies named that week; prev: the week before's
    (stories, new_kev count, incidents count), or None if there's nothing to compare with."""
    security = [s for s in stories if s["severity"] in SECURITY]
    placed = [s for s in security if s["where"] or s["blamed"]]
    numbers = _week_numbers(stories, len(new_kev), len(incidents))
    before = _week_numbers(prev[0], prev[1], prev[2]) if prev else {}
    gulf, gulf_dropped = gulf_split([s for s in stories if s["severity"] != "blue" and
                                     (s.get("category") == "regional" or GCC & set(s["where"] + s["blamed"]))])
    geo = country_map(placed)
    for inc in incidents:
        inc["story"] = inc["stories"][-1]
    return {
        "numbers": [{"key": key, "n": numbers[key], "label": one if numbers[key] == 1 else many,
                     "compared": compared(numbers[key], before.get(key))} for key, one, many in NUMBER_LABELS],
        "counts": numbers,
        "top": by_importance(group_advisories(security, "this week"))[:DIGEST_STORIES],
        "security_total": len(security),
        "new_kev": new_kev,
        "map": geo,
        "busiest": geo["countries"][:5],
        # Every country tied for the most stories, so a tie isn't reported as one winner.
        "top_countries": [c["name"] for c in geo["countries"] if c["count"] == geo["countries"][0]["count"]][:3]
                         if geo["countries"] else [],
        "placed": len(placed),
        "markets": incidents,
        "gulf": by_importance(gulf)[:5],
        "gulf_dropped": gulf_dropped,
        "upcoming": upcoming,
    }
