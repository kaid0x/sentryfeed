"""Vulnerability centre: CISA's exploited list, EPSS scores, and CVE lookups.

Three questions about a flaw, from three sources:
- How bad would it be?           CVSS, from NVD (enrich.py already looks these up)
- How likely is it to be used?   EPSS, from FIRST: the chance of exploitation in the next 30 days
- Is it already being used?      KEV, CISA's catalogue of flaws exploited in real attacks

The collector refreshes the KEV catalogue and EPSS scores once a day. The CVE page can also look
up a CVE SentryFeed hasn't seen, live, within per-visitor and daily limits.

Run `python vulns.py` to refresh now and print what changed.
"""
import json
import re
import time
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests

import enrich
from db import connect, get_meta, set_meta

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = "SentryFeed/0.1 (+https://github.com/kaid0x/sentryfeed)"
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
DUBAI = ZoneInfo("Asia/Dubai")     # "today" for deadlines is today in Dubai, wherever the server is

REFRESH_EVERY = timedelta(hours=20)    # once a day, whichever collector run comes first
EPSS_BATCH = 100                       # the API takes up to 100 CVEs per request
NEWS_DAYS = 14                         # EPSS for CVEs in the news this long
DETAILS_FOR_NEW_KEV_DAYS = 30          # NVD descriptions fetched ahead for recent KEV additions
DETAILS_BUDGET = 100                   # ... at most this many per run (then the rest of the catalogue, oldest gaps last)

# Live lookups (a CVE nobody has asked about yet). Each costs the Pi a few seconds and
# uses the NVD key's quota, so they're limited per visitor and per day.
LOOKUPS_PER_VISITOR_HOUR = 30
LOOKUPS_PER_DAY = 500
LIVE_TIMEOUT = 8


def normalise(text):
    """ "cve-2026-72979 " -> "CVE-2026-72979", or None if it isn't shaped like a CVE ID."""
    cve_id = (text or "").strip().upper()
    return cve_id if CVE_ID_RE.match(cve_id) else None


def today():
    return datetime.now(DUBAI).date()


def _due(conn, key):
    """True if this daily download hasn't happened in the last REFRESH_EVERY."""
    last = get_meta(conn, key)
    return not last or datetime.now(timezone.utc) - datetime.fromisoformat(last) > REFRESH_EVERY


# ---------- Daily refresh (collector) ----------

def refresh_kev(conn):
    """Replace the KEV table with CISA's current catalogue. Returns how many were new."""
    resp = requests.get(KEV_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
    resp.raise_for_status()
    rows = resp.json()["vulnerabilities"]
    before = {r["cve_id"] for r in conn.execute("SELECT cve_id FROM kev")}
    with conn:
        conn.execute("DELETE FROM kev")
        conn.executemany(
            """INSERT OR REPLACE INTO kev (cve_id, vendor, product, name, description, date_added, due_date,
                                           required_action, ransomware, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(v["cveID"].upper(), v.get("vendorProject") or "", v.get("product") or "",
              v.get("vulnerabilityName") or v["cveID"], v.get("shortDescription"), v["dateAdded"],
              v.get("dueDate"), v.get("requiredAction"), int(v.get("knownRansomwareCampaignUse") == "Known"),
              v.get("notes")) for v in rows if normalise(v.get("cveID"))],
        )
    set_meta(conn, "kev_fetched", datetime.now(timezone.utc).isoformat())
    return len({normalise(v["cveID"]) for v in rows} - before) if before else 0


def fetch_epss(cve_ids, timeout=20):
    """{cve_id: (score, percentile, day)} for the given CVEs, up to EPSS_BATCH per request."""
    found = {}
    ids = sorted(set(cve_ids))
    for start in range(0, len(ids), EPSS_BATCH):
        batch = ids[start:start + EPSS_BATCH]
        resp = requests.get(EPSS_URL, params={"cve": ",".join(batch)},
                            headers={"User-Agent": USER_AGENT}, timeout=timeout)
        resp.raise_for_status()
        for row in resp.json().get("data", []):
            found[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]), row["date"])
        if start + EPSS_BATCH < len(ids):
            time.sleep(1)       # be gentle with a free API
    return found


def save_epss(conn, scores):
    with conn:
        conn.executemany("INSERT OR REPLACE INTO epss (cve_id, score, percentile, day) VALUES (?, ?, ?, ?)",
                         [(cve_id, *values) for cve_id, values in scores.items()])


def tracked_cves(conn):
    """Every CVE the site shows: the whole KEV catalogue and the CVEs in recent news."""
    since = (datetime.now(timezone.utc) - timedelta(days=NEWS_DAYS)).isoformat()
    ids = {r["cve_id"] for r in conn.execute("SELECT cve_id FROM kev")}
    for row in conn.execute("SELECT cves FROM items WHERE cves != '' AND published >= ?", (since,)):
        ids.update(row["cves"].split(","))
    return ids


def fill_recent_kev_details(conn, log):
    """NVD descriptions and fix links for recently listed flaws and CVEs in recent news (some were
    looked up before descriptions were kept), so their pages and the patch queue need no live lookup.
    Uses the same pacing as the collector's own CVE lookups."""
    key = enrich.api_key()
    pace = enrich.PACE_WITH_KEY if key else enrich.PACE_NO_KEY
    since = (today() - timedelta(days=DETAILS_FOR_NEW_KEV_DAYS)).isoformat()
    have = {r["cve_id"] for r in conn.execute("SELECT cve_id FROM cve_details")}
    missing = [r["cve_id"] for r in conn.execute(
        "SELECT cve_id FROM kev WHERE date_added >= ? ORDER BY date_added DESC", (since,)) if r["cve_id"] not in have]
    news_since = (datetime.now(timezone.utc) - timedelta(days=NEWS_DAYS)).isoformat()
    for row in conn.execute("SELECT cves FROM items WHERE cves != '' AND published >= ? ORDER BY published DESC",
                            (news_since,)):
        missing += [c for c in row["cves"].split(",") if c not in have and c not in missing]
    # Then the rest of CISA's catalogue: the vendor track record needs each flaw's publication date.
    queued = set(missing)
    missing += [r["cve_id"] for r in conn.execute("SELECT cve_id FROM kev ORDER BY date_added DESC")
                if r["cve_id"] not in have and r["cve_id"] not in queued]
    done = 0
    for cve_id in missing[:min(DETAILS_BUDGET, pace["budget"])]:
        try:
            enrich.save_lookup(conn, cve_id, enrich.lookup(cve_id, key))
        except (enrich.RateLimited, requests.RequestException) as e:
            log(f"  ! NVD: {e.__class__.__name__}; the rest next run")
            break
        done += 1
        time.sleep(pace["delay"])
    return done, len(missing) - done


def update(conn, log=print):
    """The collector's step: refresh KEV and EPSS once a day, and fill in recent KEV details."""
    if _due(conn, "kev_fetched"):
        new = refresh_kev(conn)
        total = conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
        log(f"KEV: {total} flaws on CISA's list" + (f", {new} new since the last download" if new else ""))
    if _due(conn, "epss_fetched"):
        ids = tracked_cves(conn)
        save_epss(conn, fetch_epss(ids))
        set_meta(conn, "epss_fetched", datetime.now(timezone.utc).isoformat())
        log(f"EPSS: scores for {len(ids)} CVEs")
    done, left = fill_recent_kev_details(conn, log)
    if done or left:
        log(f"CVE details from NVD: {done} fetched, {left} left for later runs")


# ---------- Reading (the pages) ----------

def recent_kev(conn, days=30):
    since = (today() - timedelta(days=days)).isoformat()
    return [dict(r) for r in conn.execute(
        """SELECT k.*, e.score AS epss, e.percentile AS epss_percentile
           FROM kev k LEFT JOIN epss e ON e.cve_id = k.cve_id
           WHERE k.date_added >= ? ORDER BY k.date_added DESC, k.cve_id""", (since,))]


def kev_between(conn, first_day, last_day):
    """Flaws CISA added between two dates, inclusive, newest first, with EPSS."""
    return [dict(r) for r in conn.execute(
        """SELECT k.*, e.score AS epss FROM kev k LEFT JOIN epss e ON e.cve_id = k.cve_id
           WHERE k.date_added BETWEEN ? AND ? ORDER BY k.date_added DESC, k.cve_id""",
        (first_day.isoformat(), last_day.isoformat()))]


def kev_total(conn):
    return conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0]


def epss_for(conn, cve_ids):
    marks = ",".join("?" * len(cve_ids))
    return {r["cve_id"]: dict(r) for r in conn.execute(
        f"SELECT * FROM epss WHERE cve_id IN ({marks})", list(cve_ids))} if cve_ids else {}


def kev_ids(conn, cve_ids):
    marks = ",".join("?" * len(cve_ids))
    return {r["cve_id"] for r in conn.execute(
        f"SELECT cve_id FROM kev WHERE cve_id IN ({marks})", list(cve_ids))} if cve_ids else set()


def cvss_for(conn, cve_ids):
    marks = ",".join("?" * len(cve_ids))
    return {r["cve_id"]: r["cvss"] for r in conn.execute(
        f"SELECT cve_id, cvss FROM cve_cache WHERE cve_id IN ({marks})", list(cve_ids))} if cve_ids else {}


def news_by_likelihood(conn, stories, limit=15):
    """The CVEs in these stories, most likely to be exploited first: [{cve_id, epss, ..., story}]."""
    first_story = {}
    for s in stories:
        for cve_id in s["cves"]:
            first_story.setdefault(cve_id, s)
    ids = list(first_story)
    scores, listed, cvss = epss_for(conn, ids), kev_ids(conn, ids), cvss_for(conn, ids)
    rows = [{"cve_id": c, "epss": scores[c]["score"] if c in scores else None,
             "percentile": scores[c]["percentile"] if c in scores else None,
             "kev": c in listed, "cvss": cvss.get(c), "story": first_story[c]} for c in ids]
    rows.sort(key=lambda r: (r["epss"] is None, -(r["epss"] or 0), not r["kev"]))
    return rows[:limit]


def stories_mentioning(conn, cve_id, limit=10):
    return [dict(r) for r in conn.execute(
        """SELECT id, source, title, link, published, severity FROM items
           WHERE (',' || cves || ',') LIKE ? ORDER BY published DESC LIMIT ?""",
        (f"%,{cve_id},%", limit))]


def can_look_up(conn, visitor, now=None):
    """None if a live lookup is allowed now, otherwise why not (plain text)."""
    now = now or datetime.now(timezone.utc)
    hour = (now - timedelta(hours=1)).isoformat()
    day = (now - timedelta(days=1)).isoformat()
    if conn.execute("SELECT COUNT(*) FROM cve_lookups WHERE at >= ?", (day,)).fetchone()[0] >= LOOKUPS_PER_DAY:
        return "Live lookups are paused until tomorrow: SentryFeed has used today's allowance."
    mine = conn.execute("SELECT COUNT(*) FROM cve_lookups WHERE visitor = ? AND at >= ?", (visitor, hour)).fetchone()[0]
    if mine >= LOOKUPS_PER_VISITOR_HOUR:
        return f"You've looked up {LOOKUPS_PER_VISITOR_HOUR} new CVEs in the last hour; please try again later."
    return None


def look_up(conn, cve_id, visitor):
    """Everything known about a CVE, asking NVD and FIRST live if SentryFeed has never seen it.
    Returns (details, epss, note): note explains anything that couldn't be fetched."""
    details = conn.execute("SELECT * FROM cve_details WHERE cve_id = ?", (cve_id,)).fetchone()
    score = conn.execute("SELECT * FROM epss WHERE cve_id = ?", (cve_id,)).fetchone()
    note = None
    if details is None or score is None:
        note = can_look_up(conn, visitor)
        if note is None:
            now = datetime.now(timezone.utc)
            with conn:
                conn.execute("DELETE FROM cve_lookups WHERE at < ?", ((now - timedelta(days=2)).isoformat(),))
                conn.execute("INSERT INTO cve_lookups (visitor, at) VALUES (?, ?)", (visitor, now.isoformat()))
            if details is None:
                try:
                    enrich.save_lookup(conn, cve_id, enrich.lookup(cve_id, enrich.api_key(), timeout=LIVE_TIMEOUT))
                except (enrich.RateLimited, requests.RequestException):
                    note = "NVD didn't answer just now, so the description and score are missing. Try again in a minute."
            if score is None:
                try:
                    save_epss(conn, fetch_epss([cve_id], timeout=LIVE_TIMEOUT))
                except (requests.RequestException, ValueError, KeyError):
                    note = note or "FIRST's EPSS service didn't answer just now. Try again in a minute."
            details = conn.execute("SELECT * FROM cve_details WHERE cve_id = ?", (cve_id,)).fetchone()
            score = conn.execute("SELECT * FROM epss WHERE cve_id = ?", (cve_id,)).fetchone()
    details = dict(details) if details else None
    if details:
        details["refs"] = json.loads(details["refs"] or "[]")
    return details, (dict(score) if score else None), note


# ---------- Patch this first ----------

QUEUE_NEWS_DAYS = 7         # CVEs in this week's news
QUEUE_KEV_DAYS = 30         # and flaws CISA added this month, or whose deadline is still ahead
QUEUE_SIZE = 25

# The points, shown on the page next to each flaw so the order can always be checked.
POINTS_KEV = 40
POINTS_RANSOMWARE = 10
POINTS_EPSS = 30            # times the chance of exploitation (0 to 1)
POINTS_CVSS_MAX = 10        # 7.0 scores 3, 8.0 scores 5, 9.0 scores 8, 9.8 or more scores 10
POINTS_PER_ARTICLE = 2
POINTS_NEWS_MAX = 10
POINTS_DUE_SOON = 5         # CISA's deadline within a week
DUE_SOON_DAYS = 7


def _details_for(conn, cve_ids):
    marks = ",".join("?" * len(cve_ids))
    rows = conn.execute(f"SELECT * FROM cve_details WHERE cve_id IN ({marks})", list(cve_ids)) if cve_ids else []
    return {r["cve_id"]: {**dict(r), "refs": json.loads(r["refs"] or "[]")} for r in rows}


def _fix(details):
    """What NVD says about a fix: (status, link or None)."""
    if details is None:
        return "unchecked", None
    patch = next((r["url"] for r in details["refs"] if "Patch" in r["tags"]), None)
    if patch:
        return "patch", patch
    advisory = next((r["url"] for r in details["refs"] if "Vendor Advisory" in r["tags"]), None)
    if advisory:
        return "advisory", advisory
    return "none", None


def patch_queue(conn, stories, product_match=None):
    """The flaws most worth fixing first. stories: security stories from the last QUEUE_NEWS_DAYS days,
    grouped and prepared. product_match(vendor, product, name) -> My stack product ids, for KEV flaws.
    Returns the top QUEUE_SIZE as dicts with their points spelled out."""
    mentions = {}
    for s in stories:
        for cve_id in s["cves"]:
            m = mentions.setdefault(cve_id, {"articles": 0, "stories": [], "products": set()})
            m["articles"] += 1 + len(s["also"])
            m["stories"].append(s)
            m["products"].update(s["products"])
    since, now_day = (today() - timedelta(days=QUEUE_KEV_DAYS)).isoformat(), today()
    kev = {r["cve_id"]: dict(r) for r in conn.execute(
        "SELECT * FROM kev WHERE date_added >= ? OR due_date >= ?", (since, now_day.isoformat()))}
    named = list(set(mentions) - set(kev))
    if named:
        marks = ",".join("?" * len(named))
        kev.update({r["cve_id"]: dict(r) for r in conn.execute(f"SELECT * FROM kev WHERE cve_id IN ({marks})", named)})
    ids = set(mentions) | set(kev)
    scores, details, cached = epss_for(conn, ids), _details_for(conn, ids), cvss_for(conn, ids)

    rows = []
    for cve_id in ids:
        k, d, e, m = kev.get(cve_id), details.get(cve_id), scores.get(cve_id), mentions.get(cve_id)
        cvss = (d or {}).get("cvss") if (d or {}).get("cvss") is not None else cached.get(cve_id)
        why = []
        if k:
            why.append(("kev", "On CISA's exploited list", POINTS_KEV))
            if k["ransomware"]:
                why.append(("ransomware", "Used by ransomware", POINTS_RANSOMWARE))
        if e and round(e["score"] * POINTS_EPSS) >= 1:
            why.append(("epss", f"{epss_words(e['score'])} chance of use in 30 days", round(e["score"] * POINTS_EPSS)))
        if cvss is not None and cvss >= 7:
            why.append(("cvss", f"Rated {cvss} out of 10", min(POINTS_CVSS_MAX, round((cvss - 6) * 2.6))))
        if m:
            n = m["articles"]
            why.append(("news", f"In {n} article{'s' if n != 1 else ''} this week", min(POINTS_NEWS_MAX, n * POINTS_PER_ARTICLE)))
        if k and k["due_date"] and 0 <= (date.fromisoformat(k["due_date"]) - now_day).days <= DUE_SOON_DAYS:
            why.append(("due", f"CISA deadline {due_words(k['due_date'])}", POINTS_DUE_SOON))
        if not why:
            continue
        # A heading in words: CISA's name, or Microsoft's advisory title (one per CVE), else the ID.
        stories_here = (m or {}).get("stories", [])
        msrc = next((s["headline"] for s in stories_here if s["source"] == "Microsoft MSRC"), None)
        products = set((m or {}).get("products", ()))
        if k and product_match:
            products.update(product_match(k["vendor"], k["product"], k["name"]))
        fix, fix_link = _fix(d)
        lead = max(stories_here, key=lambda s: 1 + len(s["also"])) if stories_here else None
        rows.append({
            "cve_id": cve_id,
            "title": (k["name"] if k else None) or msrc or cve_id,
            "vendor": f"{k['vendor']} {k['product']}" if k else None,
            "story": lead if not msrc and not k else None,
            "why": why,
            "total": sum(p for _, _, p in why),
            "epss": e["score"] if e else None,
            "fix": fix,
            "fix_link": fix_link,
            "products": sorted(products),
            "date": (k["date_added"] if k else None) or (lead["published"][:10] if lead and lead["published"] else None),
        })
    rows.sort(key=lambda r: (-r["total"], -(r["epss"] or 0), r["cve_id"]))
    return rows[:QUEUE_SIZE]


# ---------- Vendor track record ----------

KEV_LAUNCH_DAY = "2021-11-03"   # CISA's list began with hundreds of older flaws added at once
LISTED_SOON_DAYS = 30


def vendor_slug(name):
    return re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")


def cve_year(cve_id):
    return int(cve_id.split("-")[1])


def vendor_index(conn):
    """Every vendor on CISA's list: [{vendor, slug, total, added_this_year, ransomware, top_product}], most first."""
    year = str(today().year)
    vendors = {}
    for r in conn.execute("SELECT cve_id, vendor, product, date_added, ransomware FROM kev"):
        v = vendors.setdefault(r["vendor"], {"vendor": r["vendor"], "slug": vendor_slug(r["vendor"]), "total": 0,
                                             "added_this_year": 0, "ransomware": 0, "products": {}})
        v["total"] += 1
        v["added_this_year"] += r["date_added"].startswith(year)
        v["ransomware"] += r["ransomware"]
        v["products"][r["product"]] = v["products"].get(r["product"], 0) + 1
    rows = []
    for v in vendors.values():
        products = v.pop("products")
        product, count = max(products.items(), key=lambda kv: (kv[1], kv[0]))
        rows.append({**v, "top_product": product, "top_product_count": count, "product_names": sorted(products)})
    rows.sort(key=lambda v: (-v["total"], v["vendor"].lower()))
    return rows


def vendor_detail(conn, slug):
    """One vendor's record, or None if CISA has never listed it."""
    rows = [dict(r) for r in conn.execute(
        """SELECT k.*, d.published FROM kev k LEFT JOIN cve_details d ON d.cve_id = k.cve_id
           ORDER BY k.date_added DESC, k.cve_id DESC""")]
    rows = [r for r in rows if vendor_slug(r["vendor"]) == slug]
    if not rows:
        return None
    this_year = today().year
    # Exploited flaws by the year they were disclosed (the year in the CVE ID), first year to now.
    by_year = {}
    for r in rows:
        by_year[cve_year(r["cve_id"])] = by_year.get(cve_year(r["cve_id"]), 0) + 1
    first = min(by_year)
    years = [{"year": y, "count": by_year.get(y, 0)} for y in range(min(first, this_year - 5), this_year + 1)]
    # Products with more than one exploited flaw.
    products = {}
    for r in rows:
        p = products.setdefault(r["product"], {"product": r["product"], "count": 0, "first": r["date_added"],
                                               "latest": r["date_added"], "ransomware": 0})
        p["count"] += 1
        p["first"] = min(p["first"], r["date_added"])
        p["latest"] = max(p["latest"], r["date_added"])
        p["ransomware"] += r["ransomware"]
    repeats = sorted((p for p in products.values() if p["count"] > 1), key=lambda p: (-p["count"], p["product"]))
    # Days from publication to CISA's listing, leaving out the launch-day batch.
    gaps = sorted((date.fromisoformat(r["date_added"]) - date.fromisoformat(r["published"][:10])).days
                  for r in rows if r["published"] and r["date_added"] != KEV_LAUNCH_DAY)
    gaps = [g for g in gaps if g >= 0]
    eligible = sum(1 for r in rows if r["date_added"] != KEV_LAUNCH_DAY)
    timing = None
    if gaps:
        mid = len(gaps) // 2
        median = gaps[mid] if len(gaps) % 2 else (gaps[mid - 1] + gaps[mid]) // 2
        timing = {"median": median, "soon": sum(1 for g in gaps if g <= LISTED_SOON_DAYS), "n": len(gaps),
                  "eligible": eligible}
    return {
        "vendor": rows[0]["vendor"],
        "total": len(rows),
        "added_this_year": sum(1 for r in rows if r["date_added"].startswith(str(this_year))),
        "added_last_year": sum(1 for r in rows if r["date_added"].startswith(str(this_year - 1))),
        "ransomware": sum(r["ransomware"] for r in rows),
        "products": len(products),
        "years": years,
        "repeats": repeats,
        "timing": timing,
        "latest": rows[:10],
        "first_added": min(r["date_added"] for r in rows),
        "this_year": this_year,
    }


# ---------- Plain words ----------

def epss_words(score):
    """0.0097 -> "1.0%"; tiny scores aren't shown as 0%, which would read as "impossible"."""
    if score is None:
        return None
    pct = score * 100
    if pct < 0.1:
        return "under 0.1%"
    if pct < 10:
        return f"{pct:.1f}%"
    if pct >= 99.5:
        return "over 99%"      # rounding to 100% would claim a certainty EPSS never gives
    return f"{pct:.0f}%"


def percentile_words(percentile):
    """0.6095 -> "higher than 61% of all scored flaws"."""
    if percentile is None:
        return None
    share = int(percentile * 100)
    if share >= 99:
        return "among the top 1% of all scored flaws"
    return f"higher than {share}% of all scored flaws"


def due_words(due, on=None):
    """CISA's deadline in words, from today's date in Dubai."""
    if not due:
        return None
    days = (date.fromisoformat(due) - (on or today())).days
    if days > 1:
        return f"due in {days} days"
    if days == 1:
        return "due tomorrow"
    if days == 0:
        return "due today"
    return f"deadline passed {-days} day{'s' if days < -1 else ''} ago"


def main():
    conn = connect()
    update(conn)
    rows = recent_kev(conn, days=7)
    print(f"\nAdded to CISA's list in the last 7 days: {len(rows)}")
    for r in rows:
        print(f"  {r['date_added']}  {r['cve_id']:<16} {r['vendor']} {r['product']}  "
              f"EPSS {epss_words(r['epss']) or '-'}  {due_words(r['due_date'])}")
    conn.close()


if __name__ == "__main__":
    main()
