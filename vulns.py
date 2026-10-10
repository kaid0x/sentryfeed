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
DETAILS_BUDGET = 40                    # ... at most this many per run

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
    """NVD descriptions and fix links for recently listed flaws, so the KEV list's CVE pages
    open without a live lookup. Uses the same pacing as the collector's own CVE lookups."""
    key = enrich.api_key()
    pace = enrich.PACE_WITH_KEY if key else enrich.PACE_NO_KEY
    since = (today() - timedelta(days=DETAILS_FOR_NEW_KEV_DAYS)).isoformat()
    missing = [r["cve_id"] for r in conn.execute(
        """SELECT cve_id FROM kev WHERE date_added >= ? AND cve_id NOT IN (SELECT cve_id FROM cve_details)
           ORDER BY date_added DESC""", (since,))]
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
        log(f"KEV details from NVD: {done} fetched, {left} left for later runs")


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
