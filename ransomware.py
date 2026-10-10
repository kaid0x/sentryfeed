"""Ransomware stats: attacks ransomware gangs claim on their leak sites, counted by month,
country, sector and gang.

From Ransomware.live, which allows non-commercial use with credit ("Source: Ransomware.live",
linked, on any page showing the data), polling no more than every 30 minutes, and no
re-publishing of the raw data or re-serving it as an API or feed. So:
- each month's victim list is fetched, counted straight away, and only the counts are stored;
  victim names are never saved or shown,
- it runs once a day, as a collector step, and never on a visitor's request,
- the numbers appear on /ransomware only: not in /api/items or the RSS feeds.

With a free API PRO key (my.ransomware.live) in .ransomware_key, it uses api-pro. Without one it
falls back to the older keyless API, which allows one request a minute, so it fetches a single
month per run and the past year fills in over a few hours.

Run `python ransomware.py` to refresh now and print the totals.
"""
import os
import time
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import requests

from db import connect, get_meta, set_meta

KEY_FILE = Path(__file__).with_name(".ransomware_key")
PRO_URL = "https://api-pro.ransomware.live/victims/"
FREE_URL = "https://api.ransomware.live/v2/victims/{year}/{month:02d}"
USER_AGENT = "SentryFeed/0.1 (+https://github.com/kaid0x/sentryfeed)"
MONTHS = 12                         # how far back the page goes
REFRESH_EVERY = timedelta(hours=20)
CALLS_PER_RUN = {"pro": MONTHS + 2, "free": 1}   # the keyless API allows one request a minute
UNKNOWN_SECTORS = {"", "not found", "other", "unknown", "n/a"}


def api_key():
    key = os.environ.get("RANSOMWARE_LIVE_KEY")
    if not key and KEY_FILE.exists():
        key = KEY_FILE.read_text().strip()
    return key or None


def month_ids(today=None, count=MONTHS):
    """ "2026-10", "2026-09", ... newest first."""
    d = (today or date.today()).replace(day=1)
    out = []
    for _ in range(count):
        out.append(f"{d.year}-{d.month:02d}")
        d = (d - timedelta(days=1)).replace(day=1)
    return out


def fetch_month(month, key):
    """Ransomware.live's claims for one month, as a list of records (kept only in memory)."""
    year, mon = int(month[:4]), int(month[5:])
    if key:
        resp = requests.get(PRO_URL, params={"year": year, "month": f"{mon:02d}"},
                            headers={"X-API-KEY": key, "User-Agent": USER_AGENT}, timeout=60)
    else:
        resp = requests.get(FREE_URL.format(year=year, month=mon), headers={"User-Agent": USER_AGENT}, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, dict):
        data = data.get("victims") or data.get("data") or data.get("results") or []
    return data


def count(records):
    """Counts by country (ISO code, "" for unknown), sector and gang. Names are never read."""
    totals = Counter({("total", "all"): len(records)})
    for r in records:
        totals[("country", (r.get("country") or "").strip().upper()[:2])] += 1
        sector = (r.get("activity") or r.get("sector") or "").strip()
        totals[("sector", "" if sector.lower() in UNKNOWN_SECTORS else sector)] += 1
        totals[("group", (r.get("group") or r.get("group_name") or "").strip().lower())] += 1
    return totals


def save(conn, month, totals, source):
    with conn:
        conn.execute("DELETE FROM ransomware_counts WHERE month = ?", (month,))
        conn.executemany("INSERT INTO ransomware_counts (month, dimension, key, count) VALUES (?, ?, ?, ?)",
                         [(month, dim, key, n) for (dim, key), n in totals.items()])
    set_meta(conn, f"ransomware_{month}", datetime.now(timezone.utc).isoformat())
    set_meta(conn, "ransomware_source", source)


def _needs(conn, month, recent):
    """A month is fetched if it never has been; this month and last are refreshed once a day."""
    last = get_meta(conn, f"ransomware_{month}")
    if not last:
        return True
    return recent and datetime.now(timezone.utc) - datetime.fromisoformat(last) > REFRESH_EVERY


def update(conn, log=print):
    key = api_key()
    source = "pro" if key else "free"
    months = month_ids()
    wanted = [m for i, m in enumerate(months) if _needs(conn, m, recent=i < 2)]
    done = 0
    for month in wanted[:CALLS_PER_RUN[source]]:
        try:
            save(conn, month, count(fetch_month(month, key)), source)
        except (requests.RequestException, ValueError) as e:
            # Say which API and what it answered (never the key), so a failure can be diagnosed.
            api = "api-pro with the key" if key else "the keyless API"
            answer = ""
            if isinstance(e, requests.HTTPError) and e.response is not None:
                answer = f": it answered {e.response.status_code} {e.response.text[:120].strip()!r}"
            log(f"Ransomware stats: {month} failed using {api} ({e.__class__.__name__}{answer}); trying again next run")
            break
        done += 1
        if source == "pro" and done < len(wanted):
            time.sleep(1)
    if done:
        left = len(wanted) - done
        log(f"Ransomware stats: {done} month{'s' if done != 1 else ''} counted"
            + (f", {left} left for later runs" if left else "") + (" (keyless API)" if source == "free" else ""))


# ---------- Reading (the page) ----------

def stats(conn, gcc, top=10):
    """Everything /ransomware shows. gcc: the GCC's ISO codes."""
    months = month_ids()
    rows = conn.execute(
        f"SELECT month, dimension, key, count FROM ransomware_counts WHERE month IN ({','.join('?' * len(months))})",
        months).fetchall()
    by = {}
    for r in rows:
        by.setdefault(r["month"], Counter())[(r["dimension"], r["key"])] = r["count"]
    have = [m for m in reversed(months) if m in by]          # oldest first
    if not have:
        return None

    def totals(dimension, chosen):
        c = Counter()
        for m in chosen:
            for (dim, key), n in by[m].items():
                if dim == dimension:
                    c[key] += n
        return c

    current, previous = months[0], months[1]
    year_countries, year_sectors, year_groups = totals("country", have), totals("sector", have), totals("group", have)
    return {
        "months": [{"month": m, "total": by[m][("total", "all")] if m in by else None,
                    "gcc": sum(by[m][("country", cc)] for cc in gcc) if m in by else None} for m in reversed(months)],
        "covered": len(have),
        "current": {"month": current, "total": by[current][("total", "all")] if current in by else None},
        "previous": {"month": previous, "total": by[previous][("total", "all")] if previous in by else None},
        "year_total": sum(by[m][("total", "all")] for m in have),
        "countries": [(cc, n) for cc, n in year_countries.most_common() if cc][:top],
        "unknown_country": year_countries.get("", 0),
        "gcc": sorted(((cc, year_countries.get(cc, 0)) for cc in gcc), key=lambda kv: -kv[1]),
        "sectors": [(s, n) for s, n in year_sectors.most_common() if s][:top],
        "unknown_sector": year_sectors.get("", 0),
        "groups": [(g, n) for g, n in year_groups.most_common() if g][:top],
        "groups_now": [(g, n) for g, n in totals("group", [current] if current in by else []).most_common() if g][:5],
        "source": get_meta(conn, "ransomware_source"),
    }


def main():
    conn = connect()
    update(conn)
    data = stats(conn, {"AE", "SA", "QA", "KW", "BH", "OM"})
    if data:
        print(f"\n{data['covered']} of {MONTHS} months counted, {data['year_total']} claims in total")
        for m in data["months"]:
            print(f"  {m['month']}  {m['total'] if m['total'] is not None else '-':>6}  GCC {m['gcc'] if m['gcc'] is not None else '-'}")
    conn.close()


if __name__ == "__main__":
    main()
