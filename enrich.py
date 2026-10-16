import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

import learn

from db import get_meta, set_meta

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEY_FILE = Path(__file__).with_name(".nvd_api_key")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Brand-new CVEs often have no score yet; NVD usually adds one within a few days.
RECHECK_UNSCORED_AFTER = timedelta(hours=24)

# NVD allows 5 requests per 30 seconds without a key, 50 with one.
# The budget caps lookups per run so a big backlog clears over several runs
# instead of one run taking half an hour.
PACE_NO_KEY = {"delay": 6.5, "budget": 20}
PACE_WITH_KEY = {"delay": 0.7, "budget": 250}


class RateLimited(Exception):
    pass


def api_key():
    key = os.environ.get("NVD_API_KEY", "").strip()
    if not key and KEY_FILE.exists():
        key = KEY_FILE.read_text().strip()
    return key or None


def extract_cves(*texts):
    found = set()
    for text in texts:
        found.update(m.upper() for m in CVE_RE.findall(text or ""))
    return sorted(found)


def best_score(metrics):
    """Newest CVSS version wins. Within a version, prefer NVD's own ("Primary")
    score over the vendor's ("Secondary"), but take the vendor's rather than nothing."""
    for version in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version) or []
        if entries:
            primary = [e for e in entries if e.get("type") == "Primary"]
            return (primary or entries)[0]["cvssData"]["baseScore"]
    return None


# Reference tags that point at a fix or the vendor's own write-up, shown on the CVE pages.
FIX_TAGS = {"Patch", "Vendor Advisory", "Mitigation"}
MAX_REFS = 6


def lookup(cve_id, key, timeout=20):
    """What NVD knows about one CVE: {found, cvss, kev, description, published, refs, cwes}."""
    headers = {"User-Agent": "SentryFeed/0.1"}
    if key:
        headers["apiKey"] = key
    resp = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=timeout)
    if resp.status_code in (403, 429, 503):
        raise RateLimited(resp.status_code)
    nothing = {"found": False, "cvss": None, "kev": False, "description": None, "published": None, "refs": [], "cwes": []}
    if resp.status_code == 404:
        return nothing
    resp.raise_for_status()

    vulns = resp.json().get("vulnerabilities") or []
    if not vulns:
        return nothing  # reserved or not yet published in NVD
    cve = vulns[0]["cve"]
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    refs = [{"url": r["url"], "tags": sorted(FIX_TAGS & set(r.get("tags") or []))}
            for r in cve.get("references", []) if FIX_TAGS & set(r.get("tags") or [])][:MAX_REFS]
    return {"found": True, "cvss": best_score(cve.get("metrics", {})), "kev": "cisaExploitAdd" in cve,
            "description": description, "published": cve.get("published"), "refs": refs,
            "cwes": learn.nvd_labels(cve.get("weaknesses"))}


def save_lookup(conn, cve_id, found):
    """Keep a lookup's score for the stories, and its description and fix links for the CVE pages."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO cve_cache (cve_id, cvss, kev, checked_at) VALUES (?, ?, ?, ?)",
        (cve_id, found["cvss"], int(found["kev"]), now),
    )
    conn.execute(
        """INSERT OR REPLACE INTO cve_details (cve_id, found, description, cvss, published, refs, checked_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (cve_id, int(found["found"]), found["description"], found["cvss"], found["published"],
         json.dumps(found["refs"]), now),
    )
    # Old cloud schemas remain usable until the collector adds the columns.
    if get_meta(conn, "learn_schema") == "1":
        conn.execute("UPDATE cve_details SET cwes = ? WHERE cve_id = ?",
                     (json.dumps(found.get("cwes", [])), cve_id))
    conn.commit()


def tag_items(conn):
    """Record which CVE IDs each unchecked item mentions, in items.cves and in item_cves."""
    if not get_meta(conn, "item_cves_filled"):
        # item_cves arrived after many articles were tagged: index those once.
        pairs = [(cve_id, row["id"]) for row in conn.execute("SELECT id, cves FROM items WHERE cves != ''")
                 for cve_id in row["cves"].split(",")]
        conn.executemany("INSERT OR IGNORE INTO item_cves (cve_id, item_id) VALUES (?, ?)", pairs)
        set_meta(conn, "item_cves_filled", "1")      # commits the index too
    rows = conn.execute(
        "SELECT id, title, summary, link FROM items WHERE cves IS NULL"
    ).fetchall()
    for row in rows:
        ids = extract_cves(row["title"], row["summary"], row["link"])
        conn.execute("UPDATE items SET cves = ? WHERE id = ?", (",".join(ids), row["id"]))
        conn.executemany("INSERT OR IGNORE INTO item_cves (cve_id, item_id) VALUES (?, ?)",
                         [(cve_id, row["id"]) for cve_id in ids])
    conn.commit()
    return len(rows)


def _window(since):
    """SQL and parameters limiting items to those published since `since` (None: every item)."""
    return ("", ()) if since is None else (" AND (published IS NULL OR published >= ?)", (since,))


def _by_cve(conn, sql, cve_ids):
    """{cve_id: row} from `sql`, which ends in "WHERE cve_id IN", for these CVEs only.
    In chunks, since SQLite limits how many values one query can take."""
    found, ids = {}, list(cve_ids)
    for start in range(0, len(ids), 500):
        chunk = ids[start:start + 500]
        found.update((r["cve_id"], r) for r in conn.execute(f"{sql} ({','.join('?' * len(chunk))})", chunk))
    return found


def cves_to_lookup(conn, since=None):
    """CVE IDs never looked up, or looked up without a score more than a day ago, from
    articles published since `since` (None: every article). Newest articles first, so
    today's news gets scored before the backlog."""
    now = datetime.now(timezone.utc)
    window, params = _window(since)
    rows = conn.execute("SELECT id, cves, published FROM items WHERE cves != ''" + window, params).fetchall()
    # Sorted here rather than with ORDER BY, which makes SQLite walk the whole date index to
    # skip a sort. Same order as ORDER BY published DESC: newest first, undated last.
    rows.sort(key=lambda r: (r["published"] or "", r["id"]), reverse=True)
    cache = _by_cve(conn, "SELECT * FROM cve_cache WHERE cve_id IN",
                    {c for row in rows for c in row["cves"].split(",")})
    wanted, seen = [], set()
    for row in rows:
        for cve_id in row["cves"].split(","):
            if cve_id in seen:
                continue
            seen.add(cve_id)
            cached = cache.get(cve_id)
            stale = (
                cached is not None
                and cached["cvss"] is None
                and now - datetime.fromisoformat(cached["checked_at"]) > RECHECK_UNSCORED_AFTER
            )
            if cached is None or stale:
                wanted.append(cve_id)
    return wanted


def lookup_pending(conn, since=None):
    key = api_key()
    pace = PACE_WITH_KEY if key else PACE_NO_KEY
    pending = cves_to_lookup(conn, since)
    done = 0

    for cve_id in pending[: pace["budget"]]:
        try:
            found = lookup(cve_id, key)
        except RateLimited as e:
            print(f"  ! NVD rate limit ({e}); the rest will be looked up next run")
            break
        except requests.RequestException as e:
            print(f"  ! NVD unreachable ({e}); the rest will be looked up next run")
            break

        save_lookup(conn, cve_id, found)
        done += 1
        time.sleep(pace["delay"])

    return {"looked_up": done, "pending": len(pending) - done, "has_key": key is not None}


def roll_up(conn, since=None):
    """Copy CVE results onto items published since `since` (None: every item): highest score,
    and KEV if any CVE is flagged, either by NVD or in CISA's own catalogue (vulns.py downloads
    it daily; NVD can take days to catch up). Only items whose score or flag changed are written."""
    window, params = _window(since)
    rows = conn.execute("SELECT id, cves, cvss, kev FROM items WHERE cves != ''" + window, params).fetchall()
    wanted = {c for row in rows for c in row["cves"].split(",")}
    cache = _by_cve(conn, "SELECT cve_id, cvss, kev FROM cve_cache WHERE cve_id IN", wanted)
    listed = set(_by_cve(conn, "SELECT cve_id FROM kev WHERE cve_id IN", wanted))
    changed = []
    for row in rows:
        ids = row["cves"].split(",")
        hits = [cache[c] for c in ids if c in cache]
        scores = [h["cvss"] for h in hits if h["cvss"] is not None]
        kev = any(h["kev"] for h in hits) or any(c in listed for c in ids)
        cvss = max(scores) if scores else None
        if (cvss, int(kev)) != (row["cvss"], row["kev"]):
            changed.append((cvss, int(kev), row["id"]))
    conn.executemany("UPDATE items SET cvss = ?, kev = ? WHERE id = ?", changed)
    conn.commit()


def enrich(conn, since=None):
    """since: only recheck articles published since then (None: every article)."""
    tag_items(conn)
    stats = lookup_pending(conn, since)
    roll_up(conn, since)
    return stats
