import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

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
    key = os.environ.get("NVD_API_KEY")
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


def lookup(cve_id, key):
    """Returns (score or None, is_in_cisa_kev)."""
    headers = {"User-Agent": "SentryFeed/0.1"}
    if key:
        headers["apiKey"] = key
    resp = requests.get(NVD_URL, params={"cveId": cve_id}, headers=headers, timeout=20)
    if resp.status_code in (403, 429, 503):
        raise RateLimited(resp.status_code)
    if resp.status_code == 404:
        return None, False
    resp.raise_for_status()

    vulns = resp.json().get("vulnerabilities") or []
    if not vulns:
        return None, False  # reserved or not yet published in NVD
    cve = vulns[0]["cve"]
    return best_score(cve.get("metrics", {})), "cisaExploitAdd" in cve


def tag_items(conn):
    """Record which CVE IDs each unchecked item mentions."""
    rows = conn.execute(
        "SELECT id, title, summary, link FROM items WHERE cves IS NULL"
    ).fetchall()
    for row in rows:
        ids = extract_cves(row["title"], row["summary"], row["link"])
        conn.execute("UPDATE items SET cves = ? WHERE id = ?", (",".join(ids), row["id"]))
    conn.commit()
    return len(rows)


def cves_to_lookup(conn):
    """CVE IDs never looked up, or looked up without a score more than a day ago.
    Newest articles first, so today's news gets scored before the backlog."""
    now = datetime.now(timezone.utc)
    cache = {r["cve_id"]: r for r in conn.execute("SELECT * FROM cve_cache")}
    wanted, seen = [], set()
    rows = conn.execute(
        "SELECT cves FROM items WHERE cves != '' ORDER BY published DESC"
    ).fetchall()
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


def lookup_pending(conn):
    key = api_key()
    pace = PACE_WITH_KEY if key else PACE_NO_KEY
    pending = cves_to_lookup(conn)
    done = 0

    for cve_id in pending[: pace["budget"]]:
        try:
            score, kev = lookup(cve_id, key)
        except RateLimited as e:
            print(f"  ! NVD rate limit ({e}); the rest will be looked up next run")
            break
        except requests.RequestException as e:
            print(f"  ! NVD unreachable ({e}); the rest will be looked up next run")
            break

        conn.execute(
            "INSERT OR REPLACE INTO cve_cache (cve_id, cvss, kev, checked_at) VALUES (?, ?, ?, ?)",
            (cve_id, score, int(kev), datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        done += 1
        time.sleep(pace["delay"])

    return {"looked_up": done, "pending": len(pending) - done, "has_key": key is not None}


def roll_up(conn):
    """Copy CVE results onto items: highest score, and KEV if any CVE is flagged."""
    cache = {r["cve_id"]: r for r in conn.execute("SELECT cve_id, cvss, kev FROM cve_cache")}
    for row in conn.execute("SELECT id, cves FROM items WHERE cves != ''").fetchall():
        hits = [cache[c] for c in row["cves"].split(",") if c in cache]
        scores = [h["cvss"] for h in hits if h["cvss"] is not None]
        conn.execute(
            "UPDATE items SET cvss = ?, kev = ? WHERE id = ?",
            (max(scores) if scores else None, int(any(h["kev"] for h in hits)), row["id"]),
        )
    conn.commit()


def enrich(conn):
    tag_items(conn)
    stats = lookup_pending(conn)
    roll_up(conn)
    return stats
