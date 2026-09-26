from datetime import datetime, timedelta, timezone

from db import connect, count_by_category, cve_stats, save_items
from enrich import enrich
from fetch import fetch_all
from score import score_all

MAX_AGE_DAYS = 14      # ignore anything older; MSRC alone publishes its whole history
MAX_PER_SOURCE = 100   # safety cap so one noisy feed can't flood the database


def recent_only(items):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)).isoformat()
    kept, per_source = [], {}
    for item in items:
        if item["published"] and item["published"] < cutoff:
            continue
        seen = per_source.get(item["source"], 0)
        if seen >= MAX_PER_SOURCE:
            continue
        per_source[item["source"]] = seen + 1
        kept.append(item)
    return kept


def main():
    fetched = fetch_all()
    recent = recent_only(fetched)

    conn = connect()
    new = save_items(conn, recent)
    print(f"Fetched {len(fetched)} items, kept {len(recent)} from the last {MAX_AGE_DAYS} days.")
    print(f"{new} new, {len(recent) - new} already stored.")

    lookups = enrich(conn)
    note = "" if lookups["has_key"] else " (no NVD API key: slow public rate)"
    print(f"CVE lookups: {lookups['looked_up']} done, {lookups['pending']} still pending{note}")

    severity = score_all(conn)
    stats = cve_stats(conn)
    counts = count_by_category(conn)
    conn.close()

    print(f"Items mentioning CVEs: {stats['with_cves']}, scored: {stats['scored']}, "
          f"actively exploited (CISA KEV): {stats['kev']}")
    print("Severity: " + "  ".join(
        f"{c} {severity.get(c, 0)}" for c in ("red", "orange", "yellow", "green")))
    print("Database now holds:")
    for category, n in counts.items():
        print(f"  {category:<11} {n}")


if __name__ == "__main__":
    main()
