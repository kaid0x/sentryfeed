import os
import time
from datetime import datetime, timedelta, timezone

from db import ERRORS as DB_ERRORS, connect, count_by_category, cve_stats, get_meta, last_collected, mark_collected, save_items, set_meta
from enrich import enrich
from fetch import fetch_all
from grouping import rules_fingerprint, save_all as save_story_groups, tag_articles
from score import score_all
from stocks import update as update_stocks
from ransomware import update as update_ransomware
from vulns import update as update_vulns

MAX_AGE_DAYS = 14      # ignore anything older; MSRC alone publishes its whole history
MAX_PER_SOURCE = 100   # safety cap so one noisy feed can't flood the database

# Most runs recheck CVE scores and colours for the last MAX_AGE_DAYS only: the only articles a
# run can add, and most of what the pages show. A full pass rechecks every article (see
# full_pass_due), so the database isn't read in full 48 times a day.
FULL_PASS_EVERY = timedelta(hours=24)
SCORING_FILES = ("score.py", "enrich.py")

# Runs are started by the site's /tasks/collect (see trigger.py). GitHub's own schedule stays in
# the workflow as a backup; when it does fire, it skips data collected within this long.
SCHEDULED_SKIP_WITHIN = timedelta(minutes=20)


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


def full_pass_due(conn, kev_fetched_before):
    """Recheck every article on the run that refreshed CISA's list (it often adds old flaws,
    which turns old stories red), when the scoring code changed, or a day after the last one."""
    last = get_meta(conn, "full_pass_at")
    return (get_meta(conn, "kev_fetched") != kev_fetched_before
            or get_meta(conn, "scoring_rules") != rules_fingerprint(SCORING_FILES)
            or not last
            or datetime.now(timezone.utc) - datetime.fromisoformat(last) > FULL_PASS_EVERY)


def collected_recently():
    """True when the last run finished within SCHEDULED_SKIP_WITHIN. If the database can't be
    read, False: the run goes ahead and reports the problem itself."""
    try:
        conn = connect()
        try:
            when = last_collected(conn)
        finally:
            conn.close()
    except DB_ERRORS:
        return False
    return bool(when) and datetime.now(timezone.utc) - when < SCHEDULED_SKIP_WITHIN


def main():
    if os.environ.get("GITHUB_EVENT_NAME") == "schedule" and collected_recently():
        print(f"Scheduled run skipped: collected less than {SCHEDULED_SKIP_WITHIN.seconds // 60} minutes ago.")
        return
    fetched = fetch_all()
    recent = recent_only(fetched)

    conn = connect(setup=True)
    new = save_items(conn, recent)
    print(f"Fetched {len(fetched)} items, kept {len(recent)} from the last {MAX_AGE_DAYS} days.")
    print(f"{new} new, {len(recent) - new} already stored.")

    # Countries and products, once per article. If it fails, grouping works them out itself.
    try:
        print(f"Tagged {tag_articles(conn)} articles with countries and products")
    except Exception as e:
        print(f"Tagging: failed ({e.__class__.__name__}: {e})")

    # CISA's exploited list and EPSS scores, once a day. Before enrich, so a newly listed
    # flaw marks its stories as exploited in this same run. Never stops the rest of the run.
    kev_fetched_before = get_meta(conn, "kev_fetched")
    try:
        update_vulns(conn)
    except Exception as e:
        print(f"Vulnerabilities: failed ({e.__class__.__name__}: {e})")

    full = full_pass_due(conn, kev_fetched_before)
    since = None if full else (datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS)).isoformat()
    scope = "every article (full pass)" if full else f"articles from the last {MAX_AGE_DAYS} days"
    print(f"Rechecking CVE scores and colours for {scope}")

    lookups = enrich(conn, since)
    note = "" if lookups["has_key"] else " (no NVD API key: slow public rate)"
    print(f"CVE lookups: {lookups['looked_up']} done, {lookups['pending']} still pending{note}")

    severity = score_all(conn, since)
    if full:
        set_meta(conn, "full_pass_at", datetime.now(timezone.utc).isoformat())
        set_meta(conn, "scoring_rules", rules_fingerprint(SCORING_FILES))

    # Optional extra: never let it stop the rest of the run.
    try:
        update_stocks(conn)
    except Exception as e:
        print(f"Stocks: failed ({e.__class__.__name__}: {e})")

    try:
        update_ransomware(conn)
    except Exception as e:
        print(f"Ransomware stats: failed ({e.__class__.__name__}: {e})")

    # After scoring, so the saved stories carry this run's colours. If it fails, pages
    # group the stories themselves, as before.
    try:
        started = time.monotonic()
        changed, windows = save_story_groups(conn)
        print(f"Story groups: {changed} of {windows} windows changed, in {time.monotonic() - started:.1f}s")
    except Exception as e:
        print(f"Story groups: failed ({e.__class__.__name__}: {e})")

    # Totals read every article, so they're only worked out on a full pass.
    stats = cve_stats(conn) if full else None
    counts = count_by_category(conn) if full else None
    mark_collected(conn)
    conn.close()

    print(("Severity: " if full else f"Severity, last {MAX_AGE_DAYS} days: ") + "  ".join(
        f"{c} {severity.get(c, 0)}" for c in ("red", "orange", "yellow", "green")))
    if full:
        print(f"Items mentioning CVEs: {stats['with_cves']}, scored: {stats['scored']}, "
              f"actively exploited (CISA KEV): {stats['kev']}")
        print("Database now holds:")
        for category, n in counts.items():
            print(f"  {category:<11} {n}")


if __name__ == "__main__":
    main()
