"""Starts the collector on GitHub Actions when the data is stale.

GitHub's own schedule never fired for this repository (11 Oct 2026: a known GitHub problem,
where manual runs work and scheduled ones never start), so an outside service visits
/tasks/collect every 5 minutes instead. The visit carries no secret. This asks GitHub for a
run only when the last collection is over FRESH_FOR old and no run was asked for in the last
RUN_GAP, so however often anyone visits, it starts no more runs than a schedule would. The
GitHub token (GITHUB_DISPATCH_TOKEN, allowed only to start workflows in this repository)
stays in the site's settings.

Answers are 200 when all is well or a retry will sort it out, and 503 when a person needs to
look: no token, a token GitHub refuses, data over ALERT_AFTER old, or no database. The outside
service emails on failures, and switches a job off after 25 failures in a row, so passing
GitHub hiccups stay 200."""

import os
from datetime import datetime, timedelta, timezone

import requests

from db import get_meta, last_collected

REPO = "kaid0x/sentryfeed"
WORKFLOW = "collect.yml"
BRANCH = "main"

FRESH_FOR = timedelta(minutes=27)     # with a visit every 5 minutes, a run about every 30
RUN_GAP = timedelta(minutes=20)       # a run usually takes 1-3 minutes; the daily pass longer
ALERT_AFTER = timedelta(hours=2)
TIMEOUT = 10                          # seconds; the outside service gives up after 30

# GitHub's answers that a retry won't fix: a bad, expired or under-permitted token, or a
# missing workflow. 403 is also how GitHub reports a rate limit, which a retry does fix.
NEEDS_A_PERSON = {401, 403, 404, 422}

_fresh_until = None   # while the data is known to be fresh, visits don't read the database


def dispatch_token():
    return os.environ.get("GITHUB_DISPATCH_TOKEN", "").strip()


def claim(conn, now, before):
    """Record that this visit is asking for a run, unless another visit just did. The UPDATE
    only matches the value read a moment ago, so of two visits at the same instant, only one
    changes the row and goes on to ask GitHub."""
    if before is None:
        cur = conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('dispatch_at', ?)", (now,))
    else:
        cur = conn.execute("UPDATE meta SET value = ? WHERE key = 'dispatch_at' AND value = ?", (now, before))
    conn.commit()
    return cur.rowcount == 1


def release(conn, now, before):
    """GitHub didn't start a run: put back the previous value, so the next visit tries again
    instead of waiting out RUN_GAP."""
    if before is None:
        conn.execute("DELETE FROM meta WHERE key = 'dispatch_at' AND value = ?", (now,))
    else:
        conn.execute("UPDATE meta SET value = ? WHERE key = 'dispatch_at' AND value = ?", (before, now))
    conn.commit()


def ask_github(token):
    """Start the collector workflow. Returns (started, needs_a_person, detail)."""
    try:
        resp = requests.post(
            f"https://api.github.com/repos/{REPO}/actions/workflows/{WORKFLOW}/dispatches",
            json={"ref": BRANCH},
            headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
                     "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SentryFeed"},
            timeout=TIMEOUT)
    except requests.RequestException as e:
        return False, False, f"GitHub didn't answer ({e.__class__.__name__})"
    if 200 <= resp.status_code < 300:
        return True, False, "GitHub started a collector run"
    rate_limited = resp.status_code == 429 or resp.headers.get("x-ratelimit-remaining") == "0" \
        or "retry-after" in resp.headers
    return False, resp.status_code in NEEDS_A_PERSON and not rate_limited, \
        f"GitHub refused (HTTP {resp.status_code})"


def check(connect, now=None):
    """One visit. Returns (HTTP status, a line of plain text saying what happened)."""
    global _fresh_until
    now = now or datetime.now(timezone.utc)
    if _fresh_until and now < _fresh_until:
        return 200, "Fresh: nothing to do."
    token = dispatch_token()
    if not token:
        return 503, "Not set up: GITHUB_DISPATCH_TOKEN is missing."

    conn = connect()
    try:
        collected = last_collected(conn)
        age = now - collected if collected else None
        if age is not None and age < FRESH_FOR:
            _fresh_until = collected + FRESH_FOR
            return 200, f"Fresh: collected {minutes(age)} ago."

        before = get_meta(conn, "dispatch_at")
        stale = age is None or age > ALERT_AFTER
        said = f"collected {minutes(age)} ago" if age is not None else "never collected"
        if before and now - datetime.fromisoformat(before) < RUN_GAP:
            return (503 if stale else 200), f"Waiting: {said}; a run was asked for at {before[11:16]} UTC."
        stamp = now.isoformat()
        if not claim(conn, stamp, before):
            return (503 if stale else 200), f"Waiting: {said}; another visit is asking for a run."

        started, needs_a_person, detail = ask_github(token)
        if not started:
            release(conn, stamp, before)
        status = 503 if needs_a_person or stale else 200
        return status, f"{detail}; {said}."
    finally:
        conn.close()


def minutes(age):
    total = int(age.total_seconds() // 60)
    return f"{total} min" if total < 120 else f"{total // 60} h {total % 60} min"
