"""Cybersecurity events people submit: CTFs, webinars, conferences, meetups.

Anyone can submit an event through /events/submit, but nothing appears on the site
until it's approved here, on the Pi's command line. There's deliberately no admin
page, so there's no login to attack.

    python events.py pending           what's waiting, with the submitter's contact
    python events.py approve 4 [5 ...]
    python events.py reject 4 [5 ...]
    python events.py remove 4          take down an approved event
    python events.py list              upcoming approved events
"""
import hashlib
import hmac
import re
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

KINDS = [
    ("ctf", "CTF"),
    ("webinar", "Webinar"),
    ("conference", "Conference"),
    ("meetup", "Meetup"),
    ("workshop", "Workshop"),
    ("training", "Training"),
    ("other", "Other"),
]
KIND_LABELS = dict(KINDS)
DEFAULT_TZ = "Asia/Dubai"

LIMITS = {"title": 120, "organiser": 80, "location": 120, "url": 300, "description": 600, "contact": 120}
MAX_AHEAD = timedelta(days=730)        # nothing more than two years out
SUBMISSIONS_PER_DAY = 3                # per visitor
MAX_PENDING = 50                       # stop taking submissions if the queue gets this long
SHOW_ON_FEED = timedelta(days=14)      # events starting this soon also appear under the feed's Events tile
DEFAULT_LENGTH = timedelta(hours=2)    # how long an event without an end time counts as "on"

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[A-Za-z]{2,}$")


def clean_text(value, limit, multiline=False):
    """Strip control and direction-override characters, trim, and cap the length.
    Single-line fields collapse all whitespace; multi-line fields keep at most one blank line."""
    value = _CONTROL.sub("", (value or "").replace("\r\n", "\n"))
    if multiline:
        value = re.sub(r"[ \t]+", " ", value)
        value = re.sub(r"\n{3,}", "\n\n", value).strip()
    else:
        value = re.sub(r"\s+", " ", value).strip()
    return value[:limit]


def valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and "." in (parsed.hostname or "") and not parsed.username


def _parse_local(value, tz):
    """'2026-10-12T18:00' in the given zone -> aware UTC datetime, or None."""
    try:
        return datetime.fromisoformat(value).replace(tzinfo=tz).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def validate(form, now=None):
    """Returns (clean values, {field: error message}). Error messages are plain text."""
    now = now or datetime.now(timezone.utc)
    errors, data = {}, {}

    data["title"] = clean_text(form.get("title"), LIMITS["title"])
    if len(data["title"]) < 5:
        errors["title"] = "Give the event a name (at least 5 characters)."

    data["kind"] = form.get("kind", "")
    if data["kind"] not in KIND_LABELS:
        errors["kind"] = "Pick what kind of event it is."

    tz_name = form.get("tz") or DEFAULT_TZ
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        tz_name, tz = DEFAULT_TZ, ZoneInfo(DEFAULT_TZ)
    data["tz"] = tz_name

    starts = _parse_local(form.get("starts"), tz)
    ends = _parse_local(form.get("ends"), tz) if form.get("ends") else None
    if not starts:
        errors["starts"] = "Add the date and time it starts."
    elif starts > now + MAX_AHEAD:
        errors["starts"] = "That's more than two years away."
    elif (ends or starts + DEFAULT_LENGTH) < now:
        errors["starts"] = "That event has already happened."
    if form.get("ends") and not ends:
        errors["ends"] = "That end time isn't a valid date and time."
    elif ends and starts and ends < starts:
        errors["ends"] = "It can't end before it starts."
    elif ends and starts and ends - starts > timedelta(days=31):
        errors["ends"] = "Events longer than a month aren't listed."
    data["starts_at"] = starts.isoformat() if starts else None
    data["ends_at"] = ends.isoformat() if ends else None

    data["online"] = 1 if form.get("online") == "yes" else 0
    data["location"] = clean_text(form.get("location"), LIMITS["location"])
    if not data["online"] and len(data["location"]) < 2:
        errors["location"] = "Say where it's held, or mark it as online."

    data["url"] = clean_text(form.get("url"), LIMITS["url"])
    if not valid_url(data["url"]):
        errors["url"] = "Add a link to the event page, starting with https://."

    data["organiser"] = clean_text(form.get("organiser"), LIMITS["organiser"])
    if len(data["organiser"]) < 2:
        errors["organiser"] = "Who's running it?"

    data["description"] = clean_text(form.get("description"), LIMITS["description"], multiline=True)

    data["contact"] = clean_text(form.get("contact"), LIMITS["contact"])
    if data["contact"] and not _EMAIL.match(data["contact"]):
        errors["contact"] = "That doesn't look like an email address. It's optional, so you can leave it empty."
    return data, errors


def visitor_key(secret, address):
    """A keyed hash of the visitor's IP: enough to rate-limit, without storing the IP."""
    return hmac.new(secret.encode(), (address or "").encode(), hashlib.sha256).hexdigest()[:16]


def can_submit(conn, submitter, now=None):
    """None if this visitor may submit, otherwise the reason they can't (plain text)."""
    now = now or datetime.now(timezone.utc)
    pending = conn.execute("SELECT COUNT(*) FROM events WHERE status = 'pending'").fetchone()[0]
    if pending >= MAX_PENDING:
        return "Submissions are paused while the queue is reviewed. Please try again in a day or two."
    since = (now - timedelta(days=1)).isoformat()
    recent = conn.execute(
        "SELECT COUNT(*) FROM events WHERE submitter = ? AND submitted_at >= ?", (submitter, since)
    ).fetchone()[0]
    if recent >= SUBMISSIONS_PER_DAY:
        return f"You can submit up to {SUBMISSIONS_PER_DAY} events a day. Please try again tomorrow."
    return None


def save(conn, data, submitter, now=None):
    now = now or datetime.now(timezone.utc)
    cur = conn.execute(
        """INSERT INTO events (title, kind, starts_at, ends_at, tz, online, location, url, organiser,
                               description, contact, status, submitted_at, submitter)
           VALUES (:title, :kind, :starts_at, :ends_at, :tz, :online, :location, :url, :organiser,
                   :description, :contact, 'pending', :submitted_at, :submitter)""",
        {**data, "location": data["location"] or None, "description": data["description"] or None,
         "contact": data["contact"] or None, "submitted_at": now.isoformat(), "submitter": submitter},
    )
    conn.commit()
    return cur.lastrowid


def _until(start, end, now):
    if start <= now <= end:
        return "on now"
    days = (start.date() - now.date()).days
    if days <= 0:
        hours = max(1, int((start - now).total_seconds() // 3600))
        return f"in {hours}h"
    return "tomorrow" if days == 1 else f"in {days} days"


def upcoming(conn, within=None, now=None):
    """Approved events that haven't finished, soonest first. `within` limits how far ahead."""
    now = now or datetime.now(timezone.utc)
    rows = conn.execute(
        "SELECT * FROM events WHERE status = 'approved' ORDER BY starts_at"
    ).fetchall()
    found = []
    for row in rows:
        start = datetime.fromisoformat(row["starts_at"])
        end = datetime.fromisoformat(row["ends_at"]) if row["ends_at"] else start + DEFAULT_LENGTH
        if end < now or (within and start > now + within):
            continue
        event = {k: row[k] for k in ("id", "title", "kind", "starts_at", "ends_at", "tz", "online",
                                     "location", "url", "organiser", "description")}
        event["kind_label"] = KIND_LABELS.get(row["kind"], "Other")
        event["when"] = _until(start, end, now)
        local = start.astimezone(ZoneInfo(DEFAULT_TZ))
        event["starts_display"] = local.strftime("%a %d %b %Y, %H:%M") + " (Dubai)"
        event["day"], event["month"] = local.day, local.strftime("%b")
        event["where"] = "Online" if row["online"] else row["location"]
        found.append(event)
    return found


def as_feed_items(events):
    """Events shaped like feed stories, for the Events tile on the dashboard."""
    return [{
        "id": f"event-{e['id']}", "severity": "blue", "category": "event", "title": e["title"],
        "source": e["organiser"], "summary": e["description"] or "", "link": e["url"],
        "published": None, "age": e["when"], "cves": [], "kev": 0,
        "severity_reason": f"{e['kind_label']} · {e['where']} · {e['starts_display']}",
        "where": [], "blamed": [], "products": [], "also": [], "event": True,
    } for e in events]


# ---------- command line review ----------

def _safe(value):
    """Submitted text never reaches the terminal raw, so it can't send escape codes."""
    return _CONTROL.sub("?", str(value)) if value is not None else "-"


def _print_event(row):
    print(f"#{row['id']}  [{row['status']}]  {_safe(row['title'])}")
    print(f"    {KIND_LABELS.get(row['kind'], row['kind'])} · "
          f"{'Online' if row['online'] else _safe(row['location'])} · starts {row['starts_at']} UTC"
          f"{' · ends ' + row['ends_at'] + ' UTC' if row['ends_at'] else ''} (entered in {_safe(row['tz'])})")
    print(f"    organiser: {_safe(row['organiser'])}")
    print(f"    link:      {_safe(row['url'])}")
    if row["description"]:
        for line in _safe(row["description"]).splitlines():
            print(f"    | {line}")
    print(f"    contact:   {_safe(row['contact'])}   submitted {row['submitted_at'][:16]}")
    print()


def main(argv):
    from db import connect

    if len(argv) < 2 or argv[1] not in ("pending", "approve", "reject", "remove", "list"):
        print(__doc__)
        return 1
    command, ids = argv[1], argv[2:]
    conn = connect()
    if command == "pending":
        rows = conn.execute("SELECT * FROM events WHERE status = 'pending' ORDER BY submitted_at").fetchall()
        print(f"{len(rows)} waiting for review\n")
        for row in rows:
            _print_event(row)
        if rows:
            print("Approve with: python events.py approve <id>   Reject with: python events.py reject <id>")
    elif command == "list":
        for e in upcoming(conn):
            print(f"#{e['id']}  {e['starts_display']}  [{e['kind_label']}] {_safe(e['title'])} ({e['when']})")
    else:
        if not ids or not all(i.isdigit() for i in ids):
            print(f"Usage: python events.py {command} <id> [<id> ...]")
            return 1
        new_status = {"approve": "approved", "reject": "rejected", "remove": "rejected"}[command]
        allowed_from = {"approve": ("pending", "rejected"), "reject": ("pending",), "remove": ("approved",)}[command]
        now = datetime.now(timezone.utc).isoformat()
        for i in ids:
            row = conn.execute("SELECT id, title, status FROM events WHERE id = ?", (int(i),)).fetchone()
            if not row:
                print(f"#{i}: no such event")
            elif row["status"] == new_status:
                print(f"#{i}: already {new_status}")
            elif row["status"] not in allowed_from:
                print(f"#{i}: is {row['status']}; use 'approve' to bring back a rejected event")
            else:
                conn.execute("UPDATE events SET status = ?, reviewed_at = ? WHERE id = ?", (new_status, now, int(i)))
                print(f"#{i}: {new_status}  {_safe(row['title'])}")
        conn.commit()
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
