"""Patch-deadline calendar: CISA's fix-by dates for exploited flaws, as a calendar (.ics) that
Outlook, Google Calendar or Apple Calendar can subscribe to and keep up to date.

One all-day entry per deadline day, not per flaw: CISA often adds several flaws at once with
the same deadline, and a calendar with ten entries on one day is hard to read. Entries are
"free" time, so they never make anyone look busy.

Written by hand to RFC 5545 rather than with a library: CRLF line endings, lines folded at 75
bytes without splitting a character, and text escaped. CISA's text is treated as untrusted,
like feed content: control characters are removed and everything is escaped.
"""
import re
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

PAST_DAYS = 30                 # deadlines this far back stay, so a missed one is still visible
REFRESH = "PT6H"               # how often calendar apps should check; CISA's list is fetched daily

NOTE = ("CISA's deadline for US federal agencies to fix flaws that attackers are already using. "
        "It isn't binding on anyone else, but it's a widely used yardstick for how urgent a fix is.")

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")     # keeps \n, which escape() turns into \\n


def escape(text):
    """TEXT value escaping (RFC 5545 3.3.11): backslash, semicolon, comma and newlines."""
    text = _CONTROL.sub("", (text or "").replace("\r\n", "\n").replace("\r", "\n"))
    return text.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")


def fold(line):
    """Split a content line into pieces of at most 75 bytes (RFC 5545 3.1), never inside a
    UTF-8 character; each continuation starts with one space, which counts toward its 75."""
    out, current, size = [], "", 0
    for ch in line:
        n = len(ch.encode("utf-8"))
        if size + n > 75:
            out.append(current)
            current, size = " ", 1
        current += ch
        size += n
    out.append(current)
    return "\r\n".join(out)


def _vendors(flaws):
    seen = []
    for f in flaws:
        if f["vendor"] not in seen:
            seen.append(f["vendor"])
    return ", ".join(seen) if len(seen) <= 3 else ", ".join(seen[:3]) + f" and {len(seen) - 3} more"


def summary(flaws):
    """The entry's title, e.g. "CISA deadline: 3 exploited flaws (Fortinet, Microsoft, Ivanti)"."""
    if len(flaws) == 1:
        f = flaws[0]
        text = f"CISA deadline: {f['vendor']} {f['product']} ({f['cve_id']})"
    else:
        text = f"CISA deadline: {len(flaws)} exploited flaws ({_vendors(flaws)})"
    ransomware = sum(1 for f in flaws if f["ransomware"])
    if ransomware:
        text += ", used by ransomware" if len(flaws) == 1 else f", {ransomware} used by ransomware"
    return text


def description(flaws, page_url):
    lines = [NOTE, ""]
    for f in flaws:
        lines.append(f"{f['cve_id']}: {f['vendor']} {f['product']}. {(f['name'] or '').strip().rstrip('.')}.")
        try:
            added = date.fromisoformat(f["date_added"])
            listed = f"On CISA's list since {added.day} {added:%b %Y}."
        except (TypeError, ValueError):
            listed = "On CISA's list."
        lines.append(listed + (" Used by ransomware." if f["ransomware"] else ""))
        # CISA's own "required action" isn't included: it's written for US agencies (directives,
        # "see URL in Notes"). The flaw's page has the fix status and the vendor's links.
        lines.append("Fix status and vendor links: " + page_url(f["cve_id"]))
        lines.append("")
    return "\n".join(lines).strip()


def build(rows, name, calendar_url, page_url, patch_url, now=None):
    """The calendar as UTF-8 bytes. rows: CISA entries (cve_id, vendor, product, name, date_added,
    due_date, ransomware); page_url(cve_id) -> that flaw's SentryFeed page."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    days = defaultdict(list)
    for r in rows:
        try:
            days[date.fromisoformat(r["due_date"]).isoformat()].append(r)
        except (TypeError, ValueError):      # no deadline, or not a date: nothing to put on a calendar
            continue
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//SentryFeed//Patch deadlines//EN",
             "CALSCALE:GREGORIAN", "METHOD:PUBLISH",
             f"NAME:{escape(name)}", f"X-WR-CALNAME:{escape(name)}",
             f"X-WR-CALDESC:{escape(NOTE)}",
             f"SOURCE;VALUE=URI:{calendar_url}",
             f"REFRESH-INTERVAL;VALUE=DURATION:{REFRESH}", f"X-PUBLISHED-TTL:{REFRESH}"]
    for due in sorted(days):
        flaws = sorted(days[due], key=lambda f: (not f["ransomware"], f["vendor"], f["cve_id"]))
        start = date.fromisoformat(due)
        lines += ["BEGIN:VEVENT",
                  f"UID:cisa-deadline-{due}@sentryfeed.vercel.app",
                  f"DTSTAMP:{stamp}",
                  f"DTSTART;VALUE=DATE:{start:%Y%m%d}",
                  f"DTEND;VALUE=DATE:{start + timedelta(days=1):%Y%m%d}",
                  f"SUMMARY:{escape(summary(flaws))}",
                  f"DESCRIPTION:{escape(description(flaws, page_url))}",
                  f"URL;VALUE=URI:{patch_url}",
                  "TRANSP:TRANSPARENT",
                  "END:VEVENT"]
    lines.append("END:VCALENDAR")
    return ("\r\n".join(fold(line) for line in lines) + "\r\n").encode("utf-8")
