"""RSS feeds out: SentryFeed's stories, followed from a feed reader, Outlook or Slack's RSS app.

RSS 2.0, since every reader understands it. Built with ElementTree so feed content (untrusted,
like everything from the source feeds) is always escaped, and with characters XML forbids removed.
"""
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import format_datetime

FEED_DAYS = 7
MAX_ITEMS = 50
SUMMARY_CHARS = 600
# XML 1.0 allows tab, newline and carriage return, but no other control characters.
_FORBIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")

# (path name, title, description, which stories)
FEEDS = {
    "major": ("Major stories", "Confirmed exploitation, zero-days and flaws rated 9 or more out of 10."),
    "major-medium": ("Major and Medium stories", "Everything serious: Major stories, plus breaches, ransomware, "
                                                 "malware and flaws rated 7 or more out of 10."),
    "gulf": ("In the Gulf", "Security news from the Gulf's own outlets and any story naming a GCC country, "
                            "without vendor announcements."),
    "patch": ("Patch this first", "The flaws most worth fixing first this week, ranked by CISA's exploited "
                                  "list, the chance of exploitation, severity and news coverage."),
    "events": ("Events", "CTFs, webinars, conferences and meetups listed on SentryFeed, once approved."),
}


def _clean(text):
    return _FORBIDDEN.sub("", text or "")


def _date(value):
    """RFC 822 date, as RSS wants: "Sat, 10 Oct 2026 08:41:00 +0000"."""
    when = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    return format_datetime(when.astimezone(timezone.utc))


def story_item(story, severity_label):
    """A feed item for a grouped story. The guid is the story's first stored article, which stays
    the same when more outlets join, so readers don't show it twice."""
    first = min([story["id"], *(a["id"] for a in story["also"])])
    reason = story.get("reason")
    lines = [f"{severity_label}." + (f" {reason}." if reason else "") + f" From {story['source']}."]
    if story.get("summary"):
        summary = story["summary"]
        lines.append(summary if len(summary) <= SUMMARY_CHARS else summary[:SUMMARY_CHARS].rsplit(" ", 1)[0] + "…")
    if story["also"]:
        lines.append("Also reported by " + ", ".join(a["source"] for a in story["also"]) + ".")
    if story["cves"]:
        lines.append("CVEs: " + ", ".join(story["cves"][:8]) + ".")
    return {
        "title": story["headline"],
        "link": story["link"],
        "guid": f"sentryfeed-story-{first}",
        "published": story["published"],
        "description": "\n\n".join(lines),
        "category": severity_label,
    }


def patch_item(row, rank, page_url):
    """A patch-queue entry. One item per CVE, so a flaw moving up or down the queue isn't repeated."""
    why = "; ".join(f"{label} (+{points})" for _, label, points in row["why"])
    fix = {"patch": "A patch is available.", "advisory": "The vendor has an advisory.",
           "none": "No patch link in NVD's record: check the vendor.", "unchecked": "Fix not checked yet."}[row["fix"]]
    return {
        "title": f"{row['title']} ({row['cve_id']})" if row["title"] != row["cve_id"] else row["cve_id"],
        "link": page_url,
        "guid": f"sentryfeed-patch-{row['cve_id']}",
        "published": row["date"] + "T00:00:00+00:00" if row["date"] and len(row["date"]) == 10 else row["date"],
        "description": f"Number {rank} this week, {row['total']} points. Why: {why}. {fix}",
        "category": "Patch this first",
    }


def event_item(event):
    return {
        "title": event["title"],
        "link": event["url"],
        "guid": f"sentryfeed-event-{event['id']}",
        "published": event.get("reviewed_at") or event["starts_at"],
        "description": f"{event['kind_label']}, {event['where']}, {event['starts_display']}. "
                       f"Organised by {event['organiser']}." + (f"\n\n{event['description']}" if event.get("description") else ""),
        "category": event["kind_label"],
    }


def build(title, description, page_url, feed_url, items):
    """The feed as UTF-8 XML bytes, newest items first."""
    rss = ET.Element("rss", {"version": "2.0", "xmlns:atom": "http://www.w3.org/2005/Atom"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = f"SentryFeed: {title}"
    ET.SubElement(channel, "link").text = page_url
    ET.SubElement(channel, "description").text = description
    ET.SubElement(channel, "language").text = "en"
    ET.SubElement(channel, "ttl").text = "30"     # the collector runs every 30 minutes
    ET.SubElement(channel, "atom:link", {"href": feed_url, "rel": "self", "type": "application/rss+xml"})
    ET.SubElement(channel, "lastBuildDate").text = _date(datetime.now(timezone.utc))
    for it in sorted(items, key=lambda i: i["published"] or "", reverse=True)[:MAX_ITEMS]:
        node = ET.SubElement(channel, "item")
        ET.SubElement(node, "title").text = _clean(it["title"])
        if it["link"]:
            ET.SubElement(node, "link").text = it["link"]
        ET.SubElement(node, "guid", {"isPermaLink": "false"}).text = it["guid"]
        if it["published"]:
            ET.SubElement(node, "pubDate").text = _date(it["published"])
        ET.SubElement(node, "description").text = _clean(it["description"])
        ET.SubElement(node, "category").text = _clean(it["category"])
    return ('<?xml version="1.0" encoding="utf-8"?>\n' + ET.tostring(rss, encoding="unicode")).encode("utf-8")
