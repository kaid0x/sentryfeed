import html
import re
from datetime import datetime, timezone

import feedparser
import requests

from feeds import FEEDS

HEADERS = {"User-Agent": "SentryFeed/0.1 (personal threat-intel dashboard)"}
TIMEOUT = 15   # seconds; feedparser has no timeout of its own, so requests does the download
PER_FEED = 5   # how many titles to print per source when run directly

TAG_RE = re.compile(r"<[^>]+>")

# For feeds marked "cyber-only": keep an item only if its title, summary or tags
# look like cybersecurity. Plain "security" isn't enough, since Security Middle
# East also covers locks and CCTV.
CYBER_RE = re.compile(
    r"cyber|hack(?:er|ers|ed|ing)?\b|breach|ransomware|phishing|malware|spyware|data leak|leaked|"
    r"vulnerab|zero[- ]day|CVE-\d|exploit|DDoS|threat actor|infosec|information security|data protection|"
    r"\bscam|fraud|stolen data|identity theft|botnet|APT\d|SOC\b",
    re.IGNORECASE,
)


def looks_cyber(entry):
    tags = " ".join(t.get("term", "") for t in entry.get("tags", []) or [])
    return bool(CYBER_RE.search(f"{entry.get('title', '')} {entry.get('summary', '')} {tags}"))


def clean(text):
    """Strip HTML tags and entities, collapse whitespace."""
    return " ".join(html.unescape(TAG_RE.sub(" ", text or "")).split())


def published_iso(entry):
    """Feeds format dates every which way; feedparser normalises them to UTC
    struct_time. Stored as ISO 8601 so they sort and compare as plain strings."""
    t = entry.get("published_parsed") or entry.get("updated_parsed")
    if not t:
        return None
    return datetime(*t[:6], tzinfo=timezone.utc).isoformat()


def fetch_feed(category, name, url, only=None):
    """Download and parse one feed. Returns a list of item dicts; never raises,
    so one dead feed can't take down the whole run."""
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"  ! {name}: {e}")
        return []

    parsed = feedparser.parse(resp.content)
    if parsed.bozo and not parsed.entries:
        print(f"  ! {name}: could not parse feed ({parsed.bozo_exception})")
        return []

    return [
        {
            "category": category,
            "source": name,
            "title": clean(entry.get("title")) or "(no title)",
            "link": entry.get("link", "").strip(),
            "published": published_iso(entry),
            "summary": clean(entry.get("summary"))[:1000],
        }
        for entry in parsed.entries
        if only != "cyber-only" or looks_cyber(entry)
    ]


def fetch_all():
    items = []
    for category, sources in FEEDS.items():
        for name, url, *only in sources:
            items.extend(fetch_feed(category, name, url, *only))
    return items


def main():
    total = 0
    for category, sources in FEEDS.items():
        print(f"\n=== {category.upper()} ===")
        for name, url, *only in sources:
            items = fetch_feed(category, name, url, *only)
            total += len(items)
            print(f"\n[{name}] {len(items)} items")
            for item in items[:PER_FEED]:
                print(f"  - {item['title']}")
                print(f"    {item['link']}")
    print(f"\nDone. {total} items fetched across all feeds.")


if __name__ == "__main__":
    main()
