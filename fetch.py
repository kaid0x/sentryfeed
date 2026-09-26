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


def fetch_feed(category, name, url):
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
    ]


def fetch_all():
    items = []
    for category, sources in FEEDS.items():
        for name, url in sources:
            items.extend(fetch_feed(category, name, url))
    return items


def main():
    total = 0
    for category, sources in FEEDS.items():
        print(f"\n=== {category.upper()} ===")
        for name, url in sources:
            items = fetch_feed(category, name, url)
            total += len(items)
            print(f"\n[{name}] {len(items)} items")
            for item in items[:PER_FEED]:
                print(f"  - {item['title']}")
                print(f"    {item['link']}")
    print(f"\nDone. {total} items fetched across all feeds.")


if __name__ == "__main__":
    main()
