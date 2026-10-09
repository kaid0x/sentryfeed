# Feed sources, grouped by category: (name, url) or (name, url, "cyber-only").
# Category matters later: "tech-ai" is always green, everything else gets severity-scored.

FEEDS = {
    "breaking": [
        ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
        ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
        ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ],
    "deep-dives": [
        ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
        ("Schneier on Security", "https://www.schneier.com/feed/atom/"),
    ],
    "advisories": [
        ("Microsoft MSRC", "https://api.msrc.microsoft.com/update-guide/rss"),
    ],
    # Gulf and Middle East. These mix in general tech, vendor and physical-security
    # news, so only items that look like cybersecurity are kept (see fetch.CYBER_RE).
    "regional": [
        ("The National", "https://www.thenationalnews.com/arc/outboundfeeds/rss/category/future/technology/?outputType=xml", "cyber-only"),
        ("Tahawultech", "https://www.tahawultech.com/feed/", "cyber-only"),
        ("Security Middle East", "https://www.securitymiddleeastmag.com/feed/", "cyber-only"),
    ],
    "tech-ai": [
        ("TechCrunch", "https://techcrunch.com/feed/"),
        ("The Verge AI", "https://www.theverge.com/rss/ai-artificial-intelligence/index.xml"),
        ("MIT Technology Review", "https://www.technologyreview.com/feed/"),
    ],
}
