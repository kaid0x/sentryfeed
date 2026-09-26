# Feed sources, grouped by category.
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
    "tech-ai": [
        ("TechCrunch", "https://techcrunch.com/feed/"),
        ("The Verge AI", "https://www.theverge.com/rss/ai-artificial-intelligence/index.xml"),
        ("MIT Technology Review", "https://www.technologyreview.com/feed/"),
    ],
}
