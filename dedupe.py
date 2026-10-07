"""Group the same story reported by different outlets.

Two items count as the same story when they come from different sources, were
published within MAX_GAP of each other, and either mention the same CVE or have
similar enough titles. Title similarity weights rare words more than common ones,
so two headlines sharing "Kiteworks" count for much more than two sharing "flaw".

Run `python dedupe.py` to print the groups it would make from your database,
which is the way to check MIN_SIMILARITY after changing it.
"""
import math
import re
from collections import Counter
from datetime import datetime, timedelta

MIN_SIMILARITY = 0.35
MAX_GAP = timedelta(hours=72)

STOPWORDS = set("""
a an and are as at be been but by can could did do does for from had has have how in into is it
its just more most new no not now of on or our out over says say so than that the their them then
there these they this to up us was we were what when where which who why will with without you your
after amid before while about against all also any back down first get gets got here make makes
may might much off only other own same some still such take very via vs want wants way week
""".split())

TOKEN_RE = re.compile(r"cve-\d{4}-\d{4,7}|[a-z0-9]+(?:'[a-z]+)?")
CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}")


def tokens(title):
    words = set()
    for w in TOKEN_RE.findall(title.lower()):
        w = w.split("'")[0]                      # "openai's" -> "openai"
        if w.isdigit() or len(w) < 2 or w in STOPWORDS:
            continue
        if len(w) > 3 and w.endswith("s") and not w.endswith("ss"):
            w = w[:-1]                           # "attacks" -> "attack", "hours" -> "hour"
        words.add(w)
    return words


def _published(item):
    try:
        return datetime.fromisoformat(item["published"]) if item.get("published") else None
    except ValueError:
        return None


def similarity(a, b, idf):
    """Cosine similarity of two token sets, each word weighted by how rare it is."""
    shared = a & b
    if not shared:
        return 0.0
    dot = sum(idf[w] ** 2 for w in shared)
    norm = math.sqrt(sum(idf[w] ** 2 for w in a)) * math.sqrt(sum(idf[w] ** 2 for w in b))
    return dot / norm if norm else 0.0


def same_story(a, b, idf):
    """Returns why a and b look like the same story, or None."""
    if a["source"] == b["source"]:
        return None
    if (a.get("severity") == "blue") != (b.get("severity") == "blue"):
        return None                              # a webinar about a story isn't the story
    pa, pb = a["_published"], b["_published"]
    if pa and pb and abs(pa - pb) > MAX_GAP:
        return None
    if a["_cves"] & b["_cves"]:
        return "same CVE"
    score = similarity(a["_tokens"], b["_tokens"], idf)
    return f"titles {score:.2f}" if score >= MIN_SIMILARITY else None


def group_stories(items, rank):
    """Takes items already sorted best-first (by `rank`, then newest), returns one
    entry per story with the others attached as item["also"].

    Each item is only compared with the first item of each existing group, never
    with other members, so one loose match can't chain unrelated stories together."""
    for item in items:
        item["_tokens"] = tokens(item["title"])
        item["_cves"] = set(item.get("cves") or []) | set(CVE_RE.findall(item["title"].lower()))
        item["_cves"] = {c.upper() for c in item["_cves"]}
        item["_published"] = _published(item)

    df = Counter(w for item in items for w in item["_tokens"])
    n = len(items)
    idf = {w: math.log((n + 1) / (count + 1)) + 1 for w, count in df.items()}

    groups = []
    for item in items:
        for lead in groups:
            why = same_story(lead, item, idf)
            if why and all(m["source"] != item["source"] for m in lead["also"]):
                lead["also"].append({**item, "match": why})
                break
        else:
            item["also"] = []
            groups.append(item)

    for item in groups:
        for member in [item, *item["also"]]:
            for key in ("_tokens", "_cves", "_published"):
                member.pop(key, None)
    return groups


def main():
    """Print the groups the dashboard would make from the last 14 days."""
    from app import RANK, load_items_ungrouped

    items = load_items_ungrouped(14)
    groups = group_stories(items, RANK)
    merged = [g for g in groups if g["also"]]
    print(f"{len(items)} items -> {len(groups)} stories ({len(merged)} merged groups)\n")
    for g in merged:
        print(f"[{g['source']}] {g['title']}")
        for m in g["also"]:
            print(f"   + [{m['source']}] {m['title']}   ({m['match']})")
        print()


if __name__ == "__main__":
    main()
