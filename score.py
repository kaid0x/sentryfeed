import re
from collections import Counter

from db import connect

# Keyword lists are the part you'll tune most. Matching is case-insensitive,
# on whole words, against the title and summary.

# Signs of real-world exploitation: these can push anything to red.
RED_TERMS = [
    r"actively exploited",
    r"exploited in the wild",
    r"under active exploitation",
    r"mass exploitation",
    r"zero[- ]days?",
    r"0[- ]days?",
]

# Serious but not confirmed as exploited: orange when there's no CVSS score to go on.
ORANGE_TERMS = [
    r"critical",
    r"remote code execution",
    r"rce",
    r"ransomware",
    r"data breach(?:es)?",
    r"breach(?:ed|es)?",
    r"backdoor(?:ed|s)?",
    r"supply[- ]chain attacks?",
    r"nation[- ]state",
    r"malware",
    r"hacked",
    r"take[sn]? over",
    r"takeovers?",
    r"compromised?",
    r"stolen",
    r"leak(?:ed|s)?",
    r"exploit(?:s|ed)?",
]

CVSS_RED = 9.0
CVSS_ORANGE = 7.0


def _pattern(terms):
    return re.compile(r"\b(?:" + "|".join(terms) + r")\b", re.IGNORECASE)


RED_RE = _pattern(RED_TERMS)
ORANGE_RE = _pattern(ORANGE_TERMS)


def _match(regex, text):
    m = regex.search(text)
    return m.group(0).lower() if m else None


def classify(item):
    """Returns (colour, reason).

    Order of trust: CISA's exploited list, then the CVSS score, then keywords.
    Keywords only decide on their own when there is no score, except that
    exploitation language can still lift a scored item to red, because a
    medium-scored bug that's being exploited matters more than its score."""
    if item["category"] == "tech-ai":
        return "green", "tech / AI news"

    if item["kev"]:
        return "red", "CISA: actively exploited"

    text = f"{item['title']} {item['summary'] or ''}"
    red_hit = _match(RED_RE, text)
    cvss = item["cvss"]

    if cvss is not None:
        if cvss >= CVSS_RED:
            return "red", f"CVSS {cvss}"
        if red_hit:
            return "red", f"CVSS {cvss} + mentions '{red_hit}'"
        if cvss >= CVSS_ORANGE:
            return "orange", f"CVSS {cvss}"
        return "yellow", f"CVSS {cvss}"

    if red_hit:
        return "red", f"mentions '{red_hit}'"
    orange_hit = _match(ORANGE_RE, text)
    if orange_hit:
        return "orange", f"mentions '{orange_hit}'"
    return "yellow", "no severity signals"


def score_all(conn):
    """Rescore every item each run: cheap at this size, and it means a CVSS score
    that arrives later, or a tweak to the keyword lists, applies to old items too."""
    counts = Counter()
    rows = conn.execute(
        "SELECT id, category, title, summary, cvss, kev FROM items"
    ).fetchall()
    for row in rows:
        colour, reason = classify(row)
        counts[colour] += 1
        conn.execute(
            "UPDATE items SET severity = ?, severity_reason = ? WHERE id = ?",
            (colour, reason, row["id"]),
        )
    conn.commit()
    return counts


def main():
    """Rescore and show what landed in red, to sanity-check the rules."""
    conn = connect()
    counts = score_all(conn)
    print("  ".join(f"{c}: {counts.get(c, 0)}" for c in ("red", "orange", "yellow", "green")))
    print("\nRed items:")
    for row in conn.execute(
        """SELECT source, title, severity_reason FROM items
           WHERE severity = 'red' ORDER BY published DESC LIMIT 25"""
    ):
        print(f"  [{row['source']}] {row['title']}")
        print(f"      why: {row['severity_reason']}")
    conn.close()


if __name__ == "__main__":
    main()
