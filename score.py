import re
from collections import Counter

from db import connect

# Keyword lists are the part you'll tune most. Matching is case-insensitive,
# on whole words, against the title and summary.

# Webinars, virtual events, guides and similar posts in the security feeds. They can
# be worth reading, so they get their own colour instead of being hidden, and they
# never count as incidents however alarming the topic. Matched on the title only.
EVENT_TERMS = [
    r"^\[[^\]]*(?:webinar|webcast|virtual event|live event|summit|conference|"
    r"guide|e-?book|whitepaper|report|podcast|on-demand|workshop)[^\]]*\]",
    r"^(?:webinar|webcast|virtual event|live event|podcast|workshop)\b",
    r"\b(?:webinars?|webcasts?)\b",
    r"\bupcoming speaking engagements\b",
    r"^friday squid blogging\b",
]

# Signs of real-world exploitation: these can push anything to red.
RED_TERMS = [
    r"actively exploit(?:ed|ing)",
    r"exploit(?:ed|ation) in the wild",
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
    r"data theft",
    r"credential theft",
    r"extortion",
    r"wipers?",
    r"worms?",
    r"spyware",
    r"(?:info)?stealers?",
    r"botnets?",
    r"ddos",
    r"malicious (?:[\w.-]+ )?(?:packages?|extensions?|updates?|apps?)",
    r"sql injection",
    r"auth(?:entication)? bypass",
    r"privilege escalation",
]

# A keyword right after one of these is being denied, as in "not a zero-day" or
# "hasn't been exploited in the wild", so it doesn't count. Only short filler words
# may sit in between, so "Microsoft has not patched a zero-day" still counts.
NEGATION_RE = re.compile(
    r"(?:\b(?:not|never|isn't|aren't|wasn't|weren't|hasn't|haven't|hadn't|doesn't|"
    r"don't|didn't)(?:\s+(?:a|an|the|yet|been|being|be|to|currently|known|believed|"
    r"thought|actually|really|considered)){0,3}\s+"
    r"|\bno (?:evidence|sign|signs|indication|reports?)\b[^.]{0,40}\s"
    r"|\bnon-?)$",
    re.IGNORECASE,
)

CVSS_RED = 9.0
CVSS_ORANGE = 7.0


def _pattern(terms):
    return re.compile(r"\b(?:" + "|".join(terms) + r")\b", re.IGNORECASE)


EVENT_RE = re.compile("|".join(EVENT_TERMS), re.IGNORECASE)
RED_RE = _pattern(RED_TERMS)
ORANGE_RE = _pattern(ORANGE_TERMS)


def _match(regex, text):
    """First match that isn't negated, lowercased, or None."""
    for m in regex.finditer(text):
        if not NEGATION_RE.search(text[max(0, m.start() - 80):m.start()]):
            return m.group(0).lower()
    return None


def classify(item):
    """Returns (colour, reason).

    Order of trust: CISA's exploited list, then the CVSS score, then keywords.
    Keywords only decide on their own when there is no score, except that
    exploitation language can still lift a scored item to red, because a
    medium-scored bug that's being exploited matters more than its score."""
    if item["category"] == "tech-ai":
        return "green", "tech / AI news"

    if EVENT_RE.search(item["title"]):
        if item["title"].lower().startswith("friday squid blogging"):
            return "blue", "Schneier's weekly open thread"
        return "blue", "event, webinar or guide"

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
    print("  ".join(f"{c}: {counts.get(c, 0)}" for c in ("red", "orange", "yellow", "green", "blue")))
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
