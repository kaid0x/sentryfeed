"""Reviewed CWE-to-learning matches. No inference from headlines or CVE descriptions.

Resources teach a weakness class, never claim to reproduce the named CVE.
Reviewed 2026-10-16; course prerequisites and formats are displayed to readers.
"""
import json
import re

CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
PS = "https://portswigger.net/web-security/"
OST = "https://p.ost2.fyi/courses/course-v1:OpenSecurityTraining2+Vulns{}_C-family+2023_v1/about"
OWASP = "https://cheatsheetseries.owasp.org/cheatsheets/"
FAMILIES = {}


def _add(ids, title, explanation, url, provider, kind, preparation, prevention):
    family = dict(title=title, explanation=explanation, url=url, provider=provider,
                  kind=kind, preparation=preparation, prevention=prevention)
    for number in ids:
        FAMILIES[f"CWE-{number}"] = family


def _web(ids, title, explanation, topic, sheet):
    _add(ids, title, explanation, PS + topic, "PortSwigger Web Security Academy",
         "Reading and practice labs", "Free account for labs. Basic HTTP knowledge; some labs use Burp Suite.",
         OWASP + sheet + ".html" if sheet else PS + topic)


_web([89], "SQL injection", "Input changes a database command instead of being handled as data.",
     "sql-injection", "SQL_Injection_Prevention_Cheat_Sheet")
_web([78], "OS command injection", "Input changes a command that the server runs through its operating system.",
     "os-command-injection", "OS_Command_Injection_Defense_Cheat_Sheet")
_web([79], "Cross-site scripting", "Untrusted content becomes code running in another visitor's browser.",
     "cross-site-scripting", "Cross_Site_Scripting_Prevention_Cheat_Sheet")
_web([352], "Cross-site request forgery", "A site tricks a signed-in browser into sending an unwanted action to another site.",
     "csrf", "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet")
_web([22], "Path traversal", "A supplied file path escapes the directory the application intended to allow.",
     "file-path-traversal", None)
_web([918], "Server-side request forgery", "Input makes a server send a request to an unintended destination.",
     "ssrf", "Server_Side_Request_Forgery_Prevention_Cheat_Sheet")
_web([611], "XML external entities", "An XML parser follows references to outside files or services supplied in a document.",
     "xxe", "XML_External_Entity_Prevention_Cheat_Sheet")
_web([434], "Unsafe file uploads", "An application accepts a dangerous file type that can later be executed or served unsafely.",
     "file-upload", "File_Upload_Cheat_Sheet")
_web([502], "Insecure deserialization", "Rebuilding objects from untrusted saved data can trigger unintended behaviour.",
     "deserialization", "Deserialization_Cheat_Sheet")
_web([1336], "Template injection", "Input becomes part of a server-side template's instructions.",
     "server-side-template-injection", None)
_web([287], "Authentication weaknesses", "The application does not reliably check that someone is who they claim to be.",
     "authentication", "Authentication_Cheat_Sheet")
_web([862, 863, 639], "Authorization weaknesses", "The application fails to check whether this user may access a resource or perform an action.",
     "access-control", "Authorization_Cheat_Sheet")
_web([306], "Missing authentication", "A sensitive function is reachable without proving who is using it.",
     "access-control/lab-unprotected-admin-functionality", "Authentication_Cheat_Sheet")
_web([444], "HTTP request smuggling", "Servers disagree about where a request ends, letting a request be interpreted unexpectedly.",
     "request-smuggling", None)


def _memory(ids, title, explanation, course):
    _add(ids, title, explanation, OST.format(course), "OpenSecurityTraining2",
         "Video course", "Free course. C programming and memory concepts are useful; covers several weakness types.",
         "https://cwe.mitre.org/data/definitions/" + str(ids[0]) + ".html")


_memory([121], "Stack buffer overflow", "A write runs past a buffer on the stack and can overwrite nearby program state.", 1001)
_memory([122], "Heap buffer overflow", "A write runs past allocated heap storage and can damage neighbouring data.", 1001)
_memory([787], "Out-of-bounds write", "A program writes outside the memory region it is allowed to use.", 1001)
_memory([190, 191], "Integer overflow or underflow", "Arithmetic exceeds a number type's range, which can make sizes or checks incorrect.", 1001)
_memory([195, 196, 197], "Integer conversion errors", "Changing a number's size or signedness changes its meaning in a security-sensitive calculation.", 1001)
_memory([843], "Type confusion", "A program treats an object as a different type and uses its contents incorrectly.", 1002)
_memory([457, 908], "Uninitialized data", "A program uses memory before the required value has been set.", 1002)
_memory([362, 367], "Race conditions", "Another operation changes shared state between a check and the action that relies on it.", 1002)
_add([416], "Use-after-free", "A program uses memory after releasing it, when its contents may belong to something else.",
     "https://pwn.college/program-security/dynamic-allocator-misuse/", "pwn.college",
     "Practice labs", "Free account. Requires C, pointers and basic binary exploitation; begin with Freebie (Easy).",
     "https://www.cisa.gov/resources-tools/resources/memory-safe-languages-reducing-vulnerabilities-modern-software-development")
_add([134], "Uncontrolled format strings", "Untrusted input becomes formatting instructions that can read or change program memory.",
     "https://pwn.college/software-exploitation/format-string-exploits/", "pwn.college",
     "Practice labs", "Free account. Advanced: C, assembly and binary exploitation experience are useful.",
     "https://cwe.mitre.org/data/definitions/134.html")


def valid_ids(values):
    return sorted({v for v in values if isinstance(v, str) and CWE.fullmatch(v)},
                  key=lambda v: int(v[4:]))


def nvd_labels(weaknesses):
    labels = []
    for entry in weaknesses or []:
        if not isinstance(entry, dict):
            continue
        ids = valid_ids(d.get("value") for d in entry.get("description", []) if isinstance(d, dict))
        for cwe in ids:
            label = {"id": cwe, "source": str(entry.get("source") or "Unspecified contributor")[:200]}
            if label not in labels:
                labels.append(label)
    return labels


def _decode(raw):
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
        return value if isinstance(value, list) else []
    except (ValueError, TypeError):
        return []


def for_cve(details, kev):
    details, kev = details or {}, kev or {}
    sources = {}
    for label in _decode(details.get("cwes")):
        if isinstance(label, dict) and valid_ids([label.get("id")]):
            contributor = str(label.get("source") or "Unspecified contributor")[:200]
            sources.setdefault(label["id"], set()).add("NVD record: " + contributor)
    for cwe in valid_ids(_decode(kev.get("cwes"))):
        sources.setdefault(cwe, set()).add("CISA KEV")
    cards = {}
    unmatched = []
    for cwe in valid_ids(sources):
        evidence = {"id": cwe, "sources": sorted(sources[cwe]),
                    "url": "https://cwe.mitre.org/data/definitions/" + cwe[4:] + ".html"}
        family = FAMILIES.get(cwe)
        if family:
            card = cards.setdefault(family["title"], {**family, "labels": []})
            card["labels"].append(evidence)
        else:
            unmatched.append(evidence)
    pending = details.get("cwes") is None and kev.get("cwes") is None
    return {"cards": list(cards.values()), "unmatched": unmatched, "pending": pending}


def topic_id(title):
    return re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')


def catalogue():
    topics = {}
    for cwe, family in FAMILIES.items():
        topic = topics.setdefault(family['title'], {**family, 'slug': topic_id(family['title']), 'cwes': []})
        topic['cwes'].append(cwe)
    return sorted(topics.values(), key=lambda t: t['title'])


def saved_matches(conn, cve_ids):
    """Two indexed queries per batch; no live lookups and no dependency on a new schema."""
    from db import get_meta
    if get_meta(conn, 'learn_schema') != '1':
        return {}, False
    ids = sorted({c for c in cve_ids if isinstance(c, str) and re.fullmatch(r'CVE-\d{4}-\d{4,7}', c)})
    details, kev = {}, {}
    for start in range(0, len(ids), 400):
        batch = ids[start:start + 400]
        marks = ','.join('?' for _ in batch)
        for table, target in [('cve_details', details), ('kev', kev)]:
            target.update((r['cve_id'], dict(r)) for r in conn.execute(
                f'SELECT cve_id, cwes FROM {table} WHERE cve_id IN ({marks})', batch))
    return {c: for_cve(details.get(c), kev.get(c)) for c in ids}, True


def story_links(cve_ids, matches):
    counts = {}
    for cve in set(cve_ids):
        for card in matches.get(cve, {}).get('cards', []):
            counts[card['title']] = counts.get(card['title'], 0) + 1
    return [{'title': title, 'url': '/learn#' + topic_id(title)}
            for title in sorted(counts, key=lambda t: (-counts[t], t))[:3]]


def attach_stories(conn, stories):
    security = [s for s in stories if s.get('severity') in ('red', 'orange', 'yellow')]
    matches, ready = saved_matches(conn, {c for s in security for c in s.get('cves', [])})
    for s in stories:
        s['learning'] = story_links(s.get('cves', []), matches) if s.get('severity') in ('red', 'orange', 'yellow') else []
    return ready


def weekly(conn, stories, now=None):
    """Rolling seven days; counts describe saved labels, not a vulnerability ranking."""
    from datetime import datetime, timedelta, timezone
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=7)
    selected = []
    for s in stories:
        if s.get('severity') not in ('red', 'orange', 'yellow'):
            continue
        try:
            published = datetime.fromisoformat(s.get('published') or '')
            if since <= published <= now:
                selected.append(s)
        except (ValueError, TypeError):
            continue
    # CISA supplies dates, not times. Use seven calendar dates, including today in Dubai.
    from zoneinfo import ZoneInfo
    today = now.astimezone(ZoneInfo('Asia/Dubai')).date()
    recent = {r['cve_id'] for r in conn.execute(
        'SELECT cve_id FROM kev WHERE date_added BETWEEN ? AND ?',
        ((today - timedelta(days=6)).isoformat(), today.isoformat()))}
    news = {c for s in selected for c in s.get('cves', [])}
    matches, ready = saved_matches(conn, news | recent)
    topics = {}
    for cve, result in matches.items():
        for card in result['cards']:
            row = topics.setdefault(card['title'], {'title': card['title'], 'slug': topic_id(card['title']),
                                                    'cves': set(), 'news': set(), 'kev': set(), 'stories': 0})
            row['cves'].add(cve)
            if cve in news: row['news'].add(cve)
            if cve in recent: row['kev'].add(cve)
    for s in selected:
        titles = {card['title'] for c in s.get('cves', []) for card in matches.get(c, {}).get('cards', [])}
        for title in titles: topics[title]['stories'] += 1
    for row in topics.values():
        row['cves'] = sorted(row['cves'])
        row['news'] = len(row['news'])
        row['kev'] = len(row['kev'])
    ranked = sorted(topics.values(), key=lambda r: (-r['stories'], -r['kev'], r['title']))
    return {'topics': ranked, 'ready': ready, 'total': len(news | recent),
            'matched': sum(bool(r['cards']) for r in matches.values()),
            'catalogue': catalogue()}
