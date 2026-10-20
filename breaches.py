"""Source-reviewed incident connections. No inferred causal edges are published."""
import json
import re
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlsplit

CATALOGUE = Path(__file__).with_name('data') / 'breaches.json'
MECHANISMS = {'session-token-reuse': 'Stolen session token reused',
              'stolen-credential-reuse': 'Stolen credentials reused',
              'supplier-access': 'Access through a supplier',
              'software-supply-chain': 'Compromised software delivery',
              'data-processor': 'Exposure through a data processor',
              'other-supported-link': 'Other sourced connection'}
OUTCOMES = {'contained-access': 'Access reported and contained',
            'reported-compromise': 'Internal compromise reported',
            'reported-exposure': 'Data exposure reported',
            'reported-attempt': 'Attempt reported'}


def text(value, limit=1000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid catalogue text')
    return value


def source_url(value):
    text(value, 2048)
    try:
        u = urlsplit(value)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.port not in (None, 443) or any(c.isspace() for c in value):
            raise ValueError('Invalid source URL')
    except (ValueError, TypeError):
        raise ValueError('Invalid source URL') from None
    return value


def sources(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 5:
        raise ValueError('Each record needs one to five sources')
    for s in values:
        if not isinstance(s, dict):
            raise ValueError('Invalid source')
        text(s.get('label'), 150)
        source_url(s.get('url'))


def validate(graph):
    if not isinstance(graph, dict) or type(graph.get('version')) is not int or graph['version'] != 1:
        raise ValueError('Unsupported catalogue version')
    nodes, links = graph.get('nodes'), graph.get('links')
    if not isinstance(nodes, list) or not isinstance(links, list) or len(nodes) > 200 or len(links) > 400:
        raise ValueError('Catalogue limits exceeded')
    ids, edge_ids, pairs = set(), set(), set()
    for n in nodes:
        if not isinstance(n, dict):
            raise ValueError('Invalid incident')
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,79}', text(n.get('id'), 80)) or n['id'] in ids:
            raise ValueError('Invalid or duplicate incident ID')
        ids.add(n['id'])
        for key, limit in [('title', 180), ('organisation', 100), ('summary', 1000)]:
            text(n.get(key), limit)
        period = text(n.get('period'), 7)
        if not re.fullmatch(r'\d{4}-\d{2}', period):
            raise ValueError('Use a YYYY-MM incident period')
        datetime.strptime(period, '%Y-%m')
        aliases = n.get('aliases')
        if not isinstance(aliases, list) or not 1 <= len(aliases) <= 10:
            raise ValueError('Invalid aliases')
        for alias in aliases:
            text(alias, 100)
        sources(n.get('sources'))
    adjacency = {key: [] for key in ids}
    connected = set()
    for edge in links:
        if not isinstance(edge, dict):
            raise ValueError('Invalid connection')
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,79}', text(edge.get('id'), 80)) or edge['id'] in edge_ids:
            raise ValueError('Invalid or duplicate connection ID')
        edge_ids.add(edge['id'])
        a, b = edge.get('from'), edge.get('to')
        if not isinstance(a, str) or not isinstance(b, str) or a not in ids or b not in ids or a == b or (a, b) in pairs:
            raise ValueError('Invalid, duplicate or dangling connection')
        pairs.add((a, b)); adjacency[a].append(b); connected.update((a, b))
        if not isinstance(edge.get('mechanism'), str) or not isinstance(edge.get('outcome'), str) or edge['mechanism'] not in MECHANISMS or edge['outcome'] not in OUTCOMES:
            raise ValueError('Unknown connection category')
        text(edge.get('summary')); text(edge.get('scope'))
        reviewed = text(edge.get('reviewed'), 10)
        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', reviewed) or date.fromisoformat(reviewed) > date.today():
            raise ValueError('Invalid review date')
        sources(edge.get('sources'))
    if connected != ids:
        raise ValueError('Every published incident needs a reviewed connection')
    visited, active = set(), set()
    def walk(key):
        if key in active:
            raise ValueError('Cyclic incident connections')
        if key in visited:
            return
        active.add(key)
        for child in adjacency[key]:
            walk(child)
        active.remove(key); visited.add(key)
    for key in ids:
        walk(key)
    return graph


def load(path=CATALOGUE):
    return validate(json.loads(Path(path).read_text(encoding='utf-8')))


def page(graph):
    by_id = {n['id']: n for n in graph['nodes']}
    families = []
    for parent in sorted(graph['nodes'], key=lambda n: (n['period'], n['id'])):
        connections = [dict(edge, target=by_id[edge['to']], mechanism_label=MECHANISMS[edge['mechanism']],
                            outcome_label=OUTCOMES[edge['outcome']]) for edge in graph['links'] if edge['from'] == parent['id']]
        if connections:
            families.append({'parent': parent, 'connections': sorted(connections, key=lambda e: (e['target']['period'], e['id']))})
    return {'families': families, 'incident_count': len(graph['nodes']), 'connection_count': len(graph['links'])}


def candidates(graph, rows):
    """Co-mentions are private review leads, never causal assertions or public edges."""
    orgs = {}
    for n in graph['nodes']:
        orgs.setdefault(n['organisation'], set()).update(n['aliases'])
    patterns = {org: [re.compile(r'(?<!\w)' + re.escape(a) + r'(?!\w)', re.I) for a in aliases] for org, aliases in orgs.items()}
    leads, seen = [], set()
    for row in rows:
        body = str(row['title'] or '') + ' ' + str(row['summary'] or '')
        hits = sorted(org for org, regexes in patterns.items() if any(p.search(body) for p in regexes))
        if len(hits) < 2 or row['link'] in seen:
            continue
        try:
            source_url(row['link'])
        except (ValueError, TypeError):
            continue
        seen.add(row['link'])
        leads.append({'title': re.sub(r'[\x00-\x1f\x7f]', '', str(row['title'] or ''))[:300],
                      'url': row['link'], 'organisations': hits, 'status': 'co-mention only; no connection established'})
        if len(leads) >= 100:
            break
    return leads
