"""Build the browser catalogue from a pinned official ATT&CK release. No runtime network."""
import html
import hashlib
import json
from pathlib import Path
import re
import requests

COMMIT = '6cda5ad8462c79e14fbb872f4e09059b18e0cfc4'
VERSION = '19.2'
ROOT = Path(__file__).resolve().parents[1]
BASE = f'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/{COMMIT}'

def build(bundle):
    techniques = []
    tactics = {}
    for obj in bundle['objects']:
        if obj.get('revoked') or obj.get('x_mitre_deprecated'):
            continue
        refs = [r for r in obj.get('external_references', []) if r.get('source_name') == 'mitre-attack']
        if not refs:
            continue
        ref = refs[0]
        if obj['type'] == 'x-mitre-tactic':
            tactics[obj['x_mitre_shortname']] = obj['name']
        if obj['type'] != 'attack-pattern' or not re.fullmatch(r'T\d{4}(?:\.\d{3})?', ref.get('external_id', '')):
            continue
        description = re.sub(r'\(Citation:.*?\)', '', obj.get('description', ''))
        description = re.sub(r'\[([^\]]+)\]\([^)]*\)', r'\1', description)
        description = html.unescape(re.sub(r'</?(?:code|a|span|em|strong|p|br|ul|li|b|i)\b[^>]*>', '', description))
        techniques.append({'id': ref['external_id'], 'name': obj['name'], 'description': description,
                           'tactics': [p['phase_name'] for p in obj.get('kill_chain_phases', []) if p['kill_chain_name'] == 'mitre-attack'],
                           'platforms': obj.get('x_mitre_platforms', []), 'url': ref['url']})
    matrix = next(o for o in bundle['objects'] if o['type'] == 'x-mitre-matrix' and not o.get('revoked'))
    by_id = {o['id']: o for o in bundle['objects']}
    order = [by_id[i]['x_mitre_shortname'] for i in matrix['tactic_refs']]
    if len(techniques) < 500 or not all(t in tactics for t in order):
        raise ValueError('Incomplete catalogue')
    return {'version': VERSION, 'commit': COMMIT, 'domain': 'enterprise-attack',
            'tactics': [{'id': t, 'name': tactics[t]} for t in order],
            'techniques': sorted(techniques, key=lambda t: t['id'])}

def main():
    r = requests.get(BASE + f'/enterprise-attack/enterprise-attack-{VERSION}.json', timeout=(10, 60))
    r.raise_for_status()
    catalogue = build(r.json())
    catalogue['source_sha256'] = hashlib.sha256(r.content).hexdigest()
    license_response = requests.get(BASE + '/LICENSE.txt', timeout=20)
    license_response.raise_for_status()
    (ROOT / 'static/attack-LICENSE.txt').write_text(license_response.text)
    (ROOT / 'static/attack-catalogue.json').write_text(json.dumps(catalogue, ensure_ascii=False, separators=(',', ':')))
    print(len(catalogue['techniques']), 'active techniques; ATT&CK', VERSION)

if __name__ == '__main__':
    main()
