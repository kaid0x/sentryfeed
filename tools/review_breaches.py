"""Private co-mention leads and explicit, local approval of source-reviewed connections."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
import os

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import breaches
from db import DATABASE_ERRORS


def approve(catalogue, draft, output):
    graph = copy.deepcopy(catalogue)
    if not isinstance(draft, dict) or not isinstance(draft.get('nodes', []), list) or not isinstance(draft.get('links'), list) or not draft['links']:
        raise ValueError('Draft needs a nodes list and at least one reviewed link')
    graph['nodes'].extend(draft.get('nodes', []))
    graph['links'].extend(draft['links'])
    breaches.validate(graph)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=output.parent, delete=False) as f:
            temporary = Path(f.name)
            f.write(json.dumps(graph, ensure_ascii=False, indent=2) + '\n')
        os.replace(temporary, output)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    return len(draft['links'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalogue', type=Path, default=breaches.CATALOGUE)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('validate')
    suggest = sub.add_parser('suggest')
    suggest.add_argument('--days', type=int, default=14)
    suggest.add_argument('--output', type=Path, default=Path('.breach-review/leads.json'))
    accept = sub.add_parser('approve')
    accept.add_argument('--draft', type=Path, required=True)
    accept.add_argument('--confirm-source-review', action='store_true', required=True,
                        help='Confirm you reviewed each direction, scope, mechanism and cited source')
    args = parser.parse_args()
    try:
        graph = breaches.load(args.catalogue)
        if args.command == 'validate':
            print(f"Valid: {len(graph['nodes'])} incidents, {len(graph['links'])} reviewed connections")
        elif args.command == 'approve':
            if args.draft.stat().st_size > 2000000:
                raise ValueError('Draft exceeds 2 MB')
            count = approve(graph, json.loads(args.draft.read_text(encoding='utf-8')), args.catalogue)
            print(f'{count} connections added locally. Review the Git diff before committing. Nothing was pushed.')
        else:
            if not 1 <= args.days <= 90:
                raise ValueError('Choose a window from 1 to 90 days')
            if args.output.exists():
                raise ValueError('Output already exists. Choose a new filename to retain earlier review work.')
            from db import connect
            conn = connect(setup=False)
            try:
                since = (datetime.now(timezone.utc) - timedelta(days=args.days)).isoformat()
                rows = conn.execute('SELECT title, summary, link FROM items WHERE published >= ? ORDER BY published DESC LIMIT 1000', (since,)).fetchall()
                leads = breaches.candidates(graph, rows)
            finally:
                conn.close()
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open('x', encoding='utf-8') as f:
                json.dump({'status': 'private review leads; not established connections', 'leads': leads}, f, ensure_ascii=False, indent=2)
            print(f'{len(leads)} private co-mention leads written. None were published.')
    except (OSError, ValueError, TypeError, RuntimeError) + DATABASE_ERRORS as exc:
        # Fixed error categories avoid echoing draft or database contents, including secrets.
        print(f'Review command stopped ({type(exc).__name__}). Check the catalogue, draft schema or output path.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
