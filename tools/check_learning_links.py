"""Check the reviewed learning catalogue. Exit nonzero on failures, never silently drop links.

Run with the project's Python environment. No database, secrets or API keys needed.
A successful response proves reachability, not that the resource still teaches the same content.
"""
import concurrent.futures
import html
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import learn


def resource_urls():
    urls = {family[key] for family in learn.FAMILIES.values() for key in ('url', 'prevention')}
    urls.update('https://cwe.mitre.org/data/definitions/' + cwe[4:] + '.html' for cwe in learn.FAMILIES)
    return sorted(urls)


def check(url, get=requests.get):
    parts = urlsplit(url)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
        return False, 'Invalid catalogue URL'
    last = ''
    for _ in range(2):
        try:
            with get(url, timeout=(5, 10), stream=True,
                     headers={'User-Agent': 'Mozilla/5.0 (compatible; SentryFeed link checker)'}) as response:
                response.raise_for_status()
                if urlsplit(response.url).scheme != 'https':
                    return False, 'Redirected away from HTTPS'
                if 'text/html' not in response.headers.get('Content-Type', '').lower():
                    return False, 'Expected an HTML resource page'
                body = bytearray()
                for chunk in response.iter_content(8192):
                    body.extend(chunk)
                    if b'</title>' in body.lower() or len(body) >= 262144:
                        break
                match = re.search(r'<title[^>]*>(.*?)</title>', body.decode('utf-8', 'replace'), re.I | re.S)
                title = html.unescape(re.sub(r'\s+', ' ', match.group(1))).strip() if match else ''
                if not title or re.search(r'^(just a moment|access denied|not found|404|sign in|log in|robot check)', title, re.I):
                    return False, 'Missing resource title or a block/login/error page: ' + title[:120]
                return True, title[:160]
        except requests.RequestException as exc:
            last = type(exc).__name__
            if isinstance(exc, requests.HTTPError) and exc.response is not None:
                last += f' HTTP {exc.response.status_code}'
                if exc.response.status_code not in (408, 429, 500, 502, 503, 504):
                    break
    return False, last


def main():
    urls = resource_urls()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(check, urls))
    failures = 0
    for url, (ok, detail) in zip(urls, results):
        print(f'{"OK" if ok else "FAIL"} {url}: {detail}')
        if not ok and os.environ.get('GITHUB_ACTIONS') == 'true':
            # Workflow command escaping keeps remote page titles inert.
            message = f'{url}: {detail}'.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print(f'::error title=Learning resource needs review::{message}')
        failures += not ok
    print(f'{len(urls) - failures}/{len(urls)} reachable; {failures} need review.')
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
