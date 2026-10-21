# Evidence and publication notes

Prepared 21 October 2026. The companion case study is a first-person draft for Haseeb's portfolio. It has not been published to the portfolio site.

## Measurement provenance

- `evidence/pi-snapshot.txt`, response-time section: homepage 6.124730 seconds; Gulf 6.777381 seconds. Requests were made on the Pi itself, without an intervening network.
- `evidence/pi-after-step1.txt`, round 1: homepage 1.310458 seconds; Gulf 0.889341 seconds. Round 2 is faster and is deliberately not substituted for round 1.
- Reduction calculation: `(before - after) / before`. Homepage 78.60%; Gulf 86.88%; rounded to 79% and 87% in the article.
- Snapshot memory: 229 MiB used, 905 MiB available total; power flags `0x50005`. The article explicitly discloses the machine's condition.
- Collector counts: 145 finished and zero failed in the snapshot's seven-day query. The project had a shorter observed history; the article does not claim seven uninterrupted days of operation.
- Raw evidence stays private and is not linked or copied into this publication folder. It contains operational details unsuitable for a public portfolio.

## Implementation evidence

Architecture, preparation and deployment: README, collect.py, grouping.py, tursodb.py, trigger.py, and .github/workflows/collect.yml. Security controls: app.py, safefetch.py, domaincheck.py, events.py and browser tool scripts. NVD handling: enrich.py and vulns.py. Feature scope and validation: docs/password-storage.md, docs/campaign-workbench.md, docs/breach-family-tree.md and README.

The NVD recovery narrative was previously checked against actual collector logs and read-only Turso results. Latest checked run 39496415527 fetched 100 NVD details with 1665 still queued and counted two ransomware months. The article avoids presenting that changing backlog as a current fixed number.

## Images

- home.png: live https://sentryfeed.vercel.app/, captured 21 October 2026, 1280×720 viewport.
- campaign.png: live https://sentryfeed.vercel.app/campaign, same date and viewport, with the built-in fictional exercise loaded. Draft report text remains local to the tab. No evidence mappings were fabricated for the screenshot.
- Both images were visually inspected. They are viewport screenshots, not complete-page captures. Existing theme was retained.
- No Pi photograph was available in the evidence folder. None was fabricated.

## Publication checks

The root WRITEUP.md references PNG files under docs/writeup/. Preserve those paths when importing, or update them for the portfolio platform. Check heading and image rendering in that platform before publishing. Check that the live and source links remain valid at publication time.

Do not add uptime guarantees, production-user counts, financial savings, a claim that the site detects every incident, or an independent security-audit claim. No evidence supports those statements. Public feed headlines in screenshots are source reporting, not independently verified portfolio claims.
