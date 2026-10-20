# Campaign workbench: design and research

Built 20 October 2026. Route: `/campaign`, under Tools.

## Purpose

Help a reader turn a report into an evidence-backed Enterprise ATT&CK analysis. The analyst chooses mappings and objectives, preserves report passages, explains the reasoning, and marks findings reviewed. It supports campaign analysis without claiming to identify an APT group. APTs are only one possible subject: the workflow also fits unattributed campaigns and incidents.

## Research and decisions

- [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) already provides matrix annotation. Rather than build another matrix, the workbench handles the earlier task of mapping report evidence. Export follows the official [layer 4.5 specification](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md). Evidence, rationale and source are preserved in technique comments. No risk, attribution or detection-coverage scores are invented. Tactic-specific entries prevent a technique being painted under unsupported objectives.
- [Attack Flow](https://center-for-threat-informed-defense.github.io/attack-flow/overview/) models connected attacker behaviour. A tactic list is not an observed sequence, so this version groups by analyst-selected objective and explicitly avoids implying chronology. A later flow editor would need evidence-backed edges, branching and unknown order.
- [CISA mapping guidance](https://www.cisa.gov/news-events/news/best-practices-mitre-attckr-mapping) addresses mapping mistakes and analytical bias. The page returns 403 to some clients; its search-indexed description was available during research. Core product decisions are conservative: evidence before mapping, explicit IDs are drafts, sub-techniques require supporting detail, and reviewed means analyst-reviewed rather than independently verified.
- [MITRE's campaign definitions](https://attack.mitre.org/campaigns/) distinguish campaign activity from a group's broader history. This tool does not infer an actor from technique overlap or import every group technique into a campaign.
- The [official STIX repository](https://github.com/mitre-attack/attack-stix-data) supplies a pinned Enterprise 19.2 snapshot from commit `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`. There are 697 active techniques and sub-techniques; revoked/deprecated records are excluded. Navigator offered an upgrade to ATT&CK 20 during the test. This is an explicitly versioned snapshot, not a claim to use the newest release.
- [MITRE's licence](https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt) permits use with the required copyright and licence included. The full licence is bundled; SentryFeed makes no affiliation claim.

## Scope and privacy

Report text, URLs, selections, notes and imported projects stay in page memory. The only workbench fetch is its same-origin catalogue. No automatic localStorage or server storage, paid API, report upload, URL ingestion, PDF parser or AI inference. Normal site navigation and explicit external links work as usual. Project and Navigator downloads contain the analysis evidence and source URLs. Save the project to retain work between visits. Navigation with unsaved edits invokes the browser's standard warning where supported.

Users may paste 200,000 report characters and make 300 mappings. Excerpts are limited to 10,000 characters, rationales to 4,000 and source URLs to 2,000. Imports are capped at 25 MB, validate before replacement and require the same snapshot. Unknown IDs, unsupported objectives, invalid URLs, inconsistent evidence and invalid reviewed states reject the file atomically. Imported strings are rendered as text, never HTML. Sources accept HTTP/HTTPS without embedded credentials.

Each mapping records a technique, an analyst-selected tactic, exact UTF-16 report offsets, evidence excerpt, source URL, rationale and draft/reviewed state. Report edits invalidate the captured selection; mappings whose evidence no longer matches its offsets are removed, and retained mappings become drafts. This behaviour is explained in the interface. Editing a rationale or objective also returns the mapping to draft. Source URLs are captured per mapping so changing the overall report URL does not rewrite old evidence citations.

## Maintenance

`python tools/build_attack_catalogue.py` rebuilds from the pinned source. It stores the source bundle SHA-256, source commit, release version, technique IDs, descriptions, platforms and tactic membership/order. No build dependency is added to the production runtime. To upgrade ATT&CK, change the pin and version deliberately, review removed/revoked techniques and tactic changes, rebuild and repeat import/export checks. Cross-version project migration is not implemented; existing files must not be silently relabelled.

## Validation

25 isolated JavaScript behaviour checks cover draft/review transitions, invalid imports, evidence consistency, explicit-ID handling, project round-trip, safe source URLs and tactic-specific reviewed-only Navigator output. Six Flask routes/assets render with outbound requests prohibited, plus CSP markup and catalogue integrity checks. Browser checks cover manual passage selection, explicit-ID drafts, rationale/review, download/import round-trip, 390px layout and theme switching. A fictional exported layer opened in official Navigator 5.3.2 with its original ATT&CK version retained. This verifies loading, not every downstream Navigator operation. No production deployment or production data changes were made.

## Deliberately deferred

PDF ingestion; natural-language technique suggestions; actor comparisons; multi-report source management; editable campaign sequence/flow; automatic detection rules; cloud persistence; cross-version imports. These require separate designs and should not be advertised as existing capabilities.
