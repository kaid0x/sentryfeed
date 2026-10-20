# Breach family tree

Built 20 October 2026. Public route: `/breaches`, under Intel. This is a curated archive of source-supported incident connections, not an automated attribution system or a complete breach database.

## What it does

Connects an upstream incident to a downstream incident with an explicit mechanism, outcome, scope caveat, source links and review date. Initial publication contains three incident records and two connections from one researched case. The two Cloudflare incidents are separate branches from the Okta support incident, rather than an unsupported chain between the Cloudflare events. Contained access is labelled separately from reported internal compromise; neither is presented as proof of customer-data exposure.

The initial sources are first-party reports:

- [Okta's support-system disclosure](https://sec.okta.com/articles/2023/10/tracking-unauthorized-access-oktas-support-system/).
- [Cloudflare's October account](https://blog.cloudflare.com/how-cloudflare-mitigated-yet-another-okta-compromise/).
- [Cloudflare's November account](https://blog.cloudflare.com/thanksgiving-2023-security-incident/).

These sources support the displayed relationships and caveats. We do not assert independent forensic verification or a common named actor. A review date is separate from an incident month. Missing branches do not imply no further impact.

## Editorial workflow

`data/breaches.json` is the reviewed catalogue. `breaches.py` validates it before use. Public pages need no new database tables or external requests. The file is bundled with the existing Python deployment. Invalid/missing data produces an honest 503 state specific to the catalogue, not a misleading database message.

Run `python tools/review_breaches.py validate` before committing changes.

For private review leads, run `python tools/review_breaches.py suggest --days 14`. It reads up to 1,000 recent saved stories, using exact, word-bounded aliases for organisations already represented in the catalogue. Up to 100 co-mention leads are written to `.breach-review/leads.json`. No relationship is inferred; articles mentioning several organisations routinely describe unrelated facts. This command does not fetch article bodies or unknown URLs. It uses the configured database with schema setup disabled and performs only a SELECT. It does not run automatically in the collector.

The local review folder is ignored by Git and explicitly excluded from Vercel bundles. Existing lead files are not overwritten: choose a new `--output` path for subsequent runs. No unreviewed leads appear on the public page.

After reading the actual reports, prepare a private JSON draft containing `nodes` and `links` arrays. New nodes use the same schema as the catalogue; existing incident IDs are referenced without copying those nodes. Each link needs a new ID, `from`, `to`, supported `mechanism` and `outcome`, a plain explanation, scope caveat, ISO review date, and one to five supporting HTTPS sources. An article headline or co-mention is insufficient evidence.

Approve with `python tools/review_breaches.py approve --draft .breach-review/draft.json --confirm-source-review`. This validates the entire resulting graph and atomically replaces the local catalogue only if valid. Inspect the Git diff, commit, and let Haseeb push. The confirmation flag records an explicit operator action; code cannot establish whether evidence truly supports a claim. Keep that responsibility visible.

To correct an existing record, edit the reviewed catalogue, preserve the appropriate context/source, validate, and review its Git diff. Removing a connection also requires removing or reconnecting any resulting orphan incident. Version control retains the previous public record.

## Validation and constraints

Validation rejects missing sources, invalid source schemes/embedded credentials, duplicate IDs or pairs, dangling references, self-links, cycles, orphan records, invalid periods, future/missing review dates, unsupported categories and oversized catalogues. Current limits are 200 incidents and 400 connections. Text is escaped by Jinja; links are explicitly reviewed HTTPS URLs. Rendering needs no JavaScript, external chart library or additional runtime dependency. Nested lists, headings, native evidence disclosures and visible focus provide the same information on phones and keyboards.

18 isolated test cases cover catalogue integrity, invalid relationships, source validation, private candidate generation/bounds, atomic approvals, HTML escaping and honest unavailable states. Routes are checked with outbound requests blocked. First-party source links are checked independently; availability does not substitute for editorial review.

## Why the UAE domain feed remains separate

[Certificate Transparency](https://certificate.transparency.dev/) makes certificate issuance visible. Monitoring names resembling a brand can help a brand-protection team identify possible impersonation early. It does not establish that a domain is malicious, recently registered, hosted in the UAE, or currently serving a phishing page. Certificates may include harmless names and renewals; domain-only matching has false positives.

For a general news audience, an unreviewed stream of near-matches has limited value. The meaningful use case is a small named set of brands with someone reviewing alerts and an action path. At the user's request to evaluate its usefulness, this feature remains under discussion, not implemented. The proposed constraints still apply if later approved: official-domain allowlists, defanged non-clickable names, no visits to the domains, review labels and retention limits. No domain collection has been added by this work.
