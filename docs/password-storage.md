# Password-storage checker

`/storage` is a browser-only audit of stored-record formats. Built 20 October 2026. It is intended for application owners and authorised reviewers, not password recovery.

## Input and privacy

Select a UTF-8 CSV with unique headers or a JSON array of objects. Select the stored-password column and optionally a separate salt column. Prefer exporting only those columns, without identities. Limits: 5 MB, 10,000 data rows, 100 columns, 4,096 characters per field. Quoted CSV fields, escaped quotes, embedded line breaks, CRLF, UTF-8 BOMs, JSON null and missing fields are handled. Malformed rows, non-string JSON values and oversized input are rejected without echoing contents.

Analysis runs in `static/storage-check.js`, with no network, crypto operations, third-party libraries or persistence. The file remains in page memory until cleared or the tab closes; browsers do not guarantee secure erasure of memory. Only column headers appear in the selection controls. Stored values, salts and identities never appear in results or downloads. The JSON download contains aggregate counts and recognised format/settings groups, not row-level data. The first 100 setting groups are displayed; the download preserves all groups.

There is no password guessing, plaintext verification, lookup service, cracking-time estimate, candidate generation or cracking-tool export. The authorised-audit checkbox communicates scope; it cannot technically establish ownership. A fictional six-row dataset demonstrates mixed formats, a below-floor cost and repeated salt fields. Its digests are placeholders, not generated password records or a real breach dump.

## Recognition and interpretation

Supported layouts: Argon2 PHC and Django Argon2; bcrypt and Django bcrypt/bcrypt-SHA256 wrappers; Django PBKDF2-SHA256/SHA1 and scrypt; explicit Werkzeug PBKDF2-SHA256/SHA512/SHA1 and scrypt. Recognition validates structure and relevant encoded lengths/parameters; it does not prove that a library actually generated a value. Other layouts remain unknown or unsupported. Hexadecimal length is not used to assert MD5, NTLM or another algorithm, and an unknown string is not labelled plaintext.

Policy compares visible settings with the linked [OWASP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), reviewed 20 October 2026. Results say “Cost floor observed”, never “safe”. Argon2id's listed single-lane memory/time profiles are recognised; other lane counts require manual review. Bcrypt remains labelled legacy, with a specific warning below cost 10. PBKDF2 comparison depends on its PRF. Scrypt comparison uses the documented N/r/p alternatives. Very short text salts require review. No algorithm is executed to benchmark a hash.

Embedded salt fields are counted in recognised records; optional separate fields show presence only. Repetition is counted within encoding families (or the separate-column group), not across every possible encoding. Duplicate export rows can explain repeated salts. Salt presence/uniqueness cannot establish randomness or correct application use. Pepper use, password quality, password reuse, pre-hashing, operational tuning, FIPS validation and exposure after a leak cannot be established from these exports.

## Sources checked

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html): configuration guidance and migration context.
- [Django 5.2 password documentation](https://docs.djangoproject.com/en/5.2/topics/auth/passwords/) and [official hashers source](https://github.com/django/django/blob/stable/5.2.x/django/contrib/auth/hashers.py): field layout and wrappers. This identifies supported layouts, not a claim that every stored value came from Django 5.2.
- [Werkzeug security utilities](https://werkzeug.palletsprojects.com/en/stable/utils/#module-werkzeug.security) and [official source](https://github.com/pallets/werkzeug/blob/main/src/werkzeug/security.py): explicit method and salt/digest layout.
- [Argon2 RFC 9106](https://www.rfc-editor.org/info/rfc9106/) and [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md): parameter meanings and structured encoding.

## Validation

62 isolated checks cover recognised layouts, boundary costs, unsupported settings, invalid base64/digest lengths, CSV quoting and empty fields, JSON limits/types, salt repetition, and aggregate exclusion of identities/salts/digests. Browser checks cover the fictional dataset and aggregate download. The export showed six rows, two cost-floor matches and one repeated-salt group across two rows. Route/CSP/privacy and responsive checks accompany the implementation. No production records or keys are changed by this feature.
