"""Domain security check: the public settings that protect a domain's email and website.

Everything here is information any mail server or browser can already see: DNS records, read
through DNS-over-HTTPS (Cloudflare, then Google), so the lookups never touch the network the
site runs on. Each check returns a verdict in plain words, what was found, and how to fix it.

A domain from a visitor is untrusted: normalize() accepts a domain name and nothing else (no IP
addresses, ports, logins or special-use names like localhost), and every record that comes back
is shown as text, cut to a sensible length.
"""
import ipaddress
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone

import idna
import requests

RESOLVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
DNS_TIMEOUT = 3            # seconds per resolver; Google is only asked if Cloudflare fails
DEADLINE = 8               # seconds for the whole check; anything unfinished is "couldn't check"
MAX_DOMAIN = 230           # leaves room for prefixes like _mta-sts. within DNS's 253
SHOWN_RECORD = 600         # characters of a record shown on the page

CACHE_FOR = timedelta(hours=1)        # a domain checked this recently shows the saved result
KEEP_FOR = timedelta(days=1)          # saved results and the rate-limit log are deleted after this
CHECKS_PER_VISITOR_HOUR = 10
CHECKS_PER_DAY = 200

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "CAA": 257}

# Names that never belong to a public domain (RFC 6761, 6762, 7686, 8375, 9476, and common
# private ones). Checking them would mean looking at somebody's internal network naming.
SPECIAL_TLDS = {"localhost", "local", "internal", "test", "example", "invalid", "onion", "arpa",
                "alt", "lan", "home", "corp", "intranet", "private", "localdomain"}

VERDICTS = {"in": "In place", "partly": "Partly", "missing": "Missing", "problem": "Problem",
            "na": "Not needed", "unknown": "Couldn't check", "info": ""}
SCORED = ("in", "partly", "missing", "problem")


# ---------- the domain someone typed ----------

def normalize(raw):
    """(ascii domain, how to show it, a note or None) from what a visitor typed. A pasted link
    is reduced to its host. Raises ValueError with a plain-words reason."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("Type a domain, like example.com.")
    if len(text) > 300:
        raise ValueError("That's too long to be a domain name.")
    m = re.match(r"^(?:https?://)?([^/?#\s]*)(.*)$", text, re.I | re.S)
    host, rest = m.group(1), m.group(2)
    if rest and not re.match(r"^[/?#]", rest):
        raise ValueError("Type just the domain, like example.com, without spaces.")
    if "@" in host:
        raise ValueError("Type the domain on its own. For an email address, use the part after the @.")
    if host.startswith("["):
        raise ValueError("Type a domain name, not an IP address.")
    if ":" in host:
        raise ValueError("Type the domain without a port number.")
    host = host.rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Type a domain name, not an IP address.")
    note = None
    if host.startswith("www.") and host.count(".") >= 2:
        host = host[4:]
        note = "Checked without www.: email settings, like SPF and DMARC, live on the main domain."
    try:
        ascii_name = idna.encode(host, uts46=True, transitional=False).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        raise ValueError("That isn't a valid domain name.") from None
    labels = ascii_name.split(".")
    if len(labels) < 2 or len(ascii_name) > MAX_DOMAIN:
        raise ValueError("That isn't a full domain name. Type one like example.com.")
    for label in labels:
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ValueError("That isn't a valid domain name.")
    tld = labels[-1]
    if tld.isdigit() or not (tld.isalpha() or tld.startswith("xn--")):
        raise ValueError("Type a domain name, not an IP address.")
    if tld in SPECIAL_TLDS or ascii_name.endswith(".home.arpa"):
        raise ValueError("That's a private or reserved name, not a public domain.")
    try:
        shown = idna.decode(ascii_name) if "xn--" in ascii_name else ascii_name
    except (idna.IDNAError, UnicodeError, ValueError):
        shown = ascii_name
    return ascii_name, shown, note


# ---------- DNS-over-HTTPS ----------

class DNSUnavailable(Exception):
    """Neither resolver answered."""


def _txt_value(data):
    """A TXT record's text. Cloudflare quotes each string ("a" "b", with \\" \\\\ and \\DDD
    escapes); Google sends the strings already joined."""
    if not data.startswith('"'):
        return data
    out, i, inside = bytearray(), 0, False
    while i < len(data):
        ch = data[i]
        if ch == '"':
            inside = not inside
            i += 1
        elif inside and ch == "\\" and i + 1 < len(data):
            if data[i + 1:i + 4].isdigit() and len(data[i + 1:i + 4]) == 3:
                out.append(int(data[i + 1:i + 4]) & 0xFF)
                i += 4
            else:
                out += data[i + 1].encode("utf-8")
                i += 2
        elif inside:
            out += ch.encode("utf-8")
            i += 1
        else:
            i += 1          # the space between strings
    return out.decode("utf-8", "replace")


class Resolver:
    """DNS lookups for one check, shared by its threads."""

    def __init__(self, deadline=None):
        self.session = requests.Session()
        self.session.headers["Accept"] = "application/dns-json"
        self.deadline = deadline or (time.monotonic() + DEADLINE)

    def time_left(self):
        return self.deadline - time.monotonic()

    def query(self, name, rtype, cd=False):
        """{"status": DNS rcode, "ad": validated, "answers": [(type number, data)]}."""
        if self.time_left() <= 0:
            raise DNSUnavailable("out of time")
        params = {"name": name, "type": rtype}
        if cd:
            params["cd"] = "1"
        for url in RESOLVERS:
            try:
                r = self.session.get(url, params=params, timeout=min(DNS_TIMEOUT, max(0.5, self.time_left())))
                if r.status_code != 200:
                    continue
                d = r.json()
                return {"status": int(d.get("Status", -1)), "ad": bool(d.get("AD")),
                        "answers": [(int(a["type"]), str(a["data"])) for a in d.get("Answer", []) or []]}
            except (requests.RequestException, ValueError, KeyError, TypeError):
                continue
        raise DNSUnavailable(f"{rtype} {name}")

    def records(self, name, rtype):
        """The records of one type (following CNAMEs, as resolvers do); TXT records as text.
        Raises DNSUnavailable if the answer is a failure rather than "none"."""
        res = self.query(name, rtype)
        if res["status"] not in (0, 3):           # 0 = found or none of that type, 3 = no such name
            raise DNSUnavailable(f"{rtype} {name}: status {res['status']}")
        want = TYPES[rtype]
        values = [data for t, data in res["answers"] if t == want]
        return [_txt_value(v) for v in values] if rtype == "TXT" else values


def _shown(record):
    return record if len(record) <= SHOWN_RECORD else record[:SHOWN_RECORD] + "…"


def _check(key, title, what, verdict, headline, details=(), record=None, fix=None):
    return {"key": key, "title": title, "what": what, "verdict": verdict, "headline": headline,
            "details": [d for d in details if d], "record": _shown(record) if record else None, "fix": fix}


def unknown(key, title, what):
    return _check(key, title, what, "unknown", "The DNS lookups for this failed or didn't finish in time. "
                  "Try again in a minute.")


# ---------- mail servers (context, not scored) ----------

MAIL_PROVIDERS = [
    ("mail.protection.outlook.com", "Microsoft 365"), ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"), ("pphosted.com", "Proofpoint"), ("mimecast.com", "Mimecast"),
    ("messagelabs.com", "Broadcom Email Security"), ("iphmx.com", "Cisco Secure Email"),
    ("fortimailcloud.com", "FortiMail Cloud"), ("barracudanetworks.com", "Barracuda"),
    ("zoho.com", "Zoho Mail"), ("zoho.eu", "Zoho Mail"), ("protonmail.ch", "Proton Mail"),
    ("messagingengine.com", "Fastmail"), ("secureserver.net", "GoDaddy"), ("icloud.com", "iCloud Mail"),
    ("mx.cloudflare.net", "Cloudflare Email Routing"), ("amazonaws.com", "Amazon"), ("yandex.net", "Yandex"),
    ("hostinger.com", "Hostinger"), ("titan.email", "Titan"), ("emailsrvr.com", "Rackspace"),
]


def mail_provider(host):
    host = host.rstrip(".").lower()
    for suffix, name in MAIL_PROVIDERS:
        if host == suffix or host.endswith("." + suffix):
            return name
    return None


def check_mx(dns, domain):
    """(check, receives mail, mail hosts). A null MX ("0 .") says the domain takes no email."""
    what = "Which servers receive this domain's email"
    rows = []
    for data in dns.records(domain, "MX"):
        parts = data.split()
        if len(parts) == 2 and parts[0].isdigit():
            rows.append((int(parts[0]), parts[1].rstrip(".").lower()))
    rows.sort()
    if any(host == "" for _, host in rows):          # "0 ." becomes "" once the dot is stripped
        return _check("mx", "Mail servers", what, "info",
                      "This domain says it receives no email (a \"null MX\" record)."), False, []
    if not rows:
        return _check("mx", "Mail servers", what, "info",
                      "No mail servers: this domain doesn't receive email."), False, []
    hosts = [h for _, h in rows]
    providers = sorted({p for p in map(mail_provider, hosts) if p})
    headline = (f"Email is handled by {', '.join(providers)}." if providers
                else f"Email goes to {hosts[0]}" + (f" and {len(hosts) - 1} more." if len(hosts) > 1 else "."))
    return _check("mx", "Mail servers", what, "info", headline,
                  record=", ".join(f"{p} {h}" for p, h in rows)), True, hosts


# ---------- SPF ----------

SPF_LOOKUP_LIMIT = 10
_SPF_COUNTED = re.compile(r"^[+\-~?]?(include:|a$|a:|a/|mx$|mx:|mx/|ptr$|ptr:|exists:)", re.I)


def _spf_records(dns, domain):
    return [t for t in dns.records(domain, "TXT") if re.match(r"^v=spf1(\s|$)", t.strip(), re.I)]


def spf_lookups(dns, record, path, problems, memo, depth=0):
    """DNS lookups an SPF record needs, following include: and redirect= as receivers do
    (RFC 7208 4.6.4): a domain included twice is counted twice, a loop is an error. Records
    problems such as an include of a domain with no SPF record. memo: {domain: its count}."""
    count = 0
    for term in record.split()[1:]:
        low = term.lower()
        target = None
        if _SPF_COUNTED.match(low):
            count += 1
            if low.lstrip("+-~?").startswith("include:"):
                target = term.split(":", 1)[1]
        elif low.startswith("redirect="):
            count += 1
            target = term.split("=", 1)[1]
        if not target or "%" in target or depth >= SPF_LOOKUP_LIMIT:
            continue            # macros (%{i}) depend on the sender, so they can't be followed here
        target = target.rstrip(".").lower()
        if target in path:
            problems.append(f"{target} includes itself, directly or through another include: a loop, "
                            "which receivers treat as an error.")
            continue
        if target in memo:
            count += memo[target]
            continue
        try:
            found = _spf_records(dns, target)
        except DNSUnavailable:
            problems.append(f"Couldn't look up {target} in time, so the count may be low.")
            continue
        if not found:
            problems.append(f"It includes {target}, which has no SPF record. Receivers treat that as an "
                            "error, so SPF fails.")
            continue
        memo[target] = spf_lookups(dns, found[0], path | {target}, problems, memo, depth + 1)
        count += memo[target]
        if count > SPF_LOOKUP_LIMIT:
            break
    return count


def check_spf(dns, domain):
    title, what = "SPF", "Which servers may send email as this domain"
    found = _spf_records(dns, domain)
    if not found:
        return _check("spf", title, what, "missing", "No SPF record, so anyone can send email that claims to be "
                      "from this domain and receivers can't tell.",
                      fix="Publish one TXT record listing the services that send your email, for example "
                          "v=spf1 include:spf.protection.outlook.com -all for Microsoft 365. If the domain never "
                          "sends email, publish v=spf1 -all.")
    if len(found) > 1:
        return _check("spf", title, what, "problem", f"There are {len(found)} SPF records. Receivers treat that as an "
                      "error, so SPF fails for all of this domain's email.", record=" | ".join(found),
                      fix="Merge them into one record that lists every service that sends your email.")
    record = found[0].strip()
    terms = [t.lower() for t in record.split()]
    policy = next((t for t in terms if re.fullmatch(r"[+\-~?]?all", t)), None)
    redirect = next((t.split("=", 1)[1] for t in terms if t.startswith("redirect=")), None)
    problems, notes = [], []
    lookups = spf_lookups(dns, record, {domain}, problems, {})
    if policy is None and redirect and "%" not in redirect:
        try:
            target = _spf_records(dns, redirect.rstrip("."))
            if target:
                policy = next((t for t in target[0].lower().split() if re.fullmatch(r"[+\-~?]?all", t)), None)
                notes.append(f"It hands over to {redirect} (redirect=), whose ending is used.")
        except DNSUnavailable:
            pass
    if any(t.lstrip("+-~?").startswith("ptr") for t in terms):
        notes.append("It uses ptr, which the SPF standard says not to use: it's slow and unreliable.")
    if lookups > SPF_LOOKUP_LIMIT:
        problems.insert(0, f"It needs {lookups if lookups <= 20 else 'more than 20'} DNS lookups. The limit is "
                           f"{SPF_LOOKUP_LIMIT}; beyond it, receivers treat SPF as an error and it fails.")
    else:
        notes.append(f"It needs {lookups} of the {SPF_LOOKUP_LIMIT} DNS lookups SPF allows.")
    hard = [p for p in problems if not p.startswith("Couldn't")]
    if policy in ("+all", "all"):
        return _check("spf", title, what, "problem", "It ends in +all, which lets any server in the world send as "
                      "this domain. That's worse than having no record.", problems + notes, record,
                      "Replace +all with -all (or ~all).")
    if hard:
        return _check("spf", title, what, "problem", hard[0], hard[1:] + notes, record,
                      "Remove includes that don't resolve and cut the record down: drop services you no longer "
                      "use, or ask your providers for a combined include.")
    if policy == "-all":
        return _check("spf", title, what, "in", "Strict: receivers are told to reject email from servers that "
                      "aren't listed (-all).", problems + notes, record)
    if policy == "~all":
        return _check("spf", title, what, "in", "Soft (~all): email from servers that aren't listed is marked "
                      "suspicious rather than rejected. That's common, and fine when DMARC is set to quarantine "
                      "or reject.", problems + notes, record)
    return _check("spf", title, what, "partly", "It lists your servers but doesn't tell receivers what to do with "
                  "email from anywhere else (it ends in ?all, or has no ending).", problems + notes, record,
                  "End the record with -all, or ~all while you're still finding every service that sends for you.")


# ---------- DMARC ----------

def _dmarc_records(dns, name):
    return [t for t in dns.records(f"_dmarc.{name}", "TXT") if re.match(r"^v\s*=\s*DMARC1\s*(;|$)", t.strip(), re.I)]


def dmarc_tags(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags.setdefault(k.strip().lower(), v.strip())
    return tags


REGISTRY_SECOND_LEVELS = {"co", "com", "net", "org", "gov", "edu", "ac", "sch", "mil", "ltd", "plc", "nic",
                          "info", "biz", "name", "pro", "med", "or", "ne", "go", "gob", "gv", "nom", "web"}


def check_dmarc(dns, domain):
    title, what = "DMARC", "What receivers do with email that fails SPF and DKIM"
    found, inherited = _dmarc_records(dns, domain), None
    labels = domain.split(".")
    # A subdomain without its own record is covered by its main domain's (sp= if set). Without
    # the full public suffix list, stop before names like co.uk or gov.ae, which are registries.
    for i in range(1, len(labels) - 1):
        if found:
            break
        parent = ".".join(labels[i:])
        if len(labels) - i == 2 and labels[i] in REGISTRY_SECOND_LEVELS:
            break
        found = _dmarc_records(dns, parent)
        inherited = parent if found else None
    if not found:
        return _check("dmarc", title, what, "missing", "No DMARC record, so receivers have no instructions for "
                      "email that fakes this domain, and nobody tells you it's happening.",
                      fix="Publish a TXT record at _dmarc with v=DMARC1; p=none; rua=mailto:(an address for "
                          "reports). Read the reports for a few weeks, then move to p=quarantine and p=reject.")
    if len(found) > 1:
        return _check("dmarc", title, what, "problem", f"There are {len(found)} DMARC records, so receivers ignore "
                      "all of them.", record=" | ".join(found), fix="Keep exactly one record.")
    record = found[0].strip()
    tags = dmarc_tags(record)
    policy = (tags.get("sp") if inherited and tags.get("sp") else tags.get("p", "")).lower()
    details = []
    if inherited:
        details.append(f"This domain has no record of its own, so {inherited}'s applies"
                       + (" (its sp= setting, for subdomains)." if tags.get("sp") else "."))
    rua = tags.get("rua")
    details.append("Reports go to " + rua.replace("mailto:", "") + "." if rua else
                   "No reports are asked for (rua=), so you won't hear when someone fakes your email.")
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100 and policy in ("quarantine", "reject"):
        details.append(f"It only applies to {pct}% of failing email (pct={pct}).")
    sp = tags.get("sp", "").lower()
    if not inherited and sp == "none" and policy in ("quarantine", "reject"):
        details.append("Subdomains are left open (sp=none): fake email from a subdomain is still delivered.")
    if policy == "reject":
        return _check("dmarc", title, what, "in", "Strict: email that fakes this domain is rejected (p=reject).",
                      details, record)
    if policy == "quarantine":
        return _check("dmarc", title, what, "in", "Email that fakes this domain goes to spam (p=quarantine).",
                      details, record, None)
    if policy == "none":
        return _check("dmarc", title, what, "partly", "Monitoring only (p=none): fake email is reported but "
                      "still delivered.", details, record,
                      "Once the reports show your real email passing, move to p=quarantine, then p=reject.")
    return _check("dmarc", title, what, "problem", "The record has no valid policy (p=none, quarantine or reject), "
                  "so receivers treat it as monitoring at best.", details, record,
                  "Add p=none to start, then tighten it to quarantine and reject.")


# ---------- MTA-STS and TLS-RPT (encrypted delivery to this domain's mail servers) ----------

def check_mta_sts(dns, domain, receives_mail):
    title, what = "MTA-STS", "Whether other mail servers must encrypt email sent here"
    if not receives_mail:
        return _check("mta-sts", title, what, "na", "Not needed: this domain doesn't receive email.")
    found = [t for t in dns.records(f"_mta-sts.{domain}", "TXT") if re.match(r"^v=STSv1\s*(;|$)", t.strip())]
    if not found:
        return _check("mta-sts", title, what, "missing", "Not set up. Email sent here is encrypted only if both "
                      "sides agree to it, and an attacker in the middle can quietly turn that off.",
                      fix="Publish an MTA-STS policy: a TXT record at _mta-sts and a policy file at "
                          f"https://mta-sts.{domain}/.well-known/mta-sts.txt. Microsoft 365 and Google Workspace "
                          "both have guides.")
    if len(found) > 1:
        return _check("mta-sts", title, what, "problem", "There's more than one MTA-STS record, so other servers "
                      "ignore it.", record=" | ".join(found), fix="Keep exactly one record.")
    return _check("mta-sts", title, what, "in", "Turned on: the MTA-STS record is published.", record=found[0])


def check_tls_rpt(dns, domain, receives_mail):
    title, what = "TLS-RPT", "Reports when encrypted delivery to this domain fails"
    if not receives_mail:
        return _check("tls-rpt", title, what, "na", "Not needed: this domain doesn't receive email.")
    found = [t for t in dns.records(f"_smtp._tls.{domain}", "TXT") if re.match(r"^v=TLSRPTv1\s*(;|$)", t.strip())]
    if not found:
        return _check("tls-rpt", title, what, "missing", "Not set up, so you won't hear if other servers can't "
                      "deliver to you securely.",
                      fix="Publish a TXT record at _smtp._tls with v=TLSRPTv1; rua=mailto:(an address for reports).")
    return _check("tls-rpt", title, what, "in", "Turned on: other servers report failed secure deliveries.",
                  record=found[0])


# ---------- DNSSEC and CAA ----------

def check_dnssec(dns, domain):
    title, what = "DNSSEC", "Whether this domain's DNS answers are signed against forgery"
    res = dns.query(domain, "SOA")
    if res["status"] == 2:          # SERVFAIL: try again without validation to see why
        bare = dns.query(domain, "SOA", cd=True)
        if bare["status"] in (0, 3):
            return _check(title.lower(), title, what, "problem", "Signed, but the signatures don't check out, so "
                          "resolvers that verify them (Google's and Cloudflare's among them) refuse to answer. "
                          "Many people can't reach this domain at all.",
                          fix="Fix the DNSSEC setup at your DNS host, or remove the DS record at your registrar "
                              "until it's fixed.")
        raise DNSUnavailable("SOA failed with and without validation")
    if res["status"] not in (0, 3):
        raise DNSUnavailable(f"SOA status {res['status']}")
    if res["ad"]:
        return _check("dnssec", title, what, "in", "Signed, and the signatures check out.")
    return _check("dnssec", title, what, "missing", "Not signed, so a resolver can be fed forged answers for this "
                  "domain without noticing.",
                  fix="Turn on DNSSEC at your DNS host, then add the DS record it gives you at your registrar. "
                      "Many hosts, like Cloudflare, do both in one click.")


CA_NAMES = [
    ("letsencrypt.org", "Let's Encrypt"), ("pki.goog", "Google Trust Services"), ("digicert.com", "DigiCert"),
    ("sectigo.com", "Sectigo"), ("comodoca.com", "Sectigo"), ("amazon.com", "Amazon"),
    ("amazontrust.com", "Amazon"), ("amazonaws.com", "Amazon"), ("globalsign.com", "GlobalSign"),
    ("godaddy.com", "GoDaddy"), ("starfieldtech.com", "GoDaddy"), ("ssl.com", "SSL.com"),
    ("entrust.net", "Entrust"), ("buypass.com", "Buypass"), ("zerossl.com", "ZeroSSL"),
    ("harica.gr", "HARICA"), ("certum.pl", "Certum"), ("microsoft.com", "Microsoft"),
]


def check_caa(dns, domain):
    """CAA records name the certificate authorities allowed to issue for a domain. A name without
    its own records is covered by its parent's (RFC 8659), so climb until one has them."""
    title, what = "CAA", "Which certificate authorities may issue certificates for this domain"
    labels = domain.split(".")
    found, at = [], domain
    for i in range(len(labels) - 1):
        at = ".".join(labels[i:])
        found = dns.records(at, "CAA")
        if found:
            break
    issuers, wild, critical = [], [], False
    for data in found:
        m = re.match(r'^\s*(\d+)\s+([A-Za-z0-9]+)\s+"?(.*?)"?\s*$', data)
        if not m:
            continue
        tag, value = m.group(2).lower(), m.group(3).split(";")[0].strip().lower()
        if tag in ("issue", "issuewild"):
            name = next((n for d, n in CA_NAMES if value == d or value.endswith("." + d)), value) if value else None
            (issuers if tag == "issue" else wild).append(name)
        # Flag 128 marks a tag "critical": an authority that doesn't know it must refuse to issue.
        if int(m.group(1)) & 128 and tag not in ("issue", "issuewild", "iodef", "issuemail", "issuevmc"):
            critical = True
    if not issuers and not wild:
        headline = ("Not set, so any certificate authority may issue a certificate for this domain." if not found else
                    "There are CAA records, but none says who may issue (no issue tag), so any certificate "
                    "authority still may.")
        return _check("caa", title, what, "missing", headline, record=", ".join(found) if found else None,
                      fix="Add CAA records naming the authorities you use, for example 0 issue \"letsencrypt.org\".")
    details = []
    if at != domain:
        details.append(f"From {at}'s records, which cover this domain.")
    named = [n for n in issuers if n]
    if issuers and not named:
        headline = "No certificate authority may issue certificates for this domain (issue \";\")."
    else:
        headline = "Only " + ", ".join(dict.fromkeys(named or [n for n in wild if n])) + " may issue certificates."
    if critical:
        details.append("One record has a tag marked critical that certificate authorities may not know. "
                       "Those that don't must refuse to issue.")
    return _check("caa", title, what, "in", headline, details, record=", ".join(found))


# ---------- running every check ----------

GROUPS = [("email", "Email"), ("web", "Website"), ("dns", "DNS")]
GROUP_OF = {"mx": "email", "spf": "email", "dmarc": "email", "dkim": "email", "mta-sts": "email",
            "tls-rpt": "email", "https": "web", "hsts": "web", "certificate": "web", "security-txt": "web",
            "dnssec": "dns", "caa": "dns"}
ORDER = ["mx", "spf", "dmarc", "dkim", "mta-sts", "tls-rpt", "https", "hsts", "certificate", "security-txt",
         "dnssec", "caa"]
TITLES = {"mx": ("Mail servers", "Which servers receive this domain's email"),
          "spf": ("SPF", "Which servers may send email as this domain"),
          "dmarc": ("DMARC", "What receivers do with email that fails SPF and DKIM"),
          "mta-sts": ("MTA-STS", "Whether other mail servers must encrypt email sent here"),
          "tls-rpt": ("TLS-RPT", "Reports when encrypted delivery to this domain fails"),
          "dnssec": ("DNSSEC", "Whether this domain's DNS answers are signed against forgery"),
          "caa": ("CAA", "Which certificate authorities may issue certificates for this domain")}


def exists(dns, domain):
    """False if DNS has nothing at all for this name (some hosts answer "no records" rather
    than "no such name", so both count)."""
    for rtype in ("SOA", "NS", "A", "AAAA", "MX", "TXT"):
        res = dns.query(domain, rtype)
        if res["status"] == 3:
            return False
        if res["status"] == 0 and res["answers"]:
            return True
        if res["status"] == 2:
            return True     # it fails rather than not existing: let the checks say so
    return False


def run(domain, dns=None):
    """Every check for one domain, as a dict ready to save and show."""
    dns = dns or Resolver()
    started = datetime.now(timezone.utc)
    try:
        if not exists(dns, domain):
            return {"domain": domain, "checked_at": started.isoformat(), "missing_domain": True, "checks": []}
    except DNSUnavailable:
        return {"domain": domain, "checked_at": started.isoformat(), "dns_down": True, "checks": []}

    results = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        mx_future = pool.submit(check_mx, dns, domain)
        futures = {"spf": pool.submit(check_spf, dns, domain), "dmarc": pool.submit(check_dmarc, dns, domain),
                   "dnssec": pool.submit(check_dnssec, dns, domain), "caa": pool.submit(check_caa, dns, domain)}
        try:
            results["mx"], receives_mail, _hosts = mx_future.result(timeout=max(0.1, dns.time_left()))
        except Exception:                   # noqa: BLE001 - any failure here is "couldn't check"
            results["mx"], receives_mail = unknown("mx", *TITLES["mx"]), None
        if receives_mail is None:
            results["mta-sts"] = unknown("mta-sts", *TITLES["mta-sts"])
            results["tls-rpt"] = unknown("tls-rpt", *TITLES["tls-rpt"])
        else:
            futures["mta-sts"] = pool.submit(check_mta_sts, dns, domain, receives_mail)
            futures["tls-rpt"] = pool.submit(check_tls_rpt, dns, domain, receives_mail)
        wait(futures.values(), timeout=max(0.1, dns.time_left()))
        for key, future in futures.items():
            try:
                results[key] = future.result(timeout=0)
            except Exception:               # noqa: BLE001 - unfinished or failed: say so, don't guess
                results[key] = unknown(key, *TITLES[key])
    checks = [results[k] for k in ORDER if k in results]
    broken = results.get("dnssec", {}).get("verdict") == "problem"
    for c in checks:
        c["group"] = GROUP_OF[c["key"]]
        if broken and c["verdict"] == "unknown":
            c["headline"] = "Couldn't check: lookups for this domain fail because of the DNSSEC problem below."
    return {"domain": domain, "checked_at": started.isoformat(), "checks": checks}


def score(result):
    """(in place, out of): only checks with a real verdict count."""
    counted = [c for c in result["checks"] if c["verdict"] in SCORED]
    return sum(1 for c in counted if c["verdict"] == "in"), len(counted)


# ---------- saved results and rate limits ----------

def cached(conn, domain, now=None):
    now = now or datetime.now(timezone.utc)
    row = conn.execute("SELECT checked_at, result FROM domain_checks WHERE domain = ?", (domain,)).fetchone()
    if row and now - datetime.fromisoformat(row["checked_at"]) < CACHE_FOR:
        return json.loads(row["result"])
    return None


def can_check(conn, visitor, now=None):
    """None if this visitor may run a new check now, otherwise why not (plain words)."""
    now = now or datetime.now(timezone.utc)
    day = (now - timedelta(days=1)).isoformat()
    hour = (now - timedelta(hours=1)).isoformat()
    if conn.execute("SELECT COUNT(*) FROM domain_lookups WHERE at >= ?", (day,)).fetchone()[0] >= CHECKS_PER_DAY:
        return "New checks are paused until tomorrow: SentryFeed has used today's allowance. Domains checked in " \
               "the last hour still show their saved results."
    mine = conn.execute("SELECT COUNT(*) FROM domain_lookups WHERE visitor = ? AND at >= ?", (visitor, hour)).fetchone()[0]
    if mine >= CHECKS_PER_VISITOR_HOUR:
        return f"You've checked {CHECKS_PER_VISITOR_HOUR} domains in the last hour. Please try again later."
    return None


def record_check(conn, visitor, now=None):
    """Count this check against the limits, and delete anything older than KEEP_FOR."""
    now = now or datetime.now(timezone.utc)
    old = (now - KEEP_FOR).isoformat()
    with conn:
        conn.execute("DELETE FROM domain_lookups WHERE at < ?", (old,))
        conn.execute("DELETE FROM domain_checks WHERE checked_at < ?", (old,))
        conn.execute("INSERT INTO domain_lookups (visitor, at) VALUES (?, ?)", (visitor, now.isoformat()))


def save(conn, result):
    with conn:
        conn.execute("INSERT OR REPLACE INTO domain_checks (domain, checked_at, result) VALUES (?, ?, ?)",
                     (result["domain"], result["checked_at"], json.dumps(result)))
