"""Domain security check: the public settings that protect a domain's email and website.

Everything here is information any mail server or browser can already see: DNS records, read
through DNS-over-HTTPS (Cloudflare, then Google), so the lookups never touch the network the
site runs on. Each check returns a verdict in plain words, what was found, and how to fix it.

A domain from a visitor is untrusted: normalize() accepts a domain name and nothing else (no IP
addresses, ports, logins or special-use names like localhost), and every record that comes back
is shown as text, cut to a sensible length.
"""
import base64
import ipaddress
import json
import re
import secrets
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone

import idna
import requests

import safefetch
from safefetch import SPECIAL_TLDS

RESOLVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
DNS_TIMEOUT = 3            # seconds per resolver; Google is only asked if Cloudflare fails
DEADLINE = 10              # seconds for the whole check; anything unfinished is "couldn't check"
MAX_DOMAIN = 230           # leaves room for prefixes like _mta-sts. within DNS's 253
SHOWN_RECORD = 600         # characters of a record shown on the page

CACHE_FOR = timedelta(hours=1)        # a domain checked this recently shows the saved result
KEEP_FOR = timedelta(days=1)          # saved results and the rate-limit log are deleted after this
CHECKS_PER_VISITOR_HOUR = 10
CHECKS_PER_DAY = 200

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "CAA": 257}

# Names that never belong to a public domain (RFC 6761, 6762, 7686, 8375, 9476, and common
# private ones) live in safefetch.SPECIAL_TLDS, shared with the website checks.

VERDICTS = {"in": "In place", "partly": "Partly", "missing": "Missing", "problem": "Problem",
            "na": "Not needed", "notfound": "Not found", "unknown": "Couldn't check", "info": ""}
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
        self.cache, self.lock = {}, threading.Lock()     # the same record is often read by two checks

    def time_left(self):
        return self.deadline - time.monotonic()

    def query(self, name, rtype, cd=False):
        """{"status": DNS rcode, "ad": validated, "answers": [(type number, data)]}."""
        key = (name.lower(), rtype, cd)
        with self.lock:
            if key in self.cache:
                return self.cache[key]
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
                res = {"status": int(d.get("Status", -1)), "ad": bool(d.get("AD")),
                       "answers": [(int(a["type"]), str(a["data"])) for a in d.get("Answer", []) or []]}
                with self.lock:
                    self.cache[key] = res
                return res
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
        return _check("mta-sts", title, what, "na", "This domain doesn't receive email, so there's nothing to protect.")
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
        return _check("tls-rpt", title, what, "na", "This domain doesn't receive email, so there's nothing to protect.")
    found = [t for t in dns.records(f"_smtp._tls.{domain}", "TXT") if re.match(r"^v=TLSRPTv1\s*(;|$)", t.strip())]
    if not found:
        return _check("tls-rpt", title, what, "missing", "Not set up, so you won't hear if other servers can't "
                      "deliver to you securely.",
                      fix="Publish a TXT record at _smtp._tls with v=TLSRPTv1; rua=mailto:(an address for reports).")
    return _check("tls-rpt", title, what, "in", "Turned on: other servers report failed secure deliveries.",
                  record=found[0])


# ---------- DKIM ----------

# DKIM keys live at <selector>._domainkey.<domain>, and nothing lists the selectors, so the check
# tries the names mail services use. Ordered by how often they were found in a study of 74 Gulf
# and global domains; the USENIX Security 2022 DKIM study found that past about 40 names, more
# find almost nothing. A visitor can also type their own selector (the s= in a DKIM-Signature).
DKIM_SELECTORS = ["s1", "s2", "google", "selector1", "selector2", "zendesk1", "zendesk2", "k1", "k2", "k3",
                  "mandrill", "cm", "dkim", "s1024", "s2048", "mailjet", "smtp", "kl", "kl2", "krs", "mailo",
                  "mail", "mail2", "hs1", "hs2", "sel1", "default", "pm", "protonmail", "protonmail2",
                  "protonmail3", "fm1", "fm2", "fm3", "key1", "key2", "zmail", "zoho", "sig1", "brevo1", "brevo2",
                  "everlytickey1", "everlytickey2", "mxvault"]

# Who a key belongs to. A key reached through a CNAME is named by where it points, which is
# reliable; otherwise by the selector name, which is only a hint ("names used by").
DKIM_CNAME_PROVIDERS = [
    ("dkim.mail.microsoft", "Microsoft 365"), ("onmicrosoft.com", "Microsoft 365"), ("sendgrid.net", "SendGrid"),
    ("mcsv.net", "Mailchimp"), ("mandrillapp.com", "Mailchimp Transactional"), ("zendesk.com", "Zendesk"),
    ("klaviyo.com", "Klaviyo"), ("hubspotemail.net", "HubSpot"), ("mailgun.org", "Mailgun"),
    ("amazonses.com", "Amazon SES"), ("mailjet.com", "Mailjet"), ("protonmail.ch", "Proton Mail"),
    ("messagingengine.com", "Fastmail"), ("zoho.com", "Zoho Mail"), ("mtasv.net", "Postmark"),
    ("createsend.com", "Campaign Monitor"), ("brevo.com", "Brevo"), ("sendinblue.com", "Brevo"),
    ("icloud.com", "iCloud Mail"), ("google.com", "Google Workspace"),
]
DKIM_NAME_PROVIDERS = {
    "google": "Google Workspace", "selector1": "Microsoft 365", "selector2": "Microsoft 365", "s1": "SendGrid",
    "s2": "SendGrid", "k1": "Mailchimp", "k2": "Mailchimp", "k3": "Mailchimp", "mandrill": "Mailchimp Transactional",
    "zendesk1": "Zendesk", "zendesk2": "Zendesk", "kl": "Klaviyo", "kl2": "Klaviyo", "mailjet": "Mailjet",
    "hs1": "HubSpot", "hs2": "HubSpot", "protonmail": "Proton Mail", "protonmail2": "Proton Mail",
    "protonmail3": "Proton Mail", "fm1": "Fastmail", "fm2": "Fastmail", "fm3": "Fastmail", "cm": "Campaign Monitor",
    "krs": "Mailgun", "mailo": "Mailgun", "pm": "Postmark", "s1024": "Yahoo", "s2048": "Yahoo", "zmail": "Zoho Mail",
    "zoho": "Zoho Mail", "sig1": "iCloud Mail", "brevo1": "Brevo", "brevo2": "Brevo",
}
# Services whose DKIM names are fixed, and how their SPF include looks: listed in SPF but with
# no key under those names suggests DKIM isn't set up there.
DKIM_FIXED = [("Google Workspace", "_spf.google.com", ("google",)), ("SendGrid", "sendgrid.net", ("s1", "s2")),
              ("Mailchimp", "servers.mcsv.net", ("k1", "k2", "k3")), ("Zendesk", "mail.zendesk.com", ("zendesk1", "zendesk2")),
              ("Klaviyo", "klaviyo", ("kl", "kl2")), ("Mailjet", "spf.mailjet.com", ("mailjet",))]
# Filtering services in front of a domain's email; they often sign outgoing email themselves.
MAIL_GATEWAYS = [("pphosted.com", "Proofpoint"), ("ppe-hosted.com", "Proofpoint"), ("mimecast", "Mimecast"),
                 ("messagelabs.com", "Broadcom Email Security"), ("iphmx.com", "Cisco Secure Email"),
                 ("fortimailcloud.com", "FortiMail Cloud"), ("barracudanetworks.com", "Barracuda")]


def dkim_tags(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags.setdefault(k.strip().lower(), re.sub(r"\s+", "", v))
    return tags


def _der_length(b, i):
    n = b[i]
    if n < 0x80:
        return n, i + 1
    k = n & 0x7F
    if k == 0 or k > 4 or i + 1 + k > len(b):
        raise ValueError("bad length")
    return int.from_bytes(b[i + 1:i + 1 + k], "big"), i + 1 + k


def dkim_key(tags):
    """(problem or None, size in words like "2048-bit RSA", bits or None) for one key record.
    The key's own length field must match its size: a key cut short (it happens when a long
    record is pasted into a DNS form) fails every signature."""
    p, k = tags.get("p", ""), tags.get("k", "rsa").lower()
    try:
        b = base64.b64decode(p + "=" * (-len(p) % 4), validate=True)
    except (ValueError, TypeError):
        return "isn't valid base64, so receivers can't read it", None, None
    if k == "ed25519":
        return (None, "Ed25519", 256) if len(b) == 32 else ("is damaged (an Ed25519 key is 32 bytes)", None, None)
    if k != "rsa":
        return f"uses a key type receivers don't support (k={k})", None, None
    try:
        if not b or b[0] != 0x30:
            raise ValueError
        length, start = _der_length(b, 1)
        if start + length != len(b):
            return "is damaged: it's cut short or has extra data, so every signature with it fails", None, None
        def read(i):
            tag = b[i]
            n, j = _der_length(b, i + 1)
            return tag, j, j + n
        tag, s1, e1 = read(start)
        if tag == 0x30:                          # SubjectPublicKeyInfo: algorithm, then the key in a BIT STRING
            tag, s2, e2 = read(e1)
            if tag != 0x03:
                raise ValueError
            tag, s3, e3 = read(s2 + 1)
            tag, s4, e4 = read(s3)
        else:                                    # a bare RSAPublicKey: the modulus comes first
            s4, e4 = s1, e1
        bits = len(b[s4:e4].lstrip(b"\x00")) * 8
    except (ValueError, IndexError):
        return "is damaged, so receivers can't read it", None, None
    if bits < 1024:
        return f"is only {bits}-bit; receivers ignore keys under 1024 bits", None, bits
    return None, f"{bits}-bit RSA", bits


def _provider(selector, cname):
    """(provider, certain): certain when the key points to the provider's own servers."""
    if cname:
        target = cname[-1].rstrip(".").lower()
        for suffix, name in DKIM_CNAME_PROVIDERS:
            if target == suffix or target.endswith("." + suffix):
                return name, True
    return DKIM_NAME_PROVIDERS.get(selector), False


def check_dkim(dns, domain, receives_mail, mx_hosts, selector=None):
    title, what = "DKIM", "Whether email from this domain is signed"
    try:
        spf = " ".join(_spf_records(dns, domain)).lower()
    except DNSUnavailable:
        spf = ""
    sends_none = not spf or re.fullmatch(r"v=spf1\s+-all", spf.strip()) is not None
    names = [selector] if selector else DKIM_SELECTORS
    probe = "zz-" + secrets.token_hex(5)            # a name nobody uses: does the domain answer anything?

    def look(name):
        try:
            res = dns.query(f"{name}._domainkey.{domain}", "TXT")
        except DNSUnavailable:
            return name, None
        if res["status"] not in (0, 3):
            return name, None
        cname = [d.rstrip(".") for t, d in res["answers"] if t == 5]
        recs = [x for x in (_txt_value(d) for t, d in res["answers"] if t == 16)
                if re.search(r"(^|;)\s*p\s*=", x) or x.strip().lower().startswith("v=dkim1")]
        return name, (cname, recs)

    with ThreadPoolExecutor(max_workers=16) as pool:
        answers = dict(pool.map(look, names + [probe]))
    junk = answers.pop(probe)
    failed = [n for n, a in answers.items() if a is None]
    if junk is None or len(failed) > len(names) // 4:
        return unknown("dkim", title, what)
    if any(dkim_tags(r).get("p") for r in junk[1]):
        return _check("dkim", title, what, "unknown", "This domain answers every name with a key, even made-up "
                      "ones, so a key found under a common name proves nothing.")
    blank_everywhere = bool(junk[1])
    wildcard_cname = bool(junk[0])

    found, problems, weak, revoked = {}, [], [], []
    for name in names:
        a = answers.get(name)
        if not a or not a[1]:
            continue
        cname, recs = a
        keyed = [r for r in recs if dkim_tags(r).get("p")]
        if not keyed:
            revoked.append(name)
            continue
        if len(recs) > 1:
            problems.append(f"There are {len(recs)} records under {name}, so receivers can't tell which to use.")
        tags = dkim_tags(keyed[0])
        problem, size, bits = dkim_key(tags)
        who, certain = _provider(name, cname)
        if problem:
            problems.append(f"The key under {name}" + (f" ({who})" if who and certain else "") + f" {problem}.")
        if tags.get("t") and "y" in tags["t"].split(":"):
            problems.append(f"The key under {name} is in testing mode (t=y), so receivers treat its email as unsigned.")
        if tags.get("h") and "sha256" not in tags["h"].lower().split(":"):
            problems.append(f"The key under {name} only allows SHA-1, which receivers no longer accept.")
        if bits == 1024 and not cname and not problem:
            weak.append(name)
        found[name] = (who, size, bool(cname))

    def present(name):
        a = answers.get(name)
        return bool(a and (a[1] or (a[0] and not wildcard_cname)))

    gateway = next((g for suffix, g in MAIL_GATEWAYS if suffix in spf or any(suffix in h for h in mx_hosts)), None)
    m365_mx = any(h.endswith("mail.protection.outlook.com") for h in mx_hosts)
    m365_spf = "spf.protection.outlook.com" in spf
    hints, notes = [], []          # hints: something looks missing; notes: context only
    if not selector:
        if (m365_mx or m365_spf) and not present("selector1") and not present("selector2"):
            if gateway:
                notes.append(f"{gateway} handles this domain's email and may sign it under its own name, so "
                             "Microsoft 365's DKIM names being absent may be fine.")
            else:
                hints.append(("Email goes through Microsoft 365" if m365_mx else
                              "Your SPF lets Microsoft 365 send for this domain") +
                             ", but Microsoft's DKIM names (selector1, selector2) aren't set up. Microsoft then signs "
                             "with its own onmicrosoft.com name, which doesn't count for this domain's DMARC.")
        for prov, include, fixed in DKIM_FIXED:
            if include in spf and not any(present(n) for n in fixed):
                hints.append(f"Your SPF lets {prov} send for this domain, but there's no key under the names "
                             f"{prov} uses ({', '.join(fixed)}). Check DKIM in your {prov} settings; it may use a "
                             "custom name.")
    m365_fix = ("Turn on DKIM for the domain in the Microsoft Defender portal (Email & collaboration, Policies, "
                "Email authentication settings, DKIM), and publish the two CNAME records it gives you.")

    if found:
        groups = {}
        for name, (who, size, managed) in found.items():
            groups.setdefault(who or "this domain's own mail server", []).append(name)
        named = "; ".join(f"{who} ({', '.join(ns)})" for who, ns in groups.items())
        details = [f"Keys found under names used by: {named}."]
        details += [f"The key under {n} is {found[n][1]}." for n in found if found[n][1]][:8]
        if weak:
            details.append(f"Your own key{'s' if len(weak) > 1 else ''} ({', '.join(weak)}) "
                           f"{'are' if len(weak) > 1 else 'is'} 1024-bit: still accepted, but 2048 is now recommended. "
                           "(Keys a service publishes for you are its choice.)")
        if problems:
            return _check("dkim", title, what, "problem", problems[0], problems[1:] + details + hints + notes,
                          fix="Replace the broken key: publish the full key again from your mail service, in one "
                              "record. Long keys are often cut short when pasted into a DNS form.")
        if hints:
            return _check("dkim", title, what, "partly", "Some of this domain's email is signed, but not all of it "
                          "may be.", hints + details + notes,
                          fix=m365_fix if any("Microsoft's DKIM" in h for h in hints) else None)
        return _check("dkim", title, what, "in", "Signed: receivers can check that this domain's email is "
                      "genuine and unchanged.", details + notes)
    if selector:
        return _check("dkim", title, what, "missing", f"There's no DKIM key under {selector}._domainkey.{domain}.",
                      ["Check the name: it's the s= value in the DKIM-Signature header of an email from this "
                       "domain, and the d= value there should be this domain."])
    if blank_everywhere:
        if not receives_mail and sends_none:
            return _check("dkim", title, what, "na", "This domain publishes empty keys for every name, saying it "
                          "never signs email, which is right for a domain that sends none.")
        return _check("dkim", title, what, "unknown", "This domain answers every name with an empty key and "
                      "hides its real one. Type the selector from one of your emails to check it.")
    if hints and "Microsoft's DKIM" in hints[0]:
        return _check("dkim", title, what, "missing", "No DKIM key found. " + hints[0], hints[1:] + notes, fix=m365_fix)
    if not receives_mail and sends_none:
        return _check("dkim", title, what, "na", "This domain receives no email, its SPF (if any) allows no "
                      "senders, and no keys were found: DKIM is only needed for a domain that sends email.")
    return _check("dkim", title, what, "notfound", f"No key found under the {len(names)} names mail services "
                  "commonly use. That doesn't mean DKIM is off: your service may use its own name. Type the "
                  "selector from one of your emails to check it.", hints + notes + ([f"Couldn't look up "
                  f"{len(failed)} of the names in time."] if failed else []))


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


# ---------- the website (connections go through safefetch) ----------

HSTS_MIN = 15768000          # six months, the shortest guides accept; the browsers' preload list wants a year
CERT_SOON_DAYS = 14
SECURITY_TXT_BYTES = 32768
POLICY_BYTES = 16384

CERT_WORDS = [("certificate has expired", "it has expired"),
              ("hostname mismatch", "it's for a different name, not this domain"),
              ("self-signed", "it's self-signed, so browsers don't trust it"),
              ("self signed", "it's self-signed, so browsers don't trust it"),
              ("unable to get local issuer", "browsers can't trace it to an authority they trust (often the "
                                             "server leaves out part of the certificate chain)"),
              ("not yet valid", "it isn't valid yet")]


def cert_words(message):
    low = (message or "").lower()
    return next((w for k, w in CERT_WORDS if k in low), message or "it couldn't be verified")


def hsts_parse(value):
    """(max_age or None, includeSubDomains, preload) from a Strict-Transport-Security header."""
    max_age, sub, pre = None, False, False
    for part in (value or "").split(";"):
        part = part.strip()
        m = re.fullmatch(r'max-age\s*=\s*"?(\d+)"?', part, re.I)
        if m:
            max_age = int(m.group(1))
        sub = sub or part.lower() == "includesubdomains"
        pre = pre or part.lower() == "preload"
    return max_age, sub, pre


def _web_titles(key):
    return key, *TITLES[key]


def check_web(dns, domain):
    """The four website checks: HTTPS redirect, HSTS, certificate and security.txt."""
    keys = ("https", "hsts", "certificate", "security-txt")

    def every(verdict, headline):
        return {k: _check(*_web_titles(k), verdict, headline) for k in keys}
    try:
        ips = safefetch.addresses(dns, domain)
    except safefetch.Refused as e:
        return every("unknown", str(e))
    except DNSUnavailable:
        return {k: unknown(*_web_titles(k)) for k in keys}
    if not ips:
        return every("na", f"There's no website at {domain} itself: it has no web address records.")
    deadline = dns.deadline
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_https = pool.submit(safefetch.fetch, dns, f"https://{domain}/", deadline, 0, 0)
        f_http = pool.submit(safefetch.fetch, dns, f"http://{domain}/", deadline, 0)
        f_sec = pool.submit(safefetch.fetch, dns, f"https://{domain}/.well-known/security.txt", deadline,
                            SECURITY_TXT_BYTES)
        https_chain, https_err = f_https.result()
        http_chain, http_err = f_http.result()
        sec_chain, sec_err = f_sec.result()
    out = {}
    https_ok = bool(https_chain)

    # Certificate
    k = _web_titles("certificate")
    if https_ok and https_chain[0]["cert"]:
        cert = https_chain[0]["cert"]
        left = int((ssl_time(cert.get("notAfter")) - time.time()) // 86400) if cert.get("notAfter") else None
        issuer = dict(x[0] for x in cert.get("issuer", ()) if x).get("organizationName")
        details = [f"Issued by {issuer}." if issuer else None,
                   f"Valid until {long_date(datetime.fromtimestamp(ssl_time(cert['notAfter']), timezone.utc))}."
                   if cert.get("notAfter") else None]
        if left is not None and left <= CERT_SOON_DAYS:
            out["certificate"] = _check(*k, "partly", f"Valid, but it expires in {left} day{'s' if left != 1 else ''}.",
                                        details, fix="Renew it now, and make renewal automatic (most hosts and "
                                                     "Let's Encrypt clients can).")
        else:
            out["certificate"] = _check(*k, "in", f"Valid, trusted by browsers, and good for {left} more days."
                                        if left is not None else "Valid and trusted by browsers.", details)
    elif isinstance(https_err, safefetch.FetchError) and https_err.kind == "cert":
        out["certificate"] = _check(*k, "problem", f"The certificate isn't valid: {cert_words(str(https_err))}. "
                                    "Browsers show visitors a full-page warning.",
                                    fix="Install a valid certificate for this exact name, with its full chain. "
                                        "Let's Encrypt certificates are free.")
    elif https_err is not None and not isinstance(https_err, safefetch.Refused):
        out["certificate"] = _check(*k, "problem", "The website doesn't answer over HTTPS, so visitors can't "
                                    "reach it securely.", [str(https_err)],
                                    fix="Turn on HTTPS at your web host, with a free Let's Encrypt certificate "
                                        "if it doesn't come with one.")
    else:
        out["certificate"] = _check(*k, "unknown", str(https_err) if https_err else
                                    "The secure connection gave no certificate details.")

    # HSTS (browsers only honour it over a valid HTTPS connection)
    k = _web_titles("hsts")
    if https_ok:
        value = https_chain[0]["headers"].get("strict-transport-security")
        max_age, sub, pre = hsts_parse(value)
        notes = (["It covers subdomains too (includeSubDomains)."] if sub else []) + \
                (["It asks to be on browsers' built-in HTTPS-only list (preload)."] if pre else [])
        fix = ("Send the header Strict-Transport-Security: max-age=31536000; includeSubDomains from the "
               "HTTPS site, once every subdomain works over HTTPS.")
        if not value or max_age is None:
            out["hsts"] = _check(*k, "missing", "Not set, so a visitor's first visit can be quietly downgraded "
                                 "to the unencrypted site by someone on the same network.", record=value, fix=fix)
        elif max_age == 0:
            out["hsts"] = _check(*k, "missing", "Turned off (max-age=0).", record=value, fix=fix)
        elif max_age < HSTS_MIN:
            out["hsts"] = _check(*k, "partly", f"Set, but browsers only remember it for {days_words(max_age)}. "
                                 "Six months or more is the usual minimum.", notes, value, fix)
        else:
            out["hsts"] = _check(*k, "in", f"Browsers are told to use only the encrypted site for "
                                 f"{days_words(max_age)}.", notes, value)
    else:
        out["hsts"] = _check(*k, "unknown", "Couldn't be checked, because the HTTPS site didn't give a valid "
                             "answer (see Certificate).")

    # HTTPS redirect
    k = _web_titles("https")
    first = http_chain[0] if http_chain else None
    if first is None:
        if https_ok:
            out["https"] = _check(*k, "in", "Only HTTPS is offered: the plain http address doesn't answer, so "
                                  "there's nothing unencrypted to land on.", [str(http_err)] if http_err else [])
        else:
            out["https"] = _check(*k, "unknown", "The website didn't answer on either address.")
    elif first["status"] in (301, 302, 303, 307, 308) and (first["location"] or "").lower().startswith("https://"):
        notes = []
        if first["status"] in (302, 303, 307):
            notes.append(f"It's a temporary redirect ({first['status']}); a permanent one (301 or 308) lets "
                         "browsers remember it.")
        out["https"] = _check(*k, "in", "The plain http address sends visitors straight to the encrypted site.",
                              notes + [f"It goes to {first['location'][:120]}."])
    elif first["status"] in (301, 302, 303, 307, 308):
        reaches = any(h["url"].lower().startswith("https://") for h in http_chain[1:])
        out["https"] = _check(*k, "partly" if reaches else "missing",
                              "It redirects to another plain http address first" + (", then to HTTPS." if reaches else
                                                                                     ", and never reaches HTTPS."),
                              [f"First stop: {first['location'][:120]}."],
                              fix="Redirect http:// straight to https:// on the same name.")
    else:
        out["https"] = _check(*k, "missing", "The plain http address shows the site unencrypted instead of "
                              "redirecting to HTTPS.",
                              fix="Redirect every http:// request to https:// (a setting at most web hosts).")

    # security.txt
    k = _web_titles("security-txt")
    final = sec_chain[-1] if sec_chain else None
    fix = (f"Publish a plain-text file at https://{domain}/.well-known/security.txt with at least a "
           "Contact: line (an email address or form) and an Expires: date. securitytxt.org writes one for you.")
    if final is None:
        out["security-txt"] = (_check(*k, "unknown", "Couldn't be checked, because the HTTPS site didn't give a "
                                      "valid answer (see Certificate).")
                               if not https_ok else _check(*k, "missing", "Not found.", fix=fix))
    elif final["status"] != 200 or not final["url"].lower().startswith("https://"):
        out["security-txt"] = _check(*k, "missing", "Not published, so a researcher who finds a problem has "
                                     "no clear way to tell you.", fix=fix)
    else:
        text = final["body"].decode("utf-8", "replace")
        ctype = final["headers"].get("content-type", "").lower()
        fields = {}
        for line in text.splitlines():
            m = re.match(r"^([A-Za-z-]+):\s*(.+?)\s*$", line)
            if m:
                fields.setdefault(m.group(1).lower(), []).append(m.group(2))
        if "contact" not in fields or "<html" in text[:500].lower() or (ctype and not ctype.startswith("text/plain")):
            out["security-txt"] = _check(*k, "missing", "Not published: the address gives a web page, not a "
                                         "security.txt file.", fix=fix)
        else:
            contacts = [c[:100] for c in fields["contact"][:2]]
            expires = fields.get("expires", [None])[0]
            when = None
            if expires:
                try:            # RFC 3339 allows a lower-case t and z (github.com and google.com use z)
                    when = datetime.fromisoformat(expires.strip().upper().replace("Z", "+00:00"))
                    when = when if when.tzinfo else when.replace(tzinfo=timezone.utc)
                except ValueError:
                    when = None
            details = [f"Contact: {', '.join(contacts)}."]
            if expires and when is None:
                out["security-txt"] = _check(*k, "partly", "Published, but its Expires date can't be read.",
                                             details, fix="Use a date like 2027-06-30T00:00:00Z.")
            elif when is None:
                out["security-txt"] = _check(*k, "partly", "Published, but without the Expires date the standard "
                                             "requires.", details, fix="Add a line like Expires: 2027-06-30T00:00:00Z.")
            elif when < datetime.now(timezone.utc):
                out["security-txt"] = _check(*k, "problem", f"Published, but it expired on {long_date(when)}, so "
                                             "researchers can't trust its contacts are still right.", details,
                                             fix="Check the contacts and set a new Expires date, a year ahead at most.")
            else:
                out["security-txt"] = _check(*k, "in", "Published: researchers can see how to report a problem.",
                                             details + [f"Valid until {long_date(when)}."])
    return out


def ssl_time(value):
    return ssl.cert_time_to_seconds(value)


def long_date(when):
    return f"{when.day} {when:%B %Y}"


def days_words(seconds):
    days = seconds // 86400
    if days >= 365:
        years = days // 365
        return f"{years} year{'s' if years > 1 else ''}"
    if days >= 30:
        return f"{days // 30} month{'s' if days // 30 > 1 else ''}"
    return f"{days} day{'s' if days != 1 else ''}" if days else f"{seconds} seconds"


def mx_covered(host, patterns):
    """MTA-STS mx: patterns: an exact name, or *.name matching one more label on the left."""
    host = host.rstrip(".").lower()
    for p in patterns:
        p = p.rstrip(".").lower()
        if p.startswith("*."):
            if host.endswith(p[1:]) and "." not in host[: -len(p) + 1]:
                return True
        elif host == p:
            return True
    return False


def check_mta_sts_policy(dns, domain, mx_hosts, record_check):
    """The MTA-STS record only says a policy exists; the policy itself is a file on
    https://mta-sts.<domain>, fetched without following redirects (RFC 8461)."""
    title, what = TITLES["mta-sts"]
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    record = record_check.get("record")
    chain, err = safefetch.fetch(dns, url, dns.deadline, POLICY_BYTES, follow=0)
    fix = (f"Publish the policy file at {url}, served as plain text over HTTPS with a valid certificate, "
           "with version: STSv1, mode: enforce, an mx: line for each mail server, and max_age: 604800 or more.")
    if not chain:
        reason = cert_words(str(err)) if isinstance(err, safefetch.FetchError) and err.kind == "cert" else str(err)
        return _check("mta-sts", title, what, "problem", "The record says MTA-STS is on, but the policy file can't "
                      "be fetched, so other servers ignore it.", [f"{url}: {reason}"], record, fix)
    res = chain[0]
    if res["status"] != 200:
        return _check("mta-sts", title, what, "problem", "The record says MTA-STS is on, but the policy file isn't "
                      f"there (HTTP {res['status']}), so other servers ignore it.", [url], record, fix)
    fields = {}
    for line in res["body"].decode("utf-8", "replace").splitlines():
        m = re.match(r"^\s*([a-z_]+)\s*:\s*(.+?)\s*$", line)
        if m:
            fields.setdefault(m.group(1), []).append(m.group(2))
    mode = (fields.get("mode") or [""])[0].lower()
    max_age = (fields.get("max_age") or [""])[0]
    patterns = fields.get("mx", [])
    if (fields.get("version") or [""])[0] != "STSv1" or mode not in ("enforce", "testing", "none") or not max_age.isdigit():
        return _check("mta-sts", title, what, "problem", "The policy file is incomplete (it needs version, mode and "
                      "max_age), so other servers ignore it.", [url], record, fix)
    details = [f"Policy: mode {mode}, mail servers {', '.join(patterns) or 'none listed'}, remembered for "
               f"{days_words(int(max_age))}."]
    uncovered = [h for h in mx_hosts if not mx_covered(h, patterns)]
    if mode == "none":
        return _check("mta-sts", title, what, "partly", "Published but switched off (mode: none).", details, record,
                      "Set mode: testing, watch the TLS-RPT reports, then mode: enforce.")
    if uncovered:
        return _check("mta-sts", title, what, "problem", f"The policy leaves out {uncovered[0]}"
                      + (f" and {len(uncovered) - 1} more" if len(uncovered) > 1 else "") +
                      ", one of this domain's mail servers: servers that follow the policy will refuse to "
                      "deliver to it.", details, record, "List every mail server on an mx: line.")
    if mode == "testing":
        return _check("mta-sts", title, what, "partly", "Testing only: failures are reported, but email is still "
                      "delivered without encryption if an attacker strips it.", details, record,
                      "Once the TLS-RPT reports are clean, change mode: testing to mode: enforce.")
    if int(max_age) < 86400:
        details.append("It's remembered for under a day; a week or more is recommended.")
    return _check("mta-sts", title, what, "in", "Enforced: other mail servers must use encryption, with a valid "
                  "certificate, to deliver email here.", details, record)


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
          "dkim": ("DKIM", "Whether email from this domain is signed"),
          "https": ("HTTPS redirect", "Whether the plain http address sends visitors to the encrypted site"),
          "hsts": ("HSTS", "Whether browsers are told to use only the encrypted site"),
          "certificate": ("Certificate", "Whether the HTTPS certificate is valid, and how long it lasts"),
          "security-txt": ("security.txt", "Whether security researchers can find how to report a problem"),
          "dnssec": ("DNSSEC", "Whether this domain's DNS answers are signed against forgery"),
          "caa": ("CAA", "Which certificate authorities may issue certificates for this domain")}


def _mta_sts_full(dns, domain, receives_mail, hosts):
    """The MTA-STS record, then, if it's there, the policy file it points to."""
    found = check_mta_sts(dns, domain, receives_mail)
    if found["verdict"] == "in":
        return check_mta_sts_policy(dns, domain, hosts, found)
    return found


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


def run(domain, dns=None, selector=None):
    """Every check for one domain, as a dict ready to save and show. selector: a DKIM selector the
    visitor typed, checked instead of the common names."""
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
        web_future = pool.submit(check_web, dns, domain)
        try:
            results["mx"], receives_mail, hosts = mx_future.result(timeout=max(0.1, dns.time_left()))
        except Exception:                   # noqa: BLE001 - any failure here is "couldn't check"
            results["mx"], receives_mail, hosts = unknown("mx", *TITLES["mx"]), None, []
        if receives_mail is None:
            for key in ("mta-sts", "tls-rpt", "dkim"):
                results[key] = unknown(key, *TITLES[key])
        else:
            futures["mta-sts"] = pool.submit(_mta_sts_full, dns, domain, receives_mail, hosts)
            futures["tls-rpt"] = pool.submit(check_tls_rpt, dns, domain, receives_mail)
            futures["dkim"] = pool.submit(check_dkim, dns, domain, receives_mail, hosts, selector)
        wait([*futures.values(), web_future], timeout=max(0.1, dns.time_left() + 1))
        for key, future in futures.items():
            try:
                results[key] = future.result(timeout=0)
            except Exception:               # noqa: BLE001 - unfinished or failed: say so, don't guess
                results[key] = unknown(key, *TITLES[key])
        try:
            results.update(web_future.result(timeout=0))
        except Exception:                   # noqa: BLE001
            for key in ("https", "hsts", "certificate", "security-txt"):
                results[key] = unknown(key, *TITLES[key])
    checks = [results[k] for k in ORDER if k in results]
    broken = results.get("dnssec", {}).get("verdict") == "problem"
    for c in checks:
        c["group"] = GROUP_OF[c["key"]]
        if broken and c["verdict"] == "unknown":
            c["headline"] = "Lookups for this domain fail because of the DNSSEC problem below."
    return {"domain": domain, "checked_at": started.isoformat(), "selector": selector, "checks": checks}


def score(result):
    """(in place, out of): only checks with a real verdict count."""
    counted = [c for c in result["checks"] if c["verdict"] in SCORED]
    return sum(1 for c in counted if c["verdict"] == "in"), len(counted)


# ---------- saved results and rate limits ----------

def normalize_selector(raw):
    """A DKIM selector someone typed (the s= of a DKIM-Signature), or None. Raises ValueError."""
    text = (raw or "").strip().lower().rstrip(".")
    if not text:
        return None
    label = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
    if len(text) > 100 or not re.fullmatch(rf"{label}(?:\.{label})*", text):
        raise ValueError("That isn't a DKIM selector. It's the s= value in an email's DKIM-Signature header, "
                         "like selector1 or google.")
    return text


def cache_key(domain, selector):
    """Where a result is saved: a check with a typed selector is kept apart from the plain one."""
    return f"{domain} s={selector}" if selector else domain


def cached(conn, key, now=None):
    now = now or datetime.now(timezone.utc)
    row = conn.execute("SELECT checked_at, result FROM domain_checks WHERE domain = ?", (key,)).fetchone()
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


def save(conn, key, result):
    with conn:
        conn.execute("INSERT OR REPLACE INTO domain_checks (domain, checked_at, result) VALUES (?, ?, ?)",
                     (key, result["checked_at"], json.dumps(result)))
