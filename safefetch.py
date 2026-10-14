"""Fetching from a domain a visitor chose, without letting it reach anything private.

The domain check connects to websites someone else picked, which is the setup for server-side
request forgery: pointing the server at its own network, a cloud metadata address, or a port that
isn't a website. So, for every request and every redirect:

- The host is looked up through DNS-over-HTTPS (the domain check's Resolver), and every address
  must be public: no private, loopback, link-local (169.254.169.254 is the cloud metadata
  service), shared, reserved, multicast or documentation ranges, and no IPv6 forms that carry
  an IPv4 address (mapped, 6to4, Teredo, NAT64). One non-public address and the host is refused.
- The connection goes to that exact address, with the name only in TLS and the Host header, so
  a second lookup can't send it somewhere else (DNS rebinding).
- Only http on port 80 and https on 443; no logins in links; at most MAX_REDIRECTS redirects,
  each checked from scratch.
- Short timeouts, a hard deadline that closes the socket however slowly a server drips data,
  and only the first max_bytes of a body are read.

Certificates are checked against certifi's list, as requests does.
"""
import http.client
import ipaddress
import re
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit

import certifi
import idna

PORTS = {"http": 80, "https": 443}
MAX_REDIRECTS = 3
CONNECT_TIMEOUT = 3
USER_AGENT = "SentryFeed domain check (+https://sentryfeed.vercel.app/domain)"

SPECIAL_TLDS = {"localhost", "local", "internal", "test", "example", "invalid", "onion", "arpa",
                "alt", "lan", "home", "corp", "intranet", "private", "localdomain"}

# Ranges a website must never be fetched from, beyond what Python already calls non-global.
_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32",
    "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8")]


class Refused(Exception):
    """A request SentryFeed won't make; the message says why in plain words."""


class FetchError(Exception):
    """The request was allowed but failed. kind: "cert", "connect", "timeout" or "http"."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def public_ip(text):
    """True only for an address that's safe to connect to on the public internet."""
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        return False
    if any(ip in net for net in _BLOCKED if net.version == ip.version):
        return False
    return ip.is_global and not (ip.is_multicast or ip.is_private or ip.is_reserved or ip.is_loopback
                                 or ip.is_link_local or ip.is_unspecified)


def valid_host(host):
    """The ASCII form of a public host name from a link, or raises Refused."""
    host = (host or "").rstrip(".").lower()
    try:
        ascii_name = idna.encode(host, uts46=True, transitional=False).decode("ascii")
    except (idna.IDNAError, UnicodeError, ValueError):
        raise Refused(f"{host[:80]} isn't a valid host name.") from None
    labels = ascii_name.split(".")
    if len(labels) < 2 or len(ascii_name) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise Refused(f"{host[:80]} isn't a valid public host name.")
    if labels[-1] in SPECIAL_TLDS or labels[-1].isdigit() or ascii_name.endswith(".home.arpa"):
        raise Refused(f"{host[:80]} is a private or reserved name.")
    return ascii_name


def addresses(dns, host):
    """The host's public addresses, IPv4 first. [] if it has none at all. Raises Refused if any
    address isn't public: a public site has no reason to point anywhere else."""
    found = []
    for rtype in ("A", "AAAA"):
        found += dns.records(host, rtype)
    bad = [a for a in found if not public_ip(a)]
    if bad:
        raise Refused(f"{host} points to a private or reserved address, so SentryFeed won't connect to it.")
    return found


def check_url(url):
    """(scheme, ascii host or IP, port) for a link SentryFeed may fetch, or raises Refused."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in PORTS:
        raise Refused("Only http and https links are followed.")
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise Refused("Links with a login in them aren't followed.")
    try:
        port = parts.port
    except ValueError:
        raise Refused("That link has a broken port number.") from None
    if port is not None and port != {"http": 80, "https": 443}[scheme]:
        raise Refused(f"A link to port {port} isn't followed: only the standard web ports are.")
    host = parts.hostname or ""
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        if not public_ip(host):
            raise Refused("A link to a private or reserved address isn't followed.")
        return scheme, host, PORTS[scheme]
    return scheme, valid_host(host), PORTS[scheme]


class _Pinned:
    """An HTTP(S) connection to one checked address; the name is only used for TLS and Host."""

    def __init__(self, scheme, host, ip, port, timeout, context):
        cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        kwargs = {"context": context} if scheme == "https" else {}
        self.conn = cls(host, port, timeout=timeout, **kwargs)
        self.ip, self.scheme = ip, scheme
        self.sock = None            # kept here: http.client lets go of its own reference once a response starts
        self.conn.connect = self._connect

    def _connect(self):
        c = self.conn
        sock = socket.create_connection((self.ip, c.port), timeout=c.timeout)
        self.sock = sock
        if self.scheme == "https":
            sock = c._context.wrap_socket(sock, server_hostname=c.host)
            self.sock = sock
        c.sock = sock


def _context():
    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def fetch_once(dns, url, deadline, max_bytes=0):
    """One request, no redirects followed. Returns a dict: status, headers (lower-case name ->
    first value), location (absolute), body (bytes, at most max_bytes), cert (for https)."""
    scheme, host, port = check_url(url)
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        ips = addresses(dns, host)
    if not ips:
        raise FetchError("connect", f"{host} has no address, so there's nothing to connect to.")
    v4 = [a for a in ips if ":" not in a]
    ip = (v4 or ips)[0]
    left = deadline - time.monotonic()
    if left <= 0.2:
        raise FetchError("timeout", "Ran out of time.")
    pinned = _Pinned(scheme, host, ip, port, min(CONNECT_TIMEOUT, left), _context())
    conn = pinned.conn

    def cut():          # the hard deadline: shutting the socket ends any read that's still waiting
        sock = pinned.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    watchdog = threading.Timer(max(0.1, left), cut)
    watchdog.daemon = True
    watchdog.start()
    parts = urlsplit(url)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    try:
        try:
            conn.connect()
        except ssl.SSLCertVerificationError as e:
            raise FetchError("cert", e.verify_message or "the certificate couldn't be verified") from None
        except ssl.SSLError as e:
            raise FetchError("cert", f"the secure connection failed ({e.reason or 'TLS error'})") from None
        except socket.timeout:
            raise FetchError("timeout", f"{host} didn't answer in time.") from None
        except OSError as e:
            raise FetchError("connect", f"{host} refused the connection or couldn't be reached "
                                        f"({e.__class__.__name__}).") from None
        cert = conn.sock.getpeercert() if scheme == "https" else None
        conn.putrequest("GET", path, skip_accept_encoding=True)
        conn.putheader("User-Agent", USER_AGENT)
        conn.putheader("Accept", "*/*")
        conn.putheader("Connection", "close")
        conn.endheaders()
        resp = conn.getresponse()
        # The deadline closes the socket, which can look like the end of the headers or body: an
        # answer cut off that way is a timeout, never taken as the server's real answer.
        if time.monotonic() >= deadline - 0.05:
            raise FetchError("timeout", f"{host} didn't answer in time.")
        headers = {}
        for name, value in resp.getheaders():
            headers.setdefault(name.lower(), value)
        body = b""
        while max_bytes and len(body) < max_bytes and time.monotonic() < deadline:
            chunk = resp.read1(min(8192, max_bytes - len(body)))
            if not chunk:
                break
            body += chunk
        if max_bytes and len(body) < max_bytes and time.monotonic() >= deadline - 0.05:
            raise FetchError("timeout", f"{host} didn't finish answering in time.")
        location = headers.get("location")
        return {"url": url, "status": resp.status, "headers": headers, "body": body[:max_bytes], "cert": cert,
                "location": urljoin(url, location) if location else None, "ip": ip}
    except (socket.timeout, TimeoutError):
        raise FetchError("timeout", f"{host} didn't answer in time.") from None
    except (http.client.HTTPException, OSError, ValueError) as e:
        if time.monotonic() >= deadline - 0.05:
            raise FetchError("timeout", f"{host} didn't answer in time.") from None
        raise FetchError("http", f"{host} sent a broken answer ({e.__class__.__name__}).") from None
    finally:
        watchdog.cancel()
        conn.close()


def fetch(dns, url, deadline, max_bytes=0, follow=MAX_REDIRECTS):
    """A request following up to `follow` redirects, each checked like the first. Returns
    (chain, error): the responses in order, and the Refused or FetchError that stopped it, if any.
    A redirect beyond `follow` isn't fetched; the last response in the chain is then a redirect."""
    chain = []
    for _ in range(follow + 1):
        try:
            res = fetch_once(dns, url, deadline, max_bytes)
        except (Refused, FetchError) as e:
            return chain, e
        except Exception as e:                  # noqa: BLE001 - e.g. a DNS outage mid-chain
            return chain, FetchError("connect", f"The lookup failed ({e.__class__.__name__}).")
        chain.append(res)
        if res["status"] in (301, 302, 303, 307, 308) and res["location"] and len(chain) <= follow:
            url = res["location"]
            continue
        break
    return chain, None
