"""Shared host-format validation for threat-lookup parameters.

The URL *analyser* intentionally accepts malformed input — scoring a
disguised or broken link is its whole job (see the regression tests:
malformed URLs must return findings, never a 500 or a rejection).

The website *audit* is different: it makes the server fetch the target,
so its lookup parameter is validated strictly before any DNS lookup:

* IPv4 literals must match the dotted-quad shape AND every octet must be
  0–255 (the regex alone happily accepts ``999.999.999.999``).
* IPv6 literals must parse via :mod:`ipaddress` (the SSRF guard in
  ``web_audit`` then decides whether the address is public).
* Domain names must match ``DOMAIN_REGEX``: dot-separated labels of
  1–63 chars, never starting or ending with a hyphen, and an alphabetic
  TLD of at least two characters.
* ``is_public_unicast`` decides whether a resolved address may be
  connected to at all: an explicit allow of genuinely public unicast
  addresses (never a denylist), used by the SSRF guard.

The frontend mirrors these exact rules in ``frontend/src/api.ts`` so a
bad lookup is rejected in the browser before a request is ever made.
"""

import ipaddress
import re
from urllib.parse import urlparse

# Corrected form of the commonly-copied snippet: the label group needs a
# non-capturing group around it, otherwise the pattern is a syntax error.
DOMAIN_REGEX = re.compile(r"^(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$")
IP_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")


def is_public_unicast(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for a genuinely public, routable unicast address.

    ``ip.is_global`` alone is NOT sufficient (F-01): it returns True for
    NAT64 well-known-prefix addresses (``64:ff9b::/96`` — which a network
    with IPv6 egress translates to the embedded IPv4, e.g. the cloud
    metadata address) and for multicast. So deny every non-public class
    by name, and for transition mechanisms that embed an IPv4 address
    (IPv4-mapped, 6to4, Teredo, NAT64) judge the embedded address — or
    refuse the prefix outright where the platform's translation
    behaviour cannot be trusted.
    """
    if ip.is_multicast or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        # NAT64 WKP, 6to4 and Teredo embed an IPv4 address whose meaning
        # depends on translation behaviour outside this host's control;
        # reject the prefixes outright rather than trusting translation.
        if ip in ipaddress.ip_network("64:ff9b::/96"):
            return False
        if ip in ipaddress.ip_network("2002::/16"):
            return False
        if ip.teredo is not None:
            return False
        # IPv4-mapped addresses MEAN their embedded IPv4 address — judge
        # that (the stdlib classifies the mapped range inconsistently
        # across Python versions: reserved on 3.12, not-global elsewhere).
        if ip.ipv4_mapped is not None:
            return is_public_unicast(ip.ipv4_mapped)
    if ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_private:
        return False
    return ip.is_global


def is_valid_ipv4(host: str) -> bool:
    """True for a dotted-quad with every octet in 0–255."""
    if not IP_REGEX.match(host):
        return False
    return all(int(octet) <= 255 for octet in host.split("."))


def is_valid_domain(host: str) -> bool:
    """True for a syntactically valid public domain name. A single
    trailing dot (FQDN root) is accepted and ignored."""
    return bool(DOMAIN_REGEX.match(host.rstrip(".")))


def is_valid_host(host: str) -> bool:
    """True when ``host`` is a valid IPv4 literal, IPv6 literal, or
    domain name — the three shapes a lookup target may legitimately take."""
    if not host or len(host) > 253 or any(c.isspace() for c in host):
        return False
    if is_valid_ipv4(host) or is_valid_domain(host):
        return True
    try:
        ipaddress.ip_address(host)  # IPv6 literal (brackets stripped by urlparse)
        return True
    except ValueError:
        return False


def host_from_url(raw_url: str) -> str:
    """Extract the lower-cased hostname from a URL-ish string, tolerating
    a missing scheme the way the analysers do."""
    url = raw_url.strip()
    if "://" not in url:
        url = "https://" + url
    return (urlparse(url).hostname or "").lower()


def validate_lookup_host(raw_url: str) -> str | None:
    """Return an error message when the host in ``raw_url`` is not a
    valid domain or IP literal, otherwise ``None``."""
    host = host_from_url(raw_url)
    if not host:
        return "The URL has no host to look up."
    if not is_valid_host(host):
        return "That doesn't look like a valid domain name or IP address."
    return None
