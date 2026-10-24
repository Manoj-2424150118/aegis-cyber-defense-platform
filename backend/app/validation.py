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
        return f"'{host}' is not a valid domain name or IP address."
    return None
