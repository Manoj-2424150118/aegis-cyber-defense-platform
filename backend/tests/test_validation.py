"""Host-format validation for threat-lookup parameters (app/validation).

The web audit fetches its target server-side, so malformed hosts must be
rejected before DNS; the URL analyser keeps scoring malformed links
instead (covered by test_security.test_malformed_urls_never_500).
"""

import pytest

from app.modules.web_audit import UnsafeUrlError, audit_website
from app.validation import (
    host_from_url,
    is_valid_domain,
    is_valid_host,
    is_valid_ipv4,
    validate_lookup_host,
)


@pytest.mark.parametrize("host", ["example.com", "www.paypal.com", "sub.deep.example.co.in", "xn--pypal-4ve.com", "a-b.example.io"])
def test_valid_domains(host):
    assert is_valid_domain(host)
    assert is_valid_host(host)


@pytest.mark.parametrize("host", ["999.999.999.999", "256.1.1.1", "1.2.3", "1.2.3.4.5", "01a.2.3.4"])
def test_invalid_ipv4_shapes(host):
    assert not is_valid_ipv4(host)


@pytest.mark.parametrize("ip", ["192.168.10.5", "8.8.8.8", "255.255.255.255", "0.0.0.0"])
def test_valid_ipv4(ip):
    assert is_valid_ipv4(ip)
    assert is_valid_host(ip)


@pytest.mark.parametrize("host", ["bad_host.example.com", "-leading.example.com", "trailing-.example.com", "example.c", "example..com", "", "exa mple.com"])
def test_invalid_hosts(host):
    assert not is_valid_host(host)


def test_ipv6_literal_is_a_valid_host_shape():
    # Format-valid; the SSRF guard (not the format check) rejects it as
    # non-public.
    assert is_valid_host("::1")


def test_host_from_url_tolerates_missing_scheme():
    assert host_from_url("Example.COM/path?q=1") == "example.com"
    assert host_from_url("https://192.168.1.1:8443/x") == "192.168.1.1"


def test_validate_lookup_host_messages():
    assert validate_lookup_host("https://example.com/login") is None
    assert validate_lookup_host("http://192.168.1.9/paypal") is None
    assert validate_lookup_host("https://bad_host.example/login") is not None
    assert validate_lookup_host("https://999.1.1.1/login") is not None


def test_audit_rejects_malformed_host_before_fetch():
    with pytest.raises(UnsafeUrlError):
        audit_website("https://bad_host.example.com/")


def test_whitespace_url_rejected_by_schema(client):
    r = client.post("/api/tools/url", json={"url": "https://exa mple.com/login"})
    assert r.status_code == 422
    r = client.post("/api/tools/web-audit", json={"url": "https://example.com/\tlogin"})
    assert r.status_code == 422
