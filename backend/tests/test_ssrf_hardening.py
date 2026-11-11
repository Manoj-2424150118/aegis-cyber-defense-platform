"""F-01 — SSRF hardening: strict public-unicast rule + pinned connections.

Three layers are proven here:
1. ``is_public_unicast`` truth table — the prompt's deny/allow lists,
   including the forms ``is_global`` gets wrong (NAT64 ``64:ff9b::/96``,
   multicast).
2. HTTP level — every fetching endpoint (sync + streaming) refuses the
   translated / multicast / embedded-private forms with a 400 (or an SSE
   error event) and attempts NO outbound connection.
3. DNS rebinding — a name that resolves public for the check and private
   at dial time is blocked, and a successful dial goes to the validated
   address, never to the name.
"""

import ipaddress
import socket
import urllib.error

import pytest

from app.modules import web_audit
from app.modules.web_audit import UnsafeUrlError
from app.validation import is_public_unicast

DENY = [
    "224.0.0.1",  # multicast — is_global says True (measured); must deny
    "169.254.169.254",  # cloud metadata (link-local)
    "10.0.0.5",
    "172.16.0.9",
    "192.168.1.1",
    "100.64.0.1",  # CGNAT shared space
    "127.0.0.1",
    "0.0.0.0",
    "240.0.0.1",  # reserved
    "255.255.255.255",  # broadcast
    "::1",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "::ffff:127.0.0.1",  # IPv4-mapped loopback
    "::ffff:10.0.0.1",  # IPv4-mapped private
    "64:ff9b::a9fe:a9fe",  # NAT64 WKP -> 169.254.169.254
    "64:ff9b::7f00:1",  # NAT64 WKP -> 127.0.0.1
    "2002:c0a8:0101::1",  # 6to4 -> 192.168.1.1
    "2001:db8::1",  # documentation range
    "2001:0000:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
    "ff02::1",  # IPv6 multicast
]

ALLOW = [
    "93.184.216.34",  # example.com
    "1.1.1.1",
    "8.8.8.8",
    "140.82.121.4",  # github.com
    "2606:4700:4700::1111",  # cloudflare DNS
    "::ffff:8.8.8.8",  # IPv4-mapped PUBLIC — embedded address is judged
]


@pytest.mark.parametrize("addr", DENY)
def test_is_public_unicast_denies(addr):
    assert is_public_unicast(ipaddress.ip_address(addr)) is False


@pytest.mark.parametrize("addr", ALLOW)
def test_is_public_unicast_allows(addr):
    assert is_public_unicast(ipaddress.ip_address(addr)) is True


@pytest.fixture()
def no_outbound(monkeypatch):
    """Fail loudly if any code path tries to open a TCP connection."""

    def _boom(*args, **kwargs):
        raise AssertionError("outbound connection attempted for a refused target")

    monkeypatch.setattr(socket, "create_connection", _boom)
    return _boom


# The sneaky forms, exercised per endpoint (kept ≤6 per test so the
# 12/min fetch rate-limit bucket is never the reason for a refusal).
SNEAKY_URLS = [
    "http://[64:ff9b::a9fe:a9fe]/",  # NAT64 -> metadata
    "http://[64:ff9b::7f00:1]/",  # NAT64 -> loopback
    "http://224.0.0.1/",  # multicast
    "http://[::ffff:127.0.0.1]/",  # v4-mapped loopback
    "http://[2002:c0a8:0101::1]/",  # 6to4 -> 192.168.1.1
    "http://169.254.169.254/latest/meta-data/",  # the classic
]


@pytest.mark.parametrize("url", SNEAKY_URLS)
def test_web_audit_refuses_translated_and_multicast(client, no_outbound, url):
    resp = client.post("/api/tools/web-audit", json={"url": url})
    assert resp.status_code == 400
    assert "non-public address" in resp.json()["detail"]


@pytest.mark.parametrize("url", SNEAKY_URLS)
def test_url_resolve_refuses_translated_and_multicast(client, no_outbound, url):
    resp = client.post("/api/tools/url/resolve", json={"url": url})
    assert resp.status_code == 400
    assert "non-public address" in resp.json()["detail"]


@pytest.mark.parametrize("host", ["224.0.0.1", "169.254.169.254"])
def test_tls_refuses_translated_and_multicast(client, no_outbound, host):
    resp = client.post("/api/tools/tls", json={"host": host})
    assert resp.status_code == 400
    assert "non-public address" in resp.json()["detail"]


@pytest.mark.parametrize("host", ["64:ff9b::a9fe:a9fe", "::ffff:127.0.0.1"])
def test_tls_refuses_bare_ipv6_forms(client, no_outbound, host):
    # Bare IPv6 literals are stopped at the endpoint's format gate
    # (bracketless IPv6 is not a valid URL host) — still a 400, still
    # zero outbound connections; the guard-level refusal is proven
    # separately below.
    resp = client.post("/api/tools/tls", json={"host": host})
    assert resp.status_code == 400


@pytest.mark.parametrize(
    "host",
    ["64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "::ffff:127.0.0.1", "224.0.0.1",
     "2002:c0a8:0101::1", "2001:0000:4136:e378:8000:63bf:3fff:fdd2"],
)
def test_guard_itself_refuses_sneaky_forms(host):
    with pytest.raises(UnsafeUrlError, match="non-public address"):
        web_audit.assert_public_host(host)


def test_web_audit_stream_refuses_with_error_event(client, no_outbound):
    resp = client.post(
        "/api/tools/web-audit/stream", json={"url": "http://[64:ff9b::a9fe:a9fe]/"}
    )
    assert resp.status_code == 200  # SSE stream carrying an error event
    assert '"type": "error"' in resp.text
    assert "non-public address" in resp.text


def test_tls_stream_refuses_with_error_event(client, no_outbound):
    resp = client.post("/api/tools/tls/stream", json={"host": "224.0.0.1"})
    assert resp.status_code == 200
    assert '"type": "error"' in resp.text
    assert "non-public address" in resp.text


def _addrinfo_for(*ips):
    def _fake(host, port, family=0, type=0, proto=0, flags=0):
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET,
             socket.SOCK_STREAM, 6, "", (ip, 0))
            for ip in ips
        ]

    return _fake


def test_mixed_public_and_private_answers_are_refused(monkeypatch):
    """One private answer among public ones poisons the whole host."""
    monkeypatch.setattr(
        web_audit.socket, "getaddrinfo", _addrinfo_for("93.184.216.34", "10.0.0.5")
    )
    with pytest.raises(UnsafeUrlError):
        web_audit.resolve_public_addresses("mixed.example")


def test_dns_rebinding_second_resolution_private_is_blocked(monkeypatch):
    """Public at check time, private at dial time -> blocked, no dial."""
    answers = iter([("93.184.216.34",), ("169.254.169.254",)])

    def _flaky(host, port, family=0, type=0, proto=0, flags=0):
        return _addrinfo_for(*next(answers))(host, port, family, type, proto, flags)

    dialed = []

    def _record(address, *args, **kwargs):
        dialed.append(address)
        raise OSError("must never get here")

    monkeypatch.setattr(web_audit.socket, "getaddrinfo", _flaky)
    monkeypatch.setattr(web_audit.socket, "create_connection", _record)
    web_audit.assert_public_host("rebind.example")  # first (public) answer passes
    with pytest.raises(UnsafeUrlError):
        web_audit._fetch_guarded("http://rebind.example/")
    assert dialed == []  # the private second answer was never dialled


def test_connection_is_pinned_to_the_validated_address(monkeypatch):
    """The dial targets the validated IP, not the hostname."""
    monkeypatch.setattr(
        web_audit.socket, "getaddrinfo", _addrinfo_for("93.184.216.34")
    )
    dialed = []

    def _record(address, *args, **kwargs):
        dialed.append(address)
        raise OSError("stop after dial")

    monkeypatch.setattr(web_audit.socket, "create_connection", _record)
    with pytest.raises(urllib.error.URLError):
        web_audit._fetch_guarded("http://pinned.example/")
    assert dialed == [("93.184.216.34", 80)]
