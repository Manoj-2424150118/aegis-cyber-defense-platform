"""F-06 — the domain checker must not be a DNS oracle for internal names.

Before this gate, /api/tools/domain resolved any syntactically valid
name with the server's resolver: an internal hostname returned records
(a rich report), a nonexistent one returned an empty report — a clean
existence oracle for the internal namespace. Now a name resolving to a
non-public address is refused with ONE uniform message, while a name
that simply does not resolve keeps its honest empty report.
"""

import socket

from app.modules import domain_checker, web_audit


def _addrinfo_to(ip):
    def _fake(host, port, family=0, type=0, proto=0, flags=0):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    return _fake


def test_domain_resolving_internally_is_refused_uniformly(client, monkeypatch):
    monkeypatch.setattr(web_audit.socket, "getaddrinfo", _addrinfo_to("10.0.0.5"))
    called = []
    monkeypatch.setattr(
        domain_checker, "check_domain", lambda d: called.append(d) or {}
    )
    resp = client.post("/api/tools/domain", json={"domain": "intranet.example.com"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Domain resolution refused."
    assert called == []  # the checker never ran — no records leaked


def test_domain_stream_resolving_internally_is_refused_uniformly(client, monkeypatch):
    monkeypatch.setattr(web_audit.socket, "getaddrinfo", _addrinfo_to("192.168.1.10"))
    resp = client.post(
        "/api/tools/domain/stream", json={"domain": "intranet.example.com"}
    )
    assert resp.status_code == 200  # SSE stream carrying the refusal
    assert '"type": "error"' in resp.text
    assert "Domain resolution refused." in resp.text


def test_unresolvable_domain_keeps_its_honest_empty_report(client, monkeypatch):
    def _nxdomain(host, port, family=0, type=0, proto=0, flags=0):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(web_audit.socket, "getaddrinfo", _nxdomain)
    monkeypatch.setattr(
        domain_checker, "fetch_records",
        lambda d: {"a": [], "aaaa": [], "mx": [], "ns": [], "spf": [],
                   "dmarc": [], "caa": [], "cname": [], "cname_resolves": True,
                   "dkim": [], "rdap_created": None},
    )
    resp = client.post(
        "/api/tools/domain", json={"domain": "no-such-host-xyz.example.com"}
    )
    assert resp.status_code == 200  # the checker's normal empty report


def test_public_domain_passes_the_gate(client, monkeypatch):
    monkeypatch.setattr(web_audit.socket, "getaddrinfo", _addrinfo_to("93.184.216.34"))
    monkeypatch.setattr(
        domain_checker, "fetch_records",
        lambda d: {"a": ["93.184.216.34"], "aaaa": [], "mx": ["10 mail.example.com."],
                   "ns": ["ns1.example.com."], "spf": ["v=spf1 -all"],
                   "dmarc": ["v=DMARC1; p=reject"], "caa": [],
                   "cname": [], "cname_resolves": True, "dkim": [],
                   "rdap_created": None},
    )
    resp = client.post("/api/tools/domain", json={"domain": "example.com"})
    assert resp.status_code == 200
