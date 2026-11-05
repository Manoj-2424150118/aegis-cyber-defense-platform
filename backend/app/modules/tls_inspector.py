"""TLS certificate inspector — who vouches for this site, and for how long?

Opens a real TLS handshake to a public host and reports the
certificate as served: issuer, subject, SAN coverage, expiry runway,
protocol version and cipher — then grades it. Hostname verification
is done by the handshake itself when possible; if a certificate fails
verification (expired, self-signed, wrong host) the inspector retries
unverified ONLY to report what was presented, and says so plainly.

The target host passes the same public-address SSRF guard as the
website audit before any connection is made.
"""

import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from app.modules.remediation import fix_for
from app.modules.web_audit import UnsafeUrlError, assert_public_host, grade_for

_TIMEOUT = 6.0


def _rdn_name(rdn_sequence) -> str:
    parts = []
    for rdn in rdn_sequence or ():
        for key, value in rdn:
            if key in ("organizationName", "commonName"):
                parts.append(value)
    return ", ".join(parts) or "unknown"


def _san_dns(cert: dict) -> list[str]:
    return [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]


def _host_matches(host: str, names: list[str]) -> bool:
    host = host.lower()
    for name in names:
        name = name.lower()
        if name == host:
            return True
        if name.startswith("*."):
            suffix = name[1:]
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True
    return False


def _parse_cert_time(value: str) -> datetime:
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def grade_certificate(host: str, cert: dict, protocol: str | None, verified: bool, now: datetime | None = None) -> dict:
    """Pure grading — unit-tested with synthetic certificates."""
    now = now or datetime.now(timezone.utc)
    findings: list[dict] = []
    score = 0

    def add(points: int, code: str, message: str) -> None:
        nonlocal score
        score += points
        findings.append({"points": points, "code": code, "message": message, "fix": fix_for(code, audience="owner")})

    san = _san_dns(cert)
    subject_cn = _rdn_name(cert.get("subject", ()))
    issuer = _rdn_name(cert.get("issuer", ()))
    not_after = _parse_cert_time(cert["notAfter"]) if cert.get("notAfter") else None
    days_left = (not_after - now).days if not_after else None

    if verified:
        add(30, "tls-verified", "The certificate chain verifies against the public trust store — a recognised CA vouches for this site.")
    else:
        add(0, "tls-unverified", "The certificate FAILED verification (expired, self-signed, untrusted chain or wrong host). Browsers will show a warning for this site.")

    names = san or ([subject_cn] if subject_cn != "unknown" else [])
    if _host_matches(host, names):
        add(20, "tls-hostname-match", f"The certificate covers {host} — it was issued for the site you actually visited.")
    else:
        add(0, "tls-hostname-mismatch", f"The certificate does NOT cover {host} (it covers: {', '.join(names[:4]) or 'nothing recognisable'}). It belongs to a different site.")

    if days_left is None:
        add(0, "tls-expired", "The certificate has no readable expiry date — treat it as untrustworthy.")
    elif days_left < 0:
        add(0, "tls-expired", f"The certificate EXPIRED {-days_left} day(s) ago — every visitor is being warned away right now.")
    elif days_left < 15:
        add(8, "tls-expiring-soon", f"The certificate expires in {days_left} day(s) — renew it now; an expiry outage (and warning page) is imminent.")
    elif days_left < 30:
        add(14, "tls-expiring-soon", f"The certificate expires in {days_left} day(s) — renewal should already be scheduled.")
    else:
        add(20, "tls-expiry-ok", f"The certificate is valid for another {days_left} day(s).")

    if protocol in ("TLSv1.2", "TLSv1.3"):
        add(15, "tls-modern-protocol", f"The handshake negotiated {protocol} — a modern, secure protocol version.")
    elif protocol:
        add(0, "tls-weak-protocol", f"The handshake negotiated {protocol} — versions below TLS 1.2 are deprecated and considered insecure.")
    else:
        add(8, "tls-modern-protocol", "Protocol version could not be read from the handshake; chain and hostname checks still apply.")

    if san:
        add(15, "tls-san-present", f"The certificate lists {len(san)} subject-alt-name(s), the modern way to cover hostnames.")
    else:
        add(0, "tls-no-san", "The certificate has no subject-alt-names — modern browsers require SANs; a CN-only certificate is legacy and may be rejected.")

    score = min(score, 100)
    facts = {
        "issuer": issuer,
        "subject": subject_cn,
        "san": san,
        "not_after": cert.get("notAfter"),
        "days_left": days_left,
        "protocol": protocol,
        "verified": verified,
    }
    return {"host": host, "score": score, "grade": grade_for(score), "facts": facts, "findings": findings}


def _name_pairs(name: x509.Name) -> tuple:
    pairs = []
    for oid, key in ((NameOID.ORGANIZATION_NAME, "organizationName"), (NameOID.COMMON_NAME, "commonName")):
        for attr in name.get_attributes_for_oid(oid):
            pairs.append(((key, attr.value),))
    return tuple(pairs)


def _cert_dict_from_der(der: bytes) -> dict:
    """Build the ssl.getpeercert()-shaped dict from a DER certificate.
    Needed for the unverified path: with CERT_NONE, Python's
    getpeercert() returns an empty dict, so the presented certificate
    is parsed with `cryptography` instead."""
    cert = x509.load_der_x509_certificate(der)
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = tuple(("DNS", name) for name in san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san = ()
    return {
        "subject": _name_pairs(cert.subject),
        "issuer": _name_pairs(cert.issuer),
        "subjectAltName": san,
        "notAfter": cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"),
        "notBefore": cert.not_valid_before_utc.strftime("%b %d %H:%M:%S %Y GMT"),
    }


def fetch_certificate(host: str, port: int = 443) -> tuple[dict, str | None, bool]:
    """Handshake with verification first; on verification failure,
    re-handshake unverified to inspect what was presented.
    Returns (cert_dict, protocol, verified)."""
    verified_ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
            with verified_ctx.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(), tls.version(), True
    except ssl.SSLCertVerificationError:
        pass  # fall through to the unverified inspection handshake
    unverified_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified_ctx.check_hostname = False
    unverified_ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=_TIMEOUT) as sock:
        with unverified_ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            return (_cert_dict_from_der(der) if der else {}), tls.version(), False


def inspect_tls(host: str) -> dict:
    """Full inspection. Raises UnsafeUrlError for non-public hosts."""
    assert_public_host(host)
    try:
        cert, protocol, verified = fetch_certificate(host)
    except UnsafeUrlError:
        raise
    except Exception as exc:
        return {
            "host": host, "score": 0, "grade": "F", "reachable": False,
            "facts": {},
            "findings": [{"points": 0, "code": "unreachable",
                          "message": f"Could not complete a TLS handshake with {host}: {exc.__class__.__name__}. The site may be down, not serving HTTPS, or blocking inspections.",
                          "fix": fix_for("unreachable", audience="owner")}],
        }
    report = grade_certificate(host, cert, protocol, verified)
    report["reachable"] = True
    return report
