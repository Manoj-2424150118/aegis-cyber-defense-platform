"""Website security audit — is a site safe to trust with your data?

Fetches a site's response headers and TLS state and grades it on the
controls that stop man-in-the-middle attacks, clickjacking, MIME-sniffing
and XSS: HTTPS + HSTS, Content-Security-Policy, X-Frame-Options /
frame-ancestors, X-Content-Type-Options, Referrer-Policy, cookie flags
(Secure / HttpOnly / SameSite) and server version disclosure.

Only public headers are read; no intrusive probing is performed.
"""

import http.client
import ipaddress
import socket
import ssl
import urllib.request
from urllib.parse import urlparse

from app.modules.remediation import fix_for
from app.validation import is_public_unicast, is_valid_host


class UnsafeUrlError(ValueError):
    """Raised when a URL points at a non-public address (SSRF guard)."""


def resolve_public_addresses(hostname: str) -> list[str]:
    """Resolve ``hostname`` once and return its addresses — but only if
    EVERY resolved address is a genuinely public unicast address
    (``is_public_unicast``). A host answering with one public and one
    private address is an attack, not a partial success.

    Callers must connect to one of the returned addresses, never to the
    name: re-resolving at connect time is the DNS-rebinding (TOCTOU)
    hole this helper exists to close.
    """
    if not hostname:
        raise UnsafeUrlError("URL has no host.")
    if not is_valid_host(hostname):
        # Strict format gate before any DNS work: the audit performs an
        # outbound fetch, so its target must be a well-formed domain or
        # IP literal (see app/validation.py). Underscore hosts, bad
        # octets like 999.1.1.1, and other malformed names stop here.
        raise UnsafeUrlError(f"'{hostname}' is not a valid domain name or IP address.")
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeUrlError(f"Host '{hostname}' does not resolve.") from exc
    addresses: list[str] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not is_public_unicast(ip):
            raise UnsafeUrlError(
                f"Refusing to audit '{hostname}': it resolves to a non-public address ({ip})."
            )
        addresses.append(str(ip))
    if not addresses:
        raise UnsafeUrlError(f"Host '{hostname}' does not resolve.")
    return addresses


def assert_public_host(hostname: str) -> None:
    """Reject loopback / private / link-local / reserved / translated /
    multicast targets.

    Without this, the audit endpoint is a textbook SSRF primitive: anyone
    could make the server fetch cloud metadata (169.254.169.254) or internal
    admin panels. Every hostname is resolved and *every* resulting address
    must pass ``is_public_unicast`` — a bare ``is_global`` test is not
    enough (it accepts NAT64-translated and multicast addresses, F-01).
    Redirect targets are re-checked by the opener below, which closes the
    redirect-to-internal bypass, and connections are pinned to the
    validated addresses (see ``_dial_pinned``).
    """
    resolve_public_addresses(hostname)


def _dial_pinned(host: str, port: int, timeout: float) -> socket.socket:
    """Connect to a validated address for ``host`` — never to the name.

    The guard resolves and validates; the fetch used to resolve AGAIN
    independently, so a short-TTL name could answer public for the check
    and private for the connect (DNS rebinding). Dialing only addresses
    returned by ``resolve_public_addresses`` — which re-validates every
    answer at dial time — removes the second, unchecked resolution.
    Do not "simplify" this back to connecting to the hostname.
    """
    addresses = resolve_public_addresses(host)
    last_exc: OSError | None = None
    for ip in addresses:
        try:
            return socket.create_connection((ip, port), timeout=timeout)
        except OSError as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise UnsafeUrlError(f"Host '{host}' does not resolve.")  # unreachable: addresses is non-empty


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:  # noqa: D102 - see _dial_pinned
        self.sock = _dial_pinned(self.host, self.port, self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self) -> None:  # noqa: D102 - see _dial_pinned
        self.sock = _dial_pinned(self.host, self.port, self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # server_hostname stays the ORIGINAL name, so certificate
        # validation still applies to the real host, not the pinned IP.
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):  # noqa: D102
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):  # noqa: D102
        return self.do_open(_PinnedHTTPSConnection, req, context=self._context)


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = 3

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        if parsed.scheme not in ("http", "https"):
            raise UnsafeUrlError("Redirect to a non-HTTP scheme was blocked.")
        assert_public_host(parsed.hostname or "")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

REQUIRED_HEADERS = {
    "strict-transport-security": (20, "HSTS forces browsers to use HTTPS, blocking downgrade / MITM attacks."),
    "content-security-policy": (20, "CSP is the strongest in-browser defence against XSS and data injection."),
    "x-content-type-options": (10, "Prevents MIME-sniffing attacks that turn uploads into executables."),
    "x-frame-options": (10, "Stops clickjacking by preventing the site being framed by attackers."),
    "referrer-policy": (5, "Controls how much URL information leaks to other sites."),
    "permissions-policy": (5, "Limits browser features (camera, mic, location) the page can abuse."),
}


def grade_for(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "D" if score >= 35 else "F"


def audit_headers(url: str, headers: dict[str, str], cookies: list[str], https: bool) -> dict:
    """Pure scoring function — unit-tested without any network."""
    lower = {k.lower(): v for k, v in headers.items()}
    findings: list[dict] = []
    score = 0
    if https:
        score += 15
        findings.append({"points": 15, "code": "https", "message": "Site is served over HTTPS."})
    else:
        findings.append({"points": 0, "code": "no-https", "message": "Site is NOT using HTTPS — never enter passwords or card details here."})
    for name, (points, why) in REQUIRED_HEADERS.items():
        if name == "x-frame-options" and "frame-ancestors" in lower.get("content-security-policy", ""):
            score += points
            findings.append({"points": points, "code": name, "message": "Clickjacking protection provided via CSP frame-ancestors."})
        elif name in lower:
            score += points
            findings.append({"points": points, "code": name, "message": f"{name} is set. {why}"})
        else:
            findings.append({"points": 0, "code": f"missing-{name}", "message": f"Missing {name}. {why}"})
    cookie_issues = []
    for cookie in cookies:
        c = cookie.lower()
        if "secure" not in c:
            cookie_issues.append("a cookie without the Secure flag")
        if "httponly" not in c:
            cookie_issues.append("a cookie without HttpOnly (readable by scripts — XSS can steal it)")
        if "samesite" not in c:
            cookie_issues.append("a cookie without SameSite (CSRF risk)")
    if not cookies:
        # No cookies = no cookie attack surface (nothing to hijack, steal
        # or abuse for CSRF). That is at least as safe as perfectly-flagged
        # cookies, so the category earns full marks — with the reasoning
        # shown, never silently.
        score += 15
        findings.append({"points": 15, "code": "no-cookies", "message": "No cookies are set — there is no cookie attack surface at all (nothing to hijack, steal, or abuse for CSRF), so this category earns full marks."})
    elif not cookie_issues:
        score += 15
        findings.append({"points": 15, "code": "cookies-ok", "message": "Cookies carry Secure, HttpOnly and SameSite protections."})
    else:
        findings.append({"points": 0, "code": "cookie-flags", "message": "Cookie problems: " + "; ".join(sorted(set(cookie_issues))) + "."})
    if "server" in lower and any(ch.isdigit() for ch in lower["server"]):
        findings.append({"points": 0, "code": "server-version", "message": f"Server banner leaks version details ('{lower['server']}') that help attackers pick exploits."})
    if "x-powered-by" in lower:
        findings.append({"points": 0, "code": "x-powered-by", "message": f"X-Powered-By advertises the stack ('{lower['x-powered-by']}') — free reconnaissance for attackers."})
    if lower.get("access-control-allow-origin", "").strip() == "*":
        findings.append({"points": 0, "code": "cors-wildcard", "message": "CORS allows ANY website to read responses (Access-Control-Allow-Origin: *) — dangerous for APIs holding user data."})
    if https and "cache-control" not in lower:
        findings.append({"points": 0, "code": "cache-control", "message": "No Cache-Control header — browsers and proxies may keep copies of sensitive pages. Add no-store on pages with logins, payments or personal data."})
    score = min(score, 100)
    for f in findings:
        f.setdefault("fix", fix_for(f["code"], audience="owner"))
    return {"url": url, "score": score, "grade": grade_for(score), "findings": findings}


def _fetch_guarded(url: str, timeout: float = 8.0):
    """Fetch ``url`` following only SSRF-safe redirects (guard re-checked
    on every hop by the redirect handler). Returns (final_url, headers,
    cookies). Caller must have validated scheme + host already."""
    # Browser-compatible UA with the scanner identified in the
    # comment field (the Googlebot convention): some sites serve a
    # stripped bot-variant page with most security headers missing,
    # and the audit should grade what a real visitor's browser
    # receives — while still honestly naming the scanner.
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; Aegis-Security-Audit/1.7; +https://aegis-cyber-defense-platform.onrender.com)"},
        method="GET",
    )
    ctx = ssl.create_default_context()
    opener = urllib.request.build_opener(
        # ProxyHandler({}) disables environment proxies on purpose: a
        # proxy would resolve the name itself and defeat IP pinning.
        urllib.request.ProxyHandler({}),
        _GuardedRedirectHandler(), _PinnedHTTPHandler(), _PinnedHTTPSHandler(context=ctx),
    )
    with opener.open(req, timeout=timeout) as resp:  # nosec B310 - scheme + public-IP allowlist enforced by caller + handler; connections pinned to validated addresses
        headers = dict(resp.headers.items())
        cookies = resp.headers.get_all("Set-Cookie") or []
        return resp.geturl(), headers, cookies


def audit_website(raw_url: str, timeout: float = 8.0) -> dict:
    url = raw_url.strip()
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https URLs can be audited.")
    assert_public_host(parsed.hostname or "")
    try:
        final_url, headers, cookies = _fetch_guarded(url, timeout)
    except ValueError:
        raise
    except Exception as exc:
        return {
            "url": raw_url, "score": 0, "grade": "F", "reachable": False,
            "findings": [{"points": 0, "code": "unreachable", "message": f"Could not fetch the site safely: {exc.__class__.__name__}. It may be offline, blocking audits, or using invalid TLS.", "fix": fix_for("unreachable", audience="owner")}],
        }
    result = audit_headers(final_url, headers, cookies, https=final_url.startswith("https://"))
    result["reachable"] = True
    return result
