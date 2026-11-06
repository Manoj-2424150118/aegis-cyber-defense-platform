"""Redirect-chain tracer — where does this link actually end up?

Shorteners, tracking wrappers and open redirects all hide the final
destination behind one or more hops. This module follows the chain one
hop at a time — re-running the SSRF guard on *every* hop, because a
public URL that redirects to 169.254.169.254 is still an SSRF attack —
and scores the final destination with the URL engine, so the report
judges the page the victim would really land on.
"""

import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

from app.modules.url_analyzer import analyze_url
from app.modules.web_audit import assert_public_host

MAX_HOPS = 6
TIMEOUT_SECONDS = 6.0
_USER_AGENT = "Mozilla/5.0 (compatible; Aegis-Redirect-Tracer/1.7; +https://aegis-cyber-defense-platform.onrender.com)"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse urllib's automatic following — hops are followed manually
    so each one is SSRF-checked and recorded."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _fetch_status(url: str, method: str) -> tuple[int, str | None]:
    """One request, no redirect following. Returns (status, Location)."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}, method=method)
    try:
        with _OPENER.open(req, timeout=TIMEOUT_SECONDS) as resp:
            return resp.status, resp.headers.get("Location")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Location") if exc.headers else None


def _probe(url: str) -> tuple[int, str | None]:
    status, location = _fetch_status(url, "HEAD")
    if status in (405, 501):  # some servers refuse HEAD — retry as GET
        status, location = _fetch_status(url, "GET")
    return status, location


def trace_redirects(raw_url: str) -> dict:
    url = raw_url.strip()
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https links can be traced.")
    if not parsed.hostname:
        raise ValueError("The link has no host to trace.")

    chain: list[dict] = []
    current = url
    error: str | None = None
    for _ in range(MAX_HOPS + 1):
        host = urlparse(current).hostname or ""
        assert_public_host(host)  # ValueError (UnsafeUrlError) on private targets
        try:
            status, location = _probe(current)
        except Exception as exc:  # unreachable / TLS failure / timeout — a result, not a 500
            error = f"Could not reach {host}: {exc.__class__.__name__}."
            break
        chain.append({"url": current, "status": status})
        if status in (301, 302, 303, 307, 308) and location:
            nxt = urljoin(current, location)
            if urlparse(nxt).scheme not in ("http", "https"):
                error = "The chain tried to redirect to a non-web address and was stopped."
                break
            if len(chain) > MAX_HOPS:
                error = f"Redirect chain exceeded {MAX_HOPS} hops — treated as a redirect loop risk."
                break
            current = nxt
            continue
        break

    final = analyze_url(current)
    hosts = {urlparse(step["url"]).hostname for step in chain}
    return {
        "url": raw_url,
        "final_url": current,
        "hops": max(len(chain) - 1, 0),
        "chain": chain,
        "crossed_domains": len(hosts) > 1,
        "reachable": error is None,
        "error": error,
        "final_risk_score": final.risk_score,
        "final_verdict": final.verdict,
        "final_findings": final.findings,
    }
