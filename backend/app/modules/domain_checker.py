"""Domain & email-security checker — can this domain be impersonated?

Looks up the DNS records that decide whether anyone on the internet
can send mail *as* a domain and whether its DNS is professionally run:
A/AAAA liveness, MX, SPF, DMARC (the anti-spoofing policy), and CAA
(which certificate authorities may issue for the domain).

Scoring is split from fetching (``evaluate_domain`` is a pure function
of the record set) so the rubric is unit-tested without any network.
"""

import dns.exception
import dns.resolver

from app.modules.remediation import fix_for
from app.modules.web_audit import grade_for

_TIMEOUT = 5.0


def _resolve(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> list[str]:
    try:
        answers = resolver.resolve(name, rdtype, lifetime=_TIMEOUT)
        return [rdata.to_text().strip().strip('"') for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.exception.DNSException):
        return []


def fetch_records(domain: str) -> dict:
    """All DNS lookups for the checker. Only DNS queries are made —
    the domain is format-validated by the caller, and DNS itself
    cannot be used to reach internal services."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _TIMEOUT
    txt = _resolve(resolver, domain, "TXT")
    dmarc_txt = _resolve(resolver, f"_dmarc.{domain}", "TXT")
    return {
        "a": _resolve(resolver, domain, "A"),
        "aaaa": _resolve(resolver, domain, "AAAA"),
        "mx": _resolve(resolver, domain, "MX"),
        "ns": _resolve(resolver, domain, "NS"),
        "spf": [t for t in txt if t.lower().startswith("v=spf1")],
        "dmarc": [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")],
        "caa": _resolve(resolver, domain, "CAA"),
    }


class _DomainContext:
    def __init__(self, domain: str, records: dict):
        self.domain = domain
        self.records = records
        self.findings: list[dict] = []
        self.score = 0

    def add(self, points: int, code: str, message: str) -> None:
        self.score += points
        self.findings.append({"points": points, "code": code, "message": message, "fix": fix_for(code, audience="owner")})


def _stage_dns(ctx: _DomainContext) -> None:
    r = ctx.records
    if r["a"] or r["aaaa"]:
        ctx.add(10, "dns-live", f"The domain resolves ({len(r['a']) + len(r['aaaa'])} address record(s)) and has {len(r['ns'])} nameserver(s).")
    else:
        ctx.add(0, "dns-dead", "The domain does not resolve to any address — it is parked, misconfigured, or does not exist.")
    if r["mx"]:
        ctx.add(15, "mx-present", f"Mail servers are configured ({len(r['mx'])} MX record(s)) — the domain can receive email.")
    else:
        ctx.add(0, "mx-missing", "No MX records — the domain cannot receive email. Any 'mail from' this domain deserves extra suspicion, and replies to it go nowhere.")


def _stage_spf(ctx: _DomainContext) -> None:
    spf = ctx.records["spf"]
    if len(spf) > 1:
        ctx.add(0, "spf-multiple", "Multiple SPF records published — that is invalid (RFC 7208): receivers may ignore SPF entirely, leaving the domain spoofable.")
        return
    if not spf:
        ctx.add(0, "spf-missing", "No SPF record — nothing tells receivers which servers may send mail for this domain, so forged mail is harder to filter.")
        return
    record = spf[0].lower()
    if record.rstrip().endswith("-all"):
        ctx.add(25, "spf-strong", "SPF is published with a hard fail (-all): receivers are told to reject mail from unauthorised servers.")
    elif record.rstrip().endswith("~all"):
        ctx.add(12, "spf-soft", "SPF is published but ends in ~all (softfail): forgeries are only flagged, not rejected. Tighten to -all once the sender list is complete.")
    else:
        ctx.add(6, "spf-soft", "SPF is published but has no -all/~all enforcement ending, so it barely constrains forgers.")


def _stage_dmarc(ctx: _DomainContext) -> None:
    dmarc = ctx.records["dmarc"]
    if not dmarc:
        ctx.add(0, "dmarc-missing", "No DMARC record — the domain has NO anti-spoofing policy. Anyone can send mail that appears to come from this domain and most receivers will deliver it. This is the single biggest gap.")
        return
    record = dmarc[0].lower()
    if "p=reject" in record:
        ctx.add(35, "dmarc-strong", "DMARC is enforced at p=reject: unauthenticated mail using this domain is rejected by compliant receivers. This is the gold standard.")
    elif "p=quarantine" in record:
        ctx.add(24, "dmarc-quarantine", "DMARC is at p=quarantine: unauthenticated mail is sent to spam rather than rejected. Move to p=reject once reporting shows no legitimate senders break.")
    else:
        ctx.add(10, "dmarc-monitor", "DMARC exists but is monitor-only (p=none): it collects reports yet blocks nothing. Spoofed mail is still delivered — progress to p=quarantine, then p=reject.")


def _stage_caa(ctx: _DomainContext) -> None:
    if ctx.records["caa"]:
        ctx.add(15, "caa-present", "CAA records restrict which certificate authorities may issue certificates for this domain — a real control against mis-issuance.")
    else:
        ctx.add(0, "caa-missing", "No CAA record — any certificate authority may issue a certificate for this domain. Publishing CAA limits issuance to your chosen CA.")


DOMAIN_STAGES = [
    ("DNS liveness & mail routing", _stage_dns),
    ("SPF — who may send for this domain", _stage_spf),
    ("DMARC — the anti-spoofing policy", _stage_dmarc),
    ("CAA — certificate issuance control", _stage_caa),
]


def iter_domain_stages(domain: str, records: dict):
    ctx = _DomainContext(domain, records)
    for label, stage in DOMAIN_STAGES:
        before = len(ctx.findings)
        stage(ctx)
        yield label, ctx.findings[before:], min(ctx.score, 100)
    return ctx


def evaluate_domain(domain: str, records: dict) -> dict:
    gen = iter_domain_stages(domain, records)
    ctx = None
    while True:
        try:
            next(gen)
        except StopIteration as stop:
            ctx = stop.value
            break
    score = min(ctx.score, 100)
    return {"domain": domain, "score": score, "grade": grade_for(score), "findings": ctx.findings}


def check_domain(domain: str) -> dict:
    return evaluate_domain(domain, fetch_records(domain))
