# QA & Security Test Report — Aegis v1.3

**v1.3 addendum (23 Oct 2026):** clean-UI rebuild, Suggested Fix on every finding (remediation layer, fix-presence enforced by tests), and expanded detection (dangerous schemes, obfuscated IPs, executable/archive downloads, open-redirect params, BEC/gift-card language, mshta/rundll32/AMSI-bypass/credential-theft IOCs, EICAR identification, X-Powered-By/CORS/cache-control audit checks). Evidence: **70 pytest passed**; **sandbox battery 32 passed · 0 failed · 1 skipped** (canonical scores unchanged: URL 85, email 100, disguised EXE 40). **Production battery for v1.3: 33 passed · 0 failed · 0 skipped** (live URL). Deployment note: the platform reported the release deploy "Live" while the public URL continued serving v1.2 for ~15 minutes (dashboard showed no rollback, failure or duplicate service; verified from two independent network paths). A follow-up commit forced a fresh deploy, after which v1.3.0 was confirmed live (health version, bundle hash matching the local build, fix fields present in live findings, self-audit 100/A) and the full battery passed. Recorded here because deploy verification is part of QA, not an afterthought.

---

# QA & Security Test Report — Aegis v1.2

**v1.2 addendum (23 Oct 2026):** the Live Agent View release. Every analyser engine was refactored into genuine stages and is now streamed over Server-Sent Events so users watch each check execute. Evidence: **62 pytest tests passed** (incl. 6 new streaming tests asserting event order and *exact result parity* between streamed and classic endpoints — streamed findings multiset == classic findings, same scores 85/100/40); **sandbox battery 32 passed · 0 failed · 1 skipped** (33 checks, incl. 3 new stream checks: 5-step URL stream with result 85, SSRF error event on the audit stream, password stream with merged breach result); UI redesigned (v3 colour system + live console). **Production battery for v1.2: 33 passed · 0 failed · 0 skipped** (live URL, incl. all stream checks and the 100-request deterministic load loop); CI success on the release commit `051e8bd`; live stream verified in production (5 step events + result, score 85).

---

# QA & Security Test Report — Aegis v1.1

**Date:** 23 Oct 2026 · **Version under test:** v1.1 (commits `0d5bce6`, `a404966`)
**Environments:** (1) isolated sandbox — local server, throwaway SQLite DB, production config; (2) production — https://aegis-cyber-defense-platform.onrender.com

## Summary

| Layer | Result |
|---|---|
| Unit + API + security test suite (pytest) | **56 passed**, 84% coverage |
| Lint / SAST | ruff clean · Bandit 0 issues · CodeQL (GitHub) success |
| Dependency audit | pip-audit: **no known vulnerabilities** (was 60 across 4 packages before the v1.1 upgrade) |
| Sandbox QA battery (`scripts/qa_battery.py`) | **29 passed · 0 failed · 1 skipped** (skip = web-audit grade; sandbox DNS maps public hosts to a reserved range, so the SSRF guard correctly refused — verified in production instead) |
| Production QA battery (same script, live URL) | **30 passed · 0 failed · 0 skipped** |
| GitHub Actions CI (backend + frontend + Docker) | success on the release commits |

## Bugs & loopholes found by testing — and fixed

The battery exists to find real defects. It found these; each fix has a regression test:

1. **500 on malformed URLs** — `javascript:alert(1)` and other non-numeric-port URLs crashed the URL analyser (`urlparse().port` raises). Fixed with a guarded port parse + a `malformed-port` finding. *(Found by fuzzing.)*
2. **SSRF in the website-audit module** — the fetcher would request *any* address, including cloud metadata (`169.254.169.254`) and loopback admin panels, and followed redirects unchecked. Fixed: resolve-and-require-public-IP before fetching and on **every redirect hop**. Production-verified: metadata endpoint returns a clean 400 refusal.
3. **Upload DoS** — uploads were buffered whole in memory before the size check; a multi-GB file could OOM the service. Fixed: chunked reads, rejected at exactly the 10 MB cap (413).
4. **User enumeration via timing** — unknown emails answered instantly while real accounts paid an Argon2 verify. Fixed: dummy-hash verify for unknown accounts; identical generic error.
5. **Weak-password registrations** — length alone let `aaaaaaaaaaaa` through. Fixed: repetition-aware scoring cap + registration policy rejecting common/repetitive passwords.
6. **Rate-limit dilution in production** — per-IP auth limits were diluted by the platform's multiple edge proxies. Fixed: additional **per-account** login throttle (10/min) inside the route; production-verified (attempts 11–12 → 429). Sandbox and unit tests cover the per-IP limiter.
7. **Zip entry-count evasion** — archives with >1000 entries now flagged in the file scanner.
8. **Stale dependencies** — 60 known vulnerabilities (PyJWT, cryptography, Starlette, +1). Fixed: full upgrade (FastAPI 0.161, Starlette 1.9, PyJWT 2.15, cryptography 50; React 19, Vite 8, TypeScript 7), all 56 tests re-verified on the new stack, ruff rules pinned in `pyproject.toml` so tooling upgrades can't silently change CI.
9. **Missing hardening headers** — added COOP, CORP, X-Permitted-Cross-Domain-Policies; request IDs + audit logging; global handler returns generic errors (no stack traces — asserted by the battery).
10. **Health-check exemption** — `/health` no longer consumes rate-limit budget (platform health probes stay reliable).

## Battery detail (production run)

- **Functional (14):** health, SPA root, safe URL <20, phishing URL = 85/malicious, common password flagged, generator length, phishing email = 100, clean file clean, disguised EXE ≥40, register → token, vault create/decrypt round-trip, wrong master password → 400, web audit graded (example.com = F, correctly — it ships almost no security headers).
- **Attack (13):** SSRF ×3 + scheme block, SQLi login, forged JWT, oversized upload 413, malformed JSON 422, invalid fields 422, zip payload handled, no stack traces, brute-force → 429, XSS payload inert as JSON.
- **Fuzz:** 46 malformed/hostile inputs across URL + email endpoints — **zero 5xx**.
- **Load:** 100 sequential checks with byte-identical deterministic scores (0 errors); 20 concurrent health checks 20/20.

## Test-network note (transparency)

An early production battery run showed intermittent failures at registration. Root-cause analysis (curl control group: 8/8 registrations = 201; browser verification: all flows pass) traced it to the *test sandbox's egress proxy* truncating Python-urllib chunked responses (`IncompleteRead`), not to the application. The battery transport was switched to curl and the full suite then passed 30/30 in production. The incident is documented here because hiding it would make the report worthless.

## Known residual limits

- Free-tier hosting sleeps when idle (first load ~1 min) and shares CPU; Argon2 operations take ~2s there. Paid tier or a second region removes this; the application code is unchanged.
- Heuristic engines can false-positive/false-negative at the margins — findings are always explained so users can judge. See `SECURITY.md`.
