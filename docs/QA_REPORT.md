# QA & Security Test Report — Aegis v1.6

**v1.6 addendum (24 Oct 2026):** three new public tools (6 → 9) plus tool-hub UX, built to the same standard as the existing engines (staged analysis, live console streaming, a Suggested Fix on every finding — enforced by tests). (1) **Scam Message Checker** (`/api/tools/message`): SMS/WhatsApp text scored for digital-arrest/agency impersonation, KYC threats, OTP harvesting, UPI payment redirection, Telegram task scams, prize bait and crypto-doubling; every link in the message is extracted and re-scored by the URL engine. (2) **Domain Security Checker** (`/api/tools/domain`): live DNS grading — A/AAAA, MX, SPF (multiple-record invalidity, ~all softfail), DMARC strength, CAA — with a pure, network-free grading function (`evaluate_domain`) mirroring the web audit's split; the domain is format-validated before any query. (3) **TLS Certificate Inspector** (`/api/tools/tls`): real handshake behind the shared SSRF guard; grades chain verification, hostname/SAN (wildcard-aware), expiry runway and protocol; verification failures trigger an unverified re-handshake (DER parsed via `cryptography`, since CERT_NONE yields no decoded cert) so broken certificates are reported, not hidden. UX: tool filter with live count, `/` keyboard shortcut to the hero scan box, coverage/nav/proof updated to nine tools everywhere (README + `/api` threat model included). Evidence: **119 pytest passed** (19 new, incl. fix-presence across all three engines and endpoint validation), ruff + bandit clean, build clean, local smoke green (message 43–68 on scam samples, TLS guards 400). Environment note: the build sandbox intercepts DNS (fake 198.18.x answers, port 53 blocked), so the two network engines' *live-record* verification is done against the production deployment, exactly as the web audit was in v1.1–v1.3. **Production verification (24 Oct):** live `/health` 1.6.0, bundle hashes match the local build; from production's real network — domain checker: google.com 87/B (SPF ~all softfail +12, DMARC p=reject +35, CAA +15), github.com 87/B; TLS inspector: this service's own certificate 100/A (Google Trust Services, TLS 1.3, wildcard SAN matched, 57 days left), example.com 100/A; message checker KYC sample 68/suspicious. CI + CodeQL green on the release commits. An interactive browser pass confirmed the nav pill ("Live · v1.6.0"), the "9 live security tools" chip, all three new cards rendering and running cleanly, and the tool filter narrowing/updating its count live (query "password" → "2 of 9": Password Lab + Encrypted Vault, which legitimately matches on its password-manager keywords).

---

# QA & Security Test Report — Aegis v1.5

**v1.5 addendum (24 Oct 2026):** engagement + traffic-readiness release, requested by the owner after reviewing v1.4 ("doesn't look engaging; optimise element orientation like the portfolio; must stay smooth under heavy traffic"). (1) Engagement/orientation: hero now carries a working scan box (paste a link → the URL Checker adopts it and runs, via a window event) with one-tap samples; live platform-status pill in the nav fed by real `/health` data; factual proof chips only (no invented metrics — v1.3's no-vanity-stats rule stands); coverage rebuilt as interactive glass cards; sticky tool pill-nav above the grid; "How it works" 3-step section; FAQ (k-anonymity, file handling, verdict trust) in native `<details>`; scroll-reveal animations, all `prefers-reduced-motion` safe. (2) Traffic/scale: gzip for all non-stream responses (SSE streams explicitly excluded so the live console never buffers); split cache policy — content-hashed `/assets/*` are `public, max-age=31536000, immutable`, the SPA shell is `no-cache` (deploys land instantly), API stays `no-store`; per-IP/per-account rate limiting already in place since v1.1. Evidence: **100 pytest passed** (incl. new `test_perf.py` pinning the cache split, gzip, and SSE-never-gzipped), build clean, local smoke: `/health` 1.5.0, asset `Cache-Control: immutable`, gzip `Content-Encoding` present, new UI present in the bundle. **Production verification (24 Oct):** live `/health` 1.5.0 with bundle hashes matching the local build (`index-0mbXon41.js` / `index-DLJgAKEy.css`); cache + gzip headers confirmed on the real URL; self-audit still 100/A; an interactive browser pass confirmed the nav pill reads "Live · v1.5.0", the hero sample chip fills the checker, auto-scrolls, runs the live console (5/5 stages) and lands on **Malicious · 85/100** with Suggested fixes, and the coverage cards, sticky tool nav, How-it-works and expanding FAQ all render cleanly.

---

# QA & Security Test Report — Aegis v1.4

**v1.4 addendum (24 Oct 2026):** link-preview + resilience + validation release. (1) Open Graph / Twitter Card meta in `index.html` with a generated 1200×630 `og-preview-card.png` served from `/assets/`; (2) cyber-obsidian palette (`#030712` background, `#00F0FF` telemetry highlights, `#EF4444` danger), glassmorphism cards, and one fluid `cubic-bezier(0.16, 1, 0.3, 1)` motion curve across cards, panels, buttons and inputs, with monospace telemetry tokens and `prefers-reduced-motion` respected; (3) frontend fetch layer now has AbortController timeouts (20s requests, 75s stream-connect) and a single cold-start retry on network failure / 502–504 with a friendly "server waking up" error — state-changing calls (register, vault writes) never auto-retry; (4) strict domain/IP format validation (`app/validation.py`, mirrored in `frontend/src/api.ts`): domain labels per RFC-style regex, IPv4 octet range checked, enforced server-side on the outbound web-audit lookup before DNS, plus a whitespace/control-character rejection on URL request schemas. The URL analyser still scores malformed links instead of rejecting them (regression-pinned). Evidence: **96 pytest passed** (incl. new `test_validation.py`), frontend `tsc + vite build` clean, local single-service smoke: `/health` 1.4.0, OG image 200, bad-host audit 400, whitespace URL 422, `javascript:` URL still scored 200. **Production verification (24 Oct, ~2 min after push):** live `/health` reports 1.4.0 and the served CSS bundle hash matches the local build (`index-3SgHHxpt.css`, 26 cubic-bezier rules, `#030712`/`#00f0ff`/`#ef4444` tokens present); live index carries the new title + 8 `og:` tags + Twitter card; `/assets/og-preview-card.png` returns 200 image/png; canonical phishing URL still scores 85/malicious; bad-host audit 400 and whitespace URL 422 confirmed live; self-audit 100/A; hardening headers intact.

---

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
