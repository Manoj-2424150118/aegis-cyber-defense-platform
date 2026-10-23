# Security Policy

## Reporting a vulnerability
Please report vulnerabilities privately via GitHub Security Advisories
("Report a vulnerability" on the Security tab) rather than a public issue.
You should receive an acknowledgement within 72 hours.

## Security design summary
- Passwords are hashed with **Argon2id**; vault items are encrypted with
  **AES-256-GCM** under an Argon2id-derived key. Plaintext secrets are never stored.
- Breach checks use the HIBP **k-anonymity** protocol — full passwords never leave the client machine.
- Uploaded files are analysed **in memory only** and are never executed or written to disk.
- Accounts lock after 5 failed logins; auth routes are rate-limited; every response
  carries a strict set of security headers; CORS is an explicit allowlist.
- CI runs Bandit, CodeQL, Dependabot and `npm audit` on every change.

## Known limitations (honest scope)
- Static file analysis can be evaded by novel packers; Aegis is a first line of defence, not an AV replacement.
- The in-process rate limiter is per-instance; multi-replica production should use Redis (see `backend/app/rate_limit.py`).
- Heuristic URL scoring can false-positive on legitimate marketing links — findings are always explained so users can judge.
