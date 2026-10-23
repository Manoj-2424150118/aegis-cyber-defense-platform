# Aegis — Architecture & Threat Model

## 1. Purpose
Protect an *individual* (not an enterprise SOC) from the attacks that actually
compromise individuals: phishing, malicious attachments, credential theft and
reuse, secret leakage, and unsafe websites.

## 2. Threat model (STRIDE, per module)

| Module | Spoofing | Tampering | Info disclosure | DoS | Elevation |
|---|---|---|---|---|---|
| URL Analyser | Detects brand spoofing / homographs | — | Warns on non-HTTPS credential pages | — | — |
| Email Analyser | SPF/DKIM/DMARC + display-name checks | Link destination inspection | Credential-bait detection | — | BEC payment-fraud language |
| File Scanner | Magic-byte vs extension | GCM n/a; hash fingerprints | Embedded IOC / wallet extraction | Zip-bomb detection | Dropper / macro detection |
| Password Lab | — | — | k-anonymity: full hash never sent | — | Offline crack-time honesty |
| Vault | JWT-scoped ownership | AES-GCM tag rejects tampering | Ciphertext-only storage | Item size limits | Argon2id KDF slows brute force |
| Platform | Lockout + generic errors | — | Security headers, no banner | Sliding-window rate limits | Non-root Docker users |

## 3. Key engineering decisions

1. **Detection engines are pure functions.** `url_analyzer`, `file_scanner`,
   `email_analyzer`, `password_lab`, `vault` and the scoring half of
   `web_audit` take values and return values — no DB, no globals. That is why
   32 unit + API tests run in ~5 seconds with no fixtures beyond an in-memory DB.
2. **Explainability over black-box scoring.** Every point in a risk score is a
   named finding with a human message. Security tools users don't understand
   get ignored; recruiters and reviewers can also audit the logic directly.
3. **Zero-knowledge vault.** The master password never reaches the database;
   Argon2id derives the AES-256 key, GCM provides confidentiality *and*
   integrity. Verified by tests for round-trip, wrong-password and bit-flip
   tampering.
4. **Files are never executed or persisted.** The scanner works on the bytes in
   memory, caps size at 10 MB, and caps archive expansion (ratio + total) to
   neutralise zip bombs aimed at the scanner itself.
5. **The platform eats its own cooking.** The website-audit module grades
   HSTS/CSP/cookies — and the API + nginx ship exactly those headers, which an
   API test asserts on every run.
6. **Graceful degradation.** If HIBP is unreachable, the breach check falls
   back to an offline common-password corpus and says so in its response.

## 4. Data flow for a vault item
```
plaintext ──(browser)──▶ API (JWT-authenticated)
   API: salt = random(16); key = Argon2id(master_pw, salt)
        blob = AES-256-GCM(key).encrypt(nonce, plaintext)
        store base64(salt‖nonce‖ct)     ← only this touches the DB
open:  reverse; GCM tag failure ⇒ 400 (wrong password or tampering)
```

## 5. Production deployment notes
- Set `AEGIS_SECRET_KEY` from a secret manager; rotate by invalidating tokens.
- Switch `AEGIS_DATABASE_URL` to PostgreSQL; run behind the provided nginx
  (TLS termination at your load balancer / Cloudflare).
- For multi-replica: replace the in-process rate limiter store with Redis
  (interface is a single `allow(key)` method by design).
- Scale the API horizontally — it is stateless apart from the DB.

## 6. Future architecture
Browser extension → same REST API; enrichment workers (VirusTotal/URLhaus)
behind a queue; WebAuthn for passwordless vault unlock.
