# Freemium, quotas, ads and staged monetization (v2.1.0)

## Tiers (live)
| | Anonymous | Free account | Pro (data model ready; not on sale) |
|---|---|---|---|
| Tools | all 10 | all 10 | all 10 |
| Scans/day | 10 (`AEGIS_ANON_DAILY_SCAN_LIMIT`) | 50 (`AEGIS_ACCOUNT_DAILY_SCAN_LIMIT`) | unlimited |
| History | — | 30 days (`AEGIS_HISTORY_FREE_DAYS`) | unlimited |
| Vault | — | 20 items (`AEGIS_VAULT_FREE_ITEM_LIMIT`) | unlimited |
| Ads | labelled first-party slots | same slots (homepage only) | none (when launched) |

Results are never gated after the fact — quotas stop *new* checks, and
the 429 message says exactly what an account adds.

## Quota privacy design
Counters live in `scan_quota`, keyed by `HMAC-SHA256(server_secret,
identity)` where identity is `user:<id>` for signed-in calls or
`ip:<edge-ip>:<day>` for anonymous ones (edge IP = CF-Connecting-IP,
else the rate limiter's client IP). Raw IPs are never stored; rows
self-prune after 48h. Note: the CF header is trusted because the
origin sits behind Cloudflare; if the origin is ever exposed directly,
quota evasion by header spoofing is possible — the quota is a fair-use
control, not a security boundary.

## Auth (live)
- Account passwords: Argon2id (64 MB, t=3, p=2), per-user salt; breached
  passwords refused at signup via HIBP k-anonymity (local gates remain
  when HIBP is unreachable).
- Optional TOTP MFA (RFC 6238, stdlib): setup requires the account
  password; activation requires a valid code; login returns a 5-minute
  signed challenge instead of tokens until the code verifies. Disable
  requires password + code. WebAuthn is a planned addition.
- Sessions unchanged from v1.8.1 (in-memory access token, HttpOnly
  refresh cookie, CSRF header).

## Vault crypto — current model & the client-side migration (DECISION PENDING)
Current: the master password is never stored; each item is
AES-256-GCM under an Argon2id key derived per-operation on the server;
the database holds ciphertext + salt only, so DB/admin access yields
nothing readable. Gap vs full zero-knowledge: the server transiently
handles plaintext during add/open.
Target: client-side Argon2id (WASM) + WebCrypto AES-GCM so plaintext
never leaves the browser. Migration path when approved: version the
item format; on each item's next successful open, re-encrypt
client-side and replace the blob; server-format items become read-only
legacy until migrated; announce before switching the default.
This touches real user vault data, so it ships only on the owner's
explicit go-ahead.

## Ads (live infrastructure, no network yet)
- Slots are reserved fixed-height frames labelled "Sponsored", filled
  by first-party creatives served from `/ads/house.html` in a sandboxed
  iframe (no scripts). `/ads/*` responses carry their own CSP
  (`default-src 'none'; style-src 'self'; frame-ancestors 'self';
  sandbox`) and no X-Frame-Options denial.
- Consent: the banner stores a first-party-only / future-third-party
  choice; nothing third-party exists to load today. Footer "Privacy
  choices" reopens it. Ads never appear on vault/authenticated pages.

## Billing (staged — needs the owner's provider account)
Not activated: no checkout exists and the pricing page says so.
Activation checklist when the owner creates the account:
1. Razorpay (India) or Stripe account + KYC; create Pro monthly/annual
   products; put keys in Render env (never in git).
2. Hosted checkout links/buttons on /pricing; webhook endpoint with
   signature verification + idempotency mapping to `users.plan`.
3. GST invoices via the provider; refund policy already published.
4. Entitlement is already server-side (`users.plan`), so activation is
   wiring, not redesign.

## SEO (live)
Prerendered pages from `frontend/scripts/build_pages.py` (outputs
committed): 11 tool pages, 3 guides, pricing + 4 policies, per-page
title/meta/canonical/JSON-LD, sitemap with 20 URLs. The SPA server
resolves clean URLs to `<route>.html`. See the generator docstring.
