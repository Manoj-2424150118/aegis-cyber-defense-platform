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
  choice; Footer "Privacy choices" reopens it. Ads never appear on
  vault/authenticated pages.
- External network (built, inert): `GET /api/public/config` reports
  whether the network slot is live. The SPA swaps the house creative
  for the network page only when the owner has set
  `AEGIS_ADS_NETWORK_ENABLED=true` + the slot URL **and** the visitor
  consented to third-party content; the frame stays sandboxed
  (never `allow-same-origin`) and the SPA CSP gains exactly one
  `frame-src` origin — no `'unsafe-inline'`, ever. The wrapper
  template is `frontend/public/ads/network.html`; it loads nothing
  external until the owner hosts it on the ads subdomain with a real
  network account (EthicalAds/Carbon first, per spec §3).

## Billing (built, inert — needs the owner's provider account)
The code is complete and tested; it does nothing until enabled.
- `POST /api/billing/checkout` returns the provider-hosted checkout
  URL from env (Stripe Payment Links / Razorpay Payment Pages), so
  card data never touches this service. Unconfigured cycle → 503.
- `POST /api/billing/webhook/{stripe|razorpay}` verifies the HMAC
  signature (stdlib, timestamp tolerance for Stripe), de-duplicates
  on (provider, event id) in `billing_events` (payload digest only —
  raw bodies are never stored), and maps subscription state onto
  `users.plan` + `plan_period_end`.
- `app/entitlements.py` is the single gate: effective Pro honours the
  paid period end (grace), then falls back to free. Quota, vault cap,
  history window, export, API keys and monitoring all consult it.
Activation checklist (owner only):
1. Choose Stripe (global) or Razorpay (India); complete KYC; create
   the Pro monthly/annual products and hosted checkout pages there.
2. In Render env set `AEGIS_BILLING_ENABLED=true`,
   `AEGIS_BILLING_PROVIDER`, `AEGIS_BILLING_WEBHOOK_SECRET`, the two
   `AEGIS_BILLING_CHECKOUT_URL_*` values and the display prices
   `AEGIS_PRO_PRICE_*_DISPLAY` (never in git).
3. Point the provider's webhook at
   `https://<host>/api/billing/webhook/<provider>`; for Stripe, put
   the Aegis user id in the checkout's `client_reference_id` (or rely
   on customer-id linkage after the first event).
4. GST invoices/refunds run through the provider; refund policy is
   already published.

## Pro entitlements (built)
- **API keys** (`/api/keys`): Pro-only creation, shown once, stored
  as an HMAC under the server secret, revocable, accepted via
  `X-API-Key` anywhere a bearer token is. Listing shows prefixes only.
- **History export** (`GET /api/tools/history/export`): full history
  JSON download for Pro — no 30-day window, no 50-row cap (the DPDP/
  GDPR portability path). Free gets a 403 with the value prop.
- **Domain monitoring** (`/api/monitoring`): free watches 1 domain,
  Pro 10. Checks re-run the Domain Security Checker and flag grade
  changes in-product. Outbound email/push alerts are NOT built — no
  mail infrastructure exists here; adding one is an owner decision.
- **Not built**: team seats (needs an org/tenancy model — owner
  decision), an admin revenue dashboard (needs an admin-role model;
  billing state is fully visible in the provider dashboard meanwhile).

## SEO (live)
Prerendered pages from `frontend/scripts/build_pages.py` (outputs
committed): 11 tool pages, 3 guides, pricing + 4 policies, per-page
title/meta/canonical/JSON-LD, sitemap with 20 URLs. The SPA server
resolves clean URLs to `<route>.html`. See the generator docstring.
