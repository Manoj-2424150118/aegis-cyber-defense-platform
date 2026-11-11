# Detection Engine — v2.0 Design Notes

How Aegis decides what is dangerous, what changed in v2.0, and where
this implementation deliberately deviates from the upgrade spec (and
why). The spec itself lives in the security-audit folder
(`PROMPT-detection-engine-upgrade.md`).

## The reporting layer (new in v2.0)

Every engine result now carries, in addition to its legacy fields
(`findings`, `risk_score`, `verdict`, `grade` — unchanged):

- `signals` — a typed view of the findings: `id` (`engine.code`),
  `category`, `severity` (info/low/medium/high/critical, derived from
  points), `confidence`, `deterministic` (is this a fact or a
  heuristic?), `explain` (the finding text) and a **mandatory**
  `prevention.immediate` (the finding's fix). No finding ships without
  a fix; `fix_for()` has total coverage by construction and the
  fallback text is generic-but-actionable.
- `summary` — one sentence: verdict + strongest evidence.
- `prevention` — the ordered playbook: fixes of the three strongest
  findings, each with its `why` (the finding text).
- `confidence` — how much independent evidence backs the verdict,
  deliberately separate from severity: more independent categories and
  any deterministic signal raise it; a clean result states an honest
  0.55 (absence of evidence, not proof of safety).
- `verdict_band` — the five-band scale (safe / likely_safe / caution /
  suspicious / malicious at 15/40/60/80). The legacy `verdict` values
  are kept for compatibility with the UI and the trends aggregator.
- `meta` — `schema_version: "2.0"`, engine, `duration_ms`,
  `sources_used`, `degraded`, `cached`.

Posture engines (domain, TLS, web audit — whose scores grade *good*
controls, not risk) receive `summary` + `meta` only; forcing risk
severities onto positive findings would mislabel them.

## Scoring models

- The established engines keep their additive point scorers. Those
  scorers are calibrated against behaviour the test suite pins
  (e.g. the canonical phishing sample scores exactly 85), and silently
  re-basing them would invalidate that calibration. Their findings are
  *reported* through the Signal layer, and every v2 detector was added
  inside the existing engine stages so streamed step counts and the
  classic/stream parity contract hold.
- The new Secret Scanner scores natively in the spec's model
  (`detection.score_signals`): noisy-OR combination of
  `weight × confidence` per category, per-category caps (lexical 0.30,
  tracking 0.15, others 0.90–0.98) so one theme cannot stack to 100,
  and a hard rule — a deterministic critical signal floors the score
  at 90.
- Category caps for legacy engines are documented here rather than
  enforced: the additive scorers already weight their strongest
  categories conservatively, and the golden corpus in
  `tests/test_detection_v2.py` now guards the outcomes.

## What v2.0 added per engine

- **URL**: NFKC + zero-width/bidi normalisation before parsing (the
  analysed URL is the one the browser opens); `blob:` dangerous
  scheme; embedded credentials (`user:pass@`) as their own signal;
  raw Unicode hosts and mixed-script (homograph) hosts; free-hosting
  abuse (credential-lure wording on github.io/pages.dev/vercel.app/…);
  double-encoded paths; five more abuse-heavy TLDs.
- **Email**: BEC payroll-diversion module; payment-instruction
  phrases; login forms embedded in the email body; Message-ID domain
  mismatch; missing Received chain.
- **Message**: parcel/customs, family-emergency ("new number"),
  tech-support (AnyDesk/TeamViewer), fake-loan and investment-group
  playbooks; Hinglish bait terms; callback-number signal; and a
  false-positive guard — OTP bait is judged on the text with
  disclaimer sentences removed, so a bank's own "never share your OTP"
  warning no longer flags itself.
- **File**: PDF active-content markers; OOXML remote-template
  injection; archive path-traversal, nested archives and encrypted
  archives; Ethereum-wallet IOCs.
- **Domain**: DKIM selector probing with key-size estimation,
  SPF DNS-lookup count (>10 = PermError per RFC 7208), DMARC
  `pct`/`sp` gaps, dangling-CNAME subdomain-takeover detection, RDAP
  registration age. All are 0-point posture findings — the graded
  rubric is untouched.
- **TLS**: signature algorithm (SHA-1/MD5) and public-key size
  (RSA<2048 / EC<256) checks, parsed from the certificate on both the
  verified and unverified paths; 0-point findings, grades unchanged.
- **Password**: zxcvbn-style pattern detection — keyboard walks,
  ascending/descending sequences, years, leet-normalised dictionary
  words, repeated chunks — as issues, score caps and a `patterns`
  field. Raw-entropy no longer overrates patterned passwords.
- **Secret Scanner (new tool)**: AWS/GitHub/Slack/Stripe/SendGrid/
  Google key formats, private-key blocks, credentialed DB URIs, JWTs,
  URL-embedded passwords, high-entropy `key = value` assignments,
  Luhn-valid card numbers, seed-phrase labels. Output contains masked
  forms only (`AKIA…LE`); redaction is enforced by test. Smart Scan
  routes secret blobs to it.

## Deliberate deviations from the spec

1. **No external reputation APIs** (Safe Browsing / VirusTotal /
   PhishTank). They need API keys and quota on a ₹0-budget free-tier
   deployment; every v2 detector is deterministic and local instead,
   so nothing can degrade because a third party is down. RDAP is the
   one network enrichment added (public, key-free, best-effort).
2. **No QR endpoint** — decoding needs a system barcode library
   (zbar) that the free Docker image doesn't carry; QR payloads that
   arrive as URLs are scored by the URL engine as usual.
3. **SSRF TOCTOU** stays as accepted in the v1.8.1 audit: every
   redirect hop is re-validated against the public-address guard
   before fetching; full IP-pinning is not possible with the stdlib
   HTTPS stack. Documented residual risk, unchanged.
4. **Legacy verdict vocabulary kept** alongside the new five-band
   `verdict_band` field (see above) instead of replacing it.
5. **Landing-page content analysis** is limited to what the existing
   fetch engines already retrieve (headers/TLS); full DOM analysis of
   fetched pages remains future work, as does YARA/ClamAV integration
   for the file engine.

## Evaluation

`tests/test_detection_v2.py` is the standing golden corpus: schema
and prevention-coverage assertions for every engine, the adversarial
URL set (homographs, zero-width, embedded credentials, free-host
lures, double encoding), BEC/message playbooks, the disclaimer
false-positive guard, file-format detectors, secret-scanner redaction
and noisy-OR compounding, password pattern caps, and determinism
(same input → same score and findings). It runs in CI with the rest
of the suite.

## Calibration (phase 11)

The offline engines ship with a labelled golden corpus
(`backend/tests/golden_corpus.json`, 59 samples) and an evaluation
harness (`scripts/eval_detection.py`, also enforced as a pytest
release gate in `tests/test_eval_corpus.py`).

**Measured on the corpus (2026-11-11): precision 1.00, recall 1.00,
false-positive rate 0.00** — gate: recall ≥ 0.90, FPR ≤ 0.05.
Thresholds: score ≥ 40 counts as a positive for URL/message/email/
secret, ≥ 20 for file, and password positives are "flagged weak"
(score < 50). Network engines are excluded — their inputs are live
state, covered by their own unit tests.

Calibration findings that changed the engines (all deliberate,
all covered by tests):

1. **Regional brand domains were false positives.** amazon.in,
   amazon.co.uk, google.co.in scored 35 (`brand-in-host`) because
   each brand mapped to a single official domain. Brands now carry
   their full official domain set.
2. **Single-playbook scams scored below "caution".** A textbook
   digital-arrest or payroll-diversion message scored 20–30.
   Unambiguous playbook signatures now floor at 40 (hard-rule
   floors, §4); `kyc-threat` is excluded because banks send genuine
   KYC reminders.
3. **"Your parcel" was a false-positive machine.** The phrase sat
   in the digital-arrest list and flagged every delivery update.
   Removed; the scam is still caught by its agency vocabulary.
4. **OTP *delivery* looked like OTP *bait*.** A bank's own OTP
   message (code + do-not-share disclaimer, no request) no longer
   triggers `credential-bait`.
