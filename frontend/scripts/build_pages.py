#!/usr/bin/env python3
"""Prerendered content pages for Aegis (docs/SEO.md).

The app itself is a client-rendered SPA — great for using, poor for
being found. This generator emits real HTML for every tool, guide and
policy at its own crawlable URL (unique title, meta, H1, methodology,
FAQ and structured data), each deep-linking into the live tool in the
app. White-hat by construction: one intent per page, substantive
unique content, no doorway duplication.

Run:  python3 scripts/build_pages.py
Outputs into frontend/public/ (Vite copies public/ into dist/):
  tools/<slug>.html, guides/<slug>.html, pricing.html,
  privacy.html, terms.html, ad-policy.html, refund-policy.html,
  assets/pages.css, sitemap.xml
Commit the outputs; the production build needs no Python.
"""

import html
import json
from datetime import date
from pathlib import Path

SITE = "https://aegis-cyber-defense-platform.onrender.com"
PUBLIC = Path(__file__).resolve().parents[1] / "public"
TODAY = date.today().isoformat()

CSS = """
:root{--bg:#F6F4EF;--surface:#FFFDF8;--ink:#191D1A;--ink2:#49504A;--ink3:#5F665C;
--line:#E2DED2;--accent:#0E7A57;--accent-ink:#0B5C43}
@media (prefers-color-scheme:dark){:root{--bg:#0A0C0B;--surface:#101311;--ink:#EDEBE4;
--ink2:#B9BDB2;--ink3:#9AA294;--line:#232824;--accent:#2FB37F;--accent-ink:#7FD6AE}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font-family:"Geist Sans",system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.65}
.wrap{max-width:46rem;margin:0 auto;padding:0 20px}
header.site{border-bottom:1px solid var(--line);background:var(--surface)}
header.site .wrap{display:flex;align-items:center;gap:10px;padding-top:14px;padding-bottom:14px}
.logo{display:flex;align-items:center;gap:9px;font-weight:650;letter-spacing:-.02em;color:var(--ink);text-decoration:none}
.logo svg{flex:none}
header.site nav{margin-left:auto;display:flex;gap:18px;font-size:.92rem}
header.site nav a{color:var(--ink2);text-decoration:none}
header.site nav a:hover{color:var(--accent-ink)}
main{padding:34px 0 10px}
.kicker{font-family:"Geist Mono",ui-monospace,monospace;font-size:.78rem;letter-spacing:.14em;
text-transform:uppercase;color:var(--accent-ink);margin:0 0 10px}
h1{font-family:"Instrument Serif",Georgia,serif;font-weight:400;font-size:2.35rem;
line-height:1.12;letter-spacing:-.015em;margin:0 0 14px}
h2{font-size:1.28rem;letter-spacing:-.02em;margin:34px 0 10px}
h3{font-size:1.02rem;margin:20px 0 6px}
p,li{color:var(--ink2)}
.lede{font-size:1.13rem;color:var(--ink)}
a{color:var(--accent-ink)}
ul{padding-left:1.15rem}
li{margin:5px 0}
.cta{display:inline-block;background:var(--accent);color:#fff;text-decoration:none;
font-weight:600;padding:12px 22px;border-radius:999px;margin:16px 0 4px}
.cta:hover{filter:brightness(1.07)}
.note{font-size:.9rem;color:var(--ink3)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:6px 20px 14px;margin:18px 0}
details{border-top:1px solid var(--line);padding:11px 0}
details:first-of-type{border-top:none}
summary{cursor:pointer;font-weight:600;color:var(--ink)}
.related{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0 4px}
.related a{border:1px solid var(--line);border-radius:999px;padding:6px 13px;text-decoration:none;
font-size:.9rem;color:var(--ink);background:var(--surface)}
.related a:hover{border-color:var(--accent)}
table{border-collapse:collapse;width:100%;margin:14px 0;font-size:.95rem}
th,td{border:1px solid var(--line);padding:8px 11px;text-align:left;vertical-align:top}
th{background:var(--surface)}
footer.site{border-top:1px solid var(--line);margin-top:44px;padding:22px 0 30px;font-size:.9rem}
footer.site nav{display:flex;flex-wrap:wrap;gap:8px 18px}
footer.site a{color:var(--ink2);text-decoration:none}
footer.site a:hover{color:var(--accent-ink)}
code{font-family:"Geist Mono",ui-monospace,monospace;font-size:.88em}
"""

LOGO = (
    '<svg width="26" height="26" viewBox="0 0 32 32" fill="none" aria-hidden="true">'
    '<path d="M16 2 27 6v8c0 7-4.6 12.4-11 16C9.6 26.4 5 21 5 14V6Z" '
    'stroke="var(--accent)" stroke-width="2.4"/>'
    '<path d="M11.5 21.5 16 10l4.5 11.5M13.2 17.5h5.6" stroke="var(--accent)" '
    'stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def esc(text: str) -> str:
    return html.escape(text, quote=True)


def page(*, path: str, title: str, description: str, kicker: str, h1: str,
         body: str, ldjson: list[dict]) -> str:
    scripts = "\n".join(
        f'<script type="application/ld+json">{json.dumps(obj)}</script>' for obj in ldjson
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{esc(title)}</title>
<meta name="description" content="{esc(description)}" />
<link rel="canonical" href="{SITE}{path}" />
<meta property="og:type" content="website" />
<meta property="og:title" content="{esc(title)}" />
<meta property="og:description" content="{esc(description)}" />
<meta property="og:url" content="{SITE}{path}" />
<meta name="theme-color" content="#0A0C0B" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="stylesheet" href="/assets/pages.css" />
{scripts}
</head>
<body>
<header class="site"><div class="wrap">
<a class="logo" href="/">{LOGO}Aegis</a>
<nav><a href="/#tools">Tools</a><a href="/pricing">Pricing</a><a href="/guides/how-to-check-if-a-link-is-safe">Guides</a></nav>
</div></header>
<main><div class="wrap">
<p class="kicker">{esc(kicker)}</p>
<h1>{esc(h1)}</h1>
{body}
</div></main>
<footer class="site"><div class="wrap">
<nav>
<a href="/">Home</a><a href="/#tools">All tools</a><a href="/pricing">Pricing</a>
<a href="/privacy">Privacy</a><a href="/terms">Terms</a>
<a href="/ad-policy">Ad policy</a><a href="/refund-policy">Refund policy</a>
<a href="/.well-known/security.txt">security.txt</a>
</nav>
<p class="note">Aegis — free personal cyber-defense tools. Checks run without sign-up;
results are guidance, not a guarantee. Last updated {TODAY}.</p>
</div></footer>
</body>
</html>
"""


def tool_ldjson(tool: dict, path: str) -> list[dict]:
    return [
        {
            "@context": "https://schema.org",
            "@type": "WebApplication",
            "name": f"Aegis {tool['name']}",
            "url": SITE + path,
            "applicationCategory": "SecurityApplication",
            "operatingSystem": "Web",
            "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
            "description": tool["description"],
        },
        {
            "@context": "https://schema.org",
            "@type": "FAQPage",
            "mainEntity": [
                {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}}
                for q, a in tool["faq"]
            ],
        },
        {
            "@context": "https://schema.org",
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "Aegis", "item": SITE + "/"},
                {"@type": "ListItem", "position": 2, "name": "Tools", "item": SITE + "/#tools"},
                {"@type": "ListItem", "position": 3, "name": tool["name"], "item": SITE + path},
            ],
        },
    ]


def faq_html(faq: list[tuple[str, str]]) -> str:
    items = "".join(
        f"<details><summary>{esc(q)}</summary><p>{esc(a)}</p></details>" for q, a in faq
    )
    return f'<div class="card"><h2 style="margin-top:12px">Frequently asked questions</h2>{items}</div>'


def tool_body(tool: dict, by_slug: dict) -> str:
    checks = "".join(f"<li>{esc(c)}</li>" for c in tool["checks"])
    results = "".join(f"<li>{esc(r)}</li>" for r in tool["results"])
    related = "".join(
        f'<a href="/tools/{slug}">{esc(by_slug[slug]["name"])}</a>' for slug in tool["related"]
    )
    return f"""
<p class="lede">{esc(tool['lede'])}</p>
<a class="cta" href="/#{tool['anchor']}">Run the free check</a>
<p class="note">Free, no sign-up. Nothing you paste is stored unless you create an account and save it yourself.</p>
<h2>What it checks</h2>
<ul>{checks}</ul>
<h2>How it works</h2>
<p>{esc(tool['method'])}</p>
<h2>What the result means</h2>
<ul>{results}</ul>
{faq_html(tool['faq'])}
<h2>Related tools</h2>
<div class="related">{related}</div>
"""


TOOLS: list[dict] = [
    {
        "slug": "phishing-link-checker", "name": "Phishing Link Checker", "anchor": "tool-url",
        "title": "Free Phishing Link Checker — Is This Link Safe? | Aegis",
        "description": "Check if a link is safe before you click. Free phishing URL checker analysing host tricks, brand impersonation and scam patterns. No sign-up.",
        "lede": "Paste any link — from a text, email, QR code or social post — and Aegis dissects it the way a phishing kit builds it: host tricks, look-alike domains, hidden credentials and lure language, scored and explained in plain words.",
        "checks": [
            "Look-alike and homograph domains, including mixed-script Unicode hosts (a Cyrillic 'а' posing as Latin 'a')",
            "Brand names hidden in paths, subdomains and userinfo ( paypal.com@evil-host style tricks)",
            "Raw IP hosts, embedded username:password credentials, URL shorteners and open redirects",
            "Abuse-prone free hosting and newly abused top-level domains",
            "Double-encoded paths, zero-width characters and other normalisation tricks browsers resolve silently",
            "Phishing and social-engineering lure phrases in the URL itself",
        ],
        "method": "The checker normalises the URL the same way a browser does (Unicode NFKC, zero-width stripping), then applies deterministic detectors — every point in the score traces to a named signal you can read. Scores combine into a 0–100 risk score with a verdict band from safe to malicious, plus a prevention step for anything it flags.",
        "results": [
            "Safe / likely safe — no meaningful signals; still stay alert if the message itself pressured you.",
            "Caution / suspicious — one or more real phishing techniques are present; verify through the official app or site, typed by hand.",
            "Malicious — multiple strong signals agree; do not open it and warn whoever sent it, their account may be compromised.",
        ],
        "faq": [
            ("Is this link checker really free?", "Yes. Anonymous checks are free with a fair daily limit, and creating a free account raises it. The result of a check you run is never locked behind sign-up."),
            ("Do you visit the link to check it?", "The basic check analyses the URL text only — it never fetches the page, so checking a link cannot infect you. The separate Redirect Tracer follows links server-side with an SSRF-guarded fetcher when you ask it to."),
            ("Can a checker guarantee a link is safe?", "No tool can. Aegis explains the evidence it finds; a brand-new phishing domain with no tricks can score low. Treat a clean score as 'no known tricks', not a guarantee."),
        ],
        "related": ["redirect-chain-tracer", "scam-message-checker", "website-security-audit"],
    },
    {
        "slug": "redirect-chain-tracer", "name": "Redirect Chain Tracer", "anchor": "tool-url",
        "title": "Free Redirect Tracer — See Where a Link Really Goes | Aegis",
        "description": "Trace a link's full redirect chain and check the final destination before you visit. Free, SSRF-guarded, with tracker detection. No sign-up.",
        "lede": "Short links and 'you won a prize' URLs rarely land where they claim. The tracer follows every hop — shortener, tracker, open redirect — and scores the page you would actually end up on.",
        "checks": [
            "Every hop in the chain, with status codes and hosts",
            "Click-tracking parameters (40+ known trackers) and the cleaned, tracker-free link",
            "Tracking redirect wrappers used by mail and ad platforms",
            "The final destination, scored with the full phishing-link engine",
            "Chains that bounce through unrelated or newly registered domains",
        ],
        "method": "Aegis fetches the chain from its own servers with a guarded fetcher: every hop is re-validated, private and loopback addresses are refused, and only the redirect metadata is kept. Your browser never touches the suspicious site.",
        "results": [
            "A short, same-brand chain ending on the expected domain is normal for marketing mail.",
            "Long chains crossing unrelated domains, or ending on a look-alike host, are a strong phishing pattern.",
            "The cleaned link is the same destination with trackers stripped — share that one instead.",
        ],
        "faq": [
            ("Is it safe to trace a malicious link?", "Yes — the fetching happens on Aegis servers with SSRF protections, not in your browser. You see the destination without visiting it."),
            ("Why do legitimate emails redirect so much?", "Marketing platforms route clicks through their own domains to measure opens and clicks. The tracer separates that normal tracking from chains that end somewhere unexpected."),
            ("What is an open redirect?", "A trusted site that forwards visitors to any URL given in a parameter. Attackers abuse it so the first hop looks like a brand you trust while the final page is theirs."),
        ],
        "related": ["phishing-link-checker", "email-tracking-pixel-checker", "scam-message-checker"],
    },
    {
        "slug": "email-phishing-checker", "name": "Phishing Email Analyser", "anchor": "tool-email",
        "title": "Free Phishing Email Checker — Is This Email a Scam? | Aegis",
        "description": "Analyse a suspicious email's headers and content for phishing, CEO fraud and BEC: SPF/DKIM alignment, reply-to tricks, payment diversion. Free.",
        "lede": "Paste a full email — headers and body — and Aegis reads it like a mail gateway: authentication results, sender tricks, and the social-engineering patterns behind CEO fraud and invoice scams.",
        "checks": [
            "SPF, DKIM and DMARC results in the headers, and whether they align with the visible sender",
            "From / Reply-To / Return-Path mismatches and Message-ID domain mismatches",
            "CEO-fraud and BEC patterns: wire-transfer urgency, secrecy, gift cards, payroll and bank-detail changes",
            "Login forms embedded in the email body and credential-harvesting language",
            "Missing Received chain and other signs of hand-injected mail",
            "Hidden text, tracking pixels and mismatched link destinations",
        ],
        "method": "The analyser parses the RFC 5322 headers and body locally in the request — nothing is stored. Authentication findings are deterministic (they come from the headers themselves); content findings name the exact phrases and structures that fired, so you can judge the evidence yourself.",
        "results": [
            "Failed or misaligned authentication plus a payment request is the classic BEC combination — verify by phone on a known number.",
            "A clean authentication result does not make an email honest: a compromised real account passes every check. Judge the request, not just the headers.",
            "Urgency plus secrecy ('don't call, just pay') is itself a red flag, whatever the score.",
        ],
        "faq": [
            ("How do I get the full email headers?", "In Gmail: open the message, click the three dots, 'Show original'. In Outlook: File → Properties → Internet headers. Paste the whole thing, headers and body."),
            ("What is CEO fraud / BEC?", "Business email compromise: a message impersonating an executive or supplier that asks for a wire transfer, a bank-detail change, or payroll diversion. It is the costliest email crime category reported to the FBI."),
            ("Is my email stored?", "No. Analysis happens in the request and the content is not saved. Signed-in users can save the result summary to their history — the email itself is never kept."),
        ],
        "related": ["domain-spoofing-check", "email-tracking-pixel-checker", "phishing-link-checker"],
    },
    {
        "slug": "email-tracking-pixel-checker", "name": "Email Tracking Pixel Checker", "anchor": "tool-email",
        "title": "Free Email Tracking Pixel Checker — Is This Email Tracking You? | Aegis",
        "description": "Detect hidden tracking pixels and remote images in an email that report when and where you open it. Free analysis, nothing stored.",
        "lede": "Many marketing and sales emails hide a 1×1 invisible image that phones home the moment you open the message — revealing your time, place and device. Paste an email and see exactly which trackers are inside.",
        "checks": [
            "Invisible 1×1 and off-screen remote images",
            "Known email-tracking services and their per-recipient IDs",
            "Remote images generally — the mechanism every open-tracker relies on",
            "Hidden preheader text and other concealed content",
            "Links whose visible text differs from their real destination",
        ],
        "method": "The analyser parses the email's HTML for remote resources and matches image signatures and hosts against known tracker patterns. It runs on the pasted content only; Aegis never loads the images, so checking cannot trigger the tracker.",
        "results": [
            "A single tracker in a newsletter is common; in a personal-looking sales or 'just checking in' email it means your opens are being watched.",
            "Blocking remote images in your mail app disables nearly all open tracking.",
            "Tracking in a phishing email tells the sender the address is live — one more reason not to open suspicious mail.",
        ],
        "faq": [
            ("Is email tracking legal?", "It varies by jurisdiction and consent; the EU and India's DPDP Act both constrain undisclosed tracking. What matters practically: it is invisible by design, and you can block it."),
            ("How do I stop it?", "Turn off automatic image loading (Gmail: Settings → Images → Ask before displaying; Apple Mail: Privacy Protection), which breaks pixel tracking."),
            ("Does Aegis load the pixel when checking?", "Never. The analysis is purely textual — loading it would defeat the purpose."),
        ],
        "related": ["email-phishing-checker", "redirect-chain-tracer", "domain-spoofing-check"],
    },
    {
        "slug": "malware-file-scanner", "name": "File Malware Scanner", "anchor": "tool-file",
        "title": "Free File Scanner — Check Attachments for Malware Signs | Aegis",
        "description": "Static-triage an attachment for malware signs: macros, embedded scripts, remote templates, archive tricks, EICAR. Free, files never executed or stored.",
        "lede": "Upload a suspicious attachment and Aegis picks it apart without running it: document macros, embedded scripts, remote-template injection, disguised file types and archive attacks — the tricks email malware actually uses.",
        "checks": [
            "Office macros, PDF JavaScript / launch actions / embedded files, and remote-template (attachedTemplate) injection",
            "Real file type versus extension — executables disguised as documents",
            "Archive abuse: path traversal entries, nested and encrypted archives, zip-bomb ratios",
            "Known-bad hashes and the EICAR test signature",
            "Embedded URLs and wallet-address IOCs inside documents",
            "Oversized or malformed structures files use to evade scanners",
        ],
        "method": "Pure static analysis in memory: the file is parsed, never executed, and discarded when the request ends. Findings name the exact structure that fired. This is triage, not a full antivirus engine — a clean result means no known static tricks, not a guarantee.",
        "results": [
            "Any macro, script or remote template in a file you did not expect is reason enough to delete it.",
            "Encrypted archives are a classic scanner-evasion move; legitimate senders rarely use them.",
            "If the file matters, open it in a sandboxed viewer (Google Docs / Office online) rather than a desktop app.",
        ],
        "faq": [
            ("Is my file uploaded and kept?", "It is processed in memory for the analysis and never written to disk or stored. The 10 MB size cap keeps this fast and safe."),
            ("Is this a replacement for antivirus?", "No. It catches the structural tricks of malicious attachments; endpoint antivirus and sandbox detonation catch more. Use it as a fast second opinion."),
            ("Which files can I check?", "Documents (Office, PDF), archives (ZIP and similar), scripts and executables up to 10 MB — anything you might receive as an attachment."),
        ],
        "related": ["email-phishing-checker", "secret-leak-scanner", "password-strength-breach-check"],
    },
    {
        "slug": "password-strength-breach-check", "name": "Password Lab", "anchor": "tool-password",
        "title": "Free Password Strength & Breach Check | Aegis",
        "description": "Test password strength with pattern detection (keyboard walks, sequences, leetspeak) and check breach exposure via k-anonymity. Passwords never leave checks in plain form.",
        "lede": "Two questions decide whether a password survives: could a human pattern-guesser crack it, and has it already leaked? The Lab answers both — strength with real pattern detection, exposure with a privacy-preserving breach lookup.",
        "checks": [
            "Keyboard walks (qwerty, 1qaz2wsx), sequences, repeated chunks and years — the patterns cracking tools try first",
            "Leetspeak dictionary words (P@ssw0rd is still 'password')",
            "True entropy from character pools and length, not just 'has a symbol' theatre",
            "Breach exposure via Have I Been Pwned's k-anonymity API — only the first 5 characters of the SHA-1 hash leave your browser's request",
            "A generator for passphrases and random passwords that pass these same checks",
        ],
        "method": "Strength is scored on structure, not superstition: pattern findings cap the score the way real cracking order would. The breach check uses the k-anonymity model — your password and its full hash are never sent or stored.",
        "results": [
            "Length beats complexity games: a 5-word passphrase outlasts P@ssw0rd2024 by orders of magnitude.",
            "'Breached' means the password exists in public leak corpora — anyone can try it against your accounts. Change it everywhere it was reused.",
            "Every account needs a unique password; a password manager's vault (like the one here) makes that practical.",
        ],
        "faq": [
            ("Is it safe to type my password here?", "The strength check runs against the pasted text only and stores nothing; the breach check sends only a 5-character hash prefix. Still, good practice: test a similar password, not the live one, on any site — including this one."),
            ("How long should a password be?", "At least 14–16 characters for important accounts, or a 5+ word passphrase. Length is the cheapest security there is."),
            ("What is credential stuffing?", "Attackers replay leaked email/password pairs against other sites automatically. Unique passwords per site make a leak survivable."),
        ],
        "related": ["secret-leak-scanner", "malware-file-scanner", "scam-message-checker"],
    },
    {
        "slug": "scam-message-checker", "name": "Scam Message Checker", "anchor": "tool-message",
        "title": "Free Scam Message Checker — SMS, WhatsApp & UPI Scams | Aegis",
        "description": "Check a suspicious SMS, WhatsApp or Telegram message against real scam playbooks: parcel/customs, digital arrest, KYC, OTP bait, family emergency. Free.",
        "lede": "Paste the message that 'the bank', 'customs' or a 'family member in trouble' just sent you. Aegis matches it against the actual playbooks running in India and worldwide — parcel fees, digital arrest, KYC expiry, OTP bait — and shows its working.",
        "checks": [
            "Parcel/customs, digital-arrest and police-impersonation scripts",
            "Family-emergency 'new number' messages, tech-support (AnyDesk/TeamViewer) scams",
            "Fake loan, investment-group and task-earning playbooks, in English and Hinglish",
            "OTP, KYC, account-freeze and prize/lottery bait, plus callback numbers that harvest replies",
            "Links and payment handles inside the message, scored with the link engine",
            "A false-positive guard: a bank's genuine 'never share your OTP' warning scores clean",
        ],
        "method": "Playbook detectors look for the combination of hook, pressure and ask that defines each scam family — not single alarming words. Every finding quotes the pattern it matched, and genuine safety warnings are sentence-filtered before bait is judged.",
        "results": [
            "Any message asking you to share an OTP, install a screen-sharing app, or pay to release a parcel is a scam. Full stop — no legitimate body does this.",
            "'Digital arrest' does not exist: Indian police and courts do not arrest over video call or demand money to clear a case.",
            "For family emergencies, call the person's old number or a relative — never the new number that messaged you.",
        ],
        "faq": [
            ("What should I do if I already responded?", "Stop contact, call your bank's official number to freeze payments, report at cybercrime.gov.in (India) or your national portal, and warn the person being impersonated."),
            ("Does it work for WhatsApp messages?", "Yes — paste the text from any channel: SMS, WhatsApp, Telegram, email or social DMs."),
            ("Why did my bank's real warning score clean?", "Because it should. The checker strips disclaimer sentences ('never share your OTP…') before judging bait — a warning about scams is not a scam."),
        ],
        "related": ["phishing-link-checker", "email-phishing-checker", "password-strength-breach-check"],
    },
    {
        "slug": "domain-spoofing-check", "name": "Domain Security Checker", "anchor": "tool-domain",
        "title": "Free Domain Security Check — SPF, DKIM, DMARC & Spoofing | Aegis",
        "description": "Check whether a domain can be spoofed: SPF, DKIM key strength, DMARC enforcement, dangling CNAMEs and domain age. Free for any domain.",
        "lede": "Can a stranger send email as your domain? Should you trust mail from theirs? This check reads a domain's public DNS posture — the records that decide whether spoofing is trivial or blocked — and grades it.",
        "checks": [
            "SPF presence, syntax and the RFC 7208 ten-lookup limit that silently breaks it",
            "DKIM selectors and key length (weak 1024-bit keys flagged)",
            "DMARC policy strength: none vs quarantine vs reject, partial rollout (pct) and subdomain gaps",
            "Dangling CNAMEs pointing at unclaimed services — a subdomain-takeover risk",
            "MX, CAA and DNSSEC posture, and how recently the domain was registered (RDAP)",
        ],
        "method": "Everything here is public DNS and registry data, queried live. Posture findings carry no risk points against the domain's grade for being absent — the grade reflects how the records are configured, and each finding includes the concrete record to publish or fix.",
        "results": [
            "p=reject DMARC with aligned SPF/DKIM means the domain is genuinely hard to spoof.",
            "No DMARC (or p=none forever) means anyone can send as that domain and most receivers will deliver it.",
            "A domain registered days ago that emails you about payments deserves extreme suspicion.",
        ],
        "faq": [
            ("What is DMARC in one line?", "A DNS record that tells receivers what to do with mail that claims to be from your domain but fails authentication — ignore, quarantine, or reject it."),
            ("My domain has no DKIM result — is it broken?", "The checker probes common selectors; a negative means 'not detected', not 'proven absent'. Check your mail provider's settings for the real selector."),
            ("Can I check a domain I don't own?", "Yes — these are public records. Checking your bank's, employer's or a suspicious sender's domain is a legitimate trust signal."),
        ],
        "related": ["email-phishing-checker", "tls-certificate-checker", "website-security-audit"],
    },
    {
        "slug": "tls-certificate-checker", "name": "TLS Certificate Inspector", "anchor": "tool-tls",
        "title": "Free TLS/SSL Certificate Checker — Expiry, Chain & Weaknesses | Aegis",
        "description": "Inspect a site's TLS certificate: expiry, issuer, hostname match, chain, protocol versions, weak signatures and key sizes. Free.",
        "lede": "The padlock is a claim; this inspector verifies it. For any host, Aegis completes a real TLS handshake and examines the certificate — who issued it, when it expires, whether the chain and algorithms still meet modern baselines.",
        "checks": [
            "Expiry and days remaining, issuer and subject, hostname coverage (SANs)",
            "Signature algorithm (SHA-1/MD5 flagged) and key strength (RSA < 2048, EC < 256 flagged)",
            "Protocol versions offered — TLS 1.0/1.1 are obsolete",
            "Chain completeness and trust-path problems",
            "Certificate transparency and revocation-relevant basics",
        ],
        "method": "A real handshake from Aegis servers, with certificate facts parsed from the DER encoding itself. Detections are facts about the presented certificate, graded against current Mozilla/baseline requirements.",
        "results": [
            "An expired or name-mismatched certificate on a payment page: stop, do not proceed — whatever the site claims.",
            "Weak signatures and small keys are tomorrow's forgery; site owners should reissue on modern profiles.",
            "A valid certificate proves control of the domain, not honesty — phishing sites have padlocks too.",
        ],
        "faq": [
            ("Does a padlock mean a site is safe?", "It means the connection is encrypted to whoever controls that domain. Scam sites get free certificates in minutes — pair this check with the link checker."),
            ("How often should certificates be checked?", "Before expiry, always — automated monitoring matters because a lapsed cert takes a site down and trains users to click through warnings."),
            ("What is TLS 1.3 and should I require it?", "The current protocol version: faster and with obsolete cryptography removed. Supporting 1.2 + 1.3 and disabling 1.0/1.1 is the modern baseline."),
        ],
        "related": ["website-security-audit", "domain-spoofing-check", "phishing-link-checker"],
    },
    {
        "slug": "website-security-audit", "name": "Website Safety Audit", "anchor": "tool-web",
        "title": "Free Website Security Audit — Headers, Cookies & HTTPS Grade | Aegis",
        "description": "Grade a website's security configuration: HTTPS enforcement, security headers, cookie flags and mixed content. Free, one URL.",
        "lede": "For site owners and the cautious alike: enter a URL and get a graded audit of the security configuration browsers actually enforce — HTTPS, HSTS, CSP, cookie flags and the headers that decide how exploitable common bugs are.",
        "checks": [
            "HTTPS availability and redirect enforcement, HSTS presence and strength",
            "Content-Security-Policy, X-Frame-Options / frame-ancestors, nosniff, Referrer-Policy, Permissions-Policy",
            "Cookie flags: Secure, HttpOnly, SameSite on session-like cookies",
            "Mixed content and server/version disclosure headers",
            "Each missing control with the exact header to add",
        ],
        "method": "Aegis fetches the page headers with its guarded fetcher and grades against the same checklist it applies to itself (this site scores itself with the same engine). Findings are configuration facts, each with a copy-pasteable fix.",
        "results": [
            "A-grade configuration does not mean the application has no bugs — it means the browser-level safety nets are all in place.",
            "Missing CSP is the most common gap; it is also the one that turns a small XSS into a full account takeover.",
            "Cookie flags are one-line fixes with outsized effect on session theft.",
        ],
        "faq": [
            ("Can I audit a site I don't own?", "Yes — this reads only the public response headers any browser receives. It is the same information security scanners and the sites' own users can see."),
            ("Why does this site grade itself?", "Aegis eats its own cooking: the platform serves the headers this audit recommends, under a strict CSP with no inline scripts."),
            ("What grade should I aim for?", "A or A− is achievable for most sites in an afternoon of header work; the audit lists fixes in impact order."),
        ],
        "related": ["tls-certificate-checker", "domain-spoofing-check", "phishing-link-checker"],
    },
    {
        "slug": "secret-leak-scanner", "name": "Secret Scanner", "anchor": "tool-secret",
        "title": "Free Secret Scanner — Find Leaked API Keys & Credentials in Text | Aegis",
        "description": "Scan code, configs and logs for exposed secrets: AWS and GitHub keys, database URLs with passwords, JWTs, card numbers. Results are masked — raw secrets never shown or stored.",
        "lede": "One pasted .env, one committed config, one debug log in a ticket — that is how most API keys leak. Paste text here first: the scanner finds provider keys, credential-bearing URLs and seed phrases, and shows you only masked fingerprints of what it found.",
        "checks": [
            "Provider formats: AWS access keys, GitHub tokens, Slack tokens, Stripe keys, SendGrid keys, Google API keys, private-key blocks",
            "Database and service URLs with embedded passwords, and credentials in connection strings",
            "Generic 'key = value' assignments with high-entropy values, filtered against placeholders and examples",
            "JSON Web Tokens, payment card numbers (Luhn-verified), and crypto seed-phrase labels",
            "Multiple independent leaks compound — scored with a noisy-OR model, not simple addition",
        ],
        "method": "Pattern and entropy analysis on the pasted text, in the request only. Output is masked by construction (first 4 + last 2 characters) and the redaction is enforced by tests: a raw secret can never appear in a result. Found something real? Rotate it — deletion is not enough, assume it was copied.",
        "results": [
            "Live keys (production Stripe/AWS/GitHub) are critical: revoke and rotate immediately, then audit their usage logs.",
            "Test keys and examples still matter — they reveal where real ones live and how your configs are shaped.",
            "A clean scan of one file is not a clean repo: scan history (git log) is where old secrets hide.",
        ],
        "faq": [
            ("Is it safe to paste a real secret here?", "The scan runs in-request, stores nothing, and returns masked forms only. The safer habit still: scan before the text leaves your machine, and rotate anything real that you had to paste anywhere."),
            ("What should I do after finding a leaked key?", "Revoke/rotate first, then remove it from the file and history, then check the provider's logs for use. Order matters — history edits do not un-leak a key."),
            ("Does it scan my whole repository?", "This tool checks pasted text (up to 100 KB). For repos, pair it with pre-commit hooks like gitleaks; this scanner is the fast check before you paste, post or commit."),
        ],
        "related": ["password-strength-breach-check", "malware-file-scanner", "website-security-audit"],
    },
]


GUIDES: list[dict] = [
    {
        "slug": "how-to-check-if-a-link-is-safe",
        "title": "How to Check If a Link Is Safe Before You Click | Aegis Guides",
        "description": "A practical method to check if a link is safe: read the real domain, spot look-alikes, trace redirects, and verify through official channels.",
        "kicker": "Guide",
        "h1": "How to check if a link is safe before you click",
        "body": """
<p class="lede">Most phishing succeeds not because the fake page is perfect, but because the link was never really looked at. This is the two-minute method defenders use — no tools required for the first steps, and a free checker for the rest.</p>
<h2>1. Read the domain, right to left</h2>
<p>A URL's identity is its <em>registrable domain</em> — the part immediately before the first single slash. In <code>paypal.com.secure-login.xyz/login</code> the domain is <code>secure-login.xyz</code>; "paypal.com" is just a subdomain decoration. In <code>secure@paypal.com@evil.example/x</code>, everything before the last <code>@</code> is a username, and the real host comes after it. Attackers count on left-to-right reading. Read the host backwards and the tricks fall apart.</p>
<h2>2. Look for look-alike spelling</h2>
<p>Homograph and typosquat domains swap characters: <code>paypa1.com</code> (digit one), <code>rnicrosoft.com</code> (r+n posing as m), or a Cyrillic "а" that renders identically to a Latin "a". If a domain needs squinting, treat it as hostile. Aegis's <a href="/tools/phishing-link-checker">link checker</a> flags mixed-script hosts automatically — the human eye often cannot.</p>
<h2>3. Distrust urgency, not just spelling</h2>
<p>Plenty of phishing uses the real brand's name in the path of an unrelated or free-hosted domain (<code>something.pages.dev/paypal-verify</code>). The message around the link matters as much as the link: account freezes, parcel fees, refunds expiring, a boss who cannot talk — pressure is the payload. Slow down exactly when a message tells you not to.</p>
<h2>4. Preview before you visit</h2>
<p>On phones, long-press a link to see its true destination. For short links, run them through a <a href="/tools/redirect-chain-tracer">redirect tracer</a> so a server — not your browser — follows the chain and shows the final page. Never "just open it to see": modern phishing pages fingerprint and sometimes exploit on load.</p>
<h2>5. Verify out of band</h2>
<p>If the link asks you to log in, pay, or confirm anything, ignore it and go to the service the way you always do — the official app or a domain you type yourself. A legitimate request survives that detour; a phishing page cannot follow you there.</p>
<h2>The 30-second checklist</h2>
<ul>
<li>Registrable domain is exactly the brand's real domain — no extra words, hyphens or strange TLDs.</li>
<li>No IP addresses, no <code>@</code> tricks, no percent-encoded mush in the host.</li>
<li>The message's urgency has a reason that exists outside the message.</li>
<li>Redirects, if any, end on the same domain you expected.</li>
<li>When in doubt: navigate manually. Links are a convenience, not an obligation.</li>
</ul>
<p>Run any link through the <a href="/tools/phishing-link-checker">free phishing link checker</a> for the automated version of this method — every signal named, every point explained.</p>
""",
    },
    {
        "slug": "what-is-dmarc-spf-dkim",
        "title": "What Are DMARC, SPF and DKIM? Email Authentication Explained | Aegis Guides",
        "description": "SPF, DKIM and DMARC explained plainly: what each record does, why alignment matters, and how to check any domain's posture for free.",
        "kicker": "Guide",
        "h1": "What are DMARC, SPF and DKIM?",
        "body": """
<p class="lede">Email was designed without sender identity, and these three DNS records are the retrofit. Together they decide whether a stranger can send mail that claims to be from your domain — the trick behind most CEO fraud.</p>
<h2>SPF: who may send</h2>
<p>A Sender Policy Framework record lists the servers allowed to send for a domain. Receivers compare the sending server's IP against the list. Two limits matter: SPF authenticates the <em>envelope</em> sender (often invisible to you), and it breaks after ten DNS lookups — a limit bloated records silently exceed, voiding the check.</p>
<h2>DKIM: a signature on the message</h2>
<p>DomainKeys Identified Mail signs message headers and body with a private key; receivers verify with the public key published in DNS under a selector (<code>selector._domainkey.domain</code>). A valid signature proves the mail really passed through the domain's infrastructure unmodified. Keys under 2048 bits are below the modern baseline.</p>
<h2>DMARC: the policy that ties them together</h2>
<p>DMARC (Domain-based Message Authentication, Reporting and Conformance) requires that SPF or DKIM <em>align</em> with the domain in the visible From header — the one humans read — and tells receivers what to do on failure: <code>p=none</code> (watch only), <code>p=quarantine</code> (spam folder), or <code>p=reject</code> (refuse delivery). Only enforcement policies actually stop spoofing; <code>p=none</code> forever is a reporting project, not protection. Watch also for <code>pct</code> below 100 (partial rollout) and a weak subdomain policy (<code>sp=</code>), which leave subdomains spoofable.</p>
<h2>Why it matters to you</h2>
<ul>
<li><strong>Receiving:</strong> a sender domain with enforced DMARC is measurably harder to impersonate. Check the domains that email you about money with the <a href="/tools/domain-spoofing-check">domain security checker</a>.</li>
<li><strong>Sending:</strong> without DMARC enforcement, anyone can email your customers, staff or family as you — and you cannot stop them.</li>
<li><strong>Investigating:</strong> in a suspicious email's headers, failed or misaligned authentication plus a payment request is the classic business-email-compromise signature. The <a href="/tools/email-phishing-checker">email analyser</a> reads those results for you.</li>
</ul>
<h2>A sane rollout order</h2>
<p>Inventory your senders → publish SPF and DKIM for each → DMARC at <code>p=none</code> with reporting to learn your traffic → fix stragglers → raise to <code>quarantine</code>, then <code>reject</code>, with <code>pct=100</code> and an explicit subdomain policy. Most small domains finish in a week; the reporting stage is where the surprises live.</p>
""",
    },
    {
        "slug": "how-to-spot-ceo-fraud",
        "title": "How to Spot CEO Fraud and BEC Payment Scams | Aegis Guides",
        "description": "CEO fraud (business email compromise) costs billions yearly. Learn the playbook — urgency, secrecy, payment changes — and the verification habits that stop it.",
        "kicker": "Guide",
        "h1": "How to spot CEO fraud (business email compromise)",
        "body": """
<p class="lede">CEO fraud needs no malware and no broken password. It needs one convincing email, one busy employee, and one wire transfer. It is, by reported losses, the most expensive category of cybercrime — and it is stopped by habits, not software.</p>
<h2>The playbook</h2>
<ul>
<li><strong>The setup:</strong> "I'm in a meeting / travelling — handle this quietly." The impersonated executive is always unavailable for a call, by construction.</li>
<li><strong>The ask:</strong> an urgent wire, a supplier's "new bank details", gift cards for clients, or payroll sent to a changed account. The specific ask varies; the structure does not.</li>
<li><strong>The pressure:</strong> confidentiality plus deadline. Secrecy isolates the victim from the one colleague who would spot it; urgency disables deliberation.</li>
<li><strong>The address:</strong> either a look-alike domain one letter off, a free-mail account with the executive's name, or — worst case — the real mailbox of a compromised supplier. Authentication checks help with the first two and say nothing about the third.</li>
</ul>
<h2>Five verification habits that defeat it</h2>
<ul>
<li><strong>Call a known number.</strong> Any payment instruction or bank-detail change gets confirmed by voice on a number from your records — never one in the email.</li>
<li><strong>Two-person rule.</strong> Payments above a threshold need a second approver who did not receive the request.</li>
<li><strong>Slow is a control.</strong> A same-day exception process is the attack surface. Legitimate urgencies survive a one-hour verification delay.</li>
<li><strong>Read the headers.</strong> Reply-To pointing somewhere unexpected, authentication failures, a first-ever thread with no history — paste the message into the <a href="/tools/email-phishing-checker">email analyser</a> for a structured read.</li>
<li><strong>Check the domain.</strong> A look-alike sending domain registered days ago shows up in the <a href="/tools/domain-spoofing-check">domain checker</a> via RDAP age and missing DMARC.</li>
</ul>
<h2>If the money already moved</h2>
<p>Call the bank immediately — wire recalls are a race measured in hours, and the first day decides most recoveries. Then preserve the emails with full headers, report to your national cybercrime portal (India: cybercrime.gov.in; US: ic3.gov), and notify your insurer if you have one. Silence helps only the fraudster; fast reporting also protects the next target.</p>
""",
    },
]

PRICING_BODY = """
<p class="lede">Start free, stay free for everyday checks. Paid plans — launching soon — will fund monitoring, bulk scanning and API access. Nothing you check is ever locked behind a paywall after the fact.</p>
<table>
<tr><th>Capability</th><th>Anonymous</th><th>Free account</th><th>Pro — launching soon</th></tr>
<tr><td>All ten tools</td><td>Yes</td><td>Yes</td><td>Yes</td></tr>
<tr><td>Checks per day</td><td>10</td><td>50</td><td>Unlimited / bulk</td></tr>
<tr><td>Advertising</td><td>First-party, labelled</td><td>Reduced</td><td>None</td></tr>
<tr><td>Scan history</td><td>—</td><td>30 days</td><td>Unlimited + export</td></tr>
<tr><td>Encrypted vault</td><td>—</td><td>20 items</td><td>Unlimited</td></tr>
<tr><td>Domain monitoring</td><td>—</td><td>1 domain</td><td>10 domains + alerts</td></tr>
<tr><td>API access</td><td>—</td><td>—</td><td>Yes, with keys and rate limits</td></tr>
<tr><td>Support</td><td>Community</td><td>Email</td><td>Priority</td></tr>
</table>
<p>Pro is not on sale yet — no checkout, no pre-orders, no fake countdowns. Create a free account today; when Pro launches, founding accounts will be offered the launch pricing first.</p>
<a class="cta" href="/#tool-vault">Create a free account</a>
<p class="note">See the <a href="/refund-policy">refund policy</a> that will govern paid plans, and the <a href="/ad-policy">ad policy</a> for how free-tier advertising works.</p>
"""

POLICIES: list[dict] = [
    {
        "slug": "privacy", "title": "Privacy Policy | Aegis", "kicker": "Policy",
        "h1": "Privacy policy",
        "body": """
<p class="lede">Aegis is a security tool; its privacy model is part of the product. This page describes what is actually stored, in plain language, and matches the running code.</p>
<h2>Anonymous checks</h2>
<p>Tool inputs (URLs, emails, messages, files, text) are processed in the request and are <strong>not stored</strong>. Files are analysed in memory only. Two aggregate systems keep no content: the public trends feed records only scan type, verdict, score band, finding codes and — for flagged results only — the brand or registrable domain involved; daily fair-use counters store an HMAC hash of the caller identity, never a raw IP address, and self-delete within 48 hours.</p>
<h2>Accounts</h2>
<p>An account stores your email, an Argon2id password hash (never the password), your plan, optional two-factor settings, the scan-history summaries you generate while signed in, and your vault items <strong>as AES-256-GCM ciphertext</strong> encrypted under your master password. The master password is never stored; we cannot read your vault items and cannot recover them for you.</p>
<h2>What we never do</h2>
<ul>
<li>No sale or sharing of personal data, ever. Credentials are not a revenue source.</li>
<li>No third-party advertising or analytics trackers at this time. Any future advertising will be consent-gated and follow the <a href="/ad-policy">ad policy</a>.</li>
<li>No ads or trackers on authenticated or vault pages.</li>
</ul>
<h2>Your rights</h2>
<p>Under India's DPDP Act 2023, the GDPR and similar laws you may access, correct, export or delete your data. Deleting your account removes your history and vault ciphertext. Contact via the repository or security.txt channels; verified requests are actioned within 30 days.</p>
<h2>Security</h2>
<p>Report vulnerabilities via <a href="/.well-known/security.txt">security.txt</a>. Breach notification follows applicable law (including DPDP and GDPR timelines where they apply).</p>
""",
    },
    {
        "slug": "terms", "title": "Terms of Use | Aegis", "kicker": "Policy",
        "h1": "Terms of use",
        "body": """
<p class="lede">By using Aegis you agree to these terms. They are deliberately short.</p>
<h2>The service</h2>
<p>Aegis provides security-checking tools on an as-is basis. Results are heuristic guidance based on the evidence described on each tool page; they are not a guarantee that content is safe or unsafe. You remain responsible for your decisions.</p>
<h2>Acceptable use</h2>
<ul>
<li>Do not use the tools to attack, scan or probe systems you do not own or have permission to test, beyond the public-header and DNS information any browser receives.</li>
<li>Do not abuse the free tier (automated scraping, quota evasion) — use the API when it launches.</li>
<li>Do not upload material you have no right to process. Uploaded files are analysed in memory and discarded.</li>
</ul>
<h2>Accounts and the vault</h2>
<p>You are responsible for your account password and your vault master password. The master password cannot be recovered by design; losing it means losing vault contents. We may suspend accounts that violate these terms.</p>
<h2>Liability</h2>
<p>To the maximum extent permitted by law, Aegis is provided without warranties, and liability is limited to amounts you paid in the preceding three months (for most users, zero).</p>
""",
    },
    {
        "slug": "ad-policy", "title": "Advertising Policy | Aegis", "kicker": "Policy",
        "h1": "Advertising policy",
        "body": """
<p class="lede">Free checks are funded modestly and transparently. These rules bind us, not just advertisers.</p>
<ul>
<li>Every ad slot is reserved in the layout (no content shift) and labelled <strong>Sponsored</strong>.</li>
<li>Currently, slots carry first-party house messages only (our own projects and direct sponsors). Third-party ad networks, if ever added, will load only with your consent, in sandboxed frames, under this same policy.</li>
<li>No deceptive creatives: no fake security warnings, no fake download or scan buttons, no impersonation of system dialogs, no malware — a security product that runs scareware ads has no business existing.</li>
<li>Ads never appear on the vault or other authenticated/private pages, and never adjacent to a security warning in a way that implies endorsement.</li>
<li>Density is capped: at most one slot above the fold and two in-flow per page.</li>
<li>We honour Do Not Track and Global Privacy Control signals for any future personalised advertising; non-personalised is the default.</li>
</ul>
<p>Direct sponsors: security tools with a genuine product (password managers, backup, VPNs) may enquire via the repository contact channels. Revenue from advertising is reported in aggregate; user data is never part of any ad deal.</p>
""",
    },
    {
        "slug": "refund-policy", "title": "Refund Policy | Aegis", "kicker": "Policy",
        "h1": "Refund policy",
        "body": """
<p class="lede">Paid plans are not on sale yet, so no one can currently be charged. This policy is published in advance and will govern Pro from its first day of sale.</p>
<ul>
<li><strong>Cooling-off:</strong> full refund within 7 days of first purchase, no questions asked, via the original payment method.</li>
<li><strong>Renewals:</strong> cancel anytime in settings; access continues to the end of the paid period. Renewal charges are refundable within 48 hours if the plan was unused in the new period.</li>
<li><strong>Our failures:</strong> if a paid feature is withdrawn or the service is down for more than 72 consecutive hours, affected periods are refunded pro-rata on request.</li>
<li><strong>Taxes and invoices:</strong> GST/VAT-compliant invoices are issued for every charge; prices shown at checkout will always include applicable taxes.</li>
<li><strong>Chargebacks:</strong> talk to us first — refunds above are faster than a dispute for both sides.</li>
</ul>
""",
    },
]


def main() -> None:
    tools_dir = PUBLIC / "tools"
    guides_dir = PUBLIC / "guides"
    tools_dir.mkdir(exist_ok=True)
    guides_dir.mkdir(exist_ok=True)
    (PUBLIC / "assets").mkdir(exist_ok=True)
    (PUBLIC / "assets" / "pages.css").write_text(CSS.strip() + "\n")

    by_slug = {t["slug"]: t for t in TOOLS}
    urls = [("/", "1.0", "weekly")]

    for tool in TOOLS:
        path = f"/tools/{tool['slug']}"
        rendered = page(
            path=path, title=tool["title"], description=tool["description"],
            kicker="Free tool", h1=f"{tool['name']}",
            body=tool_body(tool, by_slug), ldjson=tool_ldjson(tool, path),
        )
        (tools_dir / f"{tool['slug']}.html").write_text(rendered)
        urls.append((path, "0.9", "monthly"))

    for guide in GUIDES:
        path = f"/guides/{guide['slug']}"
        rendered = page(
            path=path, title=guide["title"], description=guide["description"],
            kicker=guide["kicker"], h1=guide["h1"], body=guide["body"],
            ldjson=[{
                "@context": "https://schema.org", "@type": "Article",
                "headline": guide["h1"], "description": guide["description"],
                "dateModified": TODAY, "author": {"@type": "Organization", "name": "Aegis"},
            }],
        )
        (guides_dir / f"{guide['slug']}.html").write_text(rendered)
        urls.append((path, "0.8", "monthly"))

    pricing = page(
        path="/pricing", title="Pricing — Free, Account and Pro Plans | Aegis",
        description="Aegis pricing: free anonymous checks, a free account with history and vault, and a Pro plan (launching soon) with monitoring and API access.",
        kicker="Pricing", h1="Pricing", body=PRICING_BODY, ldjson=[],
    )
    (PUBLIC / "pricing.html").write_text(pricing)
    urls.append(("/pricing", "0.7", "monthly"))

    for policy in POLICIES:
        path = f"/{policy['slug']}"
        rendered = page(
            path=path, title=policy["title"],
            description=f"Aegis {policy['h1'].lower()} — plain-language, matching the running product.",
            kicker=policy["kicker"], h1=policy["h1"], body=policy["body"], ldjson=[],
        )
        (PUBLIC / f"{policy['slug']}.html").write_text(rendered)
        urls.append((path, "0.4", "yearly"))

    sitemap = ['<?xml version="1.0" encoding="UTF-8"?>',
               '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for path, priority, freq in urls:
        sitemap += ["  <url>", f"    <loc>{SITE}{path}</loc>",
                    f"    <lastmod>{TODAY}</lastmod>", f"    <changefreq>{freq}</changefreq>",
                    f"    <priority>{priority}</priority>", "  </url>"]
    sitemap.append("</urlset>")
    (PUBLIC / "sitemap.xml").write_text("\n".join(sitemap) + "\n")
    print(f"pages: {len(TOOLS)} tools, {len(GUIDES)} guides, {len(POLICIES)} policies, pricing; sitemap {len(urls)} urls")


if __name__ == "__main__":
    main()
