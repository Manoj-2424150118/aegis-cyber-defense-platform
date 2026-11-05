"""Suggested fixes for every finding Aegis can raise.

The platform's promise: a report must not just name a problem, it must
tell the reader exactly what to do about it — so nobody needs a second
tool (or a consultant) to act. Fixes are written for the person who
received the report: end users for links/emails/files, site owners for
the website audit.

Keys are finding codes. Parameterised codes are handled with prefix
rules in :func:`fix_for`.
"""
from __future__ import annotations

_USER = "Do not interact with it. "

FIXES: dict[str, str] = {
    # ── URL analyser ────────────────────────────────────────────────
    "unparseable": "Do not visit this address. If it arrived in a message, delete the message and report it as phishing in your mail/SMS app.",
    "no-https": "Do not enter passwords, OTPs or card details on this page — anything you type can be intercepted. Navigate to the service by typing its official address yourself and check for HTTPS there.",
    "malformed-port": "Treat the link as hostile: it is deliberately malformed to slip past filters. Delete the message; do not try variants of the address.",
    "odd-port": "Legitimate public sites use ports 80/443. Do not proceed; open the service from its official app or a bookmark instead.",
    "ip-host": _USER + "Real companies host login pages on their domain, not a bare IP. Close the page and go to the official website/app directly.",
    "punycode": "The domain may be a look-alike using foreign-script characters. Type the real brand address manually instead of following this link.",
    "many-subdomains": "Read the domain right-to-left: the real owner is the last two labels before the TLD. If that isn't the brand you expect, close the page.",
    "suspicious-tld": "This TLD is heavily abused for phishing. Only trust the link if you can independently confirm the sender sent it — call them on a known number.",
    "shortener": "Expand before you tap: paste the short link into a URL-expander, or use this checker on the expanded address. Never log in immediately after a redirect chain.",
    "high-entropy-host": "Random-looking domains are typical of malware delivery. Do not visit; if a device already did, run a full antivirus scan.",
    "hyphen-stuffing": "Extra hyphens are used to pad look-alike domains. Compare the domain letter-by-letter with the official one from the company's own app or card.",
    "brand-in-host": "This is not the brand's real domain. Do not log in. Report the page via the brand's official phishing-report address and delete the message.",
    "typosquat": "The domain is a deliberate near-miss spelling. Type the correct address yourself — never trust links that 'look close enough'.",
    "userinfo-trick": "Everything before the '@' is ignored by browsers — the real destination is what follows it, and it isn't who you think. Do not proceed.",
    "double-slash": "Treat as an obfuscated redirect. Do not follow it; navigate to the service directly.",
    "brand-in-path": "A brand name in the path means nothing — only the domain identifies the owner, and this domain is unrelated. Do not enter credentials.",
    "phish-keywords": "Credential/urgency words in a URL are bait. Slow down: open the official app and check your account status there instead.",
    "very-long": "Long URLs hide the real destination. Copy the domain part only and verify it matches the official service before visiting.",
    "encoded-path": "Heavy encoding hides the payload from filters. Do not visit; delete the message.",
    "dangerous-scheme": "This link uses a script/data scheme that can execute code or render a fake page locally. Never open it; delete the message immediately.",
    "obfuscated-ip": "The host is an IP address disguised as a number (decimal/octal/hex) to dodge blocklists. Treat exactly like a bare-IP phishing link: do not visit.",
    "executable-download": "This link downloads a program. Only ever install software from the vendor's official site or your OS app store — never from a message link.",
    "archive-download": "This link downloads an archive — a common malware wrapper. If you didn't explicitly request it, delete it unopened; if you did, scan the contents with this platform's File Scanner before extracting.",
    "redirect-param": "The link routes through a redirect parameter, so the page you see first is not the final destination. Verify the final domain before entering anything.",
    "clean": "No action needed. Stay alert: a clean heuristic score is not a guarantee — never enter an OTP you didn't initiate.",
    # ── Email analyser ──────────────────────────────────────────────
    "spf-fail": "The sender failed domain authentication — treat the message as forged. Do not reply, click, or download. Report it as phishing and delete it. If it claims to be your bank/employer, contact them via official channels.",
    "dkim-fail": "The message's cryptographic signature failed — it was likely forged or altered in transit. Do not trust its contents; verify any request out-of-band.",
    "dmarc-fail": "The sender domain's own policy says this message should not be trusted. Treat as phishing: report and delete.",
    "spf-missing": "Legitimacy can't be verified from headers alone. Be sceptical of any request: confirm via the sender's official phone number or app before acting.",
    "dkim-missing": "Legitimacy can't be verified from headers alone. Be sceptical of any request: confirm via the sender's official phone number or app before acting.",
    "dmarc-missing": "Legitimacy can't be verified from headers alone. Be sceptical of any request: confirm via the sender's official phone number or app before acting.",
    "reply-to-mismatch": "Your reply would go to a different domain than the sender's — the classic CEO-fraud pattern. Do not reply with data or approvals; forward the email to your IT/security team (or verify by calling the person on a known number).",
    "return-path-mismatch": "The bounce path disagrees with the sender — a spoofing indicator. Verify any request in the message through official channels before acting.",
    "display-name-spoof": "Ignore the friendly display name — trust only the actual address after it. If the domain isn't the organisation's real one, treat the message as impersonation and delete it.",
    "freemail-impersonation": "Real banks and companies don't send official mail from free webmail. Contact the organisation via its official app/website instead of replying.",
    "homograph-domain": "The sender domain uses look-alike characters. Do not click its links; navigate to the organisation's real site yourself.",
    "urgency-pressure": "Pressure is the payload: legitimate organisations don't force instant action. Stop, and check the claim inside the official app — if there were a real problem, it would be visible there.",
    "urgency-language": "Slow down and verify the claim in the official app or by phone before doing anything the message asks.",
    "credential-bait": "No legitimate service ever asks for passwords, PINs, OTPs or card CVVs by email. Never comply. If you already did, change that password immediately, enable MFA, and call your bank.",
    "link-text-mismatch": "The visible link text lies about the destination. Never trust it; hover/long-press links to preview the real URL, and check suspicious ones here first.",
    "malicious-link": "Do not click. Delete the message. If anyone already clicked and entered details, treat the account as compromised: change the password from a clean device and enable MFA.",
    "suspicious-link": "Don't click from the email. Open the service's official app/site directly and check whether the message's claim is even real.",
    "giftcard-scam": "No employer, bank or agency is ever paid in gift cards. Refuse, report the message, and warn the person being impersonated via a separate channel.",
    "bec-wire": "Payment-change and wire requests must always be verified by voice on a previously known number — never using contact details inside the email itself. Escalate to finance/IT before any transfer.",
    # ── File scanner ────────────────────────────────────────────────
    "type-spoofing": "Delete the file — its content is not what its name claims. If it arrived by email/message, report the sender. Do not rename it to 'make it open'.",
    "dangerous-type": "Only run/open this if you requested it from a source you fully trust. When in doubt, delete it and get the file again from the official source.",
    "double-extension": "The real type is the LAST extension — this file is disguised. Delete it; enable 'show file extensions' in your OS so disguises are visible.",
    "high-entropy": "Packed/encrypted content hides its behaviour from scanners. Unless it came from a trusted vendor through an official channel, delete it and run a full antivirus scan if it was ever opened.",
    "macros-present": "Do NOT enable macros/content if prompted. Open documents from unexpected senders in a viewer (or ask the sender for a PDF). If you enabled macros already, disconnect from the network and run a full AV scan.",
    "powershell-dropper": "This file contains a known malware download pattern. Delete it immediately and, if it was executed, isolate the machine and run a full antivirus/EDR scan.",
    "certutil-dropper": "This file abuses a built-in Windows tool to fetch malware. Delete it; if executed, treat the machine as compromised and scan fully.",
    "shell-dropper": "This file downloads and pipes code from the internet — a classic infection chain. Delete it; if executed, isolate and scan the machine.",
    "macro-autoexec": "Auto-running macros are a ransomware delivery mechanism. Delete the document; never enable macros on unexpected files.",
    "base64-pe": "An encoded Windows program is hidden inside this file. Delete it — legitimate documents and images never need to carry one.",
    "mshta-dropper": "This file invokes mshta to run remote code — a known living-off-the-land attack. Delete it and scan the machine if it was opened.",
    "rundll32-dropper": "This file abuses rundll32 to execute payloads. Delete it; if executed, run a full antivirus scan.",
    "amsi-bypass": "This file contains code that tries to blind Windows' antimalware scanning. Delete it and treat any machine that ran it as compromised.",
    "credential-theft": "This file references credential-theft tooling (e.g. Mimikatz). Delete it, and rotate passwords for any account used on a machine where it ran.",
    "embedded-url": "Note the embedded address and check it with the URL Analyser here before any interaction. Treat unexpected embedded links as hostile.",
    "embedded-ip": "Hard-coded IPs in files are typical of command-and-control traffic. Do not run the file; if it ran, scan the machine and review network connections.",
    "crypto-wallet-address": "An embedded wallet address suggests cryptojacking or payment-diversion malware. Delete the file and check your own wallet addresses in any document you reuse.",
    "zip-bomb": "Do NOT extract this archive — it is designed to exhaust disk/resources. Delete it as-is.",
    "excessive-entries": "Do not extract blindly. If the archive is expected, extract in a sandbox/VM and scan the contents with this scanner first.",
    "archive-hides-executable": "Do not run anything inside this archive. Delete it, or extract in a sandbox and scan each file before use.",
    "corrupt-archive": "Delete the file — malformed archives are used to evade scanners. Re-request the document from the sender via a separate channel if it was expected.",
    "eicar-test": "This is the EICAR standard anti-malware test file — a harmless industry test string, not real malware. No action needed; its detection confirms the scanner works.",
    # ── Website audit (for site owners) ─────────────────────────────
    "https": "Keep it: renew certificates before expiry (automate with Let's Encrypt) and redirect all HTTP traffic to HTTPS.",
    "strict-transport-security": "Keep it: ensure max-age is at least 31536000 and consider includeSubDomains + preload once every subdomain is HTTPS-only.",
    "content-security-policy": "Keep it: tighten over time — remove 'unsafe-inline'/'unsafe-eval' by moving scripts/styles to files with nonces or hashes.",
    "x-content-type-options": "Keep it: serve correct Content-Type headers for all assets so nosniff stays effective.",
    "x-frame-options": "Keep it: prefer CSP frame-ancestors (below) as the modern equivalent.",
    "referrer-policy": "Keep it: 'strict-origin-when-cross-origin' or stricter is a good default.",
    "permissions-policy": "Keep it: deny every browser feature the site does not use (camera, microphone, geolocation, payment).",
    "cookies-ok": "Keep it: also rotate session IDs after login and set a short session lifetime.",
    "no-cookies": "No action needed. If you add cookies later, set Secure + HttpOnly + SameSite=Lax (or Strict) from day one.",
    "cookie-flags": "FIX: Set every cookie with the Secure, HttpOnly and SameSite=Lax (or Strict) attributes. In most frameworks this is one config flag — e.g. SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE — then re-test here.",
    "server-version": "FIX: Hide version banners — set `ServerTokens Prod` (Apache) or `server_tokens off;` (nginx), and remove X-Powered-By (PHP: `expose_php = Off`).",
    "x-powered-by": "FIX: Remove the X-Powered-By header — it advertises your stack to attackers. PHP: `expose_php = Off`; Express: `app.disable('x-powered-by')`; or strip it in your reverse proxy.",
    "cors-wildcard": "FIX: `Access-Control-Allow-Origin: *` lets any website read your API responses. Reflect only trusted origins instead, and never combine `*` with credentialed requests.",
    "cache-control": "FIX: Add `Cache-Control: no-store` on pages that handle logins, payments or personal data so browsers don't keep sensitive copies.",
    "unreachable": "Check the site is online and its TLS certificate is valid; if you block bots, allow this audit's user agent (Aegis-Security-Audit) so customers can verify you.",
    # ── Scam-message analyser ───────────────────────────────────────
    "link-present": "Don't tap it inside the message. Open the service's official app or type its address yourself — if the claim in the message is real, it will be visible there.",
    "kyc-threat": "Do not follow any link or number in the message. Banks update KYC only inside their official app/branch. Open your banking app directly and check your account status there; report the message in your SMS/messaging app.",
    "digital-arrest": "Hang up / stop replying immediately. No Indian agency conducts arrests, video interrogations or 'verification payments' over calls or messages. Do not transfer any money; report the number at cybercrime.gov.in or call the national cyber helpline 1930.",
    "prize-scam": "Delete the message. Real winnings never arrive by random SMS/WhatsApp and never require a fee, tax or recharge to release. If a brand is named, check its official app — nothing will be waiting.",
    "task-scam": "Stop and do not pay any 'registration', 'unlock' or 'withdrawal' fee — that fee is the scam, and each payment invents a bigger one. Leave the group/chat and report it; money already sent should be reported at cybercrime.gov.in / 1930 immediately.",
    "crypto-doubling": "Do not send any money or crypto. Guaranteed-profit schemes pay early 'profits' from later victims' deposits and collapse. If you already invested, stop adding funds and report at cybercrime.gov.in.",
    "upi-payment-ask": "Never pay a personal UPI ID for fees, KYC, refunds or 'verification' — refunds and charges never work that way. Pay only inside the official app of the organisation, and verify the payee name shown by your UPI app before any transfer.",
    # ── Domain checker (for domain owners) ──────────────────────────
    "dns-live": "Keep it: monitor DNS uptime and keep at least two nameservers on separate networks.",
    "dns-dead": "FIX: Point the domain's A/AAAA records at your host (or accept that the domain is parked). If the domain should not exist publicly, keep it registered and monitored — an expired domain can be re-registered by attackers.",
    "mx-present": "Keep it: ensure every MX host itself passes this platform's Website Audit and has valid TLS.",
    "mx-missing": "FIX: If the domain sends mail, add MX records for your mail provider. If it never sends mail, publish a null MX (RFC 7505: `0 .`) plus deny-all SPF/DMARC below so forged mail is trivially detectable.",
    "spf-strong": "Keep it: re-check this score after every new sending service is added — a stale SPF that omits a real sender will hard-fail legitimate mail.",
    "spf-soft": "FIX: Once every legitimate sender is in the SPF record, change the ending from ~all (or ?all) to -all so receivers reject forgeries instead of merely flagging them.",
    "spf-multiple": "FIX: Merge all SPF values into ONE TXT record starting with v=spf1 (multiple records invalidate SPF), keeping total DNS lookups under 10.",
    "dmarc-strong": "Keep it: also publish DMARC for every subdomain (sp=reject) and review aggregate reports monthly for new sending services.",
    "dmarc-quarantine": "FIX: When DMARC aggregate reports show all legitimate mail passing, raise the policy from p=quarantine to p=reject for full spoofing protection.",
    "dmarc-monitor": "FIX: Monitor-only DMARC blocks nothing. Review the aggregate reports for 2–4 weeks, fix any legitimate sender that fails, then move to p=quarantine and finally p=reject.",
    "caa-present": "Keep it: add a CAA iodef record too, so attempted mis-issuance is reported to you.",
    "caa-missing": "FIX: Publish a CAA record naming only your certificate authority, e.g. `example.com. CAA 0 issue \"letsencrypt.org\"` (plus `0 iodef \"mailto:security@example.com\"`), so no other CA may issue for your domain.",
    # ── TLS inspector (for site owners) ─────────────────────────────
    "tls-verified": "Keep it: automate renewal (Let's Encrypt / ACME) so the chain never lapses, and monitor expiry with this inspector.",
    "tls-unverified": "FIX: Replace the certificate with one from a public CA (Let's Encrypt is free), serve the FULL chain (leaf + intermediates), and remove any expired/self-signed certificate from the TLS endpoint.",
    "tls-hostname-match": "Keep it: when adding subdomains, extend the certificate's SAN list rather than deploying mismatched certificates.",
    "tls-hostname-mismatch": "FIX: Issue a certificate that actually covers this hostname (add it to the SAN list) — a mismatched certificate triggers browser warnings and destroys trust.",
    "tls-expired": "FIX: Renew the certificate TODAY and automate renewal (ACME clients renew 30 days before expiry). An expired certificate shows every visitor a full-page warning.",
    "tls-expiring-soon": "FIX: Renew now and automate it — ACME/Let's Encrypt renewal takes minutes and prevents an expiry outage.",
    "tls-expiry-ok": "Keep it: calendar a renewal check at 30 days remaining, or automate with ACME so it never becomes urgent.",
    "tls-modern-protocol": "Keep it: disable anything below TLS 1.2 at the server so old clients negotiate up or fail closed.",
    "tls-weak-protocol": "FIX: Disable TLS 1.0/1.1 and SSLv3 at the server (nginx: `ssl_protocols TLSv1.2 TLSv1.3;`) — legacy protocols have known attacks (POODLE, BEAST).",
    "tls-san-present": "Keep it: SANs are the standard — ensure every hostname the site answers on is listed.",
    "tls-no-san": "FIX: Re-issue the certificate with subject-alt-names for every hostname — modern browsers ignore CN-only certificates.",
}

_PREFIX_FIXES = (
    ("missing-", "FIX: Add this response header on every page. Typical values are given in the finding text; on nginx use `add_header`, on Apache `Header set`, or set it in your app framework's security-headers middleware — then re-run this audit."),
)


# A few codes exist in two modules with different audiences: "no-https"
# in a link report advises the *visitor*; in a website-audit report it
# instructs the *site owner*. The audit passes audience="owner".
_OWNER_OVERRIDES: dict[str, str] = {
    "no-https": "FIX: Obtain a free TLS certificate (Let's Encrypt / your host's panel), serve the site over HTTPS, redirect all HTTP to HTTPS, then enable HSTS once stable.",
    # The email analyser uses these codes with end-user advice; the
    # domain checker needs the owner-side remediation instead.
    "spf-missing": "FIX: Publish one TXT record listing every service allowed to send for this domain, e.g. `v=spf1 include:_spf.google.com -all` — adapt the includes to your actual mail providers.",
    "dmarc-missing": "FIX: Publish a DMARC record at _dmarc.yourdomain (start with `v=DMARC1; p=none; rua=mailto:dmarc@yourdomain` to collect reports, then progress to p=reject). Without DMARC your domain can be spoofed by anyone.",
}


def fix_for(code: str, audience: str = "user") -> str:
    if audience == "owner" and code in _OWNER_OVERRIDES:
        return _OWNER_OVERRIDES[code]
    if code in FIXES:
        return FIXES[code]
    for prefix, text in _PREFIX_FIXES:
        if code.startswith(prefix):
            return text
    return "Review the finding, apply the relevant security control, and re-run this check to confirm it is resolved."
