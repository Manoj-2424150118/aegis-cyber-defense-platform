"""Scam-message analyser — SMS / WhatsApp / chat text.

The email analyser needs headers; most real-world victims only have a
*message*: a WhatsApp forward, an SMS, a Telegram pitch. This engine
scores raw message text for the patterns Indian and global scam
playbooks actually use — digital-arrest threats, KYC/account-block
fear, OTP harvesting, UPI payment redirection, Telegram task scams,
prize/cashback bait and crypto-doubling — and it extracts every link
in the message and re-scores it with the URL engine, so a "safe
sounding" text carrying a malicious link is still caught.
"""

import re

from app.modules.remediation import fix_for
from app.modules.url_analyzer import analyze_url

_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>'\"\)\]]+", re.I)
_BARE_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|in|co|io|xyz|top|click|live|vip|info|site|online|buzz|club|fun|icu|rest|best|work|pro|app|dev|me|tv|cc|biz|us|uk|ru|su|pw|tk|ml|ga|cf|gq|zip|mov)\b(?:/[^\s<>'\"\)\]]*)?",
    re.I,
)
_UPI_RE = re.compile(r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b")

OTP_BAIT = ["otp", "one time password", "share the code", "verification code", "cvv", "atm pin", "your pin", "card number", "net banking password", "internet banking password"]
KYC_THREATS = ["kyc", "account will be blocked", "account blocked", "sim will be blocked", "sim blocked", "pan card", "aadhaar", "aadhar", "account suspended", "debit card blocked", "credit card blocked", "account will be closed", "update your kyc"]
DIGITAL_ARREST = ["digital arrest", "cbi", "customs department", "cyber cell", "money laundering", "arrest warrant", "police case", "court order", "narcotics", "your parcel", "fedex", "trai", "telecom department"]
PRIZE_BAIT = ["you have won", "you've won", "lottery", "prize", "cashback", "lucky draw", "winner", "claim your", "free iphone", "free gift", "reward points expire", "kbc"]
TASK_SCAM = ["telegram", "part time job", "part-time job", "earn per day", "earn daily", "per task", "like and subscribe", "registration fee", "work from home job", "daily income", "₹5000 per day", "rs 5000 per day", "investment plan"]
CRYPTO_BAIT = ["double your money", "guaranteed returns", "guaranteed profit", "crypto investment", "bitcoin investment", "100% profit", "daily profit", "trading tips", "forex trading"]
URGENCY = ["urgent", "immediately", "within 24 hours", "today itself", "last chance", "expires today", "act now", "hurry", "final notice", "right now"]


def _verdict(score: int) -> str:
    if score >= 70:
        return "malicious"
    if score >= 40:
        return "suspicious"
    if score >= 20:
        return "low-risk"
    return "safe"


def extract_links(text: str) -> list[str]:
    """Every link a victim could tap: full URLs, www. links and bare
    domains on plausible TLDs. De-duplicated, order preserved."""
    found: list[str] = []
    for match in _URL_RE.findall(text or ""):
        found.append(match.rstrip(".,;:!?"))
    for match in _BARE_DOMAIN_RE.findall(text or ""):
        candidate = match.rstrip(".,;:!?")
        if not any(candidate in existing or existing.endswith(candidate) for existing in found):
            found.append(candidate)
    return found[:10]


class _MsgContext:
    def __init__(self, text: str):
        self.text = text or ""
        self.lower = self.text.lower()
        self.findings: list[dict] = []
        self.score = 0
        self.links = extract_links(self.text)

    def add(self, points: int, code: str, message: str) -> None:
        self.score += points
        self.findings.append({"points": points, "code": code, "message": message, "fix": fix_for(code)})

    def hits(self, phrases: list[str]) -> list[str]:
        return [p for p in phrases if p in self.lower]


def _stage_links(ctx: _MsgContext) -> None:
    worst = None
    for link in ctx.links:
        report = analyze_url(link)
        if worst is None or report.risk_score > worst.risk_score:
            worst = report
    if worst is not None:
        if worst.risk_score >= 70:
            ctx.add(30, "malicious-link", f"The message carries a link the URL Analyser scores {worst.risk_score}/100 (malicious): {worst.url}")
        elif worst.risk_score >= 40:
            ctx.add(18, "suspicious-link", f"The message carries a link the URL Analyser scores {worst.risk_score}/100 (suspicious): {worst.url}")
        elif ctx.links:
            ctx.add(5, "link-present", f"The message asks you to open a link ({ctx.links[0]}) — unsolicited links are the delivery route for most message scams, even when this one shows no strong signals.")


def _stage_harvest(ctx: _MsgContext) -> None:
    hits = ctx.hits(OTP_BAIT)
    if hits:
        ctx.add(30, "credential-bait", f"The message fishes for secrets ({', '.join(sorted(set(hits)))}) — no bank, company or officer ever asks for an OTP, PIN or CVV by message.")
    upi = _UPI_RE.findall(ctx.text)
    pay_words = ["pay", "send", "transfer", "deposit", "fee", "charge"]
    if upi and any(w in ctx.lower for w in pay_words):
        ctx.add(18, "upi-payment-ask", f"The message directs a payment to UPI ID {upi[0]} — scammers route 'fees' and 'charges' to personal UPI IDs; legitimate organisations collect through their official app/website.")


def _stage_playbooks(ctx: _MsgContext) -> None:
    if ctx.hits(DIGITAL_ARREST):
        ctx.add(25, "digital-arrest", "Digital-arrest / agency-impersonation pattern: Indian police, CBI, TRAI and customs NEVER arrest or interrogate over a call or message, and never demand money to 'clear' a case.")
    if ctx.hits(KYC_THREATS):
        ctx.add(20, "kyc-threat", "KYC / account-block threat: banks never block accounts over SMS/WhatsApp links — KYC is updated inside the bank's own app or branch.")
    task_hits = ctx.hits(TASK_SCAM)
    if task_hits and task_hits != ["telegram"]:  # a bare mention of Telegram is not a scam signal on its own
        ctx.add(20, "task-scam", "Job/task scam pattern (Telegram tasks, per-day earnings, registration fees): real employers never pay for likes/subscriptions and never charge a fee to start work.")
    if ctx.hits(PRIZE_BAIT):
        ctx.add(18, "prize-scam", "Prize/lottery/cashback bait: you cannot win a contest you never entered, and real prizes never require paying a 'processing fee' first.")
    if ctx.hits(CRYPTO_BAIT):
        ctx.add(18, "crypto-doubling", "Guaranteed-return investment pitch: no legitimate investment guarantees profit — 'double your money' and 'daily profit' offers are always fraud.")
    if "gift card" in ctx.lower:
        ctx.add(18, "giftcard-scam", "The message asks for gift cards — no legitimate organisation is ever paid in gift cards.")


def _stage_pressure(ctx: _MsgContext) -> None:
    hits = ctx.hits(URGENCY)
    if len(hits) >= 2:
        ctx.add(10, "urgency-language", f"Manufactured urgency ({', '.join(sorted(set(hits)))}) — pressure is the payload; real institutions give you time and official channels.")


MESSAGE_STAGES = [
    ("Extracting & scoring every link", _stage_links),
    ("Credential & payment harvesting", _stage_harvest),
    ("Known scam playbooks — arrest, KYC, jobs, prizes", _stage_playbooks),
    ("Pressure & urgency tactics", _stage_pressure),
]


def iter_message_stages(text: str):
    ctx = _MsgContext(text)
    for label, stage in MESSAGE_STAGES:
        before = len(ctx.findings)
        stage(ctx)
        yield label, ctx.findings[before:], min(ctx.score, 100)
    return ctx


def analyze_message(text: str) -> dict:
    gen = iter_message_stages(text)
    ctx = None
    while True:
        try:
            next(gen)
        except StopIteration as stop:
            ctx = stop.value
            break
    score = min(ctx.score, 100)
    findings = list(ctx.findings)
    if not findings:
        findings.append({"points": 0, "code": "clean", "message": "No known scam patterns detected in this message.", "fix": fix_for("clean")})
    return {"risk_score": score, "verdict": _verdict(score), "findings": findings, "links_found": ctx.links}
