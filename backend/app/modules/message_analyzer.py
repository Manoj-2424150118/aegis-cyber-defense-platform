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

from app.modules.detection import enrich
from app.modules.remediation import fix_for
from app.modules.url_analyzer import analyze_url

_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>'\"\)\]]+", re.I)
_BARE_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|in|co|io|xyz|top|click|live|vip|info|site|online|buzz|club|fun|icu|rest|best|work|pro|app|dev|me|tv|cc|biz|us|uk|ru|su|pw|tk|ml|ga|cf|gq|zip|mov)\b(?:/[^\s<>'\"\)\]]*)?",
    re.I,
)
_UPI_RE = re.compile(r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b")

OTP_BAIT = ["otp", "one time password", "share the code", "verification code", "cvv", "atm pin", "your pin", "card number", "net banking password", "internet banking password", "otp batao", "otp share karo"]
# Protective wording banks themselves print — an OTP *mention* inside a
# disclaimer is a safety feature, not bait. Only an actual request for
# the code (or bait with no disclaimer anywhere) is scored.
OTP_REQUEST = ["share your otp", "share the otp", "send the otp", "send otp", "otp batao",
               "tell me the otp", "enter your otp", "provide the otp", "share otp",
               "share the code", "share your cvv", "send the code", "enter the code",
               "your otp is", "otp share karo", "share the verification"]
OTP_DISCLAIMER = ["never share", "do not share", "don't share", "never asks", "never ask for",
                  "bank never", "we never", "do not disclose", "never reveal"]
KYC_THREATS = ["kyc", "account will be blocked", "account blocked", "sim will be blocked", "sim blocked", "pan card", "aadhaar", "aadhar", "account suspended", "debit card blocked", "credit card blocked", "account will be closed", "update your kyc", "account band ho jayega", "band ho jayega", "kyc update karo", "khata band"]
# NOTE: bare "your parcel" / "fedex" were removed from this list in
# the phase-11 calibration: every genuine delivery notification says
# "your parcel", which made the phrase a false-positive machine. The
# arrest scam is still caught by its agency/threat vocabulary, and
# parcel-fee lures by PARCEL_SCAM below.
DIGITAL_ARREST = ["digital arrest", "cbi", "customs department", "cyber cell", "money laundering", "arrest warrant", "police case", "court order", "narcotics", "trai", "telecom department"]
PRIZE_BAIT = ["you have won", "you've won", "lottery", "prize", "cashback", "lucky draw", "winner", "claim your", "free iphone", "free gift", "reward points expire", "kbc", "inaam", "jeet gaye hain"]
TASK_SCAM = ["telegram", "part time job", "part-time job", "earn per day", "earn daily", "per task", "like and subscribe", "registration fee", "work from home job", "daily income", "₹5000 per day", "rs 5000 per day", "investment plan"]
CRYPTO_BAIT = ["double your money", "guaranteed returns", "guaranteed profit", "crypto investment", "bitcoin investment", "100% profit", "daily profit", "trading tips", "forex trading"]
URGENCY = ["urgent", "immediately", "within 24 hours", "today itself", "last chance", "expires today", "act now", "hurry", "final notice", "right now", "turant", "abhi karo"]


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
    # Judge bait on the text with disclaimer sentences removed: a
    # bank's own "never share your OTP" warning contains the bait
    # phrases as substrings, so raw substring matching flags the very
    # messages that protect people.
    kept = [sent for sent in re.split(r"[.!?\n]", ctx.lower)
            if not any(d in sent for d in OTP_DISCLAIMER)]
    cleaned = " ".join(kept)
    hits = [p for p in OTP_BAIT if p in cleaned]
    # OTP *delivery* is not bait: a genuine bank message contains the
    # code plus a do-not-share disclaimer and asks for nothing. When
    # the whole message is that shape (code present, disclaimer
    # present, no request verb surviving in the kept text), the bait
    # phrases are the bank's own wording — do not score them.
    delivery_shape = (
        any(d in ctx.lower for d in OTP_DISCLAIMER)
        and re.search(r"\b\d{4,8}\b", ctx.text)
        and not any(v in cleaned for v in ("share", "send", "enter", "provide", "tell me", "batao", "forward"))
    )
    if hits and delivery_shape:
        hits = []
    if hits:
        ctx.add(30, "credential-bait", f"The message fishes for secrets ({', '.join(sorted(set(hits)))}) — no bank, company or officer ever asks for an OTP, PIN or CVV by message.")
    if ("call" in ctx.lower or "phone" in ctx.lower) and _PHONE_RE.search(ctx.text):
        ctx.add(8, "callback-number", "The message pushes you to call a number it supplies — scammers' 'support'/'officer' lines are answered by the scam team itself. Only ever call numbers printed on your card or in the official app.")
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
    if ctx.hits(PARCEL_SCAM):
        ctx.add(20, "parcel-scam", "Parcel/customs-fee pattern: couriers and customs collect charges through their official channels, never via a link in a random message demanding a small 'clearance fee' — that fee page harvests card details.")
    if ctx.hits(FAMILY_OPENER) and ctx.hits(FAMILY_ASK):
        ctx.add(22, "family-emergency", "Family-emergency impersonation: a 'new number' claiming to be a relative in trouble, asking for money and secrecy. Call the relative on their OLD number (or another family member) before sending anything.")
    if ctx.hits(TECH_SUPPORT):
        ctx.add(20, "tech-support-scam", "Tech-support scam pattern: no company monitors your device or refunds money over unsolicited calls/messages, and none will ever ask you to install AnyDesk/TeamViewer — that hands them your screen and your banking apps.")
    loan_hits = ctx.hits(LOAN_SCAM)
    if len(loan_hits) >= 2 or "processing fee for your loan" in ctx.lower or "loan disbursement fee" in ctx.lower:
        ctx.add(18, "loan-scam", "Loan-scam pattern: 'instant/pre-approved' loans that demand a processing or disbursement fee up front. Licensed lenders deduct fees from the disbursement — they never collect them by UPI first.")
    if ctx.hits(INVESTMENT_SCAM):
        ctx.add(18, "investment-scam", "Unsolicited investment-group/tips pitch: SEBI-registered advisors do not recruit through random WhatsApp/Telegram groups promising assured returns — the 'profits' shown are staged to make you deposit more.")
    if ctx.hits(SEXTORTION):
        ctx.add(22, "sextortion", "Sextortion pattern: threats to leak private images/video unless paid are almost always bluff — the scammer rarely has anything. Do NOT pay (payment marks you as a payer and the demands grow); save the messages, block, and report to cybercrime.gov.in / your platform.")
    if ctx.hits(TAX_BENEFIT_SCAM):
        ctx.add(18, "tax-refund-scam", "Tax-refund / benefit lure: tax refunds and government benefits are credited only to the bank account registered with the department — never through a link in a message asking you to 'claim' or 'verify' to receive them.")
    if "forwarded many times" in ctx.lower:
        ctx.add(8, "forwarded-chain", "This is a mass-forwarded chain message ('forwarded many times') — chain forwards are the distribution channel for scam campaigns; treat every claim and link in it as unverified.")


def _stage_pressure(ctx: _MsgContext) -> None:
    hits = ctx.hits(URGENCY)
    if len(hits) >= 2:
        ctx.add(10, "urgency-language", f"Manufactured urgency ({', '.join(sorted(set(hits)))}) — pressure is the payload; real institutions give you time and official channels.")


PARCEL_SCAM = ["parcel held", "parcel is held", "customs fee", "pay customs", "delivery failed", "delivery attempt failed", "shipment held", "reschedule your delivery", "india post parcel", "your package is held", "clearance fee"]
FAMILY_OPENER = ["this is my new number", "my new number", "lost my phone", "changed my number", "hi mum", "hi mom", "hi maa"]
FAMILY_ASK = ["send money", "need money", "in trouble", "in hospital", "urgent money", "transfer money", "don't tell anyone", "do not tell anyone", "please help"]
TECH_SUPPORT = ["microsoft support", "your computer has a virus", "computer is infected", "device is hacked", "tech support", "refund department", "install anydesk", "install teamviewer", "download anydesk", "call our support team"]
LOAN_SCAM = ["instant loan", "loan approved", "pre-approved loan", "no cibil", "loan without documents", "processing fee for your loan", "loan disbursement fee"]
INVESTMENT_SCAM = ["stock tips", "share market tips", "trading group", "investment group", "ipo allotment", "guaranteed income", "monthly returns assured", "risk free profit", "risk-free returns", "double your investment"]
SEXTORTION = ["i have recorded you", "recorded your webcam", "your private video", "i have your video", "send bitcoin or i will", "pay or i will share", "will leak your", "your contacts will receive", "webcam footage", "pay btc or"]
TAX_BENEFIT_SCAM = ["income tax refund", "tax refund is pending", "refund of rs", "pm kisan", "benefit amount will be credited", "government benefit", " subsidy claim", "claim your refund", "it department refund"]
_PHONE_RE = re.compile(r"(?:\+\d{1,3}[\s\-]?)?(?:\d[\s\-]?){9,12}\d")


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


# Playbook signatures that are, on their own, unambiguous scam
# evidence — there is no legitimate version of a "digital arrest" or
# a sextortion demand. Per the scoring model (spec §4), hard rules
# floor the score: one confirmed playbook match is at least
# "caution", however quiet the rest of the message is. (kyc-threat is
# deliberately excluded — banks do send genuine KYC reminders, so it
# must corroborate before it can carry a verdict.)
PLAYBOOK_FLOOR_CODES = {
    "digital-arrest", "task-scam", "prize-scam", "crypto-doubling",
    "giftcard-scam", "parcel-scam", "family-emergency", "tech-support-scam",
    "loan-scam", "investment-scam", "sextortion", "tax-refund-scam",
    "credential-bait", "malicious-link",
}
PLAYBOOK_FLOOR = 40


def analyze_message(text: str) -> dict:
    import time
    started = time.perf_counter()
    gen = iter_message_stages(text)
    ctx = None
    while True:
        try:
            next(gen)
        except StopIteration as stop:
            ctx = stop.value
            break
    score = min(ctx.score, 100)
    if any(f["code"] in PLAYBOOK_FLOOR_CODES for f in ctx.findings):
        score = max(score, PLAYBOOK_FLOOR)
    findings = list(ctx.findings)
    if not findings:
        findings.append({"points": 0, "code": "clean", "message": "No known scam patterns detected in this message.", "fix": fix_for("clean")})
    return enrich({"risk_score": score, "verdict": _verdict(score), "findings": findings, "links_found": ctx.links},
                  "message", duration_ms=int((time.perf_counter() - started) * 1000))
