"""Password Lab — strength, breach exposure and secure generation.

Breach checking uses the Have-I-Been-Pwned *k-anonymity* range API: only the
first 5 hex characters of the SHA-1 hash ever leave the machine, so the
password itself is never disclosed — the same protocol used by major
password managers. A small bundled common-password list provides an
offline verdict when the network is unavailable.
"""

import hashlib
import math
import secrets
import string

import httpx

from app.config import settings

# Top common passwords (abridged) — passwords everyone must never use.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345", "12345678", "qwerty",
    "1234567", "111111", "1234567890", "123123", "abc123", "1234",
    "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123", "zaq123wsx",
    "dragon", "sunshine", "princess", "letmein", "654321", "monkey",
    "27653", "1qaz2wsx", "123321", "qwertyuiop", "superman", "asdfghjkl",
    "admin", "welcome", "login", "passw0rd", "india123", "cricket",
}
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/"
_KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "!@#$%^&*()"]
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_DICTIONARY_WORDS = COMMON_PASSWORDS | {
    "football", "master", "shadow", "michael", "ninja", "mustang",
    "charlie", "jordan", "hunter", "computer", "internet", "warrior",
    "sunshine", "princess", "baseball", "stargate", "pokemon", "naruto",
}


def _detect_patterns(password: str) -> list[tuple[str, str, int | None]]:
    """zxcvbn-style pattern detection the raw-entropy score can't see:
    returns (code, issue, score-cap-or-None) tuples. Raw entropy treats
    'qwerty123!' as ~66 bits; pattern attacks treat it as one guess."""
    lower = password.lower()
    found: list[tuple[str, str, int | None]] = []
    for row in _KEYBOARD_ROWS:
        for variant in (row, row[::-1]):
            if any(variant[i:i + 4] in lower for i in range(len(variant) - 3)):
                found.append(("keyboard-walk", "Contains a keyboard walk (qwerty / asdf / 1234 rows) — among the first patterns cracking tools try.", 30))
                break
        else:
            continue
        break
    run = 1
    ascending = descending = False
    for a, b in zip(lower, lower[1:]):
        if ord(b) - ord(a) == 1 and a.isalnum() and b.isalnum():
            run += 1
            ascending = ascending or run >= 4
        elif ord(a) - ord(b) == 1 and a.isalnum() and b.isalnum():
            run += 1
            descending = descending or run >= 4
        else:
            run = 1
    if ascending or descending:
        found.append(("sequence", "Contains a character sequence (abcd… / 4321…) — sequences are guessed almost instantly.", 35))
    import re as _re
    if _re.search(r"(?:19|20)\d{2}", password):
        found.append(("year", "Contains a year — dates and years are in every cracking wordlist.", None))
    leet_alpha = "".join(c for c in password.lower().translate(_LEET) if c.isalpha())
    dict_hit = next((w for w in _DICTIONARY_WORDS if len(w) >= 5 and w in leet_alpha), None)
    if dict_hit and password.lower() not in COMMON_PASSWORDS:
        found.append(("dictionary", f"Built on the dictionary word '{dict_hit}' (leetspeak doesn't hide it — crackers substitute 0→o, @→a automatically).", 30))
    if _re.search(r"(.{2,4})\1{1,}", password) and len(password) >= 6:
        found.append(("repeat", "Repeats a short chunk (abcabc…) — repetition adds almost no real entropy.", 35))
    return found


def _entropy_bits(password: str) -> float:
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in string.punctuation for c in password):
        charset += 32
    if any(c == " " for c in password):
        charset += 1
    if charset == 0:
        return 0.0
    return round(len(password) * math.log2(charset), 1)


def _crack_time(entropy_bits: float) -> str:
    # Assume a fast offline attack at 10 billion guesses/second (bcrypt/Argon2
    # slow this by orders of magnitude; the figure is deliberately conservative).
    guesses = 2 ** max(entropy_bits - 1, 0)
    seconds = guesses / 1e10
    if seconds < 1:
        return "instantly"
    if seconds < 60:
        return f"~{seconds:.0f} seconds"
    if seconds < 3600:
        return f"~{seconds / 60:.0f} minutes"
    if seconds < 86400:
        return f"~{seconds / 3600:.0f} hours"
    if seconds < 31_536_000:
        return f"~{seconds / 86400:.0f} days"
    if seconds < 3.15e9:
        return f"~{seconds / 31_536_000:.0f} years"
    return "centuries (practically uncrackable)"


def assess_password(password: str) -> dict:
    issues: list[str] = []
    if len(password) < 12:
        issues.append("Use at least 12 characters — length beats complexity.")
    if not any(c.isupper() for c in password):
        issues.append("Add uppercase letters.")
    if not any(c.islower() for c in password):
        issues.append("Add lowercase letters.")
    if not any(c.isdigit() for c in password):
        issues.append("Add digits.")
    if not any(c in string.punctuation for c in password):
        issues.append("Add symbols.")
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is one of the most common passwords in the world. Never use it.")
    if len(set(password)) < len(password) / 2 and len(password) >= 6:
        issues.append("Too much repetition — avoid repeated characters and patterns.")
    entropy = _entropy_bits(password)
    score = max(0, min(100, int(entropy * 1.2) - (40 if password.lower() in COMMON_PASSWORDS else 0)))
    patterns = _detect_patterns(password)
    for _code, issue, cap in patterns:
        issues.append(issue)
        if cap is not None:
            score = min(score, cap)
    # Raw charset entropy overrates repetition: "aaaaaaaaaaaa" is not a
    # 56-bit secret in practice. Cap the score when a password is built from
    # very few distinct characters (pattern/repetition attacks crush it).
    if len(password) >= 6 and len(set(password)) <= max(2, len(password) // 4):
        score = min(score, 20)
    label = "very weak" if score < 30 else "weak" if score < 50 else "fair" if score < 70 else "strong" if score < 90 else "excellent"
    # zxcvbn-style reporting layer (spec §5.2): a 0–4 strength score
    # plus explicit guess estimates per attack scenario. Purely
    # additive — the long-standing score/label fields are untouched.
    strength_score = 0 if score < 30 else 1 if score < 50 else 2 if score < 70 else 3 if score < 90 else 4
    guesses_log10 = round(max(entropy - 1, 0) * math.log10(2), 1)

    def _duration(seconds: float) -> str:
        return _crack_time(math.log2(seconds * 1e10) + 1) if seconds > 0 else "instantly"

    guesses = 2 ** max(entropy - 1, 0)
    return {
        "score": score, "label": label, "entropy_bits": entropy,
        "strength_score": strength_score,
        "guesses_log10": guesses_log10,
        "crack_times": {
            "online_throttled": _duration(guesses / (100 / 3600)),   # 100 guesses/hour
            "offline_fast_hash": _crack_time(entropy),               # 10^10 guesses/s
        },
        "patterns": [code for code, _issue, _cap in patterns],
        "estimated_crack_time_offline": _crack_time(entropy),
        "issues": issues or ["No issues found. Use a unique password per site, stored in a manager."],
        "is_common_password": password.lower() in COMMON_PASSWORDS,
    }


def breach_check_local(password: str) -> dict:
    """Offline fallback verdict (bundled list only)."""
    return {
        "breached": password.lower() in COMMON_PASSWORDS,
        "occurrences": None,
        "source": "offline-common-password-list",
        "note": "Offline check against the bundled common-password list only.",
    }


async def breach_check(password: str) -> dict:
    """k-anonymity breach lookup; degrades gracefully to the offline list."""
    # SHA-1 is mandated by the HIBP k-anonymity protocol itself, not used for storage.
    sha1 = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{settings.hibp_api_url}{prefix}",
                headers={"User-Agent": "Aegis-Cyber-Defense-Platform"},
            )
        resp.raise_for_status()
        for line in resp.text.splitlines():
            candidate, _, count = line.partition(":")
            if candidate.strip() == suffix:
                return {
                    "breached": True, "occurrences": int(count),
                    "source": "haveibeenpwned-k-anonymity",
                    "note": "This password has appeared in public data breaches. Never reuse it anywhere.",
                }
        return {
            "breached": False, "occurrences": 0,
            "source": "haveibeenpwned-k-anonymity",
            "note": "Not found in the breach corpus. That does not make a weak password safe.",
        }
    except Exception:
        return breach_check_local(password)


def generate_password(length: int = 20, symbols: bool = True) -> str:
    """Cryptographically secure generator (``secrets``, never ``random``)."""
    length = max(12, min(length, 128))
    alphabet = string.ascii_letters + string.digits + (SYMBOLS if symbols else "")
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and (not symbols or any(c in SYMBOLS for c in candidate))
        ):
            return candidate


def generate_passphrase(words: int = 5) -> str:
    """Diceware-style passphrase from a compact built-in wordlist."""
    wordlist = [
        "amber", "breeze", "cinder", "delta", "ember", "falcon", "glacier",
        "harbor", "ivory", "jungle", "karma", "lantern", "meadow", "nectar",
        "onyx", "prairie", "quartz", "raven", "saffron", "tundra", "umbra",
        "velvet", "willow", "xenon", "yonder", "zephyr", "atlas", "birch",
        "cobalt", "dune", "elm", "fjord", "garnet", "hazel", "iris", "jasper",
    ]
    chosen = [secrets.choice(wordlist) for _ in range(max(4, min(words, 10)))]
    return "-".join(chosen) + str(secrets.randbelow(100))
