"""File malware scanner — static, sandboxed, no execution, ever.

Checks a file the way a first-line SOC triage would:
hash it, verify its *real* type from magic bytes against its extension,
measure entropy (packed/encrypted payloads), hunt for embedded IOCs
(URLs, IPs, PowerShell / macro / shell droppers), apply YARA-style rules,
and flag archive bombs. The file is analysed in memory and never written
to disk or executed.
"""

import hashlib
import io
import math
import re
import zipfile

MAGIC = [
    (b"MZ", "Windows executable (PE)", {".exe", ".dll", ".scr", ".com"}),
    (b"\x7fELF", "Linux executable (ELF)", {".elf", ".bin", ""}),
    (b"%PDF", "PDF document", {".pdf"}),
    (b"PK\x03\x04", "ZIP-based archive", {".zip", ".jar", ".docx", ".xlsx", ".apk", ".pptx"}),
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (b"\x89PNG", "PNG image", {".png"}),
    (b"GIF8", "GIF image", {".gif"}),
    (b"\xd0\xcf\x11\xe0", "Legacy Office document (OLE)", {".doc", ".xls", ".ppt", ".msi"}),
    (b"#!", "Script with shebang", {".sh", ".py", ".pl", ""}),
]
DOUBLE_EXT = re.compile(r"\.(pdf|doc|docx|jpg|png|txt|xlsx)\.(exe|scr|js|vbs|bat|cmd|ps1|jar|msi)$", re.I)
DANGEROUS_EXT = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".dll", ".com", ".hta", ".lnk", ".iso", ".img"}
IOC_PATTERNS = {
    "embedded-url": re.compile(rb"https?://[a-zA-Z0-9.\-]{3,}(?::\d+)?/[^\s\"'<>]{0,80}"),
    "embedded-ip": re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"),
    "powershell-dropper": re.compile(rb"powershell[^\n]{0,120}(-enc|iex|downloadstring|invoke-expression|-w\s+hidden)", re.I),
    "certutil-dropper": re.compile(rb"certutil[^\n]{0,80}-urlcache", re.I),
    "macro-autoexec": re.compile(rb"(AutoOpen|Document_Open|Auto_Open|Workbook_Open)", re.I),
    "shell-dropper": re.compile(rb"(curl|wget)\s+[^\n]{0,100}\|\s*(sh|bash)", re.I),
    "base64-pe": re.compile(rb"TVqQ[A-Za-z0-9+/=]{40,}"),  # 'TVqQ' = base64 of 'MZ' header
    "crypto-wallet-address": re.compile(rb"\b(bc1|[13])[a-zA-HJ-NP-Za-km-z]{25,39}\b"),
}
MAX_ZIP_RATIO = 100
MAX_ZIP_TOTAL = 500 * 1024 * 1024


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


class _FileContext:
    def __init__(self, filename: str, data: bytes):
        self.filename = filename
        self.data = data
        self.name = filename.lower()
        self.ext = "." + self.name.rsplit(".", 1)[-1] if "." in self.name else ""
        self.detected_type, self.expected_exts = "unknown", None
        for magic, label, exts in MAGIC:
            if data.startswith(magic):
                self.detected_type, self.expected_exts = label, exts
                break
        self.entropy = _entropy(data)
        self.hits: dict[str, int] = {}
        self.findings: list[dict] = []
        self.score = 0

    def add(self, points: int, code: str, message: str) -> None:
        self.score += points
        self.findings.append({"points": points, "code": code, "message": message})


def _stage_fingerprint(ctx: _FileContext) -> None:
    pass  # hashes are computed for the report; the stage anchors the live trace


def _stage_type(ctx: _FileContext) -> None:
    if ctx.expected_exts is not None and ctx.ext and ctx.ext not in ctx.expected_exts:
        ctx.add(40, "type-spoofing", f"File claims to be '{ctx.ext}' but its bytes are a {ctx.detected_type} — classic malware disguise.")
    if ctx.ext in DANGEROUS_EXT:
        ctx.add(20, "dangerous-type", f"'{ctx.ext}' files can execute code. Only open them from sources you fully trust.")
    if DOUBLE_EXT.search(ctx.name):
        ctx.add(35, "double-extension", "Double extension (e.g. invoice.pdf.exe) — the real file type is the last extension.")


def _stage_entropy(ctx: _FileContext) -> None:
    if ctx.entropy > 7.5 and len(ctx.data) > 4096:
        ctx.add(20, "high-entropy", f"Entropy {ctx.entropy:.2f}/8.00 — content looks packed or encrypted, a common malware obfuscation.")
    if ctx.detected_type.startswith("Legacy Office") or (ctx.expected_exts and ".docx" in ctx.expected_exts):
        if b"vbaProject" in ctx.data or b"Macros" in ctx.data:
            ctx.add(25, "macros-present", "Document carries macros — the #1 ransomware delivery mechanism in email attachments.")


def _stage_ioc(ctx: _FileContext) -> None:
    for code, pattern in IOC_PATTERNS.items():
        count = len(pattern.findall(ctx.data))
        if count:
            ctx.hits[code] = count
    weights = {"powershell-dropper": 40, "certutil-dropper": 40, "shell-dropper": 40, "macro-autoexec": 25, "base64-pe": 30, "embedded-url": 5, "embedded-ip": 5, "crypto-wallet-address": 10}
    for code, count in ctx.hits.items():
        ctx.add(weights.get(code, 5), code, f"Found {count} indicator(s) of type '{code}' embedded in the file.")


def _stage_archive(ctx: _FileContext) -> None:
    if not zipfile.is_zipfile(io.BytesIO(ctx.data)):
        return
    try:
        with zipfile.ZipFile(io.BytesIO(ctx.data)) as zf:
            if len(zf.infolist()) > 1000:
                ctx.add(15, "excessive-entries", f"Archive contains {len(zf.infolist())} entries — far beyond normal use, a known scanner-evasion pattern.")
            total = sum(i.file_size for i in zf.infolist())
            ratio = total / max(len(ctx.data), 1)
            if ratio > MAX_ZIP_RATIO or total > MAX_ZIP_TOTAL:
                ctx.add(35, "zip-bomb", f"Archive expands {ratio:.0f}x to {total / 1e6:.0f} MB — characteristics of a zip bomb.")
            nested_exe = [i.filename for i in zf.infolist() if i.filename.lower().endswith(tuple(DANGEROUS_EXT))]
            if nested_exe:
                ctx.add(20, "archive-hides-executable", f"Archive hides executable file(s): {', '.join(nested_exe[:3])}.")
    except zipfile.BadZipFile:
        ctx.add(10, "corrupt-archive", "Archive structure is corrupt — sometimes used to evade scanners.")


FILE_STAGES = [
    ("Fingerprinting — SHA-256 · SHA-1 · MD5", _stage_fingerprint),
    ("Type verification — magic bytes vs declared extension", _stage_type),
    ("Entropy & macro analysis", _stage_entropy),
    ("Indicator scan — droppers · downloaders · suspicious strings", _stage_ioc),
    ("Archive inspection — nested payloads & zip bombs", _stage_archive),
]


def iter_file_stages(filename: str, data: bytes):
    ctx = _FileContext(filename, data)
    for label, stage in FILE_STAGES:
        before = len(ctx.findings)
        stage(ctx)
        yield label, ctx.findings[before:], min(ctx.score, 100)
    return ctx


def scan_file(filename: str, data: bytes) -> dict:
    """Analyse bytes WITHOUT executing them; nothing is written to disk."""
    gen = iter_file_stages(filename, data)
    ctx = None
    while True:
        try:
            next(gen)
        except StopIteration as stop:
            ctx = stop.value
            break
    score = min(ctx.score, 100)
    verdict = "malicious" if score >= 70 else "suspicious" if score >= 40 else "low-risk" if score >= 20 else "clean"
    findings = list(ctx.findings)
    if not findings:
        findings.append({"points": 0, "code": "clean", "message": "No static malware indicators found. This is not a guarantee — keep antivirus on."})
    return {
        "filename": filename, "size_bytes": len(ctx.data), "detected_type": ctx.detected_type,
        # SHA-1/MD5 are reported only as threat-intel fingerprints, never for security.
        "sha256": hashlib.sha256(ctx.data).hexdigest(),
        "sha1": hashlib.sha1(ctx.data, usedforsecurity=False).hexdigest(),
        "md5": hashlib.md5(ctx.data, usedforsecurity=False).hexdigest(),
        "entropy": round(ctx.entropy, 2),
        "risk_score": score, "verdict": verdict, "findings": findings, "ioc_hits": ctx.hits,
    }
