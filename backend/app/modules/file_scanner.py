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


def scan_file(filename: str, data: bytes) -> dict:
    findings: list[dict] = []
    score = 0

    def add(points: int, code: str, message: str) -> None:
        nonlocal score
        score += points
        findings.append({"points": points, "code": code, "message": message})

    name = filename.lower()
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    sha256 = hashlib.sha256(data).hexdigest()
    # SHA-1/MD5 are reported only as threat-intel fingerprints, never for security.
    sha1 = hashlib.sha1(data, usedforsecurity=False).hexdigest()
    md5 = hashlib.md5(data, usedforsecurity=False).hexdigest()

    detected_type, expected_exts = "unknown", None
    for magic, label, exts in MAGIC:
        if data.startswith(magic):
            detected_type, expected_exts = label, exts
            break

    if expected_exts is not None and ext and ext not in expected_exts:
        add(40, "type-spoofing", f"File claims to be '{ext}' but its bytes are a {detected_type} — classic malware disguise.")
    if ext in DANGEROUS_EXT:
        add(20, "dangerous-type", f"'{ext}' files can execute code. Only open them from sources you fully trust.")
    if DOUBLE_EXT.search(name):
        add(35, "double-extension", "Double extension (e.g. invoice.pdf.exe) — the real file type is the last extension.")
    entropy = _entropy(data)
    if entropy > 7.5 and len(data) > 4096:
        add(20, "high-entropy", f"Entropy {entropy:.2f}/8.00 — content looks packed or encrypted, a common malware obfuscation.")
    if detected_type.startswith("Legacy Office") or (expected_exts and ".docx" in expected_exts):
        if b"vbaProject" in data or b"Macros" in data:
            add(25, "macros-present", "Document carries macros — the #1 ransomware delivery mechanism in email attachments.")

    hits: dict[str, int] = {}
    for code, pattern in IOC_PATTERNS.items():
        count = len(pattern.findall(data))
        if count:
            hits[code] = count
    weights = {"powershell-dropper": 40, "certutil-dropper": 40, "shell-dropper": 40, "macro-autoexec": 25, "base64-pe": 30, "embedded-url": 5, "embedded-ip": 5, "crypto-wallet-address": 10}
    for code, count in hits.items():
        add(weights.get(code, 5), code, f"Found {count} indicator(s) of type '{code}' embedded in the file.")

    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                total = sum(i.file_size for i in zf.infolist())
                ratio = total / max(len(data), 1)
                if ratio > MAX_ZIP_RATIO or total > MAX_ZIP_TOTAL:
                    add(35, "zip-bomb", f"Archive expands {ratio:.0f}x to {total / 1e6:.0f} MB — characteristics of a zip bomb.")
                nested_exe = [i.filename for i in zf.infolist() if i.filename.lower().endswith(tuple(DANGEROUS_EXT))]
                if nested_exe:
                    add(20, "archive-hides-executable", f"Archive hides executable file(s): {', '.join(nested_exe[:3])}.")
        except zipfile.BadZipFile:
            add(10, "corrupt-archive", "Archive structure is corrupt — sometimes used to evade scanners.")

    score = min(score, 100)
    verdict = "malicious" if score >= 70 else "suspicious" if score >= 40 else "low-risk" if score >= 20 else "clean"
    if not findings:
        findings.append({"points": 0, "code": "clean", "message": "No static malware indicators found. This is not a guarantee — keep antivirus on."})
    return {
        "filename": filename, "size_bytes": len(data), "detected_type": detected_type,
        "sha256": sha256, "sha1": sha1, "md5": md5, "entropy": round(entropy, 2),
        "risk_score": score, "verdict": verdict, "findings": findings, "ioc_hits": hits,
    }
