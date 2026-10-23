import io
import zipfile

from app.modules.file_scanner import scan_file


def test_clean_text_file():
    r = scan_file("notes.txt", b"hello world, this is a perfectly normal note.")
    assert r["verdict"] == "clean"
    assert len(r["sha256"]) == 64


def test_exe_disguised_as_pdf():
    r = scan_file("invoice.pdf", b"MZ" + b"\x00" * 500)
    assert r["risk_score"] >= 40
    assert any(f["code"] == "type-spoofing" for f in r["findings"])


def test_double_extension_flagged():
    r = scan_file("photo.jpg.exe", b"MZ" + b"\x00" * 100)
    assert any(f["code"] in ("double-extension", "dangerous-type") for f in r["findings"])


def test_powershell_dropper_detected():
    payload = b"powershell -w hidden -enc aQBmACAAIABpAGUAeAA="
    r = scan_file("readme.txt", payload)
    assert r["ioc_hits"].get("powershell-dropper", 0) >= 1
    assert r["risk_score"] >= 40


def test_zip_with_exe_flagged():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("setup.exe", b"MZ" + b"\x00" * 50)
    r = scan_file("bundle.zip", buf.getvalue())
    assert any(f["code"] == "archive-hides-executable" for f in r["findings"])
