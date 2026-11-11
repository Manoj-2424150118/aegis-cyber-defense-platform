"""QR-code scan endpoint support (spec §11).

Decoding a QR image needs an image library; the platform deliberately
carries none in its runtime dependencies. This module therefore tries
the decoders that *may* be present in a deployment (OpenCV, pyzbar)
and otherwise returns an honest **inconclusive / degraded** result —
never a fabricated "safe": an unscanned QR code is an unknown, and
§16 forbids dressing an unknown up as a verdict.

When a decoder is available, the decoded text is handed to Smart Scan
so the payload URL/message gets the full engine treatment.
"""

from __future__ import annotations


def try_decode(data: bytes) -> str | None:
    """Best-effort QR decode via any locally available library."""
    try:  # OpenCV ships a competent built-in detector when installed.
        import cv2  # type: ignore
        import numpy as np  # type: ignore

        image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is not None:
            text, _points, _straight = cv2.QRCodeDetector().detectAndDecode(image)
            if text:
                return text
    except Exception:
        pass
    try:  # pyzbar (requires the system zbar library as well)
        import io

        from PIL import Image  # type: ignore
        from pyzbar.pyzbar import decode as _zbar_decode  # type: ignore

        found = _zbar_decode(Image.open(io.BytesIO(data)))
        if found:
            return found[0].data.decode("utf-8", "replace")
    except Exception:
        pass
    return None


def inconclusive_result() -> dict:
    """The honest answer when no decoder is available in this
    deployment: degraded, inconclusive, with prevention guidance —
    explicitly NOT a safe verdict."""
    return {
        "tool": "qr",
        "detected_type": "qr",
        "verdict": "inconclusive",
        "risk_score": None,
        "decoded_text": None,
        "summary": "QR decoding is not available in this deployment, so this code was NOT scanned. Treat it as unknown, not as safe.",
        "prevention": [
            {"priority": 1, "action": "Do not let the QR code take you straight to a login or payment page.",
             "why": "A printed or pasted QR code hides its destination until it is opened."},
            {"priority": 2, "action": "Preview the URL first (most phone cameras show it before opening) and paste it into the Link Checker here.",
             "why": "Checking the destination as text gives you the full phishing analysis."},
        ],
        "meta": {"schema_version": "2.0", "engine": "qr", "sources_used": [],
                 "degraded": True, "cached": False},
    }
