"""F-08 — the SPA bootstrap must never go back inline.

Finding (historical): an inline theme bootstrap in the served HTML was
blocked by the site's own CSP (script-src 'self', no 'unsafe-inline'),
breaking first-paint theming. The fix — an external /assets/theme-init.js
loaded in <head> — is already in place; these tests pin the invariant so
it cannot silently regress:

* both CSPs stay free of 'unsafe-inline' / 'unsafe-eval';
* frontend/index.html contains no executable inline script (JSON-LD
  data blocks are not executable and are exempt);
* the external bootstrap exists, is referenced from <head>, and does
  the theme job it claims to do.
"""

import re
from pathlib import Path

from app.headers import API_CSP, SPA_CSP

ROOT = Path(__file__).resolve().parents[2]
INDEX = (ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
THEME_INIT = ROOT / "frontend" / "public" / "assets" / "theme-init.js"


def test_csp_has_no_unsafe_inline_or_eval():
    for csp in (SPA_CSP, API_CSP):
        assert "'unsafe-inline'" not in csp
        assert "'unsafe-eval'" not in csp
    assert "script-src 'self'" in SPA_CSP


def test_no_executable_inline_scripts():
    tags = re.findall(r"<script\b[^>]*>", INDEX)
    assert tags, "index.html should load its scripts"
    for tag in tags:
        if 'type="application/ld+json"' in tag:
            continue  # data block — never executed, CSP-exempt
        assert "src=" in tag, f"inline executable script found: {tag}"


def test_theme_bootstrap_is_external_and_real():
    assert '<script src="/assets/theme-init.js"></script>' in INDEX
    assert THEME_INIT.is_file()
    body = THEME_INIT.read_text(encoding="utf-8")
    assert "aegis-theme" in body  # reads the stored theme choice
    assert "dataset.theme" in body  # applies it before first paint
