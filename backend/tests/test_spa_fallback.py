"""Regression tests for the SPA fallback path-containment guard.

The ``/{path:path}`` fallback serves files from the static dir, but the
path segment is user-controlled: before the fix, ``GET /../secret.txt``
served files outside the static dir (CodeQL py/path-injection #6/#7).
``_safe_static_path`` resolves the candidate and requires it to stay
inside the static root.
"""
from pathlib import Path

from app.main import _safe_static_path


def _tree(tmp_path: Path) -> Path:
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("SPA-INDEX")
    (static / "app.js").write_text("APP-JS")
    (tmp_path / "secret.txt").write_text("TOP-SECRET")
    (static / "escape-link").symlink_to(tmp_path / "secret.txt")
    return static


def test_legit_file_served(tmp_path):
    static = _tree(tmp_path)
    assert _safe_static_path(static, "app.js") == (static / "app.js").resolve()


def test_traversal_rejected(tmp_path):
    static = _tree(tmp_path)
    assert _safe_static_path(static, "../secret.txt") is None
    assert _safe_static_path(static, "../../etc/passwd") is None
    assert _safe_static_path(static, "assets/../../secret.txt") is None


def test_absolute_path_rejected(tmp_path):
    static = _tree(tmp_path)
    assert _safe_static_path(static, str(tmp_path / "secret.txt")) is None
    assert _safe_static_path(static, "/etc/passwd") is None


def test_missing_and_directory_rejected(tmp_path):
    static = _tree(tmp_path)
    assert _safe_static_path(static, "nope.html") is None
    assert _safe_static_path(static, "assets") is None
    assert _safe_static_path(static, "") is None


def test_symlink_escape_rejected(tmp_path):
    static = _tree(tmp_path)
    assert _safe_static_path(static, "escape-link") is None
