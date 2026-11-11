"""F-09 — the single-worker constraint must be loud, not tribal knowledge.

All limiters are per-process; a second worker silently doubles every
budget. The startup check warns when WEB_CONCURRENCY disagrees, and
the shipped backend Dockerfile is pinned to one worker.
"""

from pathlib import Path

from app.main import _worker_constraint_warning

ROOT = Path(__file__).resolve().parents[2]


def test_no_warning_when_unset_or_one(monkeypatch):
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    assert _worker_constraint_warning() is None
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    assert _worker_constraint_warning() is None


def test_warning_when_multiple_workers(monkeypatch):
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    warning = _worker_constraint_warning()
    assert warning is not None
    assert "per-process" in warning and "ONE worker" in warning


def test_backend_dockerfile_is_single_worker():
    dockerfile = (ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert '"--workers", "1"' in dockerfile
