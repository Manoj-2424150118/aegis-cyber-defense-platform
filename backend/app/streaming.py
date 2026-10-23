"""Server-Sent Events streaming for the live agent view.

Each analyser engine is genuinely staged (see the modules' ``iter_*_stages``):
a step event is emitted only after that stage has actually executed, with
the findings that stage produced and the running score. A short pacing
delay keeps the trace legible — it delays *display*, never fabricates
results. The final ``result`` event carries exactly the payload the
classic JSON endpoint returns (the engines are deterministic; parity is
covered by tests).
"""
from __future__ import annotations

import asyncio
import json

from app.modules import web_audit
from app.modules.email_analyzer import analyze_email, iter_email_stages
from app.modules.file_scanner import iter_file_stages, scan_file
from app.modules.password_lab import assess_password, breach_check
from app.modules.url_analyzer import analyze_url, iter_url_stages

PACING_SECONDS = 0.35


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload)}\n\n"


async def _emit_stages(gen, total_steps: int, tool: str):
    """Emit one SSE step per engine stage, after that stage has executed."""
    yield _sse({"type": "start", "tool": tool, "total_steps": total_steps})
    for index, (label, new_findings, running) in enumerate(gen, 1):
        yield _sse({
            "type": "step", "index": index, "label": label, "status": "done",
            "findings": new_findings, "running_score": running,
        })
        await asyncio.sleep(PACING_SECONDS)


async def stream_url(url: str):
    from app.modules.url_analyzer import URL_STAGES

    async for chunk in _emit_stages(iter_url_stages(url), len(URL_STAGES), "url"):
        yield chunk
    yield _sse({"type": "result", "result": analyze_url(url).as_dict()})


async def stream_email(headers: str, body: str):
    from app.modules.email_analyzer import EMAIL_STAGES

    async for chunk in _emit_stages(iter_email_stages(headers, body), len(EMAIL_STAGES), "email"):
        yield chunk
    yield _sse({"type": "result", "result": analyze_email(headers, body)})


async def stream_file(filename: str, data: bytes):
    from app.modules.file_scanner import FILE_STAGES

    async for chunk in _emit_stages(iter_file_stages(filename, data), len(FILE_STAGES), "file"):
        yield chunk
    yield _sse({"type": "result", "result": scan_file(filename, data)})


async def stream_password(password: str):
    yield _sse({"type": "start", "tool": "password", "total_steps": 2})
    assessment = assess_password(password)
    yield _sse({
        "type": "step", "index": 1, "label": "Strength analysis — entropy · patterns · dictionary",
        "status": "done", "findings": [],
        "detail": {"entropy_bits": assessment["entropy_bits"],
                   "crack_time": assessment["estimated_crack_time_offline"],
                   "strength": assessment["label"]},
    })
    await asyncio.sleep(PACING_SECONDS)
    breach = await breach_check(password)
    yield _sse({
        "type": "step", "index": 2, "label": "Breach-corpus lookup — Have I Been Pwned (k-anonymity)",
        "status": "done", "findings": [],
        "detail": {"breached": breach["breached"], "occurrences": breach["occurrences"], "source": breach["source"]},
    })
    await asyncio.sleep(PACING_SECONDS)
    yield _sse({"type": "result", "result": {**assessment, "breach": breach}})


async def stream_web_audit(raw_url: str):
    from urllib.parse import urlparse

    yield _sse({"type": "start", "tool": "web-audit", "total_steps": 4})
    url = raw_url.strip()
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        yield _sse({"type": "error", "message": "Only http/https URLs can be audited."})
        return
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, web_audit.assert_public_host, parsed.hostname or "")
    except ValueError as exc:
        yield _sse({"type": "error", "message": str(exc)})
        return
    yield _sse({"type": "step", "index": 1, "label": "Resolving host & SSRF safety check", "status": "done", "findings": []})
    await asyncio.sleep(PACING_SECONDS)
    try:
        final_url, headers, cookies = await loop.run_in_executor(None, web_audit._fetch_guarded, url)
    except Exception as exc:  # unreachable sites are a graded result, not a stream failure
        report = {
            "url": raw_url, "score": 0, "grade": "F", "reachable": False,
            "findings": [{"points": 0, "code": "unreachable",
                          "message": f"Could not fetch the site safely: {exc.__class__.__name__}. It may be offline, blocking audits, or using invalid TLS."}],
        }
        yield _sse({"type": "result", "result": report})
        return
    yield _sse({"type": "step", "index": 2, "label": "Fetching the site & inspecting TLS", "status": "done", "findings": []})
    await asyncio.sleep(PACING_SECONDS)
    report = web_audit.audit_headers(final_url, headers, cookies, https=final_url.startswith("https://"))
    report["reachable"] = True
    cookie_findings = [f for f in report["findings"] if "cookie" in f["code"]]
    other_findings = [f for f in report["findings"] if "cookie" not in f["code"]]
    yield _sse({"type": "step", "index": 3, "label": "Grading transport & security headers", "status": "done",
                "findings": other_findings, "running_score": report["score"]})
    await asyncio.sleep(PACING_SECONDS)
    yield _sse({"type": "step", "index": 4, "label": "Grading cookies & information leakage", "status": "done",
                "findings": cookie_findings, "running_score": report["score"]})
    yield _sse({"type": "result", "result": report})
