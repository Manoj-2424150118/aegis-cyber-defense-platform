#!/usr/bin/env python3
"""Detection calibration harness (spec §10/§12.11).

Runs the labeled golden corpus (backend/tests/golden_corpus.json)
through the offline engines and reports precision / recall / FPR per
engine and overall. Network engines (domain, TLS, web-audit) are
excluded by design: their inputs are live third-party state, not
fixtures, and they are covered by their own unit tests.

Usage:  python scripts/eval_detection.py [--json]
Exit code is non-zero when overall recall < 0.90 or FPR > 0.05 —
the release-gate thresholds from the spec.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.modules.email_analyzer import analyze_email          # noqa: E402
from app.modules.file_scanner import scan_file                # noqa: E402
from app.modules.message_analyzer import analyze_message      # noqa: E402
from app.modules.password_lab import assess_password          # noqa: E402
from app.modules.secret_scanner import scan_secrets           # noqa: E402
from app.modules.url_analyzer import analyze_url              # noqa: E402

CORPUS = json.loads((ROOT / "backend" / "tests" / "golden_corpus.json").read_text())


def _predict(engine: str, sample: dict, thresholds: dict) -> bool:
    """True = the engine calls this sample a threat (positive)."""
    if engine == "url":
        return analyze_url(sample["input"]).risk_score >= thresholds["url"]
    if engine == "message":
        return analyze_message(sample["input"])["risk_score"] >= thresholds["message"]
    if engine == "email":
        return analyze_email(sample["input"]["headers"], sample["input"]["body"])["risk_score"] >= thresholds["email"]
    if engine == "secret":
        text = sample["input"]
        if isinstance(text, dict):  # {"join": [...]} — samples stored in parts
            text = "".join(text["join"])
        return scan_secrets(text)["risk_score"] >= thresholds["secret"]
    if engine == "file":
        data = base64.b64decode(sample["input"]["base64"])
        return scan_file(sample["input"]["filename"], data)["risk_score"] >= thresholds["file"]
    if engine == "password":
        # For passwords a "positive" is a correctly-flagged WEAK password.
        return assess_password(sample["input"])["score"] < 50
    raise ValueError(engine)


def evaluate() -> dict:
    thresholds = CORPUS["thresholds"]
    report: dict[str, dict] = {}
    totals = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for engine, samples in CORPUS.items():
        if engine in ("comment", "thresholds"):
            continue
        counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "misses": []}
        for sample in samples:
            predicted = _predict(engine, sample, thresholds)
            actual = sample["label"] == "malicious"
            if predicted and actual:
                counts["tp"] += 1
            elif predicted and not actual:
                counts["fp"] += 1
                counts["misses"].append(("FP", sample["input"] if isinstance(sample["input"], str) else "multipart-sample"))
            elif not predicted and actual:
                counts["fn"] += 1
                counts["misses"].append(("FN", sample["input"] if isinstance(sample["input"], str) else "multipart-sample"))
            else:
                counts["tn"] += 1
        for key in totals:
            totals[key] += counts[key]
        report[engine] = counts
    report["overall"] = totals
    return report


def _metrics(counts: dict) -> tuple[float, float, float]:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return precision, recall, fpr


def main() -> int:
    report = evaluate()
    if "--json" in sys.argv:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"{'engine':<10} {'precision':>9} {'recall':>7} {'FPR':>6}  (tp/fp/tn/fn)")
        for engine, counts in report.items():
            p, r, f = _metrics(counts)
            print(f"{engine:<10} {p:>9.2f} {r:>7.2f} {f:>6.2f}  ({counts['tp']}/{counts['fp']}/{counts['tn']}/{counts['fn']})")
            for kind, sample in counts.get("misses", []):
                print(f"    {kind}: {sample!r:.90}")
    _p, recall, fpr = _metrics(report["overall"])
    ok = recall >= 0.90 and fpr <= 0.05
    print(f"\nRelease gate: recall {recall:.2f} (≥0.90), FPR {fpr:.2f} (≤0.05) → {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
