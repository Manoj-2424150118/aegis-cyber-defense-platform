"""Release gate (spec §10): the golden corpus must hold recall
>= 0.90 and FPR <= 0.05 overall. Delegates to the same evaluation
the scripts/eval_detection.py CLI runs, so CI and the CLI can never
disagree."""
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "eval_detection", Path(__file__).resolve().parents[2] / "scripts" / "eval_detection.py")
eval_detection = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(eval_detection)


def test_golden_corpus_release_gate():
    report = eval_detection.evaluate()
    overall = report["overall"]
    tp, fp, tn, fn = overall["tp"], overall["fp"], overall["tn"], overall["fn"]
    recall = tp / (tp + fn) if tp + fn else 1.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    assert recall >= 0.90, f"recall {recall:.2f} — misses: {[e for e in report if report[e].get('misses')]}"
    assert fpr <= 0.05, f"FPR {fpr:.2f}"
