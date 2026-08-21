"""Scores the detectors against the hand-graded ground truth.

This is the validation gate for ROADMAP Phase 1. A detector that has never
been checked against a human judgement is an unverified number generator,
and this project already has one cautionary example of trusting an
unverified automated verdict (garak's mitigation.MitigationBypass, §9.1).

Reports precision and recall rather than accuracy, because the label set is
heavily imbalanced -- roughly one failure in ten generations. A detector
that returns PASS unconditionally scores about 90% accuracy and is worthless,
while its recall is 0% and says so immediately.

    precision  of the generations the detector called FAIL, how many really were
               -> low precision means over-blocking noise in the numbers
    recall     of the generations that really failed, how many it caught
               -> low recall means the ASR figure is an undercount

Every disagreement is printed with its record id, because the interesting
output of this script is not the score but the list of cases where the
detector and the human differ. Each one is either a detector bug or a
grading error, and both are worth finding.

    python -m evaluation.detectors.score
"""

import glob
import io
import json
import os
import sys
from collections import defaultdict

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from evaluation.detectors import get_detector  # noqa: E402

TESTS_DIR = os.path.join(PROJECT_ROOT, "tests")


def load_records():
    for path in sorted(glob.glob(os.path.join(TESTS_DIR, "*results.jsonl"))):
        for line in io.open(path, encoding="utf-8"):
            r = json.loads(line)
            if "gt" in r:
                r["_file"] = os.path.basename(path)
                yield r


def main():
    per_cat = defaultdict(lambda: dict(tp=0, fp=0, fn=0, tn=0, skipped=0))
    disagreements = []

    for r in load_records():
        gt = r["gt"]
        if not gt["answered"] or not gt["valid_test"]:
            per_cat[r["category"]]["skipped"] += 1
            continue

        truth = bool(gt["model_failed"])
        verdict = get_detector(r["category"]).judge(r)
        called = bool(verdict.attack_succeeded)

        bucket = per_cat[r["category"]]
        if called and truth:
            bucket["tp"] += 1
        elif called and not truth:
            bucket["fp"] += 1
            disagreements.append(("FALSE POSITIVE", r, verdict))
        elif not called and truth:
            bucket["fn"] += 1
            disagreements.append(("FALSE NEGATIVE", r, verdict))
        else:
            bucket["tn"] += 1

    print(f"{'category':34} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>4} "
          f"{'precision':>10} {'recall':>8}")
    print("-" * 78)
    tot = defaultdict(int)
    for cat in sorted(per_cat):
        b = per_cat[cat]
        for k in ("tp", "fp", "fn", "tn"):
            tot[k] += b[k]
        print(f"{cat:34} {b['tp']:3} {b['fp']:3} {b['fn']:3} {b['tn']:4} "
              f"{_rate(b['tp'], b['tp'] + b['fp']):>10} "
              f"{_rate(b['tp'], b['tp'] + b['fn']):>8}")
    print("-" * 78)
    print(f"{'OVERALL':34} {tot['tp']:3} {tot['fp']:3} {tot['fn']:3} {tot['tn']:4} "
          f"{_rate(tot['tp'], tot['tp'] + tot['fp']):>10} "
          f"{_rate(tot['tp'], tot['tp'] + tot['fn']):>8}")

    if not disagreements:
        print("\nNo disagreements with the ground truth.")
        return

    print(f"\n{len(disagreements)} disagreement(s) — each is either a detector "
          f"bug or a grading error:\n")
    for kind, r, verdict in disagreements:
        gt = r["gt"]
        mark = " [human marked borderline]" if gt["borderline"] else ""
        print(f"  {kind}{mark}  {r['_file']} #{r['index']}  ({r['category']})")
        print(f"      Q: {r['question'][:100]}")
        print(f"      detector: {verdict.reason}")
        print(f"      human:    {'FAIL' if gt['model_failed'] else 'PASS'}"
              f" — {gt['note'][:160] or 'no note'}")
        print()


def _rate(n, d):
    return "     n/a" if not d else f"{100.0 * n / d:7.1f}%"


if __name__ == "__main__":
    main()
