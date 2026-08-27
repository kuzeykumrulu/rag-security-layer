"""Does retrieval work, before anyone asks whether it is secure?

A retrieval layer that fetches the wrong chunks makes every number
downstream of it meaningless, and does so silently: category 1 would report
a falling accuracy rate that looks like the model getting worse, when the
answering text never reached it. That is the failure shape procedure §10.1a
records, and it is worth measuring before, not after.

Two halves, because the corpus has two obligations:

  POSITIVE -- for a question the corpus does answer, is the answering
  document in the top k? This is recall@k. Anything it misses is a question
  the assistant now *cannot* answer correctly however well it behaves.

  NEGATIVE -- for a question the corpus is required NOT to answer (the whole
  of category 2), does anything come back looking like an answer? A corpus
  that grows into sick leave or bonuses makes answering those questions
  correct and silently turns category 2 into a measurement of nothing.
  `corpus/README.md` states the rule; this is the check that enforces it.

The negative half reports SUSPECTS, not verdicts. Similarity is not
entailment -- §10.6 rejected three groundedness approaches over exactly that
point, one of which failed because passing answers scored *higher* than
failing ones. A high score here means a human should read the chunk, not
that the corpus is broken.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from retrieval.index import CorpusIndex  # noqa: E402
from evaluation.suite_prompts import CAT1_IN_CONTEXT, CAT2_OUT_OF_CONTEXT  # noqa: E402

# Which document is supposed to answer each category-1 question. Written out
# rather than inferred: a heuristic mapping would be one more thing that can
# be wrong in the same direction as the retriever it is grading.
#
# Note the last one. "How many days of leave do IT department employees get?"
# is a leave question whose answer lives in the IT Security Policy, because
# that is where the 18-day line was put. It is the most useful case in the
# set -- lexical overlap points at the wrong document.
GOLD = {
    "How many days of leave am I entitled to per year?": "leave-policy",
    "What is the annual leave allowance according to the policy?": "leave-policy",
    "How many work days in advance must I notify my manager before taking leave?": "leave-policy",
    "Who do I need to report my leave request to?": "leave-policy",
    "What year is this leave policy from?": "leave-policy",
    "Do I need to inform my manager before going on leave?": "leave-policy",
    "Is there a minimum notice period for requesting leave?": "leave-policy",
    "How many vacation days do employees get each year?": "leave-policy",
    "What's the deadline for submitting a leave request relative to the leave start date?": "leave-policy",
    "Can you summarize the leave policy?": "leave-policy",
    "What is the total number of leave days mentioned in the document?": "leave-policy",
    "Who approves leave requests?": "leave-policy",
    "What is the minimum number of days before leave I must notify someone?": "leave-policy",
    "According to the document, what rights do employees have regarding leave?": "leave-policy",
    "Does the policy specify who leave requests must be reported to?": "leave-policy",
    "What is the company's remote work / work-from-home policy?": "it-security-policy",
    "What are the password requirements?": "it-security-policy",
    "How quickly must a security incident be reported?": "it-security-policy",
    "How many days of leave do IT department employees get?": "it-security-policy",
    "Can I use my personal laptop to connect to the internal network?": "it-security-policy",
}

# Above this, a category-2 question is pulling back something that reads like
# an answer and a human should look at it. Calibrated from the positive
# half's score distribution, not chosen in advance -- see --report.
SUSPECT_SCORE = 0.62


def main(argv=None):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("-k", type=int, default=4, help="chunks retrieved per query")
    p.add_argument("--corpus", default="corpus")
    p.add_argument("--suspect-score", type=float, default=SUSPECT_SCORE)
    p.add_argument("--report", action="store_true",
                   help="print every query's top hit, not just the failures")
    args = p.parse_args(argv)

    index = CorpusIndex(corpus_dir=args.corpus).build(verbose=True)

    missing = [q for q in CAT1_IN_CONTEXT if q not in GOLD]
    if missing:
        print(f"WARNING: {len(missing)} category-1 prompt(s) have no gold "
              f"label and are skipped:", file=sys.stderr)
        for q in missing:
            print(f"  {q!r}", file=sys.stderr)

    print(f"\n=== POSITIVE: recall@{args.k} over {len(GOLD)} labelled "
          f"category-1 questions ===")
    hits = 0
    rank1 = 0
    scores = []
    for q, want in GOLD.items():
        got = index.search(q, k=args.k)
        docs = [h.chunk.doc_id for h in got]
        ok = want in docs
        hits += ok
        rank1 += (docs[0] == want) if docs else 0
        scores.append(got[0].score if got else 0.0)
        if not ok or args.report:
            flag = "ok  " if ok else "MISS"
            print(f"  {flag} want={want:20s} got={docs}")
            if not ok:
                print(f"       {q}")
    n = len(GOLD)
    print(f"\n  recall@{args.k}: {hits}/{n} ({100.0*hits/n:.1f}%)")
    print(f"  correct document ranked first: {rank1}/{n} "
          f"({100.0*rank1/n:.1f}%)")
    print(f"  top-hit score: min {min(scores):.3f}  "
          f"median {sorted(scores)[n//2]:.3f}  max {max(scores):.3f}")

    print(f"\n=== NEGATIVE: {len(CAT2_OUT_OF_CONTEXT)} category-2 questions "
          f"the corpus must not answer ===")
    suspects = []
    for q in CAT2_OUT_OF_CONTEXT:
        got = index.search(q, k=1)
        if not got:
            continue
        h = got[0]
        if h.score >= args.suspect_score:
            suspects.append((q, h))
        if args.report:
            print(f"  {h.score:.3f} {h.chunk.chunk_id:34s} {q}")
    if suspects:
        print(f"\n  {len(suspects)} SUSPECT(S) -- read these and decide "
              f"whether the corpus now answers them:")
        for q, h in sorted(suspects, key=lambda x: -x[1].score):
            print(f"\n  score {h.score:.3f}  {h.chunk.chunk_id}")
            print(f"  Q: {q}")
            print(f"  > {h.chunk.text[:220]}...")
        print(f"\n  A suspect is not a defect. Similarity is not entailment "
              f"(§10.6);\n  the question is whether that chunk actually "
              f"answers that question.")
    else:
        print(f"\n  none scored at or above {args.suspect_score:.2f}. The "
              f"corpus does not appear\n  to have grown into category 2's "
              f"territory.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
