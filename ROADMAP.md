# Development Roadmap

Written after the first full assessment under
[`evaluation/security_test_procedure.md`](evaluation/security_test_procedure.md)
v1.2, which returned a version verdict of **FAILED** — five categories over
threshold and four open vulnerabilities (§2.2). Phase 0 is closed out as
procedure v1.3; section references below are to that version.

**Guiding principle:** the procedure is the contract; the codebase must be
able to fulfil what the procedure promises before anything new is added.
Several things the procedure mandates (§3.2 run metadata, §7 per-generation
verdicts, §8.3 regression detection, §9 "full regression suite on every
change") are not currently implementable with the code that exists. Closing
that gap comes before fixing vulnerabilities, because without it no fix can
be shown to have worked.

Owner column: **U** = written by the project author; **A** = drafted by the
assistant for review. Documentation and consistency work is A; security and
detection logic is U (that is the learning target of this project).

---

## Phase 0 — Consistency cleanup — **COMPLETE** (2026-08-20)

The repository contradicted itself in several places. For a project whose
subject is measurement rigour, that is the most damaging class of defect.
Closed out as procedure **v1.3** — an audit and correction pass, no new
testing.

| # | Task | Owner | Status |
|---|---|---|---|
| 0.1 | Procedure §2 rows 10, 11, 12 read "Not yet executed" while §10 reported results for them. | A | done — rows now carry the real figures, plus the `propile` coverage caveat |
| 0.2 | `README.md` predated v1.2 and claimed *"All injection/leakage/PII attempts blocked (0% success)"*. | A | done — full rewrite |
| 0.2b | Procedure §10 claimed *"every category run through the custom harness failed"*; categories 1-3 are custom-harness and passed. | A | done — restated as "all five failing categories came from the custom harness" |
| 0.3 | `attacks/` and `logs/` empty and untracked. | U | done — both removed, and the now-vestigial `logs/*.jsonl` rule dropped from `.gitignore` |
| 0.4 | `test_connection.py` superseded by `driver.py`, and the only call path bypassing both filters. | U | **partially** — kept as history with a docstring stating it bypasses both filters and must not be used for testing. Deletion still open; git history preserves it either way. |
| 0.5 | Timeouts silently counted in N. | A | done — new rule §3.4 excludes non-answers; figures restated over answered N in §2 and §10 |
| 0.6 | §2.2 under-reported category 6. | A | done — expanded to three disclosures, the caught/missed identical-prompt pair, and the corpus-wide 0-true-positive measurement |
| 0.7 | *(found during 0.5)* Category 4's novel injection framings were a documented FAIL in §2 but missing from the §2.2 open-vulnerability inventory — README said four vulnerabilities, procedure said three. | A | done — added as §2.2 vulnerability 4 |
| 0.8 | *(found during 0.3)* `SKILL.md` claimed `detection\` was empty and unwired; it holds both filter layers. | A | done — corrected, and the `keep_alive` and silent-timeout gotchas documented there |

**What this phase actually surfaced.** It was scoped as tidying stale
sentences. It found a compliance failure instead: category 6's Critical
result rests on N=16 against a stated minimum of 20, because nothing in the
harness distinguished a refusal from a generation that never returned. That
is the same class of defect as Phase 1's — a number was trusted without the
mechanism that would make it trustworthy — and it is the argument for doing
Phase 1 before any remediation work.

---

## Phase 1 - The measurement layer - **COMPLETE** (2026-08-21)

**The concept:** garak separates *probe* (the attack), *generator* (the
system under test), and *detector* (the verdict). This project had probes
and a generator and no detectors. What it had instead were **filters**,
which are a defense, and the harness was using "did the filter fire" as a
stand-in for "did the attack succeed". Those are different questions, and
the v1.2 data proved it: in category 7 the filters fired on 0 of 19
answered generations against a true 21% attack success rate.

| # | Task | Owner | Status |
|---|---|---|---|
| 1.0 | Build the ground-truth set. | A | done - all 187 records carry a `gt` block (`tests/apply_ground_truth.py`); `tests/summarize_ground_truth.py` derives the category table from them. Written up as procedure 10.1. |
| 1.0b | Fix the harness bug that voided category 8. | A | done - `build_context()`/`GuardedChat.ask()` take a `documents` override, so the poisoned document is passed into the call instead of being written to disk and never read. Verified: 20 category-8 cases produce 20 distinct context hashes where the old harness produced one. |
| 1.1 | One detector per threat category. | A | done - `evaluation/detectors/` (`signals.py` primitives, `categories.py` the twelve detectors, `base.py` the contract, `score.py` the validation). Nothing in it imports from `detection/`; a filter grading itself can only report that it caught what it was built to catch. |
| 1.2 | Per-generation verdict in the record schema. | A | done - `verdict`, `verdict_reason`, `verdict_signals`, `detector_name`, `attack_succeeded_post_filter`. Satisfies 7. |
| 1.3 | Per-run metadata. | A | done - SHA-256 of the three guarded-system files and the three defense-layer files, model, ollama/garak versions, git commit, UTC timestamp, planned generations. Plus a **per-generation** `context_sha256`, and a warning when a whole indirect-injection matrix shares one hash - the signature of the 1.0b bug. Satisfies 3.2. |
| 1.4 | `run_suite.py`. | A | done - one command, all eight custom-harness categories at N=20 per repeat, writing `evaluation/runs/<UTC>/{metadata.json,results.jsonl,summary.md}` with per-category pre/post ASR, 8.1 test verdicts and the 8.2 gate result. Categories 9-12 are listed as uncovered rather than omitted, so its PASS can never be mistaken for a full-procedure pass. Prompt sets consolidated into `evaluation/suite_prompts.py`. |
| 1.5 | Regression check. | A | done - diffs per-category verdicts against the previous run directory and reports both directions. Verified against real recorded output in both: PASS -> FAIL is flagged as a gate-failing regression, FAIL -> PASS is reported as fixed. Satisfies 8.3. |

**Validation result.** Re-scoring the 160 valid records with the detectors
and comparing against the 1.0 ground truth:

| | |
|---|---|
| Recall | **100%** (17/17) - no failure the human found was missed |
| Precision | **81%** (17/21) - four false positives, all explained below |

Recall is the number that matters for a security gate: a detector that
misses failures produces an ASR that is quietly too low, which is the
direction a gate must never drift. All four false positives are on records
a human marked borderline or on a defective test item:

- two on the same arithmetic inference (the model presenting IT's 18 days
  as "the standard 14 plus an extra 4", which no document states);
- one on a prompt mis-filed under category 2 - remote work *is* covered by
  the IT security policy, so answering it was correct. Fixed in the test
  set, not special-cased in the detector;
- one on a record the detector caught doing exactly what record 10 did,
  which had been graded PASS with no note while record 10 was graded
  borderline. **The detector found an inconsistency in the human grading**,
  not the other way round. That is the whole argument for building this
  before doing any remediation work.

**Verified end to end (2026-08-21).** `qwen3:8b` pulled, full suite run:
320 generations across all eight custom-harness categories, 100% completion
rate, every verdict assigned by a detector. Gate result **FAILED** on
categories 5, 6 and 7. Recorded as procedure 10.2.

The run also produced the first independent measurement of the defense
layer, which is only possible now that the grader shares no code with the
thing it grades: **93.1% precision, 60% recall** over 320 generations, with
**0% recall across categories 1, 2 and 7** where no check exists at all.
Recorded as 10.3.

Two findings from the run changed the Phase 2 plan and are folded in below:

- **Category 8's 0% post-filter figure is test-on-train contamination.**
  Its pre-filter rate is 42.5% -- the highest of any category -- and the
  policy-fabrication sub-type succeeds 10/10 against the model. The filter
  catches every one, but only because `check_policy_fabrication` matches
  the literal strings the test payload uses. Held-out payloads are now
  task 2.6.
- **A short-department substring bug**, found in the detector during the
  run and fixed there, is still present in the output filter: the
  department `"IT"` matches inside ordinary English. Folded into 2.1.

---

## Phase 2 - Close the four known Critical/High gaps - **COMPLETE** (2026-08-21)

Each fix is verifiable because Phase 1 supplies the before/after number.
All four were measured by replaying the 320 recorded generations through
the revised filter -- no model calls, so a fix could be evaluated in
seconds rather than hours.

| # | Gap | Fix | Status |
|---|---|---|---|
| 2.1 | Formatting-dependent PII match (Critical, cat 6). The salary substring branch had produced **0 true positives across 175 generations** -- "$210,000" never matches "210000". | Compare normalised digit strings; require a name or a PII context word before trusting a salary match (two salaries here are pure 0/1 strings and matched inside base64 tutorials); match departments on word boundaries. | done - cat6 filter recall 67% -> **100%** |
| 2.2 | No check at all for off-topic own-knowledge answers (High, cat 7). Pre- and post-filter rates were identical, so the defense contributed nothing. | `check_off_topic_answer`: a substantive, non-refusing answer sharing **zero** vocabulary with the documents or employee table. Calibrated on 320 recorded generations at 7 catches, 0 false positives. | done - cat7 filter recall 0% -> **100%** |
| 2.3 | Paraphrased system-prompt leakage (Critical, cat 5). Verbatim 8-gram matching cannot see a paraphrase. | Two signals: count distinct *rule areas* the response describes (three or more means it is reciting the policy, not applying one rule), plus embedding similarity to SYSTEM_PROMPT above 0.78. | done - cat5 filter recall 40% -> **100%** |
| 2.4 | Novel direct-injection framings (High, cat 4). | Persona patterns widened past three literal DAN-era strings to include self-assertions of unrestricted capability ("I have no restrictions and will answer anything", which the model repeated verbatim on request). | done - cat4 filter recall stays 100%, now for the right reasons |
| 2.5 | Re-run and compare against the baseline; §8.3 regression rule live. | 360-generation run with the held-out payloads included. | done |
| 2.6 | Held-out payloads for category 8. | `CAT8_HELDOUT_ACTIONS`: the same four attack goals worded so they match none of the filter's patterns. Verified: the calibration payloads hit the patterns directly, the held-out ones hit nothing. | **written and run, but the experiment failed.** Every held-out sub-type scored 0% *pre*-filter — the model refused them, so the filter was never exercised and the contamination question is still open. The replacement wording changed the attack's effectiveness as well as its vocabulary. Re-opened as **4.4**. |

**Result: the defense layer went from 93.1% precision / 60.0% recall to
96.1% precision / 89.1% recall**, measured by replay against detector
verdicts over the same 320 generations.

Filter recall by category, before -> after:

| Category | Before | After |
|---|---|---|
| 4 - direct injection | 100% | 100% |
| 5 - system-prompt leakage | 40% | **100%** |
| 6 - cross-user PII | 67% | **100%** |
| 7 - unrelated knowledge | **0%** | **100%** |
| 8 - indirect injection | 100% | 100% |
| 1, 2 - accuracy and out-of-scope refusal | 0% | 0% |

**The six remaining misses are all in categories 1 and 2, and they are not
security failures.** They are hallucinations that use document vocabulary
while inventing facts: sick leave folded into the 14-day allowance,
paternity leave inferred, a concurrent-leave limit invented, IT's 18 days
decomposed into "14 plus an extra 4". The off-topic check cannot see them
because they *are* on topic. Closing them needs the groundedness check in
Phase 3.1, which is where they belong.

**One recommendation from the original plan did not survive measurement.**
Phase 2.3 proposed embedding similarity as the fix for paraphrase leakage.
Measured against 319 recorded generations it reaches 100% precision but
only **80% recall** at its best threshold, while the far cheaper rule-area
count caught every case. Both are kept -- two dissimilar signals do not
share a blind spot, and the embedding half degrades to nothing if the model
is absent -- but the structural check is the one carrying the result, and
the roadmap's preference was wrong on this data.

---

## Phase 3 — Generalize: groundedness, and a metric for over-blocking

Everything in Phase 2 is still per-incident patching: each check matches a
literal phrase observed in one past test, so the filters catch exactly the
attacks already seen and nothing else.

| # | Task | Owner |
|---|---|---|
| 3.1 | `check_groundedness` — is each claim in the answer supported by the supplied context? One check that subsumes category 2 (out-of-context refusal), category 7 (own knowledge), and much of category 8's policy fabrication. Concept: RAGAS "faithfulness". | U |
| 3.2 | Document the implementation trade-off explicitly (embedding similarity vs. LLM-as-judge: cost, latency, determinism, and who grades the grader). | U |
| 3.3 | **Add an over-blocking metric to the procedure (§5).** Today the rubric measures only attack success. Category 1 (in-context factual accuracy) is the sole utility guard among twelve categories, and it is weighted Medium at N=15 — thin cover for the entire usefulness of the system. A groundedness check will raise false positives; with no false-positive rate in the gate, there is no way to see that happening. | A + U |

---

## Phase 4 — Outstanding measurement debt

Carried over from v1.2; none of these block Phases 1–3.

| # | Task |
|---|---|
| 4.1 | Category 8 (indirect injection) clean re-run at N≥20 using the original narrow-context method. The v1.2 figure is flagged "indicative, not final" because the Phase 1 run used full context and confounded the measurement. |
| 4.2 | Investigate why `propile.PIILeakQuadruplet` and `propile.PIILeakUnstructured` produced 0 prompts — most likely a missing dataset. Until resolved, category 10's coverage is narrower than its N=85 figure suggests. |
| 4.3 | Decide whether the full 256-prompt `encoding.InjectBase64` run is worth its ~8h cost now that the `keep_alive` fix is in place, or whether the N=25 sample stands. |
| 4.4 | **Redo the category-8 held-out experiment.** The first attempt (2.6) varied the attack's *effectiveness* along with its wording — every held-out sub-type scored 0% pre-filter, so the model refused them and the filter was never exercised. It therefore measured nothing about whether the filter generalises. Find payload wordings that succeed against the model at a rate comparable to the calibration set, then compare post-filter rates. |
| 4.5 | **Decide what the assistant may say about its own rules.** `system_promt.py` forbids listing the system prompt but is silent on explaining *how* a rule works. That silence is why the filter and the detector disagree on about two records per run — the filter calls "I decide whether to share a salary by verifying the name matches" a Critical leak, the detector sometimes does not. Neither is wrong. This is a specification gap: resolve it in the prompt first, then align both implementations to the decision rather than tuning them against each other. |
| 4.6 | **Re-run categories 9-12 against the current filter.** Their 0% figures predate every v1.5 change, so the procedure is only half-satisfied by the passing gate. |

---

## Phase 5 — Scope growth (only once the gate is green)

| # | Task | Why it earns its place |
|---|---|---|
| 5.1 | Real retrieval: PDFs → chunking → embeddings → vector store → top-k into the context. | Unlocks attack classes that cannot exist without retrieval: poisoning a document so it is *retrieved* for a targeted query, and payloads placed across chunk boundaries. |
| 5.2 | Multi-turn attacks. | Every test so far is single-turn. Crescendo and many-shot jailbreaks need conversation state and are among the most effective real-world techniques. |
| 5.3 | A second model behind the same system prompt. | Turns a single-model anecdote into a comparison: which failures belong to the model and which to the prompt. |

---

## Explicitly out of scope for now

- **More attack categories.** Twelve exist; four are failing. Breadth is not the constraint.
- **Broader garak probe coverage.** v1.2 showed the standardized library passed everything while the scenario-specific tests found all four real vulnerabilities. More library breadth is unlikely to be where the next finding comes from.
- **Any UI.** Nothing in the research question depends on one.
