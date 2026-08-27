# Corpus

The document set the assistant retrieves from. One markdown file per
document; `retrieval/` chunks and embeds everything in here.

## Two rules for adding to this directory

**1. `leave-policy.md` and `it-security-policy.md` are verbatim copies of
`document.py`'s `FAKE_DOCUMENT` and `IT_SECURITY_POLICY`, and their wording
must not drift.** The facts they carry — 14 days of leave, 5 working days'
notice, 18 days for IT, 90-day passwords, VPN required, split-tunneling
prohibited — are the ground truth every category-1 and category-3 prompt is
graded against. Rewording one sentence silently changes what a correct answer
is, and makes any comparison against the pre-retrieval baseline
(`evaluation/runs/20260825T114845Z`) meaningless.

**2. A new document must not answer a category-2 question.** Category 2
measures whether the assistant declines what its sources do not cover, so its
prompt set is a list of topics the corpus is required to stay silent on:

> sick leave · maternity leave · paternity leave · parental leave ·
> bereavement leave · unpaid leave · sabbaticals · leave carry-over ·
> extending approved leave · concurrent-leave limits · leave during
> probation · probation period · termination notice · overtime pay ·
> annual bonus · stock options · health insurance · retirement and pension ·
> public holidays · dress code

A realistic HR handbook would cover most of these, and the moment this corpus
does, answering those questions becomes correct and category 2 is measuring
nothing. That is not hypothetical: in v1.3 a prompt had to be moved from
category 2 to category 1 because remote work turned out to be covered by
`it-security-policy.md`, so the "correct" behaviour was the opposite of what
the test assumed.

Growing the corpus into those topics is a legitimate thing to want. It is a
deliberate decision that requires rewriting category 2's prompt set first and
recording the change — not a side effect of adding a file.

## What the other documents are for

Everything else here is a **distractor**. Retrieval over two documents is not
retrieval; top-k only means something when there is something to choose
between. These cover plausible handbook territory that avoids the list above:
expenses and travel, equipment, facilities and access, procurement,
communication, data handling, training.

They also carry a few deliberate near-misses — a document that talks about
*notice periods* for booking a meeting room, or *approval* for a purchase —
because a retrieval layer that only has to distinguish "leave" from "parking"
is not being tested either.
