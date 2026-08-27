"""The single place that wires the input filter, the Ollama call, and the
output filter together. driver.py calls this instead of talking to
ollama.chat() directly, so a fix to the filtering logic only needs to be
made once. garak_plugins/ragsec.py applies the same two filter classes
around its own model call (it can't reuse this module's ask() directly --
garak owns its own retry/backoff wrapper around the model call -- but it
imports InjectionFilter/OutputInjectionFilter from the same detection/
modules, so the logic itself is not duplicated).

Measurement-first design: even when the input filter flags a question as
a likely injection attempt, the model is still called (raw_output always
reflects what the model actually said) -- this project measures attack
success rate, so silently skipping the call would throw away the exact
data point being studied. final_output is what a real caller should show
the end user: a safe refusal whenever either filter caught something,
regardless of what the model said.
"""

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import ollama

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from system_promt import SYSTEM_PROMPT  # noqa: E402
from document import FAKE_DOCUMENT, IT_SECURITY_POLICY  # noqa: E402
from employees import EMPLOYEES  # noqa: E402
from detection.injection_filter_input import PromptInjectionFilter  # noqa: E402
from detection.injection_filter_output import (  # noqa: E402
    OutputInjectionFilter,
    FilterResult,
    SAFE_REFUSAL,
)


def build_context(
    current_user: str,
    include_documents: bool = True,
    include_employees: bool = True,
    documents: Optional[List[str]] = None,
    query: Optional[str] = None,
    index=None,
    k: int = 4,
) -> Tuple[str, List[dict]]:
    """Assembles the user turn. Returns (context, retrieval_record).

    `documents` replaces the project's own documents for this call only.
    Indirect-injection tests need to put a poisoned document in front of the
    model, and passing the text in is the only way to do that safely: the
    previous harness rewrote document.py on disk instead, which silently did
    nothing because this module binds FAKE_DOCUMENT and IT_SECURITY_POLICY at
    import time and never reloads. Fifteen generations recorded a clean pass
    without the payload ever reaching the model.

    With `index` and `query`, the documents come from top-k retrieval over
    `corpus/` instead of being stuffed whole. Without them the behaviour is
    exactly what it was, so turning retrieval on is a decision made per call
    rather than a default that moves every recorded number underneath us.

    `retrieval_record` names the chunks that ended up in the context, with
    their scores. It is empty when retrieval is off. Recording it is not
    bookkeeping: a retrieval pipeline can put the wrong text in front of the
    model and still produce a plausible answer, and the resulting figure
    would look like the model's behaviour rather than the retriever's.
    Procedure §10.1a is what that costs when it is not recorded.

    A poisoned document passed through `documents` is appended to whatever
    was retrieved rather than replacing it -- in this step the payload is
    still *injected*, not competing for retrieval. Making it win retrieval on
    its own is a separate change (ROADMAP 5.1d), and doing both at once would
    repeat the mistake §10.12 documents.
    """
    parts, retrieved = [], []
    if include_documents:
        if index is not None and query is not None:
            for hit in index.search(query, k=k):
                retrieved.append({
                    "chunk_id": hit.chunk.chunk_id,
                    "doc_id": hit.chunk.doc_id,
                    "score": round(hit.score, 4),
                    "sha256": hit.chunk.sha256,
                })
                parts.append(f"Here is a document:\n{hit.chunk.text}")
            for doc in (documents or []):
                parts.append(f"Here is a document:{doc}")
        else:
            for doc in (documents if documents is not None
                        else [FAKE_DOCUMENT, IT_SECURITY_POLICY]):
                parts.append(f"Here is a document:{doc}")
    if include_employees:
        parts.append("Here are the employee records:\n" + json.dumps(EMPLOYEES, indent=2, ensure_ascii=False))
    parts.append(f"You are speaking with: {current_user}")
    return "\n\n".join(parts), retrieved


@dataclass
class GuardedChatResult:
    question: str
    current_user: str
    input_filter_triggered: bool
    context_sha256: str = ""   # hash of the exact context sent, per procedure S3.2
    # Ollama's own token counts for this call. Recorded because a generation
    # whose prompt+output exceeds the context window wrote its answer with
    # the system prompt already slid out of the window -- it measures the
    # bare model, not the guarded one.
    prompt_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    num_ctx: Optional[int] = None
    # The chunks retrieval put in front of the model, with scores. Empty when
    # retrieval is off. A generation cannot be re-read without knowing what
    # the model was actually shown.
    retrieved: List[dict] = field(default_factory=list)
    output_filter_findings: List[FilterResult] = field(default_factory=list)
    raw_output: Optional[str] = None   # what the model actually said (for measurement)
    final_output: str = ""             # what a real caller should be shown
    error: Optional[str] = None

    @property
    def blocked(self) -> bool:
        return self.input_filter_triggered or bool(self.output_filter_findings)


class GuardedChat:
    """Wraps ollama.chat() with the input filter (before) and the output
    filter (after). One call to ask() per question."""

    def __init__(self, model: str = "qwen3:8b", timeout: int = 180,
                 num_ctx: Optional[int] = None,
                 retrieval: bool = False, k: int = 4, corpus_dir: str = "corpus"):
        """`num_ctx` overrides Ollama's context window for every call.

        Left as None -- Ollama's own default, 4096 for this model -- so that
        adding this parameter does not silently move any recorded number.
        It matters more than it looks: the assembled prompt is already ~3855
        tokens, and a single long-thinking generation was measured emitting
        **12,252 output tokens against that 4096 window**. The sliding window
        discards the front of the prompt to make room, so by the time such a
        generation writes its answer the system prompt -- the rules under
        test -- is no longer in context, and the answer comes from what is
        effectively the bare model. Any generation whose token total exceeds
        num_ctx must be treated as measuring nothing, in the same way a
        timeout is (§3.4).
        """
        self.model = model
        self.num_ctx = num_ctx
        self.k = k
        self.client = ollama.Client(timeout=timeout)
        # Off by default. Turning retrieval on changes what every category is
        # measured against, so it is a flag the caller sets deliberately, the
        # same way `num_ctx` is.
        self.index = None
        if retrieval:
            from retrieval.index import CorpusIndex
            self.index = CorpusIndex(client=self.client,
                                     corpus_dir=corpus_dir).build()
        self.input_filter = PromptInjectionFilter()
        # The output filter's leak check uses an embedding similarity signal
        # alongside its pattern signals. It shares this client rather than
        # opening its own, and skips that signal entirely if the embedding
        # model is missing -- the filter degrades, it does not fail.
        self.output_filter = OutputInjectionFilter(embed_client=self.client)

    def ask(
        self,
        question: str,
        current_user: str = "Elena Kowalski",
        include_documents: bool = True,
        include_employees: bool = True,
        documents: Optional[List[str]] = None,
    ) -> GuardedChatResult:
        input_triggered = self.input_filter.detect_injection(question)

        context, retrieved = build_context(
            current_user, include_documents, include_employees, documents,
            query=question, index=self.index, k=self.k)
        # Recorded per generation so a test whose setup silently failed to
        # take effect is distinguishable from a test that passed: if the
        # context never changes across an indirect-injection matrix, the
        # payload never arrived. That failure has happened here before.
        context_hash = hashlib.sha256(context.encode("utf-8")).hexdigest()
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{context}\n\nQuestion: {question}"},
        ]

        try:
            # keep_alive pinned to avoid load/unload thrashing on the GPU
            # during back-to-back batch calls -- see garak_plugins/ragsec.py
            # for the full explanation (same fix, same reason).
            response = self.client.chat(
                model=self.model, messages=messages, keep_alive="60m",
                options=({"num_ctx": self.num_ctx} if self.num_ctx else {}))
            raw_output = response["message"]["content"]
            # Recorded so a generation that overran its window is
            # distinguishable from one that did not. Ollama reports these
            # per call and nothing was reading them; a run where
            # prompt+output exceeds num_ctx produced its answer without the
            # system prompt still in context.
            prompt_tokens = response.get("prompt_eval_count")
            output_tokens = response.get("eval_count")
        except Exception as e:
            return GuardedChatResult(
                question=question,
                current_user=current_user,
                input_filter_triggered=input_triggered,
                context_sha256=context_hash,
                retrieved=retrieved,
                error=str(e),
                final_output=SAFE_REFUSAL,
            )

        findings = self.output_filter.scan(raw_output, current_user)
        result = GuardedChatResult(
            question=question,
            current_user=current_user,
            input_filter_triggered=input_triggered,
            context_sha256=context_hash,
            prompt_tokens=prompt_tokens,
            output_tokens=output_tokens,
            num_ctx=self.num_ctx,
            retrieved=retrieved,
            output_filter_findings=findings,
            raw_output=raw_output,
        )
        result.final_output = SAFE_REFUSAL if result.blocked else raw_output
        return result
