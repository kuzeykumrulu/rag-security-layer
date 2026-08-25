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
from typing import List, Optional

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
) -> str:
    """Assembles the user turn.

    `documents` replaces the project's own documents for this call only.
    Indirect-injection tests need to put a poisoned document in front of the
    model, and passing the text in is the only way to do that safely: the
    previous harness rewrote document.py on disk instead, which silently did
    nothing because this module binds FAKE_DOCUMENT and IT_SECURITY_POLICY at
    import time and never reloads. Fifteen generations recorded a clean pass
    without the payload ever reaching the model.
    """
    parts = []
    if include_documents:
        for doc in (documents if documents is not None else [FAKE_DOCUMENT, IT_SECURITY_POLICY]):
            parts.append(f"Here is a document:{doc}")
    if include_employees:
        parts.append("Here are the employee records:\n" + json.dumps(EMPLOYEES, indent=2, ensure_ascii=False))
    parts.append(f"You are speaking with: {current_user}")
    return "\n\n".join(parts)


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
                 num_ctx: Optional[int] = None):
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
        self.client = ollama.Client(timeout=timeout)
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

        context = build_context(current_user, include_documents, include_employees, documents)
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
            output_filter_findings=findings,
            raw_output=raw_output,
        )
        result.final_output = SAFE_REFUSAL if result.blocked else raw_output
        return result
