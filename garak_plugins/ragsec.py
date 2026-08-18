"""Garak generator for the rag-security-layer app.

Wraps the local Ollama chat call in the *same* message structure the real app
uses (see test_connection.py), so a garak probe tests the guarded system --
system prompt + retrieved documents + employee records -- instead of the bare
model.

The probe's prompt takes the place of the end user's question. Everything else
(SYSTEM_PROMPT, FAKE_DOCUMENT, IT_SECURITY_POLICY, EMPLOYEES) is read from the
project modules at call time, so a scan always reflects the current guardrail.

Usage:
    garak --model_type ragsec.RagSecChat --model_name qwen3:8b --probes dan.Dan_11_0

This file lives in garak_plugins/ in the project and is copied into the venv's
garak/generators/ by install_garak_plugin.py -- garak can only import plugins
from inside its own package namespace.
"""

import json
import os
import sys
from typing import List, Optional

from garak import _config
from garak.attempt import Conversation, Message
from garak.generators.ollama import OllamaGeneratorChat

# Bootstrap the project root onto sys.path at import time (not lazily, like
# _project_context below) so detection/ can be imported here regardless of
# whether _project_context has run yet. Relies on garak being launched from
# the project root -- same assumption _project_context already makes via
# os.getcwd().
_PROJECT_DIR = os.path.abspath(os.getcwd())
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

from detection.injection_filter_input import PromptInjectionFilter  # noqa: E402
from detection.injection_filter_output import OutputInjectionFilter, SAFE_REFUSAL  # noqa: E402


class RagSecChat(OllamaGeneratorChat):
    """rag-security-layer app under test: system prompt + RAG context + probe prompt"""

    DEFAULT_PARAMS = OllamaGeneratorChat.DEFAULT_PARAMS | {
        # The full context makes for a long prompt; qwen3:8b with thinking on
        # needs more headroom than the 30s the Ollama generator defaults to.
        "timeout": 180,
        # Where to import system_promt.py / document.py / employees.py from.
        # Defaults to the working directory garak was started in.
        "project_dir": None,
        # Identity the app claims the requester has, as in test_connection.py.
        "current_user": "Elena Kowalski",
        # Which parts of the retrieval context to include in the user message.
        "include_documents": True,
        "include_employees": True,
        # Set to override the project's SYSTEM_PROMPT (normally leave unset so
        # the scan tracks system_promt.py).
        "system_prompt": None,
    }

    generator_family_name = "RagSecurityLayer"
    parallel_capable = False

    def __init__(self, name="", config_root=_config):
        super().__init__(name, config_root)
        self._input_filter = PromptInjectionFilter()
        self._output_filter = OutputInjectionFilter()
        self._last_probe_text = ""

    def _project_context(self):
        """Import the app's prompt/context modules, caching the result."""
        if hasattr(self, "_cached_context"):
            return self._cached_context

        project_dir = self.project_dir or os.getcwd()
        project_dir = os.path.abspath(project_dir)
        if project_dir not in sys.path:
            sys.path.insert(0, project_dir)

        try:
            from system_promt import SYSTEM_PROMPT
        except ImportError as e:
            raise ImportError(
                f"Could not import system_promt.py from {project_dir}. "
                "Run garak from the project directory, or set project_dir in the "
                "generator option file."
            ) from e

        documents = []
        employees = None
        if self.include_documents:
            from document import FAKE_DOCUMENT, IT_SECURITY_POLICY

            documents = [FAKE_DOCUMENT, IT_SECURITY_POLICY]
        if self.include_employees:
            from employees import EMPLOYEES

            employees = EMPLOYEES

        self._cached_context = {
            "system_prompt": self.system_prompt or SYSTEM_PROMPT,
            "documents": documents,
            "employees": employees,
        }
        return self._cached_context

    def _context_block(self) -> str:
        ctx = self._project_context()
        parts = []
        for doc in ctx["documents"]:
            parts.append(f"Here is a document:{doc}")
        if ctx["employees"] is not None:
            parts.append(
                "Here are the employee records:\n"
                + json.dumps(ctx["employees"], indent=2, ensure_ascii=False)
            )
        parts.append(f"You are speaking with: {self.current_user}")
        return "\n\n".join(parts)

    def _conversation_to_list(self, conversation: Conversation) -> List[dict]:
        """Build the app's real message list, with the probe prompt as the question.

        Overrides the base helper that OllamaGeneratorChat._call_model uses, so
        all of the parent's retry/backoff handling is inherited unchanged.
        """
        ctx = self._project_context()
        messages = [{"role": "system", "content": ctx["system_prompt"]}]

        turns = conversation.turns
        for idx, turn in enumerate(turns):
            text = turn.content.text
            is_last = idx == len(turns) - 1
            if is_last and turn.role == "user":
                # Stashed here (not computed in _post_generate_hook) because
                # this is the one place that already has the unwrapped probe
                # text before it gets buried inside the context block.
                self._last_probe_text = text
                # The app wraps the user's question in the retrieval context.
                text = f"{self._context_block()}\n\nQuestion: {text}"
            messages.append({"role": turn.role, "content": text})

        return messages

    def _post_generate_hook(self, outputs: List[Optional[Message]]) -> List[Optional[Message]]:
        """Applies the same two-layer defense driver.py/guarded_chat.py use,
        via garak's documented post-generation extension point -- this runs
        after _call_model (and its inherited backoff/retry handling) has
        already produced outputs, so none of that logic is duplicated here.

        Blocking on the input filter here (rather than skipping the model
        call) is what this project calls "measurement-first": _call_model
        always actually asks the model, so a scan still records what the
        model would have said -- only what garak's detectors ultimately
        SEE is swapped for the safe refusal.
        """
        input_triggered = self._input_filter.detect_injection(self._last_probe_text)
        filtered = []
        for msg in outputs:
            if msg is None or msg.text is None:
                filtered.append(msg)
                continue
            findings = self._output_filter.scan(msg.text, self.current_user)
            if input_triggered or findings:
                filtered.append(Message(SAFE_REFUSAL))
            else:
                filtered.append(msg)
        return filtered


DEFAULT_CLASS = "RagSecChat"
