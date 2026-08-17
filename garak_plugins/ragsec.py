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
from typing import List

from garak.attempt import Conversation
from garak.generators.ollama import OllamaGeneratorChat


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
                # The app wraps the user's question in the retrieval context.
                text = f"{self._context_block()}\n\nQuestion: {text}"
            messages.append({"role": turn.role, "content": text})

        return messages


DEFAULT_CLASS = "RagSecChat"
