"""Drive the rag-security-layer guarded assistant with an arbitrary question.

This is test_connection.py generalized: it builds the exact same message
structure (SYSTEM_PROMPT + FAKE_DOCUMENT + IT_SECURITY_POLICY + EMPLOYEES +
a "You are speaking with" identity line) that test_connection.py and the
garak_plugins/ragsec.py generator use, but accepts any question and any
claimed identity instead of a hardcoded one -- so you can actually probe the
app's behavior instead of just replaying its one canned example.

Run from anywhere; it locates the project root relative to this file and
imports system_promt.py / document.py / employees.py from there.

Usage:
    python driver.py "How many days of leave am I entitled to?"
    python driver.py --user "Elena Kowalski" "What is my salary?"
    python driver.py --user "Elena Kowalski" "What is Sebastian Muller's salary?"
    python driver.py --no-documents --no-employees "What's the capital of France?"
    python driver.py --raw   # print the exact messages sent, then exit (no model call)

Requires a local Ollama server (default http://127.0.0.1:11434) with the
target model pulled (default qwen3:8b -- `ollama pull qwen3:8b`).
"""

import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import ollama  # noqa: E402
from system_promt import SYSTEM_PROMPT  # noqa: E402
from document import FAKE_DOCUMENT, IT_SECURITY_POLICY  # noqa: E402
from employees import EMPLOYEES  # noqa: E402


def build_context(current_user: str, include_documents: bool, include_employees: bool) -> str:
    parts = []
    if include_documents:
        parts.append(f"Here is a document:{FAKE_DOCUMENT}")
        parts.append(f"Here is a document:{IT_SECURITY_POLICY}")
    if include_employees:
        parts.append("Here are the employee records:\n" + json.dumps(EMPLOYEES, indent=2, ensure_ascii=False))
    parts.append(f"You are speaking with: {current_user}")
    return "\n\n".join(parts)


def build_messages(question: str, current_user: str, include_documents: bool, include_employees: bool):
    context = build_context(current_user, include_documents, include_employees)
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"{context}\n\nQuestion: {question}"},
    ]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("question", nargs="?", default="How many days of leave am I entitled to?")
    p.add_argument("--user", default="Elena Kowalski", help='identity for the "You are speaking with" line')
    p.add_argument("--model", default="qwen3:8b")
    p.add_argument("--no-documents", action="store_true", help="omit FAKE_DOCUMENT/IT_SECURITY_POLICY from context")
    p.add_argument("--no-employees", action="store_true", help="omit the employee records from context")
    p.add_argument("--timeout", type=int, default=180, help="seconds; qwen3 thinking mode can be slow")
    p.add_argument("--raw", action="store_true", help="print the exact messages that would be sent, then exit")
    args = p.parse_args()

    messages = build_messages(
        args.question, args.user, not args.no_documents, not args.no_employees
    )

    if args.raw:
        for m in messages:
            print(f"--- {m['role']} ({len(m['content'])} chars) ---")
            print(m["content"])
        return

    client = ollama.Client(timeout=args.timeout)
    resp = client.chat(model=args.model, messages=messages)
    print(resp["message"]["content"])


if __name__ == "__main__":
    main()
