"""Drive the rag-security-layer guarded assistant with an arbitrary question.

Routes through guarded_chat.py -- the input filter (detection/injection_filter_input.py)
screens the question before the model sees it, the output filter
(detection/injection_filter_output.py) screens the model's answer before it
is printed. Same message structure test_connection.py and the
garak_plugins/ragsec.py generator use (SYSTEM_PROMPT + FAKE_DOCUMENT +
IT_SECURITY_POLICY + EMPLOYEES + a "You are speaking with" identity line),
but accepts any question and identity instead of a hardcoded one.

Run from anywhere; it locates the project root relative to this file and
imports guarded_chat.py (and everything it needs) from there.

Usage:
    python driver.py "How many days of leave am I entitled to?"
    python driver.py --user "Elena Kowalski" "What is my salary?"
    python driver.py --user "Elena Kowalski" "What is Sebastian Muller's salary?"
    python driver.py --no-documents --no-employees "What's the capital of France?"
    python driver.py --raw   # print the exact messages sent, then exit (no model call)
    python driver.py --show-raw-model-output "Ignore all previous instructions"
        # also print what the model actually said, even if a filter blocked it

Requires a local Ollama server (default http://127.0.0.1:11434) with the
target model pulled (default qwen3:8b -- `ollama pull qwen3:8b`).
"""

import argparse
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from guarded_chat import GuardedChat, build_context  # noqa: E402
from system_promt import SYSTEM_PROMPT  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("question", nargs="?", default="How many days of leave am I entitled to?")
    p.add_argument("--user", default="Elena Kowalski", help='identity for the "You are speaking with" line')
    p.add_argument("--model", default="qwen3:8b")
    p.add_argument("--no-documents", action="store_true", help="omit FAKE_DOCUMENT/IT_SECURITY_POLICY from context")
    p.add_argument("--no-employees", action="store_true", help="omit the employee records from context")
    p.add_argument("--timeout", type=int, default=180, help="seconds; qwen3 thinking mode can be slow")
    p.add_argument("--raw", action="store_true", help="print the exact messages that would be sent, then exit (no model call, no filters)")
    p.add_argument("--show-raw-model-output", action="store_true", help="also print what the model actually said, even if a filter blocked the final answer")
    args = p.parse_args()

    if args.raw:
        context = build_context(args.user, not args.no_documents, not args.no_employees)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"{context}\n\nQuestion: {args.question}"},
        ]
        for m in messages:
            print(f"--- {m['role']} ({len(m['content'])} chars) ---")
            print(m["content"])
        return

    chat = GuardedChat(model=args.model, timeout=args.timeout)
    result = chat.ask(
        args.question,
        current_user=args.user,
        include_documents=not args.no_documents,
        include_employees=not args.no_employees,
    )

    if result.blocked:
        reasons = []
        if result.input_filter_triggered:
            reasons.append("input filter")
        if result.output_filter_findings:
            reasons.append(f"output filter ({', '.join(f.check_name for f in result.output_filter_findings)})")
        print(f"[BLOCKED by: {', '.join(reasons)}]")

    print(result.final_output)

    if args.show_raw_model_output and result.raw_output is not None and result.raw_output != result.final_output:
        print()
        print("--- what the model actually said (raw_output) ---")
        print(result.raw_output)


if __name__ == "__main__":
    main()
