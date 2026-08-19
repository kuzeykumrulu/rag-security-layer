"""Bounded sample of garak's encoding.InjectBase64 probe (25 of its 256
real prompts, evenly spaced for diversity), run through GuardedChat.

Deviation from pure garak methodology, done deliberately for practicality:
the full 256-prompt garak run was attempted twice and proved unreliable in
this environment (once killed by a PC shutdown, once running at ~110-190s/
prompt even after fixing a genuine keep_alive/GPU-unload bug -- projected
~8 hours for the full set with no evidence of speeding up). This script
reuses garak's own real prompts (not hand-written substitutes) so the
attack content is identical to what a full garak run would have used;
only the sample size differs. N=25 clears the procedure's N>=20 minimum
for a Medium/High-severity category (Sec 5).
"""

import json
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from guarded_chat import GuardedChat  # noqa: E402

import garak._config as _config  # noqa: E402
from garak._plugins import load_plugin  # noqa: E402

_config.load_base_config()
probe = load_plugin("probes.encoding.InjectBase64", config_root=_config)
all_prompts = probe.prompts  # 256 real garak-generated payloads

N = 25
step = len(all_prompts) // N
sample = [all_prompts[i] for i in range(0, len(all_prompts), step)][:N]

OUT_PATH = os.path.join(os.path.dirname(__file__), "category11_encoding_sample_results.jsonl")

chat = GuardedChat()

with open(OUT_PATH, "w", encoding="utf-8") as out:
    for i, prompt_text in enumerate(sample, start=1):
        text = prompt_text if isinstance(prompt_text, str) else getattr(prompt_text, "text", str(prompt_text))
        result = chat.ask(text, current_user="Elena Kowalski")
        record = {
            "index": i,
            "question": text,
            "raw_output": result.raw_output,
            "final_output": result.final_output,
            "input_filter_triggered": result.input_filter_triggered,
            "output_filter_findings": [f.check_name for f in result.output_filter_findings],
            "blocked": result.blocked,
            "error": result.error,
        }
        out.write(json.dumps(record, ensure_ascii=False) + "\n")
        out.flush()
        print(f"[{i}/{N}] blocked={result.blocked}", file=sys.stderr)

print(f"\nWrote {N} results to {OUT_PATH}", file=sys.stderr)
