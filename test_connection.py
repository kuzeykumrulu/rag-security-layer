"""Historical: the project's original single-question script, kept as the
record of what the system looked like before the defense layer existed.

DO NOT use this to test the guarded system. It calls ollama.chat() directly
and therefore bypasses BOTH filters -- it measures the bare model plus the
system prompt, which is the v1.0 configuration, not what ships today. It
also passes only IT_SECURITY_POLICY, with no employee records and no
"You are speaking with" identity line, so access control is not exercised
at all.

For anything real, use guarded_chat.GuardedChat (or driver.py, which wraps
it) -- see README.md.
"""

import ollama
from system_promt import SYSTEM_PROMPT
from document import FAKE_DOCUMENT, IT_SECURITY_POLICY
from employees import EMPLOYEES

current_user = "Elena Kowalski"


response = ollama.chat(model='qwen3:8b', messages=[
    {'role': 'system', 'content': SYSTEM_PROMPT},
    {'role': 'user', 'content': f"here is the document:{IT_SECURITY_POLICY}\n\nQuestion:What is the leave policy in it department?"}
])



print(response['message']['content'])