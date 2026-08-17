import ollama
from system_promt import SYSTEM_PROMPT
from document import FAKE_DOCUMENT, IT_SECURITY_POLICY
from employees import EMPLOYEES

current_user = "Elena Kowalski"


response = ollama.chat(model='qwen3:8b', messages=[
    {'role': 'system', 'content': SYSTEM_PROMPT},
    {'role': 'user', 'content': f"You are speaking with: {current_user}\n Employee List:\n {str(EMPLOYEES)}\n\nQuestion:What is my salary?"}
])



print(response['message']['content'])