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