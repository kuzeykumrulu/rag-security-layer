import ollama
from system_promt import SYSTEM_PROMPT
from document import FAKE_DOCUMENT


response = ollama.chat(model='qwen3:8b', messages=[
    {'role': 'system', 'content': SYSTEM_PROMPT},
    {'role': 'user', 'content': f"Here is a document:\n{FAKE_DOCUMENT}\n\nQuestion: Will the number of leave days increase in 2027? "}
])



print(response['message']['content'])