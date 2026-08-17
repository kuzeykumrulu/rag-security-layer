import json
from system_promt import SYSTEM_PROMPT

config = {
    "ollama": {
        "OllamaGeneratorChat": {
            "system_prompt": SYSTEM_PROMPT
        }
    }
}

with open("garak_config.json", "w") as f:
    json.dump(config, f, indent=2)