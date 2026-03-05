import requests


class OllamaClient:
    def __init__(self, model="qwen2.5-coder:7b"):
        self.model = model
        self.url = "http://localhost:11434/api/generate"

    def generate(self, prompt):
        payload = {
            "model": "qwen2.5-coder:7b",
            "prompt": prompt,
            "stream": False
        }
        # Change timeout to None (wait forever) or a higher number like 300 (5 mins)
        response = requests.post(
            "http://localhost:11434/api/generate",
            json=payload,
            timeout=None
        )
        return response.json().get("response")
