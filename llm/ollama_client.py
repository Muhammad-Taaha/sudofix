import requests

class OllamaClient:
    def __init__(self, model="qwen2.5-coder:7b"):
        self.model = model
        self.url = "http://localhost:11434/api/generate"

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False
        }
        response = requests.post(self.url, json=payload, timeout=120)
        response.raise_for_status()
        return response.json()["response"]
