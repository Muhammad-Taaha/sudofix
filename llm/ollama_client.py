import requests
import json
import time


class OllamaClient:
    def __init__(self, model="qwen2.5-coder:7b", host="http://localhost:11434"):
        self.model = model
        self.url = f"{host}/api/generate"
        self.timeout = 3000  # seconds

    def generate(self, prompt, max_retries=2):
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": 1024,  # limit output length
                "temperature": 0.2,  # lower randomness
            },
        }
        for attempt in range(max_retries + 1):
            try:
                response = requests.post(
                    self.url, json=payload, timeout=self.timeout)
                response.raise_for_status()
                data = response.json()
                result = data.get("response", "").strip()
                if result:
                    return result
                else:
                    print(f"⚠️ Attempt {
                          attempt+1}: Ollama returned empty response")
                    # Optionally, wait and retry
                    time.sleep(2)
            except requests.exceptions.Timeout:
                print(f"⚠️ Attempt {attempt+1}: Ollama timeout")
            except requests.exceptions.ConnectionError:
                print(f"⚠️ Attempt {
                      attempt+1}: Cannot connect to Ollama at {self.url}")
                print("   Make sure Ollama is running: 'ollama serve'")
                return None
            except Exception as e:
                print(f"⚠️ Attempt {attempt+1}: {e}")
        return None

    # Optional: test method
    def test(self):
        return self.generate("Say 'hello'")
