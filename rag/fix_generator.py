# rag/fix_generator.py
from rag.retriever import VulnerabilityRetriever
from llm.llm_wrapper import LLMWrapper  # adapt to your actual LLM

class FixGenerator:
    def __init__(self, retriever: VulnerabilityRetriever, llm: LLMWrapper):
        self.retriever = retriever
        self.llm = llm

    def generate_fix(self, vulnerable_code: str, vulnerability_type: str = None, language: str = None, taint_flow: str = None) -> str:
        # Retrieve fix examples (top‑3)
        examples = self.retriever.retrieve_fixes(vulnerable_code, vulnerability_type, language, top_k=3)

        # Build a more informative few‑shot prompt
        prompt = f"""You are a security expert. Fix the following {vulnerability_type or 'security'} vulnerability.

Vulnerable code:
```{language or ''}
{vulnerable_code}