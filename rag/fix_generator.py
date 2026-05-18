# rag/fix_generator.py
from rag.retriever import VulnerabilityRetriever
from llm.llm_wrapper import LLMWrapper  # adapt to your actual LLM module

class FixGenerator:
    def __init__(self, retriever: VulnerabilityRetriever, llm: LLMWrapper):
        self.retriever = retriever
        self.llm = llm

    def generate_fix(self, vulnerable_code: str, language: str = None, pattern: str = None) -> str:
        # Build query from vulnerable code and optional hints
        query = f"Fix this {language or ''} {pattern or ''} vulnerability: {vulnerable_code[:500]}"
        examples = self.retriever.retrieve_fixes(query, top_k=3)
        
        # Build few-shot prompt
        prompt = "You are a security expert. Based on the following examples of fixed code, generate a fixed version for the given vulnerable code.\n\n"
        for ex in examples:
            prompt += f"Example (Pattern: {ex['pattern']}, Language: {ex['language']}):\nFixed code:\n{ex['fixed_code']}\n\n"
        prompt += f"Now fix this vulnerable code:\n{vulnerable_code}\n\nFixed code:"
        
        return self.llm.generate(prompt)