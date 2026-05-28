import hashlib
import traceback
import os
from typing import Optional, List, Dict, Any

from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner, RepoWalker
from vector_store.store import VectorStore
from llm.ollama_client import OllamaClient
from git_controller.git_checker import Checker
from controllers.data_base_controller import Postgres
from sastscanner.core.rule_engine import RuleEngine
from sastscanner.findings.finding import Finding
from rag.retriever import VulnerabilityRetriever   # your reranker RAG


class CliAgent:
    def __init__(self, repo_path: str, command: str, dry_run: bool = False):
        self.repo_path = repo_path
        self.command = command
        self.dry_run = dry_run

        # Core components
        self.vector_store = VectorStore()                     # for other tasks (e.g., general embeddings)
        self.llm = OllamaClient()
        self.redis_manager = RedisManager()
        self.redis_client = self.redis_manager.connect()
        self.git_controller = Checker(command)
        self.data_base = Postgres()
        self.sast_engine = RuleEngine()
        # Reranker RAG for vulnerability fixes
        self.fix_retriever = VulnerabilityRetriever(chroma_dir="./rag/chroma_db_reranker_ready")

        # Ensure fixes directory exists
        os.makedirs("fixes", exist_ok=True)

    # ----------------------------------------------------------------------
    # Helper: map a finding (rule name / message) to a vulnerability pattern
    # ----------------------------------------------------------------------
    def _infer_pattern_from_finding(self, finding: Finding) -> Optional[str]:
        """Convert a SAST finding into one of the known pattern names."""
        rule_text = (finding.rule_name + " " + finding.message).lower()
        if any(k in rule_text for k in ["sql", "database", "query", "injection"]):
            return "sql_injection"
        if any(k in rule_text for k in ["command", "exec", "shell", "os", "system"]):
            return "command_injection"
        if any(k in rule_text for k in ["xss", "script", "alert", "cross-site"]):
            return "xss"
        if any(k in rule_text for k in ["auth", "login", "permission", "access", "role"]):
            return "auth"
        if any(k in rule_text for k in ["path", "traversal", "directory", "file", "read"]):
            return "file"
        if any(k in rule_text for k in ["crypto", "encrypt", "decrypt", "secret", "key"]):
            return "crypto"
        if any(k in rule_text for k in ["deserialization", "pickle", "unserialize"]):
            return "deserialization"
        if any(k in rule_text for k in ["data", "exposure", "leak", "info"]):
            return "data_exposure"
        if any(k in rule_text for k in ["logic", "business", "workflow"]):
            return "business_logic"
        if any(k in rule_text for k in ["config", "misconfiguration"]):
            return "config"
        return None

    # ----------------------------------------------------------------------
    # Core processing logic (caching, SAST, RAG, LLM)
    # ----------------------------------------------------------------------
    def _process_logic(self, chunk_dict: Dict[str, Any], task_prompt: str) -> Optional[str]:
        content = chunk_dict.get("content", "")
        metadata = chunk_dict.get("metadata", {})
        file_name = chunk_dict.get("file_name", "Unknown File")
        detected_lang = metadata.get("language", "").lower()

        if not detected_lang:
            print(f"⚠️ Unknown language for {file_name}, skipping")
            return None

        if self.dry_run:
            print(f"✅ [DRY RUN] Parsed {file_name} [{detected_lang}]")
            return "dry_run_output"

        # Cache key includes language, content, and task
        cache_key = hashlib.sha256(
            f"{detected_lang}:{content}:{task_prompt}".encode()
        ).hexdigest()
        cached = self.redis_client.get(cache_key)
        if cached:
            print(f"✅ Cache hit for {file_name} [{detected_lang}]")
            return cached.decode()

        # --- SAST analysis (only for review/security tasks) ---
        is_review_task = "review" in task_prompt.lower() or "security" in task_prompt.lower()
        findings: List[Finding] = []
        pattern: Optional[str] = None

        if is_review_task:
            print(f"🔍 Running SAST rules on {file_name} [{detected_lang}]...")
            try:
                findings = self.sast_engine.scan(chunk_dict, {"repo_path": self.repo_path})
            except Exception as e:
                print(f"⚠️ SAST engine error: {e}")
            if not findings:
                print(f"⏭️ No SAST issues found in {file_name}, skipping LLM call")
                return None
            else:
                print(f"🔍 SAST found {len(findings)} potential issue(s) in {file_name}")
                pattern = self._infer_pattern_from_finding(findings[0])
                print(f"   🔎 Inferred pattern: {pattern}")

        # --- RAG retrieval using the reranker RAG (only for security review) ---
        examples: List[Dict] = []
        if is_review_task and findings:
            print(f"🔎 Retrieving similar vulnerable‑fixed pairs for {file_name} ({detected_lang})...")
            # Use the reranker retriever instead of the general vector store
            similar = self.fix_retriever.retrieve_fixes(
                vulnerable_code=content,
                vulnerability_type=pattern,
                language=detected_lang,
                top_k=3
            )
            if similar:
                examples = similar
                print(f"✅ Retrieved {len(similar)} relevant examples")
                for idx, ex in enumerate(examples[:2]):
                    print(f"   Example {idx+1}: pattern={ex['pattern']}, language={ex['language']}")
                    print(f"      Fixed code preview: {ex['fixed_code'][:150]}...")
            else:
                print(f"⚠️ No similar examples for {detected_lang}" + (f" with pattern {pattern}" if pattern else ""))

        # --- Build the prompt with SAST findings and RAG examples ---
        prompt = f"""{task_prompt}

Language: {detected_lang.upper()}

Static analysis detected the following issues:
"""
        if findings:
            for f in findings:
                prompt += f"- {f.message} (lines {f.line_start}-{f.line_end}, severity: {f.severity})\n"
        else:
            prompt += "None.\n"

        if examples:
            prompt += "\nHere are REAL examples of similar vulnerabilities and their CORRECT fixes:\n"
            for i, ex in enumerate(examples):
                prompt += f"\nExample {i+1} (pattern: {ex['pattern']}, language: {ex['language']}):\n"
                # Optionally show the vulnerable code from the example (if available)
                if ex.get('vulnerable_code_example'):
                    prompt += f"Vulnerable code:\n```{detected_lang}\n{ex['vulnerable_code_example']}\n```\n"
                prompt += f"Fixed code:\n```{detected_lang}\n{ex['fixed_code']}\n```\n"
            prompt += """
IMPORTANT INSTRUCTIONS:
- Do NOT invent new libraries, packages, or functions that do not exist in the examples or original code.
- If you need to store secrets (API keys, passwords), use environment variables (e.g., os.getenv in Python, os.LookupEnv in Go).
- Do NOT print or expose secrets in logs or HTTP responses.
- Provide a complete, working fix that would compile/run without errors.
- If the original code uses a framework (Flask, Django, net/http), follow its patterns.

Based on these examples and instructions, suggest a concrete, compilable fix for the vulnerabilities found.
"""
        else:
            prompt += """
No similar examples were found. Provide a best‑practice fix using standard libraries only. Do not invent new packages.
"""

        prompt += f"\nNow analyze this code and provide a fixed version:\n```{detected_lang}\n{content}\n```"

        print(f"📡 SENDING TO OLLAMA: {file_name} [{detected_lang}] ...")
        try:
            response = self.llm.generate(prompt)
            print(f"\n📝 LLM RESPONSE for {file_name}:\n{response}\n{'-'*50}\n")
            if not response:
                print(f"⚠️ LLM returned empty for {file_name}")
                return None

            print(f"✅ LLM SUCCESS: Generated response for {file_name}")
            self._cache_response(cache_key, response)
            self._update_vector_store(chunk_dict, response)

            # Save response to markdown file for review
            output_file = "llm_fixes.md"
            with open(output_file, "a") as f:
                f.write(f"## {file_name}\n\n")
                f.write(f"**Language:** {detected_lang.upper()}\n\n")
                f.write("**Issues detected:**\n")
                for fnd in findings:
                    f.write(f"- {fnd.message} (lines {fnd.line_start}-{fnd.line_end}, severity: {fnd.severity})\n")
                if pattern:
                    f.write(f"\n**Inferred pattern:** `{pattern}`\n")
                f.write(f"\n**Suggested Fix:**\n{response}\n\n---\n\n")
            print(f"📁 Appended response to {output_file}")

            return response
        except Exception as e:
            traceback.print_exc()
            return None

    # ----------------------------------------------------------------------
    # Public command methods
    # ----------------------------------------------------------------------
    def review_code(self, chunk_dict: Dict[str, Any]) -> Optional[str]:
        prompt = (
            "You are a senior security engineer. Review this code for vulnerabilities, "
            "edge cases, and architecture. If vulnerabilities exist, suggest concrete fixes "
            "based on the provided examples."
        )
        return self._process_logic(chunk_dict, prompt)

    def generate_test(self, chunk_dict: Dict[str, Any]) -> Optional[str]:
        prompt = (
            "You are a senior engineer. Generate high‑quality unit tests using the "
            "appropriate testing framework for this code."
        )
        return self._process_logic(chunk_dict, prompt)

    def generate_documentation(self, chunk_dict: Dict[str, Any]) -> Optional[str]:
        prompt = (
            "You are a senior engineer. Write professional technical documentation "
            "(docstrings and logic explanation)."
        )
        return self._process_logic(chunk_dict, prompt)

    # ----------------------------------------------------------------------
    # Helpers for caching and vector store updates
    # ----------------------------------------------------------------------
    def _cache_response(self, cache_key: str, response: str) -> None:
        self.redis_manager.save_to_reddis(cache_key, response.strip())

    def _update_vector_store(self, chunk_dict: Dict[str, Any], response: str) -> None:
        try:
            enriched_metadata = {
                **chunk_dict,
                "llm_insight": response
            }
            print(f"📦 Indexing {chunk_dict.get('file_name')} into vector store")
            print("ℹ️ Dynamic addition to vector store is disabled (static dataset).")
        except Exception as e:
            print(f"❌ Error while updating vector store: {e}")
            traceback.print_exc()