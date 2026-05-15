import hashlib
import traceback
from typing import Optional, List, Dict, Any

from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner, RepoWalker
from vector_store.store import VectorStore
from llm.ollama_client import OllamaClient
from git_controller.git_checker import Checker
from controllers.data_base_controller import Postgres
from sastscanner.core.rule_engine import RuleEngine
from sastscanner.findings.finding import Finding


class CliAgent:
    def __init__(self, repo_path: str, command: str, dry_run: bool = False):
        self.repo_path = repo_path
        self.command = command
        self.dry_run = dry_run

        # Core components
        self.vector_store = VectorStore()              # upgraded with metadata filtering
        self.llm = OllamaClient()
        self.redis_manager = RedisManager()
        self.redis_client = self.redis_manager.connect()
        self.git_controller = Checker(command)
        self.data_base = Postgres()
        self.sast_engine = RuleEngine()                # loads all rules automatically

    # ----------------------------------------------------------------------
    # Helper: map a finding (rule name / message) to a vulnerability pattern
    # ----------------------------------------------------------------------
    def _infer_pattern_from_finding(self, finding: Finding) -> Optional[str]:
        """Convert a SAST finding into one of the known pattern names."""
        rule_text = (finding.rule_id + " " + finding.message).lower()
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
        return None   # unknown pattern – will use language‑only filter

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
                # Infer pattern from the first finding (most relevant)
                pattern = self._infer_pattern_from_finding(findings[0])

        # --- RAG retrieval (only if we have findings and a language) ---
        examples: List[Dict] = []
        if is_review_task and findings:
            print(f"🔎 Retrieving similar vulnerable‑fixed pairs for {file_name} ({detected_lang})...")
            similar = self.vector_store.query(
                query_text=content,
                top_k=3,
                language=detected_lang,
                pattern=pattern   # may be None → language‑only filter
            )
            if similar:
                examples = similar
                print(f"✅ Retrieved {len(similar)} relevant examples")
            else:
                print(f"⚠️ No similar examples for {detected_lang}" + (f" with pattern {pattern}" if pattern else ""))

        # --- Build the prompt with SAST findings and RAG examples ---
        prompt = f"{task_prompt}\n\nLanguage: {detected_lang.upper()}\n"
        if findings:
            sast_summary = "\n".join([
                f"- {f.message} (lines {f.line_start}-{f.line_end}, severity: {f.severity})"
                for f in findings
            ])
            prompt += f"\nStatic analysis detected the following issues:\n{sast_summary}\n"

        if examples:
            prompt += "\nHere are examples of similar vulnerabilities and their fixes:\n"
            for i, ex in enumerate(examples):
                prompt += f"\nExample {i+1} (pattern: {ex['pattern']}, language: {ex['language']}):\n"
                prompt += f"Fixed code:\n```{detected_lang}\n{ex['fixed_code']}\n```\n"
            prompt += "\nBased on these examples, suggest a concrete fix for the vulnerabilities found.\n"

        prompt += f"\nNow analyze this code:\n```{detected_lang}\n{content}\n```"

        print(f"📡 SENDING TO OLLAMA: {file_name} [{detected_lang}] ...")
        try:
            response = self.llm.generate(prompt)
            if not response:
                print(f"⚠️ LLM returned empty for {file_name}")
                return None

            print(f"✅ LLM SUCCESS: Generated response for {file_name}")
            self._cache_response(cache_key, response)
            self._update_vector_store(chunk_dict, response)
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
        """Optional: add newly processed chunk + LLM insight to vector store."""
        try:
            enriched_metadata = {
                **chunk_dict,
                "llm_insight": response
            }
            print(f"📦 Indexing {chunk_dict.get('file_name')} into vector store")
            # The new VectorStore may not support dynamic addition; we keep this
            # as a no‑op or log. If you want to add new data, extend VectorStore.
            # For now, just log.
            print("ℹ️ Dynamic addition to vector store is disabled (static dataset).")
        except Exception as e:
            print(f"❌ Error while updating vector store: {e}")
            traceback.print_exc()