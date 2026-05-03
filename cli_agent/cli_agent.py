import hashlib
import traceback
from controllers.reddis_controller import RedisManager
from controllers.repo_scanner import RepoScanner, RepoWalker
from vector_store.store import VectorStore
from llm.ollama_client import OllamaClient
from git_controller.git_checker import Checker
from controllers.data_base_controller import Postgres
from sastscanner.core.rule_engine import RuleEngine  # corrected import
from sastscanner.finding import Finding


class CliAgent:
    def __init__(self, repo_path, command, dry_run=False):
        self.repo_path = repo_path
        self.vector_store = VectorStore()
        self.llm = OllamaClient()
        self.reddis_manager = RedisManager()
        self.redis_client = self.reddis_manager.connect()
        self.git_controller = Checker(command)
        self.data_base = Postgres()
        self.dry_run = dry_run
        self.sast_engine = RuleEngine()  # loads all rules automatically

    def _process_logic(self, chunk_dict, task_prompt):
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

        # 🛡️ SAST filter (only for review/security tasks)
        is_review_task = (
            "review" in task_prompt.lower() or "security" in task_prompt.lower()
        )
        findings = []
        if is_review_task:
            print(f"🔍 Running SAST rules on {file_name} [{detected_lang}]...")
            try:
                findings = self.sast_engine.scan(
                    chunk_dict, {"repo_path": self.repo_path}
                )
            except Exception as e:
                print(f"⚠️ SAST engine error: {e}")
            if not findings:
                print(f"⏭️ No SAST issues found in {
                      file_name}, skipping LLM call")
                return None
            else:
                print(f"🔍 SAST found {len(findings)} potential issue(s) in {
                    file_name}")

        # RAG retrieval for review tasks (only if SAST found something)
        examples = ""
        if is_review_task and findings:
            print(f"🔎 Retrieving similar vulnerable‑fixed pairs for {
                file_name} ({detected_lang})...")
            similar = self.vector_store.query(
                content, top_k=3, language=detected_lang)
            if similar:
                example_texts = []
                for i, ex in enumerate(similar):
                    vuln = ex.get("vulnerable_code", "")
                    fixed = ex.get("fixed_code", "")
                    if vuln and fixed:
                        example_texts.append(
                            f"Example {
                                i+1} (CVE {ex.get('cve_id', 'unknown')}):\n"
                            f"VULNERABLE:\n```{detected_lang}\n{vuln}\n```\n"
                            f"FIXED:\n```{detected_lang}\n{fixed}\n```"
                        )
                examples = "\n\n".join(example_texts)
                print(f"✅ Retrieved {len(similar)} relevant examples")
            else:
                print(f"⚠️ No similar examples for {detected_lang}")

        # Build prompt with SAST findings and RAG examples
        prompt = f"{task_prompt}\n\nLanguage: {detected_lang.upper()}\n"
        if findings:
            sast_summary = "\n".join([f"- {f.message} (lines {f.line_start}-{
                f.line_end}, severity: {f.severity})" for f in findings])
            prompt += f"\nStatic analysis detected the following issues:\n{
                sast_summary}\n"
        if examples:
            prompt += (
                f"\nHere are examples of similar vulnerabilities and their fixes:\n{
                    examples}\n"
            )
        prompt += f"\nNow analyze this code:\n```{
            detected_lang}\n{content}\n```"

        print(f"📡 SENDING TO OLLAMA: {file_name} [{detected_lang}] ...")
        try:
            response = self.llm.generate(prompt)
            if not response:
                print(f"⚠️ LLM returned empty for {file_name}")
                return None

            print(f"✅ LLM SUCCESS: Generated response for {file_name}")
            self.caching_the_response(cache_key, response)
            self.make_vector(chunk_dict, response)
            return response
        except Exception as e:
            traceback.print_exc()
            return None

    def review_code(self, chunk_dict):
        prompt = "You are a senior security engineer. Review this code for vulnerabilities, edge cases, and architecture. If vulnerabilities exist, suggest concrete fixes based on the provided examples."
        return self._process_logic(chunk_dict, prompt)

    def generate_test(self, chunk_dict):
        prompt = "You are a senior engineer. Generate high-quality unit tests using the appropriate testing framework for this code."
        return self._process_logic(chunk_dict, prompt)

    def generate_documentation(self, chunk_dict):
        prompt = "You are a senior engineer. Write professional technical documentation (docstrings and logic explanation)."
        return self._process_logic(chunk_dict, prompt)

    def caching_the_response(self, cache_key, response):
        self.reddis_manager.save_to_reddis(cache_key, response.strip())

    def make_vector(self, chunk_dict, response):
        try:
            enriched_metadata = {**chunk_dict, "llm_insight": response}
            print(f"📦 Indexing {chunk_dict.get(
                'file_name')} into vector store")
            self.vector_store.add([chunk_dict["content"]], [enriched_metadata])
            self.vector_store.save("vector_store")
            print("✅ Vector store updated")
        except Exception as e:
            print(f"❌ Error updating vector store: {e}")
            traceback.print_exc()
