import os
from typing import List, Dict, Any
from pathlib import Path

# Import your existing parser factory
from parser.parser_factory import ParserFactory
from parser.ast_nodes import UnifiedNode

from .rule_runner import RuleRunner
from ..findings.finding import Finding


class Orchestrator:
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.parser_factory = ParserFactory()
        self.rule_runner = RuleRunner()

    def scan_file(self, file_path: str) -> List[Finding]:
        """Parse a single file and run rules on each node."""
        parser = self.parser_factory.get_parser(file_path)
        if not parser:
            return []
        try:
            nodes = parser.parse(file_path)  # returns List[UnifiedNode]
        except Exception as e:
            print(f"❌ Parse error in {file_path}: {e}")
            return []

        # Convert UnifiedNode to the dict format expected by rules
        # (or adapt rules to accept UnifiedNode directly)
        findings = []
        for node in nodes:
            chunk_dict = self._node_to_dict(node, file_path)
            context = {"repo_path": str(
                self.repo_path), "file_path": file_path}
            node_findings = self.rule_runner.run(chunk_dict, context)
            findings.extend(node_findings)
        return findings

    def scan_repository(self) -> List[Finding]:
        """Walk the repo and scan all source files."""
        all_findings = []
        # Simple walk – you can reuse your existing file filtering logic
        for root, _, files in os.walk(self.repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                if not self._is_source_file(file_path):
                    continue
                findings = self.scan_file(file_path)
                all_findings.extend(findings)
        return all_findings

    def _is_source_file(self, file_path: str) -> bool:
        """Check if file extension is supported."""
        supported = {".py", ".java", ".js", ".go",
                     ".rs", ".c", ".cpp", ".rb", ".php"}
        return Path(file_path).suffix.lower() in supported

    def _node_to_dict(self, node: UnifiedNode, file_path: str) -> Dict[str, Any]:
        """Convert UnifiedNode to the chunk dict format expected by rules."""
        return {
            "content": node.code,
            "file_path": file_path,
            "file_name": Path(file_path).name,
            "start_line": node.start_line,
            "end_line": node.end_line,
            "language": node.language,
            "metadata": {"language": node.language},
        }
