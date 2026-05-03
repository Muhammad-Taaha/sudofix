from abc import ABC, abstractmethod
from typing import List, Dict, Any

from sastscanner.findings.finding import Finding


class BaseRule(ABC):
    """
    this is the base calss for all of the rules

    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def severity(self) -> str:
        pass

    @property
    def cwe_id(self) -> Optional[str]:
        return None

    @abstractmethod
    def check(self, node: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        """
        Check a single code chunk (node) for violations.
        node: a chunk dict from RepoScanner (contains 'content', 'metadata.language', 'start_line', 'end_line', etc.)
        context: additional context (e.g., repo_id, file_path)
        Returns a list of Findings (empty if none).
        """
        pass
