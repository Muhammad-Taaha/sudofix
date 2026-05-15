"""Check for outdated dependencies using public registry APIs."""

from __future__ import annotations

import dataclasses
import time
from typing import List, Optional, Dict, Tuple

import requests
from packaging.version import Version, InvalidVersion

from sca.resolver.base import ResolvedPackage
from sca.utils import get_logger

logger = get_logger(__name__)


@dataclasses.dataclass
class OutdatedFinding:
    package_name: str
    ecosystem: str
    current_version: str
    latest_version: str
    file_paths: List[str] = dataclasses.field(default_factory=list)


class OutdatedChecker:
    """Query public registries for the latest version of each package."""

    def check(self, packages: List[ResolvedPackage], imports: Optional[Dict[str, List[Tuple[str, int]]]] = None) -> List[OutdatedFinding]:
        start = time.time()
        findings = []
        for pkg in packages:
            latest = self._get_latest_version(pkg.name, pkg.ecosystem)
            if not latest:
                continue
            if self._is_outdated(pkg.version, latest):
                file_paths = []
                if imports and pkg.name in imports:
                    file_paths = [fp for fp, _ in imports[pkg.name]]
                findings.append(
                    OutdatedFinding(
                        package_name=pkg.name,
                        ecosystem=pkg.ecosystem,
                        current_version=pkg.version,
                        latest_version=latest,
                        file_paths=file_paths,
                    )
                )
        elapsed = time.time() - start
        logger.info(f"Outdated check completed in {elapsed:.2f}s for {len(packages)} packages")
        return findings

    def _get_latest_version(self, name: str, ecosystem: str) -> Optional[str]:
        """Query the appropriate registry API."""
        try:
            if ecosystem == "pypi":
                resp = requests.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
                resp.raise_for_status()
                data = resp.json()
                return data["info"]["version"]
            elif ecosystem == "npm":
                resp = requests.get(f"https://registry.npmjs.org/{name}/latest", timeout=10)
                resp.raise_for_status()
                data = resp.json()
                return data["version"]
            elif ecosystem == "maven":
                resp = requests.get(
                    f"https://search.maven.org/solrsearch/select?q=g:{name}&rows=1&wt=json", timeout=10
                )
                resp.raise_for_status()
                docs = resp.json().get("response", {}).get("docs", [])
                if docs:
                    return docs[0].get("latestVersion")
            elif ecosystem == "go":
                resp = requests.get(f"https://proxy.golang.org/{name}/@latest", timeout=10)
                resp.raise_for_status()
                data = resp.json()
                return data.get("Version")
        except Exception as e:
            logger.warning(f"Failed to get latest version for {ecosystem}:{name}: {e}")
        return None

    @staticmethod
    def _is_outdated(current: str, latest: str) -> bool:
        try:
            cur = Version(current)
            lat = Version(latest)
            return cur < lat
        except InvalidVersion:
            return current != latest