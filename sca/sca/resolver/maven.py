"""Resolve Maven dependencies using mvn dependency:tree or pom.xml parsing."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from lxml import etree

from sca.resolver.base import DependencyResolver, ResolvedPackage
from sca.utils import get_logger

logger = get_logger(__name__)

# Namespace for Maven POM
MAVEN_NS = {"mvn": "http://maven.apache.org/POM/4.0.0"}


class MavenResolver(DependencyResolver):
    ecosystem = "maven"

    def can_handle(self, manifest_paths: List[str]) -> bool:
        return any(Path(p).name == "pom.xml" for p in manifest_paths)

    def resolve(self, project_path: str) -> List[ResolvedPackage]:
        root = Path(project_path).resolve()
        packages: Dict[str, ResolvedPackage] = {}

        # Strategy 1: Use mvn dependency:tree (if mvn is available)
        if self._mvn_available():
            try:
                return self._resolve_via_mvn(root)
            except Exception as e:
                logger.warning("mvn dependency:tree failed, falling back to pom parsing", error=str(e))

        # Strategy 2: Parse pom.xml recursively (best-effort)
        pom_files = sorted(root.rglob("pom.xml"))
        for pom_path in pom_files:
            try:
                packages.update(self._parse_pom_recursive(pom_path))
            except Exception as e:
                logger.warning("Failed to parse pom.xml", path=str(pom_path), error=str(e))

        logger.info("Maven resolution complete", total_packages=len(packages))
        return list(packages.values())

    def _mvn_available(self) -> bool:
        return (
            os.environ.get("SCA_ALLOW_SUBPROCESS", "1") == "1"
            and subprocess.call(
                ["mvn", "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            == 0
        )

    def _resolve_via_mvn(self, root: Path) -> List[ResolvedPackage]:
        cmd = [
            "mvn",
            "dependency:tree",
            "-DoutputType=json",
            "-f", str(root / "pom.xml"),
        ]
        # If multi-module, run at the root; the command will aggregate
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(root),
        )
        if result.returncode != 0:
            raise RuntimeError(f"mvn failed: {result.stderr}")

        import json
        data = json.loads(result.stdout)
        packages = {}
        # The output format: {"dependencies": [ {"groupId": "...", "artifactId": "...", "version": "...", "children": [...]}, ...] }
        for dep in data.get("dependencies", []):
            self._process_mvn_node(dep, packages, is_direct=True)
        return list(packages.values())

    def _process_mvn_node(self, node: dict, packages: dict, is_direct: bool = False) -> None:
        group = node.get("groupId", "")
        artifact = node.get("artifactId", "")
        version = node.get("version", "unknown")
        name = f"{group}:{artifact}"
        key = f"{name}@{version}"
        if key not in packages:
            deps = set()
            for child in node.get("children", []):
                child_name = f"{child.get('groupId', '')}:{child.get('artifactId', '')}"
                deps.add(child_name)
            packages[key] = ResolvedPackage(
                name=name,
                version=version,
                ecosystem="maven",
                is_direct=is_direct,
                dependencies=deps,
                resolved_from="mvn-dependency-tree",
            )
        # Recursively process children
        for child in node.get("children", []):
            self._process_mvn_node(child, packages, is_direct=False)

    def _parse_pom_recursive(self, pom_path: Path, parent_deps: Optional[Set[str]] = None) -> Dict[str, ResolvedPackage]:
        """Parse a single pom.xml and its child modules, returning resolved packages."""
        tree = etree.parse(str(pom_path))
        root = tree.getroot()

        packages = {}

        # Get current project coordinates
        parent_coords = self._get_project_coordinates(root)
        if parent_coords:
            name, version = parent_coords
            key = f"{name}@{version}"
            packages[key] = ResolvedPackage(
                name=name,
                version=version,
                ecosystem="maven",
                is_direct=True,
                resolved_from=str(pom_path),
            )

        # Resolve properties for substitution
        props = self._resolve_properties(root)

        # Process dependencies
        deps_elem = root.find("mvn:dependencies", MAVEN_NS)
        if deps_elem is not None:
            for dep in deps_elem.findall("mvn:dependency", MAVEN_NS):
                group = dep.findtext("mvn:groupId", namespaces=MAVEN_NS, default="")
                artifact = dep.findtext("mvn:artifactId", namespaces=MAVEN_NS, default="")
                version_elem = dep.find("mvn:version", MAVEN_NS)
                version = version_elem.text if version_elem is not None else "unknown"
                # Substitute properties like ${some.version}
                version = self._substitute_props(version, props)
                if not version:
                    version = "unknown"
                dep_name = f"{group}:{artifact}"
                dep_key = f"{dep_name}@{version}"
                if dep_key not in packages:
                    packages[dep_key] = ResolvedPackage(
                        name=dep_name,
                        version=version,
                        ecosystem="maven",
                        is_direct=True,
                        resolved_from=str(pom_path),
                    )

        # Handle multi-module: parse child poms
        modules_elem = root.find("mvn:modules", MAVEN_NS)
        if modules_elem is not None:
            for module_elem in modules_elem.findall("mvn:module", MAVEN_NS):
                module_name = module_elem.text
                if module_name:
                    child_pom = (pom_path.parent / module_name / "pom.xml").resolve()
                    if child_pom.exists():
                        packages.update(self._parse_pom_recursive(child_pom))

        return packages

    def _get_project_coordinates(self, root: etree.Element) -> Optional[Tuple[str, str]]:
        group = root.findtext("mvn:groupId", namespaces=MAVEN_NS)
        artifact = root.findtext("mvn:artifactId", namespaces=MAVEN_NS)
        version = root.findtext("mvn:version", namespaces=MAVEN_NS)
        # groupId might be inherited from parent, but for simplicity we skip if missing
        if artifact and version:
            # If group missing, check parent element
            if not group:
                parent = root.find("mvn:parent", MAVEN_NS)
                if parent is not None:
                    group = parent.findtext("mvn:groupId", namespaces=MAVEN_NS)
            if group:
                return (f"{group}:{artifact}", version)
        return None

    def _resolve_properties(self, root: etree.Element) -> Dict[str, str]:
        props = {}
        props_elem = root.find("mvn:properties", MAVEN_NS)
        if props_elem is not None:
            for child in props_elem:
                tag = child.tag.split("}")[-1]  # remove namespace
                props[tag] = child.text or ""
        return props

    @staticmethod
    def _substitute_props(version: str, props: Dict[str, str]) -> str:
        # Replace ${...} placeholders
        def replacer(m):
            key = m.group(1)
            return props.get(key, m.group(0))
        return re.sub(r'\$\{([^}]+)\}', replacer, version)