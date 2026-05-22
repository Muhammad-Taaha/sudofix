"""License compliance, NOTICE generation, and SBOM signing."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set

from sca.utils import get_logger

logger = get_logger(__name__)

# License classifications
PERMISSIVE_LICENSES = {
    "MIT", "Apache-2.0", "Apache-2", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "MPL-2.0", "EPL-2.0", "LGPL-2.1+", "LGPL-3.0+"
}

COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-3.0", "AGPL-3.0", "SSPL-1.0"
}

PROPRIETARY_LICENSES = {
    "Proprietary", "Commercial", "Unlicense", "Custom"
}


@dataclass
class LicenseInfo:
    """License information."""
    spdx_id: str
    name: str
    copyright_holders: List[str]
    files: List[str]


class NoticeGenerator:
    """Generate NOTICE.txt files for license attribution."""
    
    def __init__(self):
        self.licenses: Dict[str, LicenseInfo] = {}
    
    def add_license(self, spdx_id: str, name: str, copyright_holders: List[str], file_path: str):
        """Add a license finding."""
        if spdx_id not in self.licenses:
            self.licenses[spdx_id] = LicenseInfo(
                spdx_id=spdx_id,
                name=name,
                copyright_holders=list(set(copyright_holders)),
                files=[file_path]
            )
        else:
            self.licenses[spdx_id].files.append(file_path)
            self.licenses[spdx_id].copyright_holders = list(
                set(self.licenses[spdx_id].copyright_holders) | set(copyright_holders)
            )
    
    def generate_notice(self) -> str:
        """Generate NOTICE content."""
        lines = [
            "NOTICE",
            "=" * 70,
            "",
            "This software includes components with the following licenses:",
            "",
        ]
        
        # Group by license
        by_license = {}
        for info in self.licenses.values():
            if info.spdx_id not in by_license:
                by_license[info.spdx_id] = []
            by_license[info.spdx_id].append(info)
        
        for spdx_id, infos in sorted(by_license.items()):
            lines.append(f"\n{spdx_id}")
            lines.append("-" * 40)
            
            all_holders = set()
            all_files = set()
            for info in infos:
                all_holders.update(info.copyright_holders)
                all_files.update(info.files)
            
            if all_holders:
                lines.append("Copyright holders:")
                for holder in sorted(all_holders):
                    lines.append(f"  - {holder}")
            
            if all_files:
                lines.append("\nFound in:")
                for file_path in sorted(all_files)[:10]:  # Limit to 10 files
                    lines.append(f"  - {file_path}")
                if len(all_files) > 10:
                    lines.append(f"  - ... and {len(all_files) - 10} more")
        
        return "\n".join(lines)
    
    def save_notice(self, output_file: str = "NOTICE.txt"):
        """Save NOTICE to file."""
        Path(output_file).write_text(self.generate_notice())
        logger.info(f"NOTICE file generated: {output_file}")


class ComplianceReport:
    """Generate compliance reports."""
    
    def __init__(self):
        self.permissive_licenses: Set[str] = set()
        self.copyleft_licenses: Set[str] = set()
        self.proprietary_licenses: Set[str] = set()
        self.unknown_licenses: Set[str] = set()
    
    def add_licenses(self, licenses: List[str]):
        """Add licenses and classify them."""
        for lic in licenses:
            if lic in PERMISSIVE_LICENSES:
                self.permissive_licenses.add(lic)
            elif lic in COPYLEFT_LICENSES:
                self.copyleft_licenses.add(lic)
            elif lic in PROPRIETARY_LICENSES:
                self.proprietary_licenses.add(lic)
            else:
                self.unknown_licenses.add(lic)
    
    def generate_report(self) -> str:
        """Generate compliance report."""
        lines = [
            "License Compliance Report",
            "=" * 70,
            "",
        ]
        
        lines.append(f"Permissive Licenses ({len(self.permissive_licenses)}):")
        for lic in sorted(self.permissive_licenses):
            lines.append(f"  ✓ {lic}")
        
        lines.append(f"\nCopyleft Licenses ({len(self.copyleft_licenses)}):")
        for lic in sorted(self.copyleft_licenses):
            lines.append(f"  ⚠ {lic} (may require source code disclosure)")
        
        if self.proprietary_licenses:
            lines.append(f"\nProprietary Licenses ({len(self.proprietary_licenses)}):")
            for lic in sorted(self.proprietary_licenses):
                lines.append(f"  ! {lic}")
        
        if self.unknown_licenses:
            lines.append(f"\nUnknown Licenses ({len(self.unknown_licenses)}):")
            for lic in sorted(self.unknown_licenses):
                lines.append(f"  ? {lic}")
        
        # Summary
        lines.append("\nSummary:")
        lines.append(f"  Total Licenses: {len(self.permissive_licenses) + len(self.copyleft_licenses) + len(self.proprietary_licenses) + len(self.unknown_licenses)}")
        
        if self.copyleft_licenses:
            lines.append(f"  ⚠ WARNING: Copyleft licenses detected ({len(self.copyleft_licenses)})")
        else:
            lines.append("  ✓ No copyleft licenses detected")
        
        return "\n".join(lines)
    
    def save_report(self, output_file: str = "compliance-report.txt"):
        """Save report to file."""
        Path(output_file).write_text(self.generate_report())
        logger.info(f"Compliance report generated: {output_file}")
    
    def is_compliant(self, forbidden_licenses: Optional[List[str]] = None) -> bool:
        """Check if compliant with policy."""
        if forbidden_licenses is None:
            forbidden_licenses = list(COPYLEFT_LICENSES)
        
        found_forbidden = self.copyleft_licenses & set(forbidden_licenses)
        return len(found_forbidden) == 0
