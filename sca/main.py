#!/usr/bin/env python3
"""Main CLI entry point for Software Composition Analysis Toolkit."""

import argparse
import sys
import json
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_argparse() -> argparse.ArgumentParser:
    """Setup command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Software Composition Analysis Toolkit - Analyze dependencies, licenses, and vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze current directory
  python main.py
  
  # Analyze specific folder
  python main.py /path/to/project
  
  # Analyze with git history
  python main.py --git-history /path/to/project
  
  # Analyze with custom cache directory
  python main.py --cache-dir /tmp/sca-cache /path/to/project
  
  # Output as JSON
  python main.py --output-json /path/to/project
  
  # Analyze single file (will detect surrounding project context)
  python main.py /path/to/package.json
  
  # Verbose output for debugging
  python main.py --verbose /path/to/project
        """
    )
    
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Path to project folder or manifest file (default: current directory)"
    )
    
    parser.add_argument(
        "--cache-dir",
        default=None,
        help="Directory for caching license and vulnerability data"
    )
    
    parser.add_argument(
        "--config-file",
        default=None,
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--git-history",
        action="store_true",
        help="Include git history analysis"
    )
    
    parser.add_argument(
        "--max-history-commits",
        type=int,
        default=None,
        help="Maximum number of git commits to analyze"
    )
    
    parser.add_argument(
        "--history-since",
        default=None,
        help="Analyze git commits since this date (e.g., '2024-01-01')"
    )
    
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="Output results as JSON"
    )
    
    parser.add_argument(
        "--output-file",
        default=None,
        help="Write output to file instead of stdout"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--no-subprojects",
        action="store_true",
        help="Disable sub-project detection (treat as single project)"
    )
    
    return parser.parse_args()


def find_project_root(start_path: Path) -> Path:
    """Find the project root by looking for common markers."""
    markers = [
        ".git",
        "package.json",
        "setup.py",
        "pyproject.toml",
        "pom.xml",
        "go.mod",
        "Cargo.toml",
        "composer.json",
        "Gemfile",
        "requirements.txt",
    ]
    
    current = start_path.resolve()
    
    # If it's a file, start from its parent
    if current.is_file():
        current = current.parent
    
    for parent in [current] + list(current.parents):
        for marker in markers:
            if (parent / marker).exists():
                logger.debug(f"Found project root at {parent} (marker: {marker})")
                return parent
    
    # If no markers found, return the original path
    logger.debug(f"No project markers found, using {current}")
    return current


def print_results(results: Dict[str, Any], verbose: bool = False):
    """Pretty print analysis results."""
    print("\n" + "=" * 80)
    print("SOFTWARE COMPOSITION ANALYSIS RESULTS")
    print("=" * 80)
    
    # Check if we have any results
    if not results:
        print("\n⚠️  No results returned from analysis")
        return
    
    # Summary
    if "sub_projects" in results:
        num_projects = len(results["sub_projects"])
        total_packages = sum(len(p.get("packages", [])) for p in results["sub_projects"])
        total_vulns = sum(len(p.get("vulnerabilities", [])) for p in results["sub_projects"])
        total_licenses = sum(len(p.get("license_findings", [])) for p in results["sub_projects"])
        total_outdated = sum(len(p.get("outdated", [])) for p in results["sub_projects"])
        print("\n==================== Summary ====================")
        print(f"  Projects analyzed: {num_projects}")
        print(f"  Total packages found: {total_packages}")
        print(f"  Total vulnerabilities: {total_vulns}")
        print(f"  License findings: {total_licenses}")
        print(f"  Outdated packages: {total_outdated}")
        
        if results.get("history_findings"):
            print(f"  • Git history issues: {len(results['history_findings'])}")
        
        if total_packages == 0:
            print("\n  ⚠️  No packages found! This could mean:")
            print("     1. No manifest files (package.json, requirements.txt, etc.) found")
            print("     2. Manifest files exist but no resolvers are available")
            print("     3. The dependency resolution failed silently")
            if verbose:
                print("\n  💡 Tip: Run with --verbose to see more details")
    
    # Per-project details
    if results.get("sub_projects"):
        for i, project in enumerate(results["sub_projects"], 1):
            print(f"\n📁 Project {i}: {project.get('project_path', 'unknown')}")
            print("-" * 40)
            
            packages = project.get("packages", [])
            if packages:
                print(f"  📦 Packages ({len(packages)}):")
                for pkg in packages[:5]:  # Show first 5
                    name = pkg.get("name", "unknown")
                    version = pkg.get("version", "unknown")
                    ecosystem = pkg.get("ecosystem", "unknown")
                    print(f"    • {name}@{version} [{ecosystem}]")
                if len(packages) > 5:
                    print(f"    ... and {len(packages) - 5} more")
            else:
                print(f"  📦 Packages: 0 found")
            
            vulnerabilities = project.get("vulnerabilities", [])
            if vulnerabilities:
                print(f"\n  ⚠️  Vulnerabilities ({len(vulnerabilities)}):")
                for vuln in vulnerabilities[:5]:
                    pkg = vuln.get("package", "unknown")
                    severity = vuln.get("severity", "unknown")
                    title = vuln.get("title", "No description")
                    print(f"    • {pkg}: {title} [{severity}]")
                if len(vulnerabilities) > 5:
                    print(f"    ... and {len(vulnerabilities) - 5} more")
            
            outdated = project.get("outdated", [])
            if outdated:
                print(f"\n  📅 Outdated packages ({len(outdated)}):")
                for out in outdated[:3]:
                    pkg = out.get("package_name", "unknown")
                    current = out.get("current_version", "unknown")
                    latest = out.get("latest_version", "unknown")
                    print(f"    • {pkg}: {current} -> {latest}")
            
            license_findings = project.get("license_findings", [])
            if license_findings:
                print(f"\n  📄 License findings ({len(license_findings)}):")
                for lic in license_findings[:3]:
                    file_path = lic.get("file_path", "unknown")
                    license_expr = lic.get("license_expression", "unknown")
                    print(f"    • {file_path}: {license_expr}")
    
    # Git history findings
    if results.get("history_findings"):
        print(f"\n📜 Git History Findings ({len(results['history_findings'])}):")
        for finding in results["history_findings"][:5]:
            commit = finding.get("commit_hash", "unknown")[:8]
            finding_type = finding.get("type", "unknown")
            print(f"    • [{commit}] {finding_type}")
    
    print("\n" + "=" * 80)


def main():
    """Main entry point."""
    args = setup_argparse()
    
    # Setup logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Verbose mode enabled")
    
    # Determine the path to analyze
    input_path = Path(args.path).resolve()
    
    # If it's a single file, try to find project root
    if input_path.is_file():
        project_root = find_project_root(input_path)
        logger.info(f"Single file mode: analyzing {input_path.name} in project {project_root}")
        analysis_path = project_root
    else:
        # Directory mode
        analysis_path = input_path
        logger.info(f"Directory mode: analyzing {analysis_path}")
    
    # Check if the path exists
    if not analysis_path.exists():
        logger.error(f"Path does not exist: {analysis_path}")
        sys.exit(1)
    
    # List manifest files for debugging
    if args.verbose:
        manifest_patterns = ["package.json", "requirements.txt", "pyproject.toml", "pom.xml", "go.mod", "Cargo.toml"]
        logger.debug(f"Checking for manifest files in {analysis_path}")
        for pattern in manifest_patterns:
            manifest_path = analysis_path / pattern
            if manifest_path.exists():
                logger.debug(f"  Found: {pattern}")
            else:
                logger.debug(f"  Not found: {pattern}")
    
    try:
        # Import the analyze function from sca.__init__
        from sca import analyze
        
        logger.info("Starting analysis...")
        start_time = datetime.now()
        
        # Run analysis
        results = analyze(
            project_path=str(analysis_path),
            cache_dir=args.cache_dir,
            config_file=args.config_file,
            include_git_history=args.git_history,
            max_history_commits=args.max_history_commits,
            history_since=args.history_since,
            no_subprojects=args.no_subprojects,
        )
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        # Add metadata to results
        if isinstance(results, dict):
            results["metadata"] = {
                "analysis_path": str(analysis_path),
                "original_input": str(input_path),
                "timestamp": start_time.isoformat(),
                "duration_seconds": duration,
                "single_file_mode": input_path.is_file(),
                "git_history_enabled": args.git_history,
            }
        
        # Output results
        if args.output_json:
            output_data = json.dumps(results, indent=2, default=str)
            
            if args.output_file:
                with open(args.output_file, 'w') as f:
                    f.write(output_data)
                print(f"Results written to {args.output_file}")
            else:
                print(output_data)
        else:
            print_results(results, verbose=args.verbose)
            print(f"\n✅ Analysis completed in {duration:.2f} seconds")
            
            # Show summary of findings
            if isinstance(results, dict) and results.get("sub_projects"):
                total_packages = sum(len(p.get("packages", [])) for p in results["sub_projects"])
                if total_packages == 0:
                    print("\n💡 Tip: No packages were detected. Make sure your project has:")
                    print("   - package.json for Node.js/npm projects")
                    print("   - requirements.txt or pyproject.toml for Python")
                    print("   - pom.xml for Java/Maven")
                    print("   - go.mod for Go")
                    print("   - Cargo.toml for Rust")
        
        # Return appropriate exit code
        if isinstance(results, dict):
            has_vulns = any(
                len(p.get("vulnerabilities", [])) > 0 
                for p in results.get("sub_projects", [])
            )
            sys.exit(1 if has_vulns else 0)
        else:
            sys.exit(0)
        
    except ImportError as e:
        logger.error(f"Failed to import analyze function from sca module: {e}")
        logger.error("Make sure you have a valid sca module with __init__.py containing analyze()")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()