# Software Composition Analysis (SCA) Toolkit

A comprehensive, pluggable, and high-performance Software Composition Analysis (SCA) engine that scans projects for dependencies, licenses, vendored code, security vulnerabilities, outdated packages, and more.

Designed for **monorepos**, the toolkit supports multiple ecosystems out of the box and is easily extensible through a modular plugin architecture.

---

# Features

- Multi-ecosystem dependency resolution
  - npm
  - PyPI
  - Maven
  - Go
  - Swift
  - Rust
  - Ruby
  - .NET

- License detection
  - Uses ScanCode to identify SPDX licenses and copyright holders

- Vendored code identification
  - Detects embedded open-source packages

- Security rule scanning
  - ast-grep rules for insecure patterns
  - Examples:
    - `eval`
    - `dangerouslySetInnerHTML`

- Vulnerability mapping
  - Offline OSV/NVD database support
  - Reachability analysis

- Outdated dependency detection
  - Checks package registries for latest versions

- Git history scanning
  - Inspects deleted and modified files in past commits

- Binary fingerprinting
  - Extracts library names and versions from:
    - ELF
    - PE
    - Mach-O binaries

- Monorepo support
  - Automatically detects and scans sub-projects

- Caching
  - SQLite-based cache for:
    - file scans
    - dependency resolution
    - API responses

- CLI support
  - JSON output
  - Human-readable summaries

---

# Installation

## Prerequisites

- Python 3.9 or later
- `git` (optional, required for history scanning)
- `scancode-toolkit`
- `ast-grep` (optional)

### ScanCode Toolkit

Install from:

https://github.com/nexB/scancode-toolkit

Ensure it is available in your system `PATH`.

### ast-grep

Documentation:

https://ast-grep.github.io/

Can also be installed automatically through:

```bash
pip install ast-grep-py
```

---

# Install from Source

```bash
git clone https://github.com/your-org/sca-toolkit
cd sca-toolkit

python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

pip install -r requirements.txt
pip install -e .
```

After installation, the `sca` command becomes available.

---

# Quick Start

## Run Your First Scan

```bash
sca scan /path/to/your/project
```

This prints a summary of findings to the console.

---

## JSON Output

```bash
sca scan /path/to/your/project --json > results.json
```

---

# Vulnerability Database

The engine uses a local vulnerability database.

## Download Latest OSV Data

```bash
sca update-db --download
```

---

## Import Existing JSON Files

```bash
sca update-db --input /path/to/osv_json_files
```

---

# Git History Scanning

```bash
sca scan /path/to/project --history --max-history-commits 50
```

---

# List Available Security Rules

```bash
sca rules
```

---

# Generate Default Configuration

```bash
sca config
```

Creates:

```text
sca-config.yml
```

in the current working directory.

---

# Command Line Interface

```text
sca <command> [options]
```

---

# Commands

## scan

Run a full SCA scan.

```bash
sca scan PROJECT_PATH [options]
```

### Options

| Option | Description |
|---|---|
| `PROJECT_PATH` | Path to the project root |
| `--cache-dir DIR` | Custom cache directory |
| `--history` | Include Git history scanning |
| `--max-history-commits N` | Limit history commits |
| `--history-since DATE` | Scan commits after date |
| `--json` | Output machine-readable JSON |

---

## update-db

Update vulnerability database.

```bash
sca update-db [options]
```

### Options

| Option | Description |
|---|---|
| `--download` | Download latest OSV data |
| `--input DIR` | Import local OSV JSON files |

---

## rules

List all available security rules.

```bash
sca rules
```

---

## config

Generate default configuration.

```bash
sca config
```

---

# Configuration

The engine looks for:

```text
sca-config.yml
```

in the project root or current working directory.

Environment variables are also supported:

- `SCA_CACHE_DIR`
- `SCA_LOG_LEVEL`

---

# Default Configuration

```yaml
cache_dir: ~/.cache/sca

ignore_patterns:
  - .git
  - node_modules
  - __pycache__
  - vendor
  - dist
  - build

timeouts:
  file_scan: 120
  network: 30

severity_threshold: LOW
```

---

# Configuration Options

| Key | Description |
|---|---|
| `cache_dir` | Cache and temporary storage |
| `ignore_patterns` | Glob exclusions |
| `timeouts.file_scan` | Per-file ScanCode timeout |
| `timeouts.network` | Network/API timeout |
| `severity_threshold` | Minimum vulnerability severity |

Supported severities:

- LOW
- MEDIUM
- HIGH
- CRITICAL

---

# Output Format

When using `--json`, the output structure is:

```json
{
  "status": "ok",
  "sub_projects": [
    {
      "project_path": "/abs/path",
      "packages": [],
      "imports": {},
      "license_findings": [],
      "vendored_matches": [],
      "rule_findings": [],
      "vulnerabilities": [],
      "outdated": [],
      "binary_pseudo_deps": []
    }
  ],
  "history_findings": []
}
```

---

# Supported Ecosystems

| Ecosystem | Manifest / Lockfile | Resolver Module |
|---|---|---|
| npm | package.json, package-lock.json, yarn.lock | `sca.resolver.plugins.npm` |
| PyPI | requirements.txt, poetry.lock, Pipfile.lock | `sca.resolver.plugins.pypi` |
| Maven | pom.xml | `sca.resolver.plugins.maven` |
| Go | go.mod, go.sum | `sca.resolver.plugins.go` |
| Swift | Package.resolved | `sca.resolver.plugins.swift` |
| Rust | Cargo.toml, Cargo.lock | `sca.resolver.plugins.rust` |
| Ruby | Gemfile.lock | `sca.resolver.plugins.ruby` |
| .NET | packages.config | `sca.resolver.plugins.dotnet` |

All resolvers are loaded automatically through the plugin system.

---

# Adding a New Ecosystem

1. Implement `DependencyResolver`
2. Place resolver inside:

```text
sca/resolver/plugins/
```

3. Register the resolver

---

# Architecture

## File I/O & Hashing

Responsible for:

- file discovery
- `.gitignore` filtering
- SHA-256 hashing
- delta generation

Module:

```text
file_hasher.py
```

---

## Dependency Resolution

Located in:

```text
resolver/plugins/
```

Each resolver parses manifests and lockfiles into `ResolvedPackage` objects.

---

## Scanning

### License & Vendored Scanning

Module:

```text
scanners.py
```

Uses ScanCode integration.

### Rule Scanning

Module:

```text
rule_scanner.py
```

Uses ast-grep rules.

---

## Vulnerability & Outdated Analysis

### Vulnerability Mapping

```text
vulnerability_mapper.py
```

### Outdated Detection

```text
outdated_checker.py
```

---

## Caching

SQLite-based cache layer.

Module:

```text
cache.py
```

---

## CLI

Argparse-based command-line interface.

Module:

```text
cli.py
```

---

## Import Mapping

Extracts imports from source files.

Module:

```text
import_mapper.py
```

---

# Design Philosophy

The engine is designed to fail gracefully.

A resolver or scanner failure does not terminate the entire scan process.

---

# Development

## Setup

```bash
python -m venv .venv

# Linux/macOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate

pip install -r requirements-dev.txt
pip install -e .

pre-commit install
```

---

# Run Tests

```bash
pytest
```

---

# Add a New Resolver

1. Create a file inside:

```text
src/sca/resolver/plugins/
```

2. Implement:
   - `ecosystem`
   - `can_handle`
   - `resolve`

3. Register it in:

```text
src/sca/resolver/plugins/__init__.py
```

4. Add tests:

```text
tests/test_my_ecosystem_resolver.py
```

---

# Add a New Security Rule

Place a YAML file inside:

```text
src/sca/db/rules/
```

Example:

```yaml
id: unique-rule-id
message: "Description of the issue"
severity: high
language: Python

rule:
  pattern: eval($$)
```

The rule scanner automatically discovers new rules.

---

# Contributing

Contributions are welcome.

## Workflow

1. Fork the repository
2. Create a feature branch
3. Add tests
4. Run:

```bash
pytest
```

5. Submit a pull request

---

# License

This project is proprietary until further notice.

See:

```text
LICENSE.txt
```

for details.

Third-party tools such as ScanCode and ast-grep remain under their respective licenses.

---

# Support

For issues, questions, or feature requests:

- Contact the maintainers
- Open a GitHub issue