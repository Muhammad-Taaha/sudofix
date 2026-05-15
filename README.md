# 🔒 sudofix: Multi-Language SAST Scanner with Taint Analysis & RAG-Powered Fixes

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Languages](https://img.shields.io/badge/languages-7+-orange)](https://github.com)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**sudofix** is a production-ready Static Application Security Testing (SAST) tool that scans source code for security vulnerabilities across **7+ programming languages** using **AST-based pattern rules**, **taint analysis** (data-flow tracking), and **RAG-powered fix generation** with local LLM integration. Designed for accuracy, extensibility, and seamless CI/CD integration.

## ✨ Features

- **Multi-language support**: Python, Java, JavaScript/TypeScript, Go, C, C++, Rust
- **Rich rule set**: 60+ rules covering injection, authentication, cryptography, file handling, XSS, deserialization, network, framework, business logic, and more
- **Taint analysis**: Tracks user input from sources to sinks with full data-flow propagation
- **Flat AST normalization**: All languages produce unified node structure (UnifiedNode, CallNode, AssignNode)
- **Advanced rule engine**: Auto-discovers rules in subdirectories; each rule is a Python class
- **Smart caching**: Redis-backed AST caching for 60-80% faster re-scans
- **Multiple output formats**: CLI (colored), JSON, SARIF (OASIS standard)
- **Incremental scanning**: Only processes changed files after git commits
- **RAG-powered fix generation**: Uses Sentence-Transformers embeddings and FAISS vector store to find similar vulnerabilities and generate context-aware fixes
- **Local LLM inference**: Ollama integration for generating fix suggestions without external API calls
- **t-SNE visualization**: Analyze vulnerability embeddings and clustering patterns
- **CI/CD ready**: Easy integration with GitHub Actions, GitLab CI, pre-commit hooks

## 📁 Project Structure

```
repo-llm/
├── main.py                          # CLI entry point
├── git_controller/                  # Git scanning and RAG pipeline
│   └── scan_and_fix.py
├── controllers/                     # Scanning & database controllers
├── parser/                          # Multi-language AST parsers (tree-sitter)
├── sastscanner/                     # Core SAST engine
│   ├── core/                        # Orchestrator, rule engine
│   ├── rules/                       # Vulnerability rules (60+ rules)
│   │   ├── injection/
│   │   ├── auth/
│   │   ├── crypto/
│   │   ├── file/
│   │   ├── xss/
│   │   ├── deserialization/
│   │   ├── network/
│   │   ├── framework/
│   │   ├── business_logic/
│   │   └── misc/
│   ├── taint/                       # Taint analysis engine
│   ├── findings/                    # Finding models & formatters
│   └── cache/                       # Redis caching
├── rag/                             # RAG pipeline
│   ├── embeddings.py                # Sentence-Transformers integration
│   ├── vector_store.py              # FAISS vector store management
│   ├── retriever.py                 # Similarity search for vulnerabilities
│   ├── generator.py                 # Fix generation with context
│   └── visualise_embeddings.py      # t-SNE visualization
├── llm/                             # Ollama client for local inference
├── testcases/                       # Test suite (vulnerable + safe code)
├── diagrams/                        # Generated visualizations
├── docker-compose.yml               # Redis & database services
└── req.txt                          # Dependencies
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Redis (for caching; optional but recommended)
- Git (for cloning repositories)
- Ollama (optional, for LLM fix suggestions)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/repo-llm.git
cd repo-llm

# Create virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate   on Windows

# Install dependencies
pip install -r req.txt

# (Optional) Start Redis with Docker Compose
docker-compose up -d redis

# (Optional) Run Ollama and pull a model
ollama pull codellama:7b
```

### Basic Usage

#### Scan a Local Directory

```bash
# Basic scan
python main.py --path /path/to/your/code

# Output as JSON
python main.py --path /path/to/your/code --format json --output results.json

# Enable taint analysis (data-flow tracking)
python main.py --path /path/to/your/code --taint

# Only specific rule categories
python main.py --path /path/to/your/code --rules injection,crypto

# Incremental scan (only changed files since last scan)
python main.py --path /path/to/your/code --incremental

# Output as SARIF (CI/CD friendly)
python main.py --path /path/to/your/code --format sarif --output results.sarif
```

#### Full RAG Pipeline with Fixes

```bash
# Scan repository and generate fixes using RAG
python git_controller/scan_and_fix.py --repo https://github.com/example/vuln-app.git

# Local directory with fix generation
python main.py --path /path/to/your/code --llm --rag

# Use specific LLM model
python main.py --path /path/to/your/code --llm --model codellama:13b
```

#### Visualizations

```bash
# Generate t-SNE visualization of vulnerability embeddings
python rag/visualise_embeddings.py --n_samples 2000 --output diagrams/tsne.png

# Analyze embedding clusters
python rag/visualise_embeddings.py --analysis --output diagrams/analysis.png
```

## 🧪 Testing

```bash
# Run all tests
pytest testcases/

# Test SAST only
python testcases/run_sast_tests.py

# Test specific category
python testcases/run_sast_tests.py --category injection

# Test AST parsing
python inspect_ast.py --code 'if (x > 0) { return true; }'

# Generate test cases for custom rules
python testcases/generate_all_test_cases.py
```

## 🔧 Configuration

Create a `.env` file in the project root:

```ini
# Redis (caching)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0

# LLM (optional)
OLLAMA_HOST=http://localhost:11434
LLM_MODEL=codellama:7b

# RAG & Embeddings
EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
FAISS_INDEX_PATH=./data/faiss_index
VECTOR_STORE_PATH=./data/vector_store.pkl

# Scanner
MAX_FILE_SIZE_MB=10
PARALLEL_WORKERS=4
TIMEOUT_SECONDS=300
CACHE_TTL_HOURS=24
```

## 📝 Writing Custom Rules

Create a new Python file in `sastscanner/rules/<category>/` and inherit from `BaseRule`.

### Example Rule

```python
from typing import List, Dict, Any
from ..base_rule import BaseRule
from ...findings.finding import Finding
from parser.ast_nodes import CallNode

class MyCustomRule(BaseRule):
    @property
    def name(self) -> str:
        return "Dangerous Function Call"

    @property
    def severity(self) -> str:
        return "HIGH"

    @property
    def cwe_id(self) -> str:
        return "CWE-999"

    def check(self, chunk: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        lang = self._get_language(chunk)
        if lang != "python":
            return []
        
        nodes = chunk.get("nodes", [])
        findings = []
        
        for node in nodes:
            if isinstance(node, CallNode) and node.callee == "dangerous_func":
                findings.append(self._create_finding(chunk, node))
        
        return findings

    def _create_finding(self, chunk, node):
        return Finding(
            self.name,
            self.severity,
            chunk.get("file_path", ""),
            node.start_line,
            node.end_line,
            "Dangerous function `dangerous_func` used.",
            node.code,
            self.cwe_id,
        )
```

Rules are automatically discovered – no registration needed.

## 🧠 RAG Pipeline

The RAG (Retrieval-Augmented Generation) system enhances fix generation by:

1. **Embedding vulnerabilities** using Sentence-Transformers
2. **Storing in FAISS** for fast similarity search
3. **Retrieving similar vulnerabilities** from the corpus
4. **Generating context-aware fixes** with local LLMs

### How It Works

```bash
# Step 1: Build embeddings from vulnerability dataset
python rag/embeddings.py --build-index

# Step 2: Query similar vulnerabilities
python rag/retriever.py --query "SQL injection in user login" --top-k 5

# Step 3: Generate fixes with context
python rag/generator.py --vulnerability "SQL injection" --context "Django ORM"

# Step 4: Visualize embeddings
python rag/visualise_embeddings.py --n_samples 2000
```

### Performance

- **Cached ASTs** (Redis): 60-80% faster re-scans
- **Parallel workers** (default 4): Scale with CPU cores
- **Incremental scanning**: Only processes changed files
- **FAISS indexing**: Sub-millisecond similarity search on 10K+ vulnerabilities

## 🔌 CI/CD Integration

### GitHub Actions

```yaml
name: SAST Security Scan

on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install dependencies
        run: |
          pip install -r req.txt
      
      - name: Run Repo-LLM SAST
        run: |
          python main.py --path . --format sarif --output results.sarif
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
sast:
  stage: test
  script:
    - pip install -r req.txt
    - python main.py --path $CI_PROJECT_DIR --format json --output gl-sast.json
  artifacts:
    reports:
      sast: gl-sast.json
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
- repo: local
  hooks:
    - id: repo-llm
      name: Run SAST scan
      entry: python main.py --path . --rules injection,auth,crypto
      language: system
      pass_filenames: false
      stages: [commit]
```

## 📊 Output Formats

### CLI (Default)

```
[HIGH] SQL Injection in login.py:42
  Location: login.py:42:15-42:35
  CWE: CWE-89
  Vulnerable Code: query = f"SELECT * FROM users WHERE id={user_id}"
  Severity: HIGH
```

### JSON

```json
{
  "results": [
    {
      "rule_id": "injection_sql",
      "severity": "HIGH",
      "file": "login.py",
      "line": 42,
      "column": 15,
      "message": "SQL Injection",
      "code": "query = f\"SELECT * FROM users WHERE id={user_id}\"",
      "cwe_id": "CWE-89"
    }
  ]
}
```

### SARIF

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Repo-LLM",
          "version": "1.0.0"
        }
      },
      "results": [...]
    }
  ]
}
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-rule`)
3. Add your rule in `sastscanner/rules/` (follow category structure)
4. Add test cases (vulnerable + safe examples) in `testcases/`
5. Run tests: `pytest testcases/`
6. Run linter: `black . && mypy .`
7. Submit a pull request

## ⚠️ Disclaimer

This tool performs **static analysis only** – it does not execute code. False positives may occur; **manual validation is recommended**. Use only on repositories you own or have permission to test.

## 📄 License

MIT © sudofix Contributors

## 🙏 Acknowledgements

- **Tree-sitter** for fast multi-language AST parsing
- **Sentence-Transformers** for semantic embeddings
- **FAISS** for efficient similarity search
- **Ollama** for local LLM inference
- **Redis** for caching
- Hugging Face for pre-trained vulnerability classifiers
- Open-source vulnerability datasets that powered the RAG corpus

## 📬 Contact

For questions, issues, or contributions, please open an issue on GitHub or contact the maintainers.

---

<div align="center">⭐ Star us on GitHub – it helps!</div>
