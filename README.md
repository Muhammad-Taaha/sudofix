# Repo-LLM Integration

**AI-powered security analysis for code repositories** – combining SAST, SCA, RAG, and LLMs.

## Overview

Repo-LLM is a unified pipeline that analyzes source code repositories for security vulnerabilities, dependency risks, and generates intelligent reports using large language models. It integrates:

- **SAST** (Static Application Security Testing) – taint analysis + rule‑based scanning  
- **SCA** (Software Composition Analysis) – dependency vulnerability scanning (pure‑Python wrapper using `npm audit`, `pip‑audit`, `osv‑scanner`)  
- **RAG** (Retrieval-Augmented Generation) – fetch relevant vulnerability fixes from a vector database  
- **LLM** – generate reviews, tests, or documentation using local models (e.g., Ollama)

## Features

- ✅ Parse multiple languages (Python, JavaScript, Java, Go, Rust, C/C++) via Tree‑sitter  
- ✅ Taint tracking across functions and files  
- ✅ Custom rule engine for security patterns  
- ✅ Dependency scanning (NPM, PyPI, Rust, Go, Java, C/C++)  
- ✅ LLM‑powered code review, test generation, and documentation  
- ✅ Redis caching and PostgreSQL persistence  
- ✅ Interactive / CLI mode selection (SAST only / SCA only / full pipeline)  
- ✅ Monorepo support – scans all sub‑projects

## Architecture
```
User Input (repo path, command, mode)
                │
                ▼
┌─────────────────────────────────────────┐
│   main.py │
│ - Parse arguments │
│ - Interactive mode selection │
│ - Dispatch to SAST / SCA / Full │
└────────────┬────────────────┬────────────┘
│ │
┌────────▼────────┐ ┌────▼───────────┐
│ SAST pipeline │ │ SCA pipeline │
│ (taint+rules) │ │ (scan_deps) │
└────────┬────────┘ └────┬───────────┘
│ │
└────────┬───────┘
▼
┌───────────────┐
│ RAG + LLM │
│ (CliAgent) │
└───────────────┘
```
text

### Directory Structure
repo-llm/
├── main.py # Entry point (pipeline orchestrator)
├── cli_agent/ # LLM interaction (Ollama)
├── controllers/ # DB (Postgres) + Redis + repo scanner
├── sastscanner/ # Taint engine + rule engine
├── parser/ # Tree‑sitter based AST parsers
├── rag/ # Vector store + retriever (vulnerability fixes)
├── sca/ # SCA module
│ └── sca_simple.py # Pure‑Python multi‑ecosystem scanner
├── vector_store/ # ChromaDB / embeddings
├── dataset/ # Vulnerability dataset (CVE fixes)
├── requirements.txt
└── README.md

text

## Prerequisites

- **Python 3.10+**
- **PostgreSQL** (for storing repo metadata)
- **Redis** (for caching processed chunks)
- **Ollama** (or any OpenAI‑compatible LLM) for the `cli_agent`
- Optional but recommended for SCA:
  - `pip-audit` (Python)
  - `npm` (Node.js) – only if you scan JS projects
  - `osv-scanner` (multi‑language fallback) – one binary for all

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-org/repo-llm.git
cd repo-llm
2. Set up Python environment
bash
python -m venv venv
source venv/bin/activate   # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
3. Install optional SCA tools (for dependency scanning)
bash
# Python dependencies scanner
pip install pip-audit

# Node.js (if you scan npm projects)
sudo apt install npm   # or use your package manager

# Universal scanner (OSV)
wget https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_linux_amd64
chmod +x osv-scanner_linux_amd64
sudo mv osv-scanner_linux_amd64 /usr/local/bin/osv-scanner
4. Set up databases
PostgreSQL: create a database and user, then update controllers/data_base_controller.py with connection details.

Redis: ensure Redis is running (default localhost:6379).

Vector store: the rag/ module expects a pre‑built ChromaDB or embeddings. You can populate it using making_vector_db.py.

5. Configure LLM
Edit cli_agent/cli_agent.py to point to your Ollama endpoint (default http://localhost:11434). Make sure the model (e.g., llama3.2) is pulled:

bash
ollama pull llama3.2
Usage
Run the pipeline on a local repository:

bash
python main.py /path/to/repo review
You will be prompted to choose a mode:

text
🔍 What would you like to run?
  1) SAST only (code analysis + LLM)
  2) SCA only (dependency scanning)
  3) Full pipeline (both)
Alternatively, use command‑line flags:

bash
python main.py /path/to/repo review --mode sast   # SAST only
python main.py /path/to/repo review --mode sca    # SCA only
python main.py /path/to/repo review --mode full   # full pipeline
Commands
review – perform security analysis and generate a natural language report.

test – generate unit tests for the code chunks (LLM).

doc – generate documentation comments.

How It Works
SAST Pipeline
Repo Scanner – walks the directory and splits code into chunks (functions, classes, etc.) using language‑specific parsers.

Taint Engine – tracks data flow from sources (user input) to sinks (dangerous functions).

Rule Engine – applies custom YAML/JSON rules to detect patterns (e.g., hardcoded secrets, SQL injection).

LLM Review – sends the chunk + findings + optional SCA context to the LLM for final analysis.

SCA Pipeline
Detects lockfiles/manifests (package.json, requirements.txt, Cargo.lock, go.mod, pom.xml, etc.).

Calls ecosystem‑specific tools (npm audit, pip-audit, cargo audit, govulncheck) or falls back to osv-scanner.

Returns a list of vulnerable dependencies (package, version, CVE, severity).

Generates a sca_report.md file and, in full mode, passes the context to the LLM.

RAG Integration
The rag/ module retrieves similar vulnerability fixes from a pre‑computed vector database (based on the CVEfixes dataset).

Retrieved patches are fed to the LLM to suggest concrete code fixes.

Configuration
Rules for SAST
Add custom rules in sastscanner/rules/ (JSON or YAML). Each rule defines:

id, severity, message

pattern (AST query) or taint configuration

Example rule (Python hardcoded password):

json
{
  "id": "PY001",
  "severity": "HIGH",
  "message": "Hardcoded password detected",
  "pattern": "(password|passwd|secret)\\s*=\\s*['\"][^'\"]+['\"]"
}
LLM Model
In cli_agent/cli_agent.py, modify:

python
self.model = "llama3.2"          # Ollama model name
self.api_url = "http://localhost:11434/api/generate"
Database Schema
PostgreSQL table repositories is automatically created. Redis keys are sha256(command:content) with 24h TTL.

Extending
Adding a New Language
Add a Tree‑sitter grammar in parser/ (e.g., swift_parser.py).

Update parser_factory.py to recognise file extensions.

Implement the UnifiedNode conversion.

Adding a New SCA Ecosystem
Edit sca/sca_simple.py – add a detection function and a scanner (e.g., composer_audit for PHP). The dispatcher will call it automatically when a lockfile is detected.

Custom LLM Prompts
Override methods in cli_agent/cli_agent.py:

review_code(chunk) – for security analysis

generate_test(chunk) – for unit test generation

generate_documentation(chunk) – for docstring generation

Troubleshooting
Issue	Solution
No module named 'magic'	pip install python-magic and sudo apt install libmagic1
SCA not available	Ensure sca/sca_simple.py exists and required tools (pip-audit, npm, osv-scanner) are in PATH.
Redis connection failed	Start Redis: redis-server
PostgreSQL error	Check credentials in data_base_controller.py and ensure the database is created.
LLM returns empty	Verify Ollama is running and the model is pulled.
Performance Tips
Use Redis to avoid re‑processing unchanged chunks (enabled by default).

For large repositories, run --mode sast first, then --mode sca separately.

The vector database (RAG) is optional – you can disable it by commenting out retrieval calls in cli_agent.

Contributing
Pull requests are welcome. Please follow the existing code style and add tests for new features.

License
[Your chosen license – e.g., MIT]

Built with Tree‑sitter, Ollama, PostgreSQL, Redis, and a lot of ❤️.

text


