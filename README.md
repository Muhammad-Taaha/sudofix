# Sudofix Integration

**AI-powered security analysis for code repositories** – combining SAST, SCA, RAG, and LLMs.

---

## Overview

Sudofix is a unified pipeline that analyzes source code repositories for security vulnerabilities, dependency risks, and generates intelligent reports using large language models.

It integrates:

- **SAST (Static Application Security Testing)** – taint analysis + rule-based scanning  
- **SCA (Software Composition Analysis)** – dependency vulnerability scanning using `pip-audit`, `npm audit`, and `osv-scanner`  
- **RAG (Retrieval-Augmented Generation)** – fetch relevant vulnerability fixes from a vector database  
- **LLM** – generate reviews, tests, and documentation using local models (e.g., Ollama)

---

## Features

- ✅ Multi-language parsing (Python, JavaScript, Java, Go, Rust, C/C++) via Tree-sitter  
- ✅ Taint tracking across functions and files  
- ✅ Custom rule engine for detecting vulnerabilities  
- ✅ Dependency scanning (NPM, PyPI, Rust, Go, Java, C/C++)  
- ✅ LLM-powered:
  - Code review  
  - Test generation  
  - Documentation generation  
- ✅ Redis caching for performance  
- ✅ PostgreSQL persistence  
- ✅ CLI + interactive mode  
- ✅ Monorepo support  

---
```
## Architecture


User Input (repo path, command, mode)
                  │
                  ▼
┌─────────────────────────────────────────┐
│ main.py                                 │
│ - Parse arguments                       │
│ - Interactive mode selection            │
│ - Dispatch to SAST / SCA / Full         │
└────────────┬────────────────┬───────────┘
             │                │
┌───────▼───────┐ ┌─────▼──────────┐
│ SAST pipeline │ │ SCA pipeline   │
│ (taint+rules) │ │ (scan_deps)    │
└───────┬───────┘ └─────┬──────────┘
        │               │
        └────────┬──────┘
                 ▼
        ┌────────────────┐
        │ RAG + LLM      │
        │ (CliAgent)     │
        └────────────────┘


---
```
## Directory Structure

```
repo-llm/
├── main.py # Entry point
├── cli_agent/ # LLM interaction (Ollama)
├── controllers/ # DB + Redis + repo scanner
├── sastscanner/ # Taint + rule engine
├── parser/ # Tree-sitter parsers
├── rag/ # Vector retrieval
├── sca/ # Dependency scanner
│ └── sca_simple.py
├── vector_store/ # ChromaDB / embeddings
├── dataset/ # CVE fixes dataset
├── requirements.txt
└── README.md
```

---

## Prerequisites

- Python 3.10+
- PostgreSQL
- Redis
- Ollama (or OpenAI-compatible LLM)

Optional tools for SCA:

- `pip-audit`
- `npm`
- `osv-scanner`

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-org/repo-llm.git
cd repo-llm
2. Set up Python environment
python -m venv venv
source venv/bin/activate     # Windows: venv\Scripts\activate
pip install -r requirements.txt
3. Install SCA tools
pip install pip-audit

sudo apt install npm

wget https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_linux_amd64
chmod +x osv-scanner_linux_amd64
sudo mv osv-scanner_linux_amd64 /usr/local/bin/osv-scanner
4. Setup Databases

PostgreSQL → create DB and update config in:

controllers/data_base_controller.py

Redis:

redis-server

Vector DB:

python making_vector_db.py
Configure LLM (Ollama)
ollama pull llama3.2

Edit:

# cli_agent/cli_agent.py
self.model = "llama3.2"
self.api_url = "http://localhost:11434/api/generate"
Usage
Run pipeline
python main.py /path/to/repo review
Select mode
1) SAST only
2) SCA only
3) Full pipeline
CLI mode
python main.py /path/to/repo review --mode sast
python main.py /path/to/repo review --mode sca
python main.py /path/to/repo review --mode full
Commands
Command	Description
review	Security analysis + report
test	Generate unit tests
doc	Generate documentation
How It Works
SAST Pipeline
Repo Scanner → splits code into chunks
Taint Engine → tracks data flow
Rule Engine → applies vulnerability rules
LLM → final analysis
SCA Pipeline
Detects dependency files:
package.json, requirements.txt, Cargo.lock, etc.
Runs:
npm audit
pip-audit
osv-scanner
Outputs:
Vulnerability list
sca_report.md
RAG Integration
Retrieves similar vulnerability fixes from vector DB
Uses CVE dataset
Feeds fixes into LLM for better suggestions
Configuration
SAST Rules

Example:

{
  "id": "PY001",
  "severity": "HIGH",
  "message": "Hardcoded password detected",
  "pattern": "(password|passwd|secret)\\s*=\\s*['\"][^'\"]+['\"]"
}

Location:

sastscanner/rules/
Database Schema
PostgreSQL → repository metadata
Redis → cache (sha256(command:content), TTL 24h)
Extending
Add New Language
Add parser in parser/
Update parser_factory.py
Implement UnifiedNode
Add New SCA Tool

Edit:

sca/sca_simple.py
Custom LLM Prompts

Modify:

review_code()
generate_test()
generate_documentation()
Troubleshooting
Issue	Solution
No module named 'magic'	pip install python-magic && sudo apt install libmagic1
SCA not working	Ensure tools are installed
Redis error	redis-server
PostgreSQL error	Check credentials
LLM empty output	Ensure Ollama is running
Performance Tips
Use Redis caching (enabled by default)
Run SAST and SCA separately for large repos
Disable RAG if not needed
Contributing

Pull requests are welcome. Please follow code style and add tests.

License

MIT (or your preferred license)

Tech Stack
Tree-sitter
Ollama
PostgreSQL
Redis
ChromaDB
