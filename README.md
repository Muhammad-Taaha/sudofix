# Sudofix Integration

**AI-powered security analysis for code repositories** – combining SAST, SCA, RAG, and LLMs.

**Version 1.0** – AI-driven vulnerability detection, analysis, and automated fix generation for code repositories.

Sudofix Integration combines static analysis (SAST), software composition analysis (SCA), retrieval-augmented generation (RAG), and large language models to identify security vulnerabilities in source code and propose concrete, context-aware fixes. It supports multiple programming languages, scales to large codebases, and provides both a CLI and a terminal UI (TUI) for interactive workflows.

---

## ✨ Key Features

- **Multi-language AST parsing** – Uses tree-sitter grammars for Python, JavaScript, Java, C/C++, Go, Rust, and more.
- **SAST & Taint analysis** – Custom rule engine + taint tracking to detect injection, XSS, path traversal, etc.
- **SCA (Software Composition Analysis)** – Scans dependencies for known vulnerabilities (integrates with `scancode-toolkit`).
- **RAG-based augmentation** – ChromaDB vector store with reranking, pre‑indexed vulnerability dataset (CVEfixes, high‑confidence security fixes).
- **LLM integration** – Works with local models via Ollama (or any OpenAI‑compatible endpoint) to generate natural‑language explanations and ready‑to‑apply patches.
- **Git integration** – Monitors commits, interacts with GitHub webhooks, and checks out historical vulnerable versions.
- **Terminal UI** – Full‑screen TUI to navigate findings, review suggested fixes, and run analysis interactively.
- **Pipeline automation** – `pipeline.py` orchestrates the entire workflow: cloning, parsing, detection, RAG retrieval, fix generation, and reporting.
- **Docker support** – `docker-compose.yml` included for easy deployment with ChromaDB, Redis, and the analysis worker.

---


```
├── cli_agent/ # Command‑line interface & automation scripts
├── controllers/ # Database, Redis, repo scanner controllers
├── dataset/ # CVE patches, CVEfixes, metadata for RAG
├── git_controller/ # Git operations, webhook handlers, commit watching
├── llm/ # Ollama client and LLM abstractions
├── parser/ # Language‑specific parsers (Python, Java, JS, C++, Go, Rust)
├── rag/ # ChromaDB stores, dataset cleaning, RAG pipeline
├── sastscanner/ # Core SAST engine: rules, taint tracking, findings
├── sca/ # SCA module (dependency scanning)
├── tui/ # Terminal UI components (editor, system monitor, LLM info)
├── tree-sitter-*/ # Vendor tree-sitter grammars (C++, Rust, etc.)
├── vector_store/ # Embeddings, parquet indexes, ChromaDB utils
├── main.py # Entry point for CLI/TUI
├── pipeline.py # Automated end‑to‑end pipeline
├── docker-compose.yml # Services: ChromaDB, Redis, (optional) Ollama
└── requirements.txt # Python dependencies
```


---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com/) (or another LLM backend) – optional but recommended
- Docker & Docker Compose (for ChromaDB + Redis)

### Installation

```bash
git clone https://github.com/your-org/sudofix-integration.git
cd sudofix-integration
python -m venv venv
source venv/bin/activate   # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt

## 📁 Project Structure (Highlights)

Quick Start (Docker)
bash
docker-compose up -d
python main.py --help

Basic Usage
Analyze a local repository

bash
python main.py scan /path/to/repo --lang python
Run the full pipeline on a remote GitHub repo

bash
python pipeline.py --repo https://github.com/example/vuln-app --output report.json
Launch the TUI

bash
python tui_app.py
RAG query – ask about a vulnerability pattern

bash
python query_rag.py "SQL injection in Python with sqlite3"
🧠 How It Works
Repository loading – Clones or uses local path, extracts commit history.

Parsing – Builds ASTs using language‑specific tree‑sitter parsers.

SAST analysis – Applies rule set (e.g., taint tracking, insecure function calls).

SCA – Scans dependency manifests (package.json, requirements.txt, etc.) for known CVEs.

RAG enrichment – For each finding, retrieves similar vulnerability examples + fixes from the pre‑indexed dataset.

LLM fix generation – Prompts the model with source code, vulnerability description, and retrieved examples to produce a concrete patch.

Reporting & TUI – Findings are stored (SQLite/Postgres), displayed interactively, or exported as JSON.
```
🧩 Components Overview
Module	Description
parser/	Factory + language parsers; yields AST nodes, dependency graphs, and chunks.
sastscanner/	Rule engine with data flow analysis; supports custom YAML rules.
sca/	Wrappers for scancode-toolkit and pip-audit; produces SBOM + CVE mapping.
rag/	ChromaDB collection with cross‑encoder reranker; stores embeddings from CVEfixes.
llm/	Async client for Ollama, handles prompt templating and streaming.
tui/	Textual‑based UI with live system monitoring, code editor, and diff viewer.
git_controller/	Manages commit ranges, checkout of vulnerable versions, and webhook endpoints.
```
## 📊 Dataset & RAG Performance
CVEfixes subset (high‑confidence security fixes) is cleaned and indexed.

Vector store uses all‑MiniLM‑L6‑v2 embeddings (configurable) and a cross‑encoder for reranking.

Filtered dataset: rag/cleaned_vulnerability_dataset_filtered.csv (about 15k high‑quality examples).

Evaluation scripts: rag-fix/rag_generate_and_evaluate.py measures fix correctness.

## 🔧 Configuration
Most settings are in environment variables or a .env file:

ini
# LLM
OLLAMA_BASE_URL=http://localhost:11434
LLM_MODEL=llama3.2:3b

# Vector DB
CHROMA_HOST=localhost
CHROMA_PORT=8000
RERANKER_MODEL=cross-encoder/ms-marco-MiniLM-L-6-v2

# Git
GITHUB_WEBHOOK_SECRET=your_secret
You can also modify pipeline.py directly for custom workflows.

##🧪 Testing & Evaluation
Test cases for SAST – testcases/ contains generators for SQLi, XSS, path traversal, etc.

AST inspection – inspect_ast.py to debug tree‑sitter output.

RAG diagnostics – rag_diagnostic.py checks retrieval quality.

End‑to‑end – pipeline.py --eval runs on a labeled test set and computes accuracy metrics.

##📦 Dependencies
Major libraries:

tree-sitter + language bindings

chromadb, sentence-transformers, FlagEmbedding

textual (TUI), ollama, fastapi (webhook endpoint)

scancode-toolkit, pip-audit

pandas, numpy, pyarrow

See requirements.txt for the full list.

##🤝 Contributing
We welcome contributions! Please follow these steps:

Fork the repository.

Create a feature branch (git checkout -b feature/new-rule).

Add tests under testcases/ or tests/.

Run python pipeline.py --smoke to validate changes.

Open a pull request with a clear description.

Areas that need help:

Additional tree‑sitter grammars (C#, PHP, Ruby).

More SAST rules (e.g., crypto misuse, race conditions).

Support for other LLM backends (OpenAI, Anthropic, vLLM).

##📄 License
This project is licensed under the Apache 2.0 License – see the LICENSE file for details.
##
📬 Contact & Acknowledgments
Maintainer: [Muhammad-taaha / Team Sudofix]

Built with: Tree‑sitter, ChromaDB, Ollama

Dataset: CVEfixes and CVE‑patch‑dataset

💬 Example Commands
Command	Description
python main.py scan ~/myproject --lang java --output findings.json	Scan Java project, save results
python pipeline.py --repo https://github.com/example/repo --fix	Clone, scan, and automatically generate fixes
python query_rag.py "command injection" --top-k 5	Retrieve top 5 similar vulnerability examples
python tui_app.py	Launch interactive terminal UI
Tip: For the best fix generation, run Ollama with a model fine‑tuned on code (e.g., codellama, deepseek-coder).

# Happy secure coding! 🔒
