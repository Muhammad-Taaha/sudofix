#!/usr/bin/env python3
"""
RAG Generation & Evaluation for Vulnerability Fixing
- Uses ChromaDB vector store built by build_db_local.py
- Uses local Qwen2.5-Coder:7b via Ollama
- Evaluates generated fixes with a rule-based judge
"""

import pandas as pd
import chromadb
from sentence_transformers import SentenceTransformer
import ollama
import numpy as np
import re
import hashlib
from tqdm import tqdm
import time

# ============================================================
# CONFIGURATION
# ============================================================
CHROMA_PATH = "./chroma_db_new"               # path to your built DB
COLLECTION_NAME = "vuln_fixes"
EMBED_MODEL = "BAAI/bge-small-en-v1.5"
OLLAMA_MODEL = "qwen2.5-coder:7b"
TEST_SAMPLE_SIZE = 50                         # number of test queries
DATA_PATH = "/home/muhammad-taaha/code/repo-llm/rag/cleaned_vulnerability_dataset.csv"

# ============================================================
# LOAD VECTOR DB & EMBEDDING MODEL
# ============================================================
client = chromadb.PersistentClient(path=CHROMA_PATH)
collection = client.get_collection(COLLECTION_NAME)
print(f"✅ Loaded DB with {collection.count()} documents")

embed_model = SentenceTransformer(EMBED_MODEL)
print("✅ Embedding model loaded")

# ============================================================
# HELPER FUNCTIONS
# ============================================================
def retrieve_top_k(query_code: str, k: int = 3):
    """Return top-k fixed_code strings and their metadata."""
    query_emb = embed_model.encode(
        ["query: " + query_code],
        normalize_embeddings=True
    ).tolist()
    results = collection.query(
        query_embeddings=query_emb,
        n_results=k,
        include=["metadatas", "documents"]
    )
    fixes = [meta["fixed_code"] for meta in results["metadatas"][0]]
    return fixes  # list of k strings

def generate_fix(vuln_code: str, example_fixes: list) -> str:
    """Generate a fix using local Ollama with strict prompt."""
    # Use only the first example to keep prompt short
    example = example_fixes[0][:1500]  # truncate
    prompt = f"""Fix the security vulnerability in the code below.
Output ONLY the corrected code. No explanations, no markdown, no extra text.

VULNERABLE CODE:
{vuln_code[:2000]}

EXAMPLE FIX (use as reference):
{example}

CORRECTED CODE:"""
    
    response = ollama.generate(
        model=OLLAMA_MODEL,
        prompt=prompt,
        options={"temperature": 0.1, "num_predict": 512}
    )
    raw = response["response"].strip()
    # Remove markdown code blocks if present
    raw = re.sub(r'```\w*\n?', '', raw)
    # Remove lines starting with ### (common metadata)
    lines = [l for l in raw.split('\n') if not l.strip().startswith('###')]
    return '\n'.join(lines).strip()

# ============================================================
# RULE-BASED JUDGE (vulnerability removal check)
# ============================================================
def is_fixed(vuln_code: str, generated_code: str, vuln_type: str = "auto") -> bool:
    """
    Heuristic to check if the vulnerability is removed.
    Extend with more patterns as needed.
    """
    vuln_lower = vuln_code.lower()
    gen_lower = generated_code.lower()
    
    # SQL injection (string concatenation)
    if "select" in vuln_lower and "+" in vuln_lower:
        # Fixed if using parameterized query (?, %s, :name) or execute with tuple
        if "?" in gen_lower or "%s" in gen_lower or "execute(" in gen_lower:
            return True
        return False
    
    # Command injection (os.system, subprocess)
    if "os.system" in vuln_lower or "subprocess" in vuln_lower:
        if "os.system" not in gen_lower and "subprocess" not in gen_lower:
            return True
        # else check if input is sanitized (basic)
        if "shlex.quote" in gen_lower or "list" in gen_lower:
            return True
        return False
    
    # eval() / exec()
    if "eval(" in vuln_lower or "exec(" in vuln_lower:
        if "eval(" not in gen_lower and "exec(" not in gen_lower:
            return True
        return False
    
    # XSS (html injection)
    if "innerhtml" in vuln_lower or "document.write" in vuln_lower:
        if "textcontent" in gen_lower or "innertext" in gen_lower or "encode" in gen_lower:
            return True
        return False
    
    # Default: assume fixed if generated code is not identical to vulnerable
    # (very weak, but better than nothing)
    return vuln_code.strip() != generated_code.strip()

# ============================================================
# LOAD TEST DATA (sample from the original dataset)
# ============================================================
df = pd.read_csv(DATA_PATH)
# Clean the same way as in build script (to avoid non-code fixed_code)
bad_pattern = r"(Bugs fixed|CVE-\d{4}|^[\d\.]+\s|Copyright|License|changelog|release|patch|update)"
df = df[df['fixed_code'].notna() & df['vulnerable_code'].notna()]
df = df[~df['fixed_code'].str.contains(bad_pattern, case=False, na=False, regex=True)]
df = df[df['vulnerable_code'].str.len() <= 3000]
df = df.drop_duplicates(subset=['vulnerable_code'], keep='first')
df = df.sample(min(TEST_SAMPLE_SIZE, len(df)), random_state=42).reset_index(drop=True)
print(f"✅ Test set size: {len(df)}")

# ============================================================
# EVALUATION LOOP
# ============================================================
results = []
for idx, row in tqdm(df.iterrows(), total=len(df), desc="Evaluating"):
    vuln = row["vulnerable_code"]
    ground_truth = row["fixed_code"]
    
    # Retrieve top-3 fixes
    retrieved = retrieve_top_k(vuln, k=3)
    
    # Generate fix using the best retrieved example
    generated = generate_fix(vuln, retrieved)
    
    # Judge
    fixed = is_fixed(vuln, generated)
    
    # Optional: semantic similarity (for reference, not used as primary)
    emb_vuln = embed_model.encode(vuln, normalize_embeddings=True)
    emb_gen = embed_model.encode(generated, normalize_embeddings=True)
    sim = float(np.dot(emb_vuln, emb_gen))
    
    results.append({
        "vuln_preview": vuln[:100],
        "generated_preview": generated[:150],
        "ground_truth_preview": ground_truth[:100],
        "fixed_by_rule": fixed,
        "similarity": sim
    })

# ============================================================
# METRICS
# ============================================================
df_res = pd.DataFrame(results)
fix_success = df_res["fixed_by_rule"].mean()

print("\n==================== RESULTS ====================")
print(f"Test samples: {len(df_res)}")
print(f"Fix success rate (rule-based): {fix_success:.2%}")
print(f"Mean cosine similarity (reference only): {df_res['similarity'].mean():.3f}")

print("\n--- Example generations ---")
for i in range(min(5, len(df_res))):
    print(f"\n🔧 Sample {i+1}:")
    print(f"Vulnerable: {df_res.loc[i, 'vuln_preview']}...")
    print(f"Generated fix: {df_res.loc[i, 'generated_preview']}...")
    print(f"Fixed? {df_res.loc[i, 'fixed_by_rule']}")
    print(f"Similarity: {df_res.loc[i, 'similarity']:.3f}")

# Save detailed results
df_res.to_csv("evaluation_results.csv", index=False)
print("\n✅ Detailed results saved to evaluation_results.csv")