#!/usr/bin/env python3
"""
Corrected Vector DB Builder for Local Machine
Uses BAAI/bge-small-en-v1.5 with proper prefixes.
"""

import pandas as pd
import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm
import torch
import gc
import hashlib
import re

# Configuration
DATA_PATH = "/home/muhammad-taaha/code/repo-llm/rag/cleaned_vulnerability_dataset.csv"   # adjust if needed
CHROMA_PATH = "./chroma_db_new"                   # fresh directory
COLLECTION_NAME = "vuln_fixes"
BATCH_SIZE = 32
MAX_TOKENS = 512

# Load data
df = pd.read_csv(DATA_PATH)
print(f"Raw rows: {len(df)}")

# Clean data
bad_pattern = r"(Bugs fixed|CVE-\d{4}|^[\d\.]+\s|Copyright|License|changelog|release|patch|update)"
df = df[
    df['fixed_code'].notna() &
    df['vulnerable_code'].notna() &
    (df['fixed_code'].str.strip() != "") &
    (df['vulnerable_code'].str.strip() != "")
]
df = df[~df['fixed_code'].str.contains(bad_pattern, case=False, na=False, regex=True)]
df = df[df['vulnerable_code'].str.len() <= 3000]
df = df.drop_duplicates(subset=['vulnerable_code'], keep='first')
print(f"After cleaning: {len(df)} rows")

# Load embedding model
device = "cuda" if torch.cuda.is_available() else "cpu"
model = SentenceTransformer("BAAI/bge-small-en-v1.5", device=device)

# Helper: truncate
def truncate(text, max_chars=2000):
    if len(text) > max_chars:
        return text[:max_chars]
    return text

# ChromaDB
client = chromadb.PersistentClient(path=CHROMA_PATH)
try:
    client.delete_collection(COLLECTION_NAME)
except:
    pass
collection = client.create_collection(name=COLLECTION_NAME)

# Index in batches
for start in tqdm(range(0, len(df), BATCH_SIZE)):
    batch = df.iloc[start:start+BATCH_SIZE]
    docs, metas, ids = [], [], []
    for _, row in batch.iterrows():
        # Build document text (vulnerability description)
        doc = f"Pattern: {row.get('pattern','')}\nLanguage: {row.get('language','')}\nVulnerable code:\n{truncate(row['vulnerable_code'])}"
        docs.append(doc)
        metas.append({
            "fixed_code": truncate(row['fixed_code']),
            "pattern": str(row.get('pattern',''))[:100],
            "language": str(row.get('language',''))[:50]
        })
        ids.append(hashlib.md5(row['vulnerable_code'].encode()).hexdigest())
    
    # Embed with "passage:" prefix
    embeddings = model.encode(
        ["passage: " + doc for doc in docs],
        normalize_embeddings=True,
        convert_to_numpy=True
    )
    collection.add(
        ids=ids,
        embeddings=embeddings.tolist(),
        documents=docs,
        metadatas=metas
    )
    del embeddings
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()

print(f"✅ Done. Collection size: {collection.count()}")

# Quick test
query = "SELECT * FROM users WHERE id = '" + input("Enter a vulnerable SQL pattern (or press Enter for default): ") + "'"
query_emb = model.encode(["query: " + query], normalize_embeddings=True).tolist()
results = collection.query(query_embeddings=query_emb, n_results=1, include=["metadatas"])
if results['metadatas'] and results['metadatas'][0]:
    print("\nRetrieved fix example:\n", results['metadatas'][0][0]['fixed_code'][:500])