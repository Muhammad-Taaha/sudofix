#!/usr/bin/env python3
import os
import sys
import torch
import chromadb
from sentence_transformers import SentenceTransformer
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ---------- FORCE OFFLINE MODE (use cached models) ----------
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_HUB_OFFLINE"] = "1"

# ---------- OPTIONAL: set cache dir if needed (adjust path) ----------
# os.environ["TRANSFORMERS_CACHE"] = "/home/muhammad-taaha/.cache/huggingface"
# os.environ["HF_HOME"] = "/home/muhammad-taaha/.cache/huggingface"

# ---------- CONFIG ----------
CHROMA_DIR = "./chroma_db_reranker_ready"
EMBED_MODEL_NAME = "BAAI/bge-m3"
RERANKER_NAME = "cross-encoder/ms-marco-MiniLM-L-6-v2"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
TOP_K_RETRIEVE = 20
TOP_K_FINAL = 5

# ---------- 1. Load ChromaDB ----------
if not os.path.exists(CHROMA_DIR):
    print(f"❌ ChromaDB directory not found: {CHROMA_DIR}")
    sys.exit(1)

client = chromadb.PersistentClient(path=CHROMA_DIR)
collections = client.list_collections()
print(f"📚 Available collections: {[c.name for c in collections]}")
if not collections:
    print("❌ No collections found.")
    sys.exit(1)
collection = collections[0]
print(f"✅ Using collection: {collection.name} (size: {collection.count()})")

# ---------- 2. Load embedding model (offline) ----------
print(f"🔧 Loading embedding model {EMBED_MODEL_NAME} on {DEVICE} (offline)...")
try:
    embed_model = SentenceTransformer(EMBED_MODEL_NAME, device=DEVICE)
    print("✅ Embedding model loaded from cache.")
except Exception as e:
    print(f"⚠️ Failed to load {EMBED_MODEL_NAME}: {e}")
    print("Trying smaller model BAAI/bge-small-en-v1.5 (offline)...")
    embed_model = SentenceTransformer("BAAI/bge-small-en-v1.5", device=DEVICE)

def encode_query(text):
    # No prefix as your DB was built without "query:"
    emb = embed_model.encode([text], normalize_embeddings=True)
    return emb[0]

# ---------- 3. Load reranker (offline) ----------
print(f"🔧 Loading reranker {RERANKER_NAME} (offline)...")
try:
    reranker_tokenizer = AutoTokenizer.from_pretrained(RERANKER_NAME)
    reranker_model = AutoModelForSequenceClassification.from_pretrained(RERANKER_NAME).to(DEVICE)
    reranker_model.eval()
    print("✅ Reranker loaded from cache.")
except Exception as e:
    print(f"⚠️ Reranker failed to load: {e}")
    reranker_model = None

def rerank(query, documents, top_k=TOP_K_FINAL):
    if reranker_model is None:
        # fallback: return first top_k documents (no reranking)
        return documents[:top_k]
    pairs = [(query, doc) for doc in documents]
    scores = []
    with torch.no_grad():
        for i in range(0, len(pairs), 16):
            batch = pairs[i:i+16]
            inputs = reranker_tokenizer(batch, padding=True, truncation=True, max_length=512, return_tensors="pt").to(DEVICE)
            logits = reranker_model(**inputs).logits
            batch_scores = logits.squeeze().tolist()
            if len(batch) == 1:
                batch_scores = [batch_scores]
            scores.extend(batch_scores)
    combined = list(zip(documents, scores))
    combined.sort(key=lambda x: x[1], reverse=True)
    return [doc for doc, _ in combined[:top_k]]

# ---------- 4. Retrieve and rerank ----------
def retrieve_and_rerank(query_text):
    q_emb = encode_query(query_text)
    results = collection.query(
        query_embeddings=[q_emb.tolist()],
        n_results=TOP_K_RETRIEVE,
        include=["documents", "metadatas"]
    )
    docs = results['documents'][0]
    metas = results['metadatas'][0]
    if reranker_model is not None:
        reranked_docs = rerank(query_text, docs)
        # Align metadata
        doc_to_meta = {doc: meta for doc, meta in zip(docs, metas)}
        reranked_metas = [doc_to_meta[doc] for doc in reranked_docs]
    else:
        reranked_docs = docs[:TOP_K_FINAL]
        reranked_metas = metas[:TOP_K_FINAL]
    return reranked_docs[:TOP_K_FINAL], reranked_metas[:TOP_K_FINAL]

# ---------- 5. Test queries ----------
test_queries = {
    "sql_injection": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
    "xss": "response.write('<div>' + user_input + '</div>')",
    "hardcoded_secrets": "password = 'admin123'",
    "path_traversal": "open('../../' + filename, 'r')",
    "unsafe_eval": "eval(user_code)",
}

print("\n" + "="*70)
print("DIAGNOSTIC TEST: Reranker RAG (offline mode)")
print("="*70)

for vuln_type, query in test_queries.items():
    print(f"\n--- {vuln_type} ---")
    try:
        top_docs, top_metas = retrieve_and_rerank(query)
        if not top_docs:
            print("❌ No results")
            continue
        # Print top-1 fix snippet and heuristic
        best_doc = top_docs[0]
        best_meta = top_metas[0]
        # Extract fix
        fix_start = best_doc.find("SECURE FIX:")
        if fix_start != -1:
            fix_end = best_doc.find("\n\n", fix_start)
            fix_snippet = best_doc[fix_start:fix_end] if fix_end != -1 else best_doc[fix_start:]
            fix_code = best_doc.split("SECURE FIX:")[1].split("TASK:")[0].strip()
        else:
            fix_snippet = best_doc[:300]
            fix_code = best_doc
        print(f"Retrieved pattern: {best_meta.get('pattern', '?')}, language: {best_meta.get('language', '?')}")
        print(f"Fix snippet: {fix_snippet[:200]}...")
        
        # Heuristic check
        low = fix_code.lower()
        if vuln_type == "sql_injection":
            ok = any(kw in low for kw in ["prepare", "bind", "?", "parameter", "execute"])
        elif vuln_type == "xss":
            ok = any(kw in low for kw in ["escape", "html", "sanitize", "textcontent"])
        elif vuln_type == "hardcoded_secrets":
            ok = any(kw in low for kw in ["env", "vault", "secret", "os.environ"])
        elif vuln_type == "path_traversal":
            ok = any(kw in low for kw in ["basename", "normpath", "realpath", "sanitize"])
        elif vuln_type == "unsafe_eval":
            ok = any(kw in low for kw in ["literal_eval", "json.loads", "ast"])
        else:
            ok = False
        print(f"Heuristic: {'✅ PASS' if ok else '❌ FAIL'}")
        
        # Optionally print all top-5 patterns
        print("Top-5 retrieved patterns:")
        for i, meta in enumerate(top_metas):
            print(f"  {i+1}: {meta.get('pattern', '?')}")
    except Exception as e:
        print(f"Error: {e}")

print("\n" + "="*70)
print("DIAGNOSTIC COMPLETE")