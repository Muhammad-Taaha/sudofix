# rag/retriever.py
import os
import torch
import chromadb
from sentence_transformers import SentenceTransformer
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import numpy as np

# Force offline mode (use cached models)
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["HF_HUB_OFFLINE"] = "1"

class VulnerabilityRetriever:
    def __init__(self, chroma_dir: str = "./chroma_db_reranker_ready"):
        # Load ChromaDB collection (already built with BGE-M3 and structured passages)
        self.client = chromadb.PersistentClient(path=chroma_dir)
        collections = self.client.list_collections()
        if not collections:
            raise RuntimeError("No ChromaDB collection found")
        self.collection = collections[0]  # assume it's the correct one
        print(f"Loaded collection '{self.collection.name}' with {self.collection.count()} docs")

        # Load embedding model (same as used during indexing)
        self.embed_model = SentenceTransformer("BAAI/bge-m3", device="cuda" if torch.cuda.is_available() else "cpu")

        # Load reranker (cross-encoder)
        self.reranker_name = "cross-encoder/ms-marco-MiniLM-L-6-v2"
        self.reranker_tokenizer = AutoTokenizer.from_pretrained(self.reranker_name)
        self.reranker_model = AutoModelForSequenceClassification.from_pretrained(self.reranker_name).to(self.embed_model.device)
        self.reranker_model.eval()

        # Config
        self.top_k_retrieve = 20   # initial dense retrieval
        self.top_k_final = 5       # after reranking

    def _encode_query(self, query_text: str) -> np.ndarray:
        """Encode query exactly as during indexing (no prefix, as your DB was built without)."""
        return self.embed_model.encode([query_text], normalize_embeddings=True)[0]

    def _rerank(self, query: str, documents: list) -> list:
        """Rerank documents using cross-encoder, return sorted list."""
        pairs = [(query, doc) for doc in documents]
        scores = []
        with torch.no_grad():
            for i in range(0, len(pairs), 16):
                batch = pairs[i:i+16]
                inputs = self.reranker_tokenizer(batch, padding=True, truncation=True, max_length=512, return_tensors="pt").to(self.embed_model.device)
                logits = self.reranker_model(**inputs).logits
                scores.extend(logits.squeeze().tolist())
        combined = sorted(zip(documents, scores), key=lambda x: x[1], reverse=True)
        return [doc for doc, _ in combined]

    def retrieve_fixes(self, vulnerable_code: str, vulnerability_type: str = None, language: str = None, top_k: int = None) -> list:
        """
        Retrieve top-k fixed code examples.
        Optionally filter by vulnerability_type and language (if known from SAST).
        """
        if top_k is None:
            top_k = self.top_k_final

        # 1. Dense retrieval with proper ChromaDB filter
        q_emb = self._encode_query(vulnerable_code)

        # Build filter condition using $and for multiple fields
        if vulnerability_type and language:
            where_clause = {
                "$and": [
                    {"pattern": vulnerability_type},
                    {"language": language}
                ]
            }
        elif vulnerability_type:
            where_clause = {"pattern": vulnerability_type}
        elif language:
            where_clause = {"language": language}
        else:
            where_clause = None

        results = self.collection.query(
            query_embeddings=[q_emb.tolist()],
            n_results=self.top_k_retrieve,
            where=where_clause,
            include=["documents", "metadatas"]
        )
        docs = results['documents'][0]
        metas = results['metadatas'][0]

        # If no results with filter, fall back to unfiltered retrieval
        if not docs and where_clause is not None:
            print(f"⚠️ No results with filter (pattern={vulnerability_type}, lang={language}), falling back to unfiltered.")
            results = self.collection.query(
                query_embeddings=[q_emb.tolist()],
                n_results=self.top_k_retrieve,
                where=None,
                include=["documents", "metadatas"]
            )
            docs = results['documents'][0]
            metas = results['metadatas'][0]

        if not docs:
            return []

        # 2. Rerank
        reranked_docs = self._rerank(vulnerable_code, docs)

        # 3. Align metadata with reranked order
        doc_to_meta = {doc: meta for doc, meta in zip(docs, metas)}
        reranked_metas = [doc_to_meta[doc] for doc in reranked_docs[:top_k]]
        reranked_docs = reranked_docs[:top_k]

        # 4. Extract fix snippets from structured documents (SECURE FIX section)
        fixes = []
        for doc, meta in zip(reranked_docs, reranked_metas):
            # Extract the fix part from the passage
            if "SECURE FIX:" in doc:
                fix_part = doc.split("SECURE FIX:")[1].split("TASK:")[0].strip()
            else:
                fix_part = doc
            # Extract vulnerable code example if present
            vuln_example = ""
            if "VULNERABLE CODE:" in doc:
                try:
                    vuln_example = doc.split("VULNERABLE CODE:")[1].split("SECURE FIX:")[0].strip()
                except:
                    vuln_example = ""
            fixes.append({
                'fixed_code': fix_part,
                'pattern': meta.get('pattern'),
                'language': meta.get('language'),
                'vulnerable_code_example': vuln_example
            })
        return fixes