from typing import List, Dict
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import pickle
import os


class VectorStore:
    def __init__(self, embedder_name: str = 'all-MiniLM-L6-v2'):
        """
        embedder_name: default is generic, but strongly recommended to change to
                       'microsoft/codebert-base' for code understanding.
        """
        self.embedder = SentenceTransformer(embedder_name)
        self.dim = self.embedder.get_sentence_embedding_dimension()
        # Use inner product index for cosine similarity (requires normalized vectors)
        self.index = faiss.IndexFlatIP(self.dim)
        self.metadatas: List[Dict] = []

    def _normalize(self, vectors: np.ndarray) -> np.ndarray:
        """L2‑normalize vectors to unit length."""
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)   # avoid division by zero
        return vectors / norms

    def add(self, texts: List[str], metadatas: List[Dict]):
        if not texts:
            return
        # 1. Generate embeddings
        vectors = self.embedder.encode(texts, show_progress_bar=True)
        vectors = np.array(vectors).astype('float32')
        # 2. Normalize to unit length (cosine similarity via inner product)
        vectors = self._normalize(vectors)
        # 3. Ensure 2D and contiguous
        if vectors.ndim == 1:
            vectors = vectors.reshape(1, -1)
        vectors = np.ascontiguousarray(vectors)
        # 4. Add to FAISS
        self.index.add(vectors)
        self.metadatas.extend(metadatas)

    def query(self, text: str, top_k: int = 5):
        # 1. Embed and normalize query
        vec = self.embedder.encode([text])[0]
        vec = np.array([vec]).astype('float32')
        vec = self._normalize(vec)
        vec = np.ascontiguousarray(vec.reshape(1, -1))
        # 2. Search
        distances, indices = self.index.search(vec, top_k)
        results = []
        for idx in indices[0]:
            if idx != -1 and idx < len(self.metadatas):
                results.append(self.metadatas[idx])
        return results

    def save(self, folder_path: str):
        os.makedirs(folder_path, exist_ok=True)
        faiss.write_index(self.index, f"{folder_path}/docs.index")
        with open(f"{folder_path}/metadata.pkl", "wb") as f:
            pickle.dump(self.metadatas, f)

    def load(self, folder_path: str):
        self.index = faiss.read_index(f"{folder_path}/docs.index")
        with open(f"{folder_path}/metadata.pkl", "rb") as f:
            self.metadatas = pickle.load(f)
