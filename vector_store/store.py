from typing import List, Dict
import faiss
import numpy as np

class VectorStore:
    def __init__(self, embedder, dim: int):
        self.embedder = embedder
        self.dim = dim
        self.index = faiss.IndexFlatL2(dim)
        self.metadatas: List[Dict] = []

    def add(self, texts: List[str], metadatas: List[Dict]):
        vectors = self.embedder.embed(texts)
        vectors = np.array(vectors).astype("float32")

        self.index.add(vectors)
        self.metadatas.extend(metadatas)

    def query(self, text: str, top_k: int = 5):
        vector = self.embedder.embed([text])[0]
        vector = np.array([vector]).astype("float32")

        distances, indices = self.index.search(vector, top_k)
        results = []

        for idx in indices[0]:
            if idx < len(self.metadatas):
                results.append(self.metadatas[idx])

        return results
