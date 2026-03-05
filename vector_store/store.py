from typing import List, Dict
from sentence_transformers import SentenceTransformer
import faiss  # Facebook AI Similarity Search
import numpy as np

class VectorStore:
    def __init__(self,embedder_name='all-MiniLM-L6-v2'):
        self.embedder = SentenceTransformer(embedder_name)
        self.dim = self.embedder.get_sentence_embedding_dimension()
        self.index = faiss.IndexFlatL2(self.dim)
        self.metadatas: List[Dict] = []

    def add(self, texts: List[str], metadatas: List[Dict]):
        vectors = self.embedder.encode(texts)
        vectors = np.array(vectors).astype("float32")

        self.index.add(vectors)
        self.metadatas.extend(metadatas)

    def query(self, text: str, top_k: int = 5):
        vector = self.embedder.encode([text])[0]
        vector = np.array([vector]).astype("float32")

        distances, indices = self.index.search(vector, top_k)
        results = []

        for idx in indices[0]:
            if idx < len(self.metadatas):
                results.append(self.metadatas[idx])

        return results
        results = []

        # FAISS returns -1 if it doesn't find enough matches
        for idx in indices[0]:
            if idx != -1 and idx < len(self.metadatas):
                results.append(self.metadatas[idx])

        return results

    def save(self, folder_path: str):
        # Save the vectors
        faiss.write_index(self.index, f"{folder_path}/docs.index")
        # Save the metadata (use pickle or json)
        import pickle
        with open(f"{folder_path}/metadata.pkl", "wb") as f:
            pickle.dump(self.metadatas, f)

    def load(self, folder_path: str):
        self.index = faiss.read_index(f"{folder_path}/docs.index")
        import pickle
        with open(f"{folder_path}/metadata.pkl", "rb") as f:
            self.metadatas = pickle.load(f)
