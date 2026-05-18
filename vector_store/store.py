import numpy as np
import pandas as pd
import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any, Optional

class VectorStore:
    def __init__(self, data_path: str = "vector_store/filtered_dataset_with_embeddings.parquet"):
        print("Loading precomputed embeddings and metadata...")
        self.df = pd.read_parquet(data_path)
        # Ensure embedding column exists
        if 'embedding' not in self.df.columns:
            raise ValueError("Parquet file must contain an 'embedding' column")
        self.embeddings = np.vstack(self.df['embedding'].values)
        self.metadata = self.df[['pattern', 'language', 'fixed_code', 'vulnerable_code', 'file']].to_dict('records')
        
        # Initialize Chroma client
        self.client = chromadb.PersistentClient(path="vector_store/chroma_db")
        self.collection_name = "vuln_fixes"
        
        # Try to get existing collection, else create
        try:
            self.collection = self.client.get_collection(self.collection_name)
            print(f"Loaded existing collection with {self.collection.count()} documents")
        except:
            # Use a custom embedding function that loads the same model
            self.embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name="BAAI/bge-large-en-v1.5"
            )
            self.collection = self.client.create_collection(
                name=self.collection_name,
                embedding_function=self.embedding_fn
            )
            # Add all documents from the parquet file
            self._add_documents()
    
    def _add_documents(self, batch_size: int = 100):
        print(f"Adding {len(self.df)} documents to Chroma...")
        for i in range(0, len(self.df), batch_size):
            batch = self.df.iloc[i:i+batch_size]
            # Use fixed_code as the document text (what we retrieve)
            documents = batch['fixed_code'].tolist()
            metadatas = batch[['pattern', 'language', 'file']].to_dict('records')
            ids = [f"id_{j}" for j in range(i, i+len(batch))]
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
        print(f"Done. {self.collection.count()} documents in store.")
    
    def query(self, query_text: str, top_k: int = 3, language: Optional[str] = None, pattern: Optional[str] = None) -> List[Dict]:
        """
        Retrieve similar vulnerable/fixed pairs with optional language and pattern filters.
        """
        # Build filter condition
        where_filter = {}
        if language:
            where_filter['language'] = language
        if pattern:
            where_filter['pattern'] = pattern
        
        results = self.collection.query(
            query_texts=[query_text],
            n_results=top_k,
            where=where_filter if where_filter else None
        )
        
        # Format results
        retrieved = []
        if results['ids'][0]:
            for i in range(len(results['ids'][0])):
                retrieved.append({
                    'fixed_code': results['documents'][0][i],
                    'language': results['metadatas'][0][i]['language'],
                    'pattern': results['metadatas'][0][i]['pattern'],
                    'file': results['metadatas'][0][i].get('file', ''),
                    'similarity_score': results['distances'][0][i] if 'distances' in results else None
                })
        return retrieved
    
    def add(self, texts: List[str], metadatas: List[Dict]):
        """
        (Optional) Add new documents on the fly – not needed for static dataset.
        """
        # For completeness, but you may not need this.
        pass
    
    def save(self, path: str):
        """
        Chroma persists automatically; this method is kept for compatibility.
        """
        print(f"Chroma DB already persisted at {path}/chroma_db")