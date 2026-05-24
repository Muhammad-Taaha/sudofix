# rag/retriever.py
import numpy as np
import pandas as pd
import chromadb
from chromadb.utils import embedding_functions
from sentence_transformers import SentenceTransformer
import re
from typing import List, Dict, Any

class VulnerabilityRetriever:
    def __init__(self, data_path: str = "vector_store/filtered_dataset_with_embeddings.parquet"):
        # Load data
        self.df = pd.read_parquet(data_path)
        # Embeddings are stored as list of floats in column 'embedding'
        self.embeddings = np.vstack(self.df['embedding'].values)
        self.metadata = self.df[['pattern', 'language', 'fixed_code', 'vulnerable_code']].to_dict('records')
        
        # Load embedding model (for encoding user queries)
        self.encoder = SentenceTransformer(
                "BAAI/bge-small-en-v1.5",
                device="cpu"
            )
                    
        # Build Chroma collection
        self.client = chromadb.Client()
        self.collection = self.client.create_collection(
            name="vuln_fixes",
            embedding_function=embedding_functions.SentenceTransformerEmbeddingFunction(model_name="BAAI/bge-large-en-v1.5")
        )
        
        # Add documents in batches
        batch_size = 100
        for i in range(0, len(self.df), batch_size):
            batch = self.df.iloc[i:i+batch_size]
            self.collection.add(
                documents=batch['fixed_code'].tolist(),  # what we retrieve
                metadatas=batch[['pattern', 'language']].to_dict('records'),
                ids=[f"id_{j}" for j in range(i, i+len(batch))]
            )
        print(f"Vector store ready with {self.collection.count()} documents")

    def infer_pattern_and_language(self, query: str) -> Dict[str, str]:
        """Simple rule-based inference. Can be replaced with an LLM."""
        query_lower = query.lower()
        pattern = "misc"
        if re.search(r'sql|database|injection', query_lower):
            pattern = "sql_injection"
        elif re.search(r'command|exec|shell|os', query_lower):
            pattern = "command_injection"
        elif re.search(r'xss|script|alert|cross.?site', query_lower):
            pattern = "xss"
        elif re.search(r'auth|login|permission|access.?control', query_lower):
            pattern = "auth"
        elif re.search(r'file|path|traversal|directory', query_lower):
            pattern = "file"
        elif re.search(r'crypto|encrypt|decrypt|secret|key', query_lower):
            pattern = "crypto"
        elif re.search(r'deserialization|pickle|unserialize', query_lower):
            pattern = "deserialization"
        # Infer language
        language = "unknown"
        if "python" in query_lower:
            language = "python"
        elif "javascript" in query_lower or "js" in query_lower:
            language = "javascript"
        elif "java" in query_lower:
            language = "java"
        elif "c++" in query_lower or "cpp" in query_lower:
            language = "cpp"
        elif "go" in query_lower:
            language = "go"
        elif "rust" in query_lower:
            language = "rust"
        return {"pattern": pattern, "language": language}

    def retrieve_fixes(self, query: str, top_k: int = 5) -> List[Dict]:
        """Retrieve similar fixes with metadata filtering."""
        inferred = self.infer_pattern_and_language(query)
        # Build filter condition
        filter_condition = {}
        if inferred['pattern'] != "misc":
            filter_condition['pattern'] = inferred['pattern']
        if inferred['language'] != "unknown":
            filter_condition['language'] = inferred['language']
        
        # Query with filter
        results = self.collection.query(
            query_texts=[query],
            where=filter_condition if filter_condition else None,
            n_results=top_k
        )
        # Format results
        retrieved = []
        for i in range(len(results['ids'][0])):
            retrieved.append({
                'fixed_code': results['documents'][0][i],
                'pattern': results['metadatas'][0][i]['pattern'],
                'language': results['metadatas'][0][i]['language'],
                'similarity_score': results['distances'][0][i] if 'distances' in results else None
            })
        return retrieved