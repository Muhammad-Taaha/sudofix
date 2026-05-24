from vector_store.store import VectorStore

# 1. Initialize and Load
store = VectorStore()
store.load("vector_store")

# 2. Ask a question about your code
query = "How does the Redis manager handle connections?"
results = store.query(query, top_k=2)

# 3. See the results
print(f"🔍 Found {len(results)} relevant code chunks:\n")
for i, match in enumerate(results):
    print(f"--- Result {i+1} ---")
    print(f"File: {match['file_name']}")
    print(f"AI Insight: {match['llm_insight'][:200]}...") # Show snippet of the insight
    print("-" * 20)