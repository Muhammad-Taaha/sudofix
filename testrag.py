from vector_store.store import VectorStore

vs = VectorStore()

# Use a realistic vulnerable SQL query string
query_text = "SELECT * FROM users WHERE id = " + "123"  # example concatenation

results = vs.query(query_text, top_k=3, language="python", pattern="sql_injection")

for i, r in enumerate(results):
    print(f"{i+1}. Pattern: {r['pattern']}, Language: {r['language']}, File: {r['file']}")
    print(f"   Fixed code preview: {r['fixed_code'][:200]}...")
    print()