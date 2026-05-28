#!/usr/bin/env python3
"""
Vector DB Health Checker for Chroma (SQLite)
Tests if the database is useful for RAG‑based vulnerability fixing.
"""

import os
import sqlite3
import json
import shutil

# ========== CONFIGURATION ==========
# Set this to the DIRECTORY that contains your "chroma (2).sqlite3" file.
DB_DIRECTORY = "/home/muhammad-taaha/code/repo-llm/rag-fix"   # <--- CHANGE THIS

# Expected collection name (change if different)
COLLECTION_NAME = "vuln_fixes"

# ========== 1. INSPECT THE SQLITE DATABASE (FIXED) ==========
def inspect_sqlite(db_path):
    """Extract basic info and fixed_code samples directly from the .sqlite3 file."""
    if not os.path.exists(db_path):
        return None, 0
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # List all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    print(f"\n📂 Tables found: {tables}")
    
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"   {table}: {count} rows")
    
    # Extract fixed_code samples from embedding_metadata table
    sample_fixes = []
    total_fixes = 0
    if 'embedding_metadata' in tables:
        # Count how many metadata entries have key='fixed_code'
        cursor.execute("SELECT COUNT(*) FROM embedding_metadata WHERE key = 'fixed_code'")
        total_fixes = cursor.fetchone()[0]
        print(f"\n📝 Number of 'fixed_code' metadata entries: {total_fixes}")
        
        # Get up to 3 sample fixed_code values
        cursor.execute("""
            SELECT string_value FROM embedding_metadata 
            WHERE key = 'fixed_code' AND string_value IS NOT NULL 
            LIMIT 3
        """)
        rows = cursor.fetchall()
        for row in rows:
            if row[0]:
                sample_fixes.append(row[0][:300])
    
    conn.close()
    return sample_fixes, total_fixes

# ========== 2. TRY TO LOAD VIA CHROMADB CLIENT ==========
def try_chroma_client(directory, collection_name):
    """Attempt to load the collection using chromadb."""
    try:
        import chromadb
        from sentence_transformers import SentenceTransformer
    except ImportError:
        print("⚠️ chromadb or sentence-transformers not installed. Install with: pip install chromadb sentence-transformers")
        return None, None
    
    if not os.path.isdir(directory):
        print(f"❌ Directory not found: {directory}")
        return None, None
    
    # Check if there's a chroma.sqlite3 file; if not, try to rename the existing file
    sqlite_path = os.path.join(directory, "chroma.sqlite3")
    alt_path = os.path.join(directory, "chroma (2).sqlite3")
    
    if not os.path.exists(sqlite_path) and os.path.exists(alt_path):
        print(f"⚠️ Found 'chroma (2).sqlite3' but Chroma requires 'chroma.sqlite3'. Renaming...")
        try:
            shutil.move(alt_path, sqlite_path)
            print("✅ Renamed successfully.")
        except Exception as e:
            print(f"❌ Could not rename: {e}. Please manually rename the file to 'chroma.sqlite3'.")
            return None, None
    elif not os.path.exists(sqlite_path):
        print(f"❌ No chroma.sqlite3 found in {directory}. Cannot load via Chroma client.")
        return None, None
    
    try:
        client = chromadb.PersistentClient(path=directory)
        collections = client.list_collections()
        print(f"\n📚 Available collections: {[c.name for c in collections]}")
        
        if collection_name not in [c.name for c in collections]:
            print(f"❌ Collection '{collection_name}' not found.")
            return None, None
        
        collection = client.get_collection(collection_name)
        print(f"✅ Loaded collection '{collection_name}' with {collection.count()} entries.")
        
        # Load embedding model (assume BGE-small was used)
        model = SentenceTransformer("BAAI/bge-m3")
        return collection, model
    except Exception as e:
        print(f"❌ Chroma client error: {e}")
        return None, None

# ========== 3. PERFORM RETRIEVAL TESTS ==========
def retrieval_test(collection, model):
    """Run category‑specific queries and check if fixes make sense."""
    test_queries = {
        "sql_injection": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)",
        "xss": "response.write('<div>' + user_input + '</div>')",
        "path_traversal": "open('../../' + filename, 'r')",
        "hardcoded_secrets": "password = 'admin123'",
        "unsafe_eval": "eval(user_code)",
    }
    
    results = {}
    for vuln_type, code in test_queries.items():
        print(f"\n🔍 Testing {vuln_type}...")
        query_emb = model.encode(["query: " + code], normalize_embeddings=True).tolist()
        try:
            res = collection.query(query_embeddings=query_emb, n_results=1, include=["metadatas"])
            if res['metadatas'] and res['metadatas'][0]:
                fix = res['metadatas'][0][0].get('fixed_code', '')[:300]
                print(f"   Retrieved fix snippet:\n{fix}\n")
                # Simple heuristic checks
                if vuln_type == "sql_injection":
                    if any(x in fix.lower() for x in ['?', '%s', 'execute(', 'parameter']):
                        results[vuln_type] = "✅ good"
                    else:
                        results[vuln_type] = "⚠️ questionable"
                elif vuln_type == "xss":
                    if any(x in fix.lower() for x in ['escape', 'html.escape', 'textcontent', 'innertext']):
                        results[vuln_type] = "✅ good"
                    else:
                        results[vuln_type] = "⚠️ questionable"
                elif vuln_type == "hardcoded_secrets":
                    if any(x in fix.lower() for x in ['os.environ', 'getpass', 'secrets', 'vault']):
                        results[vuln_type] = "✅ good"
                    else:
                        results[vuln_type] = "⚠️ questionable"
                else:
                    results[vuln_type] = "✅ retrieved (manual check needed)"
            else:
                results[vuln_type] = "❌ no result"
        except Exception as e:
            print(f"   Error: {e}")
            results[vuln_type] = "❌ error"
    return results

# ========== 4. MANUAL SAMPLE INSPECTION (FALLBACK, FIXED) ==========
def manual_sample_inspection(db_path):
    """If Chroma client fails, inspect samples via SQLite."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    samples = []
    # Get vulnerable code (document) from embeddings table and join with metadata
    if 'embeddings' in [t[0] for t in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")]:
        # Get first 5 embeddings with their documents
        cursor.execute("SELECT id, document FROM embeddings WHERE document IS NOT NULL LIMIT 5")
        rows = cursor.fetchall()
        for emb_id, doc in rows:
            # Fetch fixed_code from embedding_metadata
            cursor.execute("""
                SELECT string_value FROM embedding_metadata 
                WHERE embedding_id = ? AND key = 'fixed_code'
            """, (emb_id,))
            meta_row = cursor.fetchone()
            fixed = meta_row[0][:300] if meta_row and meta_row[0] else "No fixed_code found"
            samples.append((doc[:300], fixed))
    
    conn.close()
    return samples

# ========== MAIN ==========
def main():
    print("🩺 Vector DB Health Checker")
    print("===========================")
    
    # Find the .sqlite3 file in the directory
    db_path = None
    for fname in os.listdir(DB_DIRECTORY):
        if fname.endswith(".sqlite3"):
            db_path = os.path.join(DB_DIRECTORY, fname)
            break
    
    if not db_path:
        print(f"❌ No .sqlite3 file found in {DB_DIRECTORY}. Please check the path.")
        return
    
    print(f"\n📁 Using database: {db_path}")
    
    # First try direct SQLite inspection
    sample_fixes, total_fixes = inspect_sqlite(db_path)
    if sample_fixes:
        print("\n📝 Sample 'fixed_code' entries (from metadata):")
        for i, fix in enumerate(sample_fixes[:3]):
            print(f"{i+1}. {fix}...")
    else:
        print("\n⚠️ No 'fixed_code' metadata entries found.")
    
    # Decide if DB has enough entries to be useful
    if total_fixes < 1000:
        print(f"\n⚠️ Only {total_fixes} fixes found. This is too small for effective RAG (need at least 5,000-10,000).")
        print("   Recommend rebuilding the vector DB with more data.")
        return
    
    # Try to load via Chroma client (will rename file if needed)
    collection, model = try_chroma_client(DB_DIRECTORY, COLLECTION_NAME)
    
    if collection and model:
        # Run retrieval tests
        results = retrieval_test(collection, model)
        print("\n📊 RETRIEVAL VERDICT:")
        passed = sum(1 for v in results.values() if "good" in v)
        total = len(results)
        print(f"   {passed}/{total} categories returned meaningful fixes.")
        if passed >= 3:
            print("✅ The DB is HEALTHY. Proceed with RAG fix generation.")
        elif passed >= 1:
            print("⚠️ The DB is USABLE but limited. Consider rebuilding with cleaner data.")
        else:
            print("❌ The DB contains data but retrieval is poor. Rebuild with better embedding/model.")
    else:
        # Fallback: manual sample inspection
        print("\n⚠️ Could not load Chroma collection. Falling back to manual sample inspection.")
        samples = manual_sample_inspection(db_path)
        if samples:
            print("\n🔎 Manual sample check (vulnerable code → fixed code):")
            for i, (vuln, fix) in enumerate(samples[:3]):
                print(f"\nSample {i+1}:")
                print(f"Vulnerable: {vuln}...")
                print(f"Fixed: {fix}...")
            print("\n💡 To properly test retrieval, you need to load the collection via Chroma.")
            print("   The script attempted to rename your file to 'chroma.sqlite3' but may have failed.")
            print("   Please manually rename 'chroma (2).sqlite3' to 'chroma.sqlite3' and re-run.")
        else:
            print("❌ No valid samples found. The database is likely empty or corrupted.")
    
    print("\n🏁 Done.")

if __name__ == "__main__":
    main()