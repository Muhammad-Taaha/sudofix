from rag.retriever import VulnerabilityRetriever
from cli_agent.cli_agent import CliAgent


def test_vector_db():
    print("\n==============================")
    print("🔍 TEST 1: VECTOR DB DIRECT")
    print("==============================")

    retriever = VulnerabilityRetriever()

    query = "sql injection in python login query"

    results = retriever.retrieve_fixes(query=query, top_k=3)

    print("\n📦 Retrieved Results:")
    for i, r in enumerate(results):
        print(f"\n--- RESULT {i+1} ---")
        print("Pattern:", r.get("pattern"))
        print("Language:", r.get("language"))
        print("Fix preview:\n", r.get("fixed_code", "")[:200])

    assert len(results) > 0, "❌ Vector DB is NOT returning results"
    print("\n✅ Vector DB WORKING")


def test_cli_to_retriever():
    print("\n==============================")
    print("🔍 TEST 2: CLI → RAG PIPELINE")
    print("==============================")

    agent = CliAgent(
        repo_path=".",
        command="review",
        dry_run=False
    )

    chunk = {
        "file_name": "test.py",
        "content": 'query = "SELECT * FROM users WHERE id=" + user_input',
        "metadata": {
            "language": "python"
        }
    }

    result = agent.review_code(chunk)

    print("\n📦 CLI OUTPUT:")
    print(result[:500] if result else "❌ NO OUTPUT")

    assert result is not None, "❌ CLI pipeline failed"
    print("\n✅ CLI PIPELINE WORKING")


def test_rag_is_actually_used():
    print("\n==============================")
    print("🔍 TEST 3: RAG USAGE CHECK")
    print("==============================")

    agent = CliAgent(".", "review", dry_run=False)

    chunk = {
        "file_name": "test.py",
        "content": 'os.system("rm -rf " + user_input)',
        "metadata": {
            "language": "python"
        }
    }

    print("\n🚀 Running pipeline...\n")

    result = agent.review_code(chunk)

    print("\n📊 FINAL OUTPUT:\n", result)

    print("\n⚠️ MANUAL CHECK REQUIRED:")
    print("- Did logs show 'Retrieving similar' ?")
    print("- Did you see vector DB prints?")
    print("- Did prompt include examples?")


if __name__ == "__main__":
    test_vector_db()
    test_cli_to_retriever()
    test_rag_is_actually_used()