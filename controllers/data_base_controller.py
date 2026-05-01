import os
import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor

load_dotenv()


class DatabaseConnection:
    def __init__(self):
        self.user = os.getenv("DB_USER", "devuser")
        self.password = os.getenv("DB_PASSWORD", "devpass")
        self.host = os.getenv("DB_HOST", "localhost")
        self.port = int(os.getenv("DB_PORT", 5432))
        self.database = os.getenv("DB_NAME", "code_docs")
        self.cursor_factory = RealDictCursor

    def connect(self):
        try:
            return psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                cursor_factory=self.cursor_factory,
            )
        except Exception as e:
            print(f"❌ Database Connection Error: {e}")
            return None


class Postgres(DatabaseConnection):
    def __init__(self):
        super().__init__()

    def _execute_query(self, sql, params=None, fetch=False):
        conn = self.connect()
        if not conn:
            return None

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    if fetch:
                        return cur.fetchall()
        except Exception as e:
            print(f"❌ Query Error: {e}")
            return None
        finally:
            conn.close()

    # -------------------------
    # REPOSITORY
    # -------------------------
    def save_repository(self, name: str, path: str):
        sql = """
        INSERT INTO repositories (name, path)
        VALUES (%s, %s)
        ON CONFLICT (path)
        DO UPDATE SET last_scanned = NOW()
        RETURNING id;
        """
        res = self._execute_query(sql, (name, path), fetch=True)

        if res:
            return res

        return self._execute_query(
            "SELECT id FROM repositories WHERE path = %s",
            (path,),
            fetch=True
        )

    # -------------------------
    # FILES
    # -------------------------
    def _upsert_file(self, repo_id, path, data):
        sql = """
        INSERT INTO files (repo_id, path, language, hash, size)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (repo_id, path)
        DO UPDATE SET
            hash = EXCLUDED.hash,
            language = EXCLUDED.language,
            size = EXCLUDED.size
        RETURNING id;
        """

        lang = "unknown"
        if data.get("chunks"):
            lang = data["chunks"][0].get(
                "metadata", {}).get("language", "unknown")

        params = (
            repo_id,
            path,
            lang,
            data.get("hash"),
            len(data.get("chunks", [])),
        )

        res = self._execute_query(sql, params, fetch=True)

        if res:
            return res[0]["id"]

        fallback = self._execute_query(
            "SELECT id FROM files WHERE repo_id = %s AND path = %s",
            (repo_id, path),
            fetch=True
        )

        return fallback[0]["id"] if fallback else None

    # -------------------------
    # CODE ENTITIES (FIXED CORE ISSUE)
    # -------------------------
    def save_code_entity(self, file_id: int, chunk: dict):
        sql = """
     INSERT INTO code_entities (file_id, name, hash, type)
     VALUES (%s, %s, %s, %s)
     ON CONFLICT (hash)
     DO UPDATE SET
         file_id = EXCLUDED.file_id,
         type = EXCLUDED.type
     RETURNING id;
     """

        params = (
            file_id,
            chunk.get("metadata", {}).get("name", "unknown_entity"),
            chunk.get("metadata", {}).get("hash"),
            chunk.get("metadata", {}).get("role", "code")  # 👈 FIXED
        )

        res = self._execute_query(sql, params, fetch=True)

        if res:
            return res[0]["id"]

        return None    # -------------------------
        # CHUNKS (FIXED USAGE EXPECTATION)
        # -------------------------

    def save_chunk(self, entity_id: int, chunk_dict: dict):
        sql = """
        INSERT INTO chunks (code_entity_id, content, type, token_count)
        VALUES (%s, %s, %s, %s);
        """

        params = (
            entity_id,
            chunk_dict["content"],
            chunk_dict.get("metadata", {}).get("role", "code"),
            len(chunk_dict["content"].split()),
        )

        self._execute_query(sql, params)

    # -------------------------
    # SYNC PIPELINE (FIXED FLOW)
    # -------------------------
    def sync_repo_to_db(self, repo_path: str):
        repo_name = os.path.basename(repo_path)

        repo_result = self.save_repository(repo_name, repo_path)
        if not repo_result:
            print("❌ Could not register repository.")
            return

        repo_id = repo_result[0]["id"]

        from .repo_scanner import RepoScanner
        scanner = RepoScanner(repo_path)
        all_chunks = scanner.local_scanner()

        files_map = {}

        for chunk in all_chunks:
            f_path = chunk["file_path"]

            if f_path not in files_map:
                files_map[f_path] = {
                    "chunks": [],
                    "hash": chunk["metadata"].get("file_hash"),
                }

            files_map[f_path]["chunks"].append(chunk)

        for file_path, data in files_map.items():

            file_id = self._upsert_file(repo_id, file_path, data)

            if not file_id:
                continue

            print(f"🔄 Processing {os.path.basename(file_path)}...")

            for chunk in data["chunks"]:

                # ✅ CREATE ENTITY FIRST
                entity_id = self.save_code_entity(file_id, chunk)

                if entity_id:
                    self.save_chunk(entity_id, chunk)

    # -------------------------
    # AI INSIGHTS
    # -------------------------
    def save_ai_insight(self, entity_id, insight_text, task_type, model):
        sql = """
        INSERT INTO doc_history (code_entity_id, doc_content, task_type, model)
        VALUES (%s, %s, %s, %s);
        """
        self._execute_query(sql, (entity_id, insight_text, task_type, model))

    def get_entity_id_by_hash(self, entity_hash: str):
        sql = "SELECT id FROM code_entities WHERE hash = %s LIMIT 1;"
        res = self._execute_query(sql, (entity_hash,), fetch=True)
        return res[0]["id"] if res else None
