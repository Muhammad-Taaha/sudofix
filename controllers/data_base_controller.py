import os
import psycopg2
from dotenv import load_dotenv
from psycopg2.extras import RealDictCursor
import hashlib

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
            conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                cursor_factory=self.cursor_factory,
            )
            return conn
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

    def save_repository(self, name: str, path: str):
        sql = """
        INSERT INTO repositories (name, path)
        VALUES (%s, %s)
        ON CONFLICT (path) DO UPDATE SET last_scanned = NOW()
        RETURNING id;
        """
        result = self._execute_query(sql, (name, path), fetch=True)
        if result and len(result) > 0:
            return result
        return self._execute_query("SELECT id FROM repositories WHERE path = %s", (path,), fetch=True)

    def _get_file_by_path(self, repo_id, path):
        query = "SELECT id, hash FROM files WHERE repo_id = %s AND path = %s"
        res = self._execute_query(query, (repo_id, path), fetch=True)
        return res[0] if res else None

    def _upsert_file(self, repo_id, path, data):
        query = """
        INSERT INTO files (repo_id, path, language, hash, size)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (repo_id, path)
        DO UPDATE SET hash = EXCLUDED.hash, language = EXCLUDED.language, size = EXCLUDED.size
        RETURNING id;
        """
        lang = "unknown"
        if data.get("chunks") and len(data["chunks"]) > 0:
            lang = data["chunks"][0].get(
                "metadata", {}).get("language", "unknown")

        params = (repo_id, path, lang, data.get(
            "hash"), len(data.get("chunks", [])))
        res = self._execute_query(query, params, fetch=True)
        if res and len(res) > 0:
            return res[0]["id"]

        fallback = self._execute_query(
            "SELECT id FROM files WHERE repo_id = %s AND path = %s", (repo_id, path), fetch=True)
        return fallback[0]["id"] if fallback else None

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

    def _clear_file_contents(self, file_id):
        self._execute_query(
            "DELETE FROM code_entities WHERE file_id = %s", (file_id,))

    def sync_repo_to_db(self, repo_path: str):
        repo_name = os.path.basename(repo_path)
        repo_result = self.save_repository(repo_name, repo_path)
        if not repo_result:
            return

        repo_id = repo_result[0]["id"]
        from .repo_scanner import RepoScanner
        scanned_repo = RepoScanner(repo_path)
        all_chunks = scanned_repo.local_scanner()

        files_to_process = {}
        for chunk in all_chunks:
            f_path = chunk["file_path"]
            if f_path not in files_to_process:
                files_to_process[f_path] = {
                    "chunks": [], "hash": chunk["metadata"].get("file_hash")}
            files_to_process[f_path]["chunks"].append(chunk)

        for file_path, data in files_to_process.items():
            db_file = self._get_file_by_path(repo_id, file_path)

            # --- NEW CHECK: Does the entity actually exist in the DB? ---
            entity_id = None
            if db_file:
                ent_res = self._execute_query(
                    "SELECT id FROM code_entities WHERE file_id = %s AND type = 'file_root' LIMIT 1",
                    (db_file['id'],), fetch=True
                )
                if ent_res:
                    entity_id = ent_res[0]['id']

            # ONLY skip if BOTH the hash matches AND the entity exists
            if db_file and db_file["hash"] == data["hash"] and entity_id:
                # print(f"✅ Skipping {os.path.basename(file_path)} (Fully Synced)")
                continue

            # If we reach here, either the file changed OR the entity is missing
            print(f"🔄 Syncing/Repairing {os.path.basename(file_path)}...")
            file_id = self._upsert_file(repo_id, file_path, data)

            if file_id:
                # Clear old chunks before re-syncing
                self._clear_file_contents(file_id)

                # This ensures the entity is created and we get the ID
                entity_id = self._get_or_create_file_entity(
                    file_id, os.path.basename(file_path), data["hash"])

                for chunk in data["chunks"]:
                    self.save_chunk(entity_id, chunk)

                print(f"💾 {os.path.basename(file_path)
                           } synced with Entity ID: {entity_id}")

    def _get_or_create_file_entity(self, file_id, file_name, file_hash):
        sql = """
        INSERT INTO code_entities (file_id, name, type, hash)
        VALUES (%s, %s, 'file_root', %s)
        ON CONFLICT (file_id, name) DO UPDATE SET hash = EXCLUDED.hash
        RETURNING id;
        """
        res = self._execute_query(
            sql, (file_id, file_name, file_hash), fetch=True)
        if res and len(res) > 0:
            return res[0]['id']

        # FIXED: Indented fallback logic to be inside the function
        fallback = self._execute_query(
            "SELECT id FROM code_entities WHERE file_id = %s AND name = %s",
            (file_id, file_name), fetch=True
        )
        return fallback[0]['id'] if fallback else None

    def get_unprocessed_chunk(self, task_type):
        query = '''
            SELECT c.id, c.content, e.name as entity_name, e.id as entity_id
            FROM chunks c
            JOIN code_entities e ON c.code_entity_id = e.id
            JOIN files f ON e.file_id = f.id
            LEFT JOIN doc_history h ON h.code_entity_id = e.id AND h.task_type = %s
            WHERE h.id IS NULL;
        '''
        return self._execute_query(query, (task_type,), fetch=True)

    def get_entity_id_by_hash(self, entity_hash: str):
        sql = "SELECT id FROM code_entities WHERE hash = %s LIMIT 1;"
        result = self._execute_query(sql, (entity_hash,), fetch=True)
        return result[0]['id'] if result and len(result) > 0 else None

    def get_entity_id_by_path(self, repo_id, file_path):
        """Finds the root entity ID using the file path."""
        sql = """
            SELECT e.id 
            FROM code_entities e
            JOIN files f ON e.file_id = f.id
            WHERE f.repo_id = %s AND f.path = %s AND e.type = 'file_root'
            LIMIT 1;
        """
        res = self._execute_query(sql, (repo_id, file_path), fetch=True)
        return res[0]['id'] if res else None

    def save_ai_insight(self, entity_id, insight_text, task_type, model):
        sql = "INSERT INTO doc_history (code_entity_id, doc_content, task_type, model) VALUES (%s, %s, %s, %s);"
        res = self._execute_query(
            sql, (entity_id, insight_text, task_type, model))
        return res

    def get_entity_id_by_path(self, repo_id, file_path):
        """Finds the root entity ID using the file path."""
        sql = """
        SELECT e.id 
        FROM code_entities e
        JOIN files f ON e.file_id = f.id
        WHERE f.repo_id = %s AND f.path = %s AND e.type = 'file_root'
        LIMIT 1;
     """
        res = self._execute_query(sql, (repo_id, file_path), fetch=True)
        return res[0]['id'] if res else None

    def get_entity_id_by_path(self, repo_id, file_path):
        """Finds the root entity ID using the file path."""
        sql = """
        SELECT e.id 
        FROM code_entities e
        JOIN files f ON e.file_id = f.id
        WHERE f.repo_id = %s AND f.path = %s AND e.type = 'file_root'
        LIMIT 1;
    """
        res = self._execute_query(sql, (repo_id, file_path), fetch=True)
        return res[0]['id'] if res else None

    def get_entity_id_by_path(self, repo_id, file_path):
        """Finds the root entity ID using the file path."""
        sql = """
         SELECT e.id 
         FROM code_entities e
         JOIN files f ON e.file_id = f.id
         WHERE f.repo_id = %s AND f.path = %s AND e.type = 'file_root'
         LIMIT 1;
        """
        res = self._execute_query(sql, (repo_id, file_path), fetch=True)
        return res[0]['id'] if res else None

    def get_entity_id_by_path(self, repo_id, file_path):
        """Finds the root entity ID using the file path."""
        sql = """
            SELECT e.id 
            FROM code_entities e
            JOIN files f ON e.file_id = f.id
            WHERE f.repo_id = %s AND f.path = %s AND e.type = 'file_root'
            LIMIT 1;
        """
        res = self._execute_query(sql, (repo_id, file_path), fetch=True)
        return res[0]['id'] if res else None

    def get_entity_id_by_path(self, repo_id, file_path):
        """Finds the root entity ID using the file path."""
        sql = """
            SELECT e.id 
            FROM code_entities e
            JOIN files f ON e.file_id = f.id
            WHERE f.repo_id = %s AND f.path = %s AND e.type = 'file_root'
            LIMIT 1;
        """
        res = self._execute_query(sql, (repo_id, file_path), fetch=True)
        return res[0]['id'] if res else None

    def get_entity_id_by_path(self, repo_id, file_path):
        """Finds the root entity ID using the file path."""
        sql = """
            SELECT e.id 
            FROM code_entities e
            JOIN files f ON e.file_id = f.id
            WHERE f.repo_id = %s AND f.path = %s AND e.type = 'file_root'
            LIMIT 1;
        """
        res = self._execute_query(sql, (repo_id, file_path), fetch=True)
        return res[0]['id']
