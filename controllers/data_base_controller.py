import os
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
load_dotenv()
from .repo_scanner import RepoScanner
import hashlib
class DatabaseConnection:
    def __init__(self):
        self.user = os.getenv("DB_USER", "devuser")
        self.password = os.getenv("DB_PASSWORD", "devpass")
        self.host = os.getenv("DB_HOST", "localhost")
        self.port = int(os.getenv("DB_PORT", 5432))
        self.database = os.getenv("DB_NAME", "code_docs")
        self.cursor_factory = RealDictCursor
        
    def connect(self):
        """Establish a connection to the PostgreSQL database"""
        try:
            conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password,
                cursor_factory=self.cursor_factory
            )
            print("Connected successfully")
            return conn
        except Exception as e:
            print("Failed to connect")
            print(e)
            return None


class Postgres(DatabaseConnection):
    def __init__(self):
        super().__init__()
    
    def _execute_query(self, sql, params=None, fetch=False):
        """Helper to handle connection lifecycle."""
        conn = self.connect()
        if not conn:
            return None
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    if fetch:
                        return cur.fetchall()
        finally:
            conn.close()
    def save_repository(self, name: str, path: str):
        """Ensures the repo exists and returns its ID."""
        sql = """
        INSERT INTO repositories (name, path) 
        VALUES (%s, %s) 
        ON CONFLICT (path) DO UPDATE SET last_scanned = NOW()
        RETURNING id;
        """
        # Note: You'll need a UNIQUE constraint on 'path' in your SQL for ON CONFLICT
        return self._execute_query(sql, (name, path), fetch=True)
       

    def save_file(self, repo_id: int, file_data: dict):
        """Saves file metadata and returns the file_id."""
        sql = """
        INSERT INTO files (repo_id, path, language, hash, size)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING id;
        """
        params = (
            repo_id,
            file_data['file_path'],
            file_data['metadata']['language'],
            file_data.get('hash'),
            file_data.get('size', 0)
        )
        result = self._execute_query(sql, params, fetch=True)
        return result[0]['id']

    def save_chunk(self, entity_id: int, chunk_dict: dict):
        """Saves a code chunk linked to an entity."""
        sql = """
        INSERT INTO chunks (code_entity_id, content, type, token_count)
        VALUES (%s, %s, %s, %s);
        """
        params = (
            entity_id,
            chunk_dict['content'],
            chunk_dict['metadata']['role'],
            len(chunk_dict['content'].split())  # Rough token count
        )
        self._execute_query(sql, params)    
        
    def get_existing_insights(self ,entity_name: str, entity_hash: str, task_type: str) :
        #this is the function to check if the document already exists in the code or not 
        
        query = '''
        
                SELECT h.doc_content 
                FROM doc_history h
                JOIN code_entities e ON h.code_entity_id = e.id
                WHERE e.name = %s 
                  AND e.hash = %s 
                  AND h.model = %s  -- Using 'model' column for the task type/agent info
                ORDER BY h.generated_at DESC
                LIMIT 1;
    
        '''
        result = self._execute_query(query,(entity_name, entity_hash, task_type),fetch=True)
        
        return result if result else None 
        ## this is the part that is to be implemented 
    def _get_file_by_path(self):
        pass
    def _upsert_file(self):
        pass 
    def _clear_file_contents(self):
        pass 
    def sync_repo_to_db(self,repo_path:str):
        ''' this function syncs the repo that is present in the presistant storage with the 
            the repo that is freshly parsed
        '''
        pass 
        