import os
from dotenv import load_dotenv
import psycopg2
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
    def connect(self):
        print("Connecting to PostgreSQL via Postgres subclass...")
        return super().connect()

