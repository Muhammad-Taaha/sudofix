import os
import redis
from dotenv import load_dotenv

load_dotenv()

class RedisManager:
    def __init__(self, redis_host=None, redis_port=None, redis_db=None, redis_password=None):
        # Use passed values or fall back to .env/defaults
        self.redis_host = redis_host or os.getenv("REDIS_HOST", "localhost")
        self.redis_port = redis_port or int(os.getenv("REDIS_PORT", 6379))
        self.redis_db = redis_db or int(os.getenv("REDIS_DB", 0))
        self.redis_password = redis_password or os.getenv("REDIS_PASSWORD", None)
        self.client = None

    def connect(self):
        """Establish a connection to Redis"""
        try:
            self.client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password
            )
            # Test the connection
            self.client.ping()
            print("Connected to Redis successfully")
            return self.client
        except Exception as e:
            print("Failed to connect to Redis")
            print(e)
            return None
