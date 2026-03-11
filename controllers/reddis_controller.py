import hashlib
import os

import redis
from dotenv import load_dotenv

load_dotenv()


class RedisManager:
    def __init__(
        self, redis_host=None, redis_port=None, redis_db=None, redis_password=None
    ):
        # Use passed values or fall back to .env/defaults
        self.redis_host = redis_host or os.getenv("REDIS_HOST", "localhost")
        self.redis_port = redis_port or int(os.getenv("REDIS_PORT", 6379))
        self.redis_db = redis_db or int(os.getenv("REDIS_DB", 1))
        self.redis_password = redis_password or os.getenv("REDIS_PASSWORD", None)
        self.client = None

    def connect(self):
        """Establish a connection to Redis"""
        try:
            self.client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
            )
            # Test the connection
            self.client.ping()
            print("Connected to Redis successfully")
            return self.client
        except Exception as e:
            print("Failed to connect to Redis")
            print(e)
            return None

    def save_to_reddis(self, key, value):
        """The actual low-level save command"""
        # Ensure we check self.client which was set during connect()
        if self.client is not None:
            return self.client.set(key, value)
        else:
            # This is where your error is coming from!
            print("❌ Redis client not connected!")
            return False

    def caching_the_response(self, content, response):
        """Saves LLM output to Redis using a hash of the code as the key."""
        try:
            # Generate the unique hash for the code content
            key = hashlib.sha256(content.encode()).hexdigest()

            # Save to Redis (key=hash, value=ai_response)
            self.save_to_reddis(key, response.strip())

            print(f"   💾 [REDIS] Saved! Key (Hash): {key[:10]}...")
        except Exception as e:
            print(f"   ❌ [REDIS] Save Failed: {e}")

    def delete_from_redis(self, chunk, response):
        """Deletes a specific key from Redis."""
        if self.client:
            return self.client.delete(chunk)
