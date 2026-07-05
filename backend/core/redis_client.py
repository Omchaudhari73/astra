"""
Redis client for caching and real-time communication
"""
import redis.asyncio as redis
from core.config import settings
import json
from typing import Optional, Any

class RedisClient:
    def __init__(self):
        self.redis: Optional[redis.Redis] = None
        self.pubsub = None
    
    async def initialize(self):
        """Initialize Redis connection"""
        try:
            self.redis = await redis.from_url(
                settings.REDIS_URL,
                decode_responses=True
            )
            # Test connection
            await self.redis.ping()
            self.pubsub = self.redis.pubsub()
            print("Redis connection established")
        except Exception as e:
            print(f"Redis connection failed: {e}")
            self.redis = None
    
    async def set(self, key: str, value: Any, expire: int = None):
        """Set key with optional expiration"""
        if self.redis:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            await self.redis.set(key, value, ex=expire)
    
    async def get(self, key: str) -> Optional[str]:
        """Get key value"""
        if self.redis:
            return await self.redis.get(key)
        return None
    
    async def delete(self, key: str):
        """Delete key"""
        if self.redis:
            await self.redis.delete(key)
    
    async def publish(self, channel: str, message: str):
        """Publish message to channel"""
        if self.redis:
            await self.redis.publish(channel, message)
    
    async def subscribe(self, channel: str):
        """Subscribe to channel"""
        if self.pubsub:
            await self.pubsub.subscribe(channel)
    
    async def close(self):
        """Close Redis connection"""
        if self.redis:
            await self.redis.close()
            print("Redis connection closed")

redis_client = RedisClient()
