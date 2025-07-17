from __future__ import annotations
import logging
from typing import Optional, cast, Awaitable
import redis.asyncio as redis


class RedisClient:
    def __init__(self, client: redis.Redis):
        self.client = client
        self.logger = logging.getLogger(self.__class__.__name__)

    @classmethod
    async def create(cls, redis_url: str) -> RedisClient:
        client = redis.from_url(redis_url, decode_responses=True)
        return cls(client)

    async def sadd(self, key: str, value: str) -> int:
        return await cast(Awaitable[int], self.client.sadd(key, value))

    async def sismember(self, key: str, value: str) -> bool:
        result = await cast(Awaitable[int], self.client.sismember(key, value))
        return bool(result)

    async def hset(self, key: str, field: str, value: str) -> int:
        return await cast(Awaitable[int], self.client.hset(key, field, value))

    async def hget(self, key: str, field: str) -> Optional[str]:
        return await cast(Awaitable[Optional[str]], self.client.hget(key, field))

    async def hlen(self, key: str) -> int:
        return await cast(Awaitable[int], self.client.hlen(key))

    async def hgetall(self, key: str) -> dict:
        return await cast(Awaitable[dict], self.client.hgetall(key))

    async def smembers(self, key: str) -> set:
        return await cast(Awaitable[set], self.client.smembers(key))

    async def spop(self, key: str) -> Optional[str]:
        return await cast(Awaitable[Optional[str]], self.client.spop(key))

    async def exists(self, key: str) -> bool:
        result = await cast(Awaitable[int], self.client.exists(key))
        return result > 0

    async def delete(self, key: str):
        await cast(Awaitable[None], self.client.delete(key))
    
    async def flushdb(self):
        await cast(Awaitable[None], self.client.flushdb())
        self.logger.info("Redis database cleared for a fresh scan.")

    async def close(self):
        await cast(Awaitable[None], self.client.close())

    async def ping(self) -> bool:
        try:
            return await cast(Awaitable[bool], self.client.ping())
        except Exception:
            return False 