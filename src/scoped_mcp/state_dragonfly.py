"""DragonflyBackend — redis-py backed StateBackend.

Requires: pip install scoped-mcp[dragonfly]

All keys are namespaced under scoped-mcp:{agent_id}: to prevent cross-agent
key collisions when multiple agents share a Dragonfly instance.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from .state import _sanitize_key_component

try:
    import redis.asyncio as aioredis
except ImportError as _e:
    raise ImportError(
        "DragonflyBackend requires redis-py. Install with: pip install scoped-mcp[dragonfly]"
    ) from _e

# Lua script: atomic sliding window increment using a sorted set.
# KEYS[1] = key, ARGV[1] = now (ms), ARGV[2] = window_ms, ARGV[3] = limit, ARGV[4] = uuid
# Returns current count after the operation (before potential add), or -1 if over limit.
_SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local uuid = ARGV[4]
local cutoff = now - window_ms

redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
local count = redis.call('ZCARD', key)

if count >= limit then
    redis.call('EXPIRE', key, math.ceil(window_ms / 1000) * 2)
    return -1
end

redis.call('ZADD', key, now, uuid)
redis.call('EXPIRE', key, math.ceil(window_ms / 1000) * 2)
return count + 1
"""


class DragonflyBackend:
    """StateBackend backed by Dragonfly (or any Redis-compatible server).

    Uses sorted sets with a Lua script for atomic sliding window rate limiting.
    Pub/sub is used for HITL approval notifications.
    """

    def __init__(self, url: str, agent_id: str) -> None:
        safe_agent_id = _sanitize_key_component(agent_id)
        self._prefix = f"scoped-mcp:{safe_agent_id}:"
        self._client: aioredis.Redis = aioredis.from_url(url, decode_responses=True)
        self._script: Any = self._client.register_script(_SLIDING_WINDOW_LUA)

    def _key(self, key: str) -> str:
        """Prepend the agent-scoped namespace prefix."""
        return f"{self._prefix}{key}"

    async def increment(self, key: str, window_seconds: int, limit: int) -> tuple[bool, int]:
        import time
        import uuid as _uuid

        now_ms = int(time.time() * 1000)
        window_ms = window_seconds * 1000
        entry_id = str(_uuid.uuid4())

        result = await self._script(
            keys=[self._key(key)],
            args=[now_ms, window_ms, limit, entry_id],
        )
        if result == -1:
            # Over limit — get current count for logging
            count = await self._client.zcard(self._key(key))
            return False, int(count)
        return True, int(result)

    async def set_with_ttl(self, key: str, value: str, ttl_seconds: int) -> None:
        await self._client.set(self._key(key), value, ex=ttl_seconds)

    async def get(self, key: str) -> str | None:
        return await self._client.get(self._key(key))

    async def delete(self, key: str) -> None:
        await self._client.delete(self._key(key))

    async def publish(self, channel: str, message: str) -> None:
        await self._client.publish(self._key(channel), message)

    async def subscribe(self, channel: str) -> AsyncIterator[str]:
        """Subscribe to the channel synchronously, then return an iterator."""
        pubsub = self._client.pubsub()
        # Network handshake happens here, BEFORE the caller can publish anything
        # — fixes audit v1.0 M1 where a fast operator decision could land on a
        # not-yet-subscribed channel.
        await pubsub.subscribe(self._key(channel))

        async def _iter() -> AsyncIterator[str]:
            try:
                async for msg in pubsub.listen():
                    if msg["type"] == "message":
                        yield msg["data"]
            finally:
                await pubsub.unsubscribe(self._key(channel))
                await pubsub.aclose()

        return _iter()

    async def close(self) -> None:
        await self._client.aclose()
