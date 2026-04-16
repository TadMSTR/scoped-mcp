"""Example custom module: Redis key-value store with NamespaceScope.

Copy to src/scoped_mcp/modules/redis.py and add redis[asyncio] to your dependencies.

This file demonstrates the full module authoring contract. See docs/module-authoring.md
for a complete walkthrough.
"""

from __future__ import annotations

from typing import Any, ClassVar

from scoped_mcp.modules._base import ToolModule, tool
from scoped_mcp.scoping import NamespaceScope


class RedisModule(ToolModule):
    """Redis key-value access, namespaced to the agent's scope.

    Each agent's keys are prefixed with '{agent_id}:'. Agent A cannot read
    or write Agent B's keys. Credential isolation: the REDIS_URL is held by
    the proxy and never passed to the agent.
    """

    name: ClassVar[str] = "redis"
    scoping: ClassVar[NamespaceScope] = NamespaceScope()
    required_credentials: ClassVar[list[str]] = ["REDIS_URL"]

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        try:
            import redis.asyncio as aioredis
        except ImportError:
            raise ImportError(
                "redis module requires 'redis[asyncio]>=5.0'. "
                "Install with: pip install redis[asyncio]"
            )
        self._redis = aioredis.from_url(credentials["REDIS_URL"])

    @tool(mode="read")
    async def get_key(self, key: str) -> str | None:
        """Get a value by key (scoped to agent namespace).

        Args:
            key: Key name. Automatically prefixed with '{agent_id}:'.

        Returns:
            Value string, or None if the key doesn't exist.
        """
        scoped_key = self.scoping.apply(key, self.agent_ctx)
        self.scoping.enforce(scoped_key, self.agent_ctx)
        value = await self._redis.get(scoped_key)
        return value.decode() if isinstance(value, bytes) else value

    @tool(mode="read")
    async def list_keys(self, pattern: str = "*") -> list[str]:
        """List keys matching a pattern (scoped to agent namespace).

        Args:
            pattern: Glob pattern (e.g. "session:*"). The agent namespace
                     prefix is added automatically.

        Returns:
            List of matching key names (without the agent namespace prefix).
        """
        prefix = self.scoping.apply("", self.agent_ctx)
        scoped_pattern = f"{prefix}{pattern}"
        keys = await self._redis.keys(scoped_pattern)
        # Strip the agent namespace prefix before returning to the agent
        return [k.decode().removeprefix(prefix) if isinstance(k, bytes) else k.removeprefix(prefix)
                for k in keys]

    @tool(mode="write")
    async def set_key(self, key: str, value: str, ttl: int = 0) -> bool:
        """Set a key-value pair (scoped to agent namespace).

        Args:
            key: Key name. Automatically prefixed with '{agent_id}:'.
            value: String value to store.
            ttl: Time-to-live in seconds. 0 means no expiry.

        Returns:
            True on success.
        """
        scoped_key = self.scoping.apply(key, self.agent_ctx)
        self.scoping.enforce(scoped_key, self.agent_ctx)
        result = await self._redis.set(scoped_key, value, ex=ttl if ttl > 0 else None)
        return bool(result)

    @tool(mode="write")
    async def delete_key(self, key: str) -> bool:
        """Delete a key (scoped to agent namespace).

        Args:
            key: Key name. Automatically prefixed with '{agent_id}:'.

        Returns:
            True if the key existed and was deleted, False if it didn't exist.
        """
        scoped_key = self.scoping.apply(key, self.agent_ctx)
        self.scoping.enforce(scoped_key, self.agent_ctx)
        deleted = await self._redis.delete(scoped_key)
        return deleted > 0
