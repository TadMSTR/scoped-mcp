"""StateBackend protocol and InProcessBackend.

StateBackend provides pluggable shared state for rate limiting and HITL.
The default InProcessBackend requires no external dependencies.
The DragonflyBackend (state_dragonfly.py) uses redis-py and requires
the [dragonfly] optional extra.
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import time
from collections.abc import AsyncIterator
from typing import Protocol, runtime_checkable


def _sanitize_key_component(value: str) -> str:
    """Replace Redis key-unsafe characters in a single key component.

    Colons are the Redis key namespace separator and must not appear raw
    inside a component — they would break the key hierarchy and allow one
    agent to collide with another agent's key space.
    """
    return value.replace(":", "|").replace("\n", "_").replace("\r", "_").replace("\x00", "_")


@runtime_checkable
class StateBackend(Protocol):
    """Shared state store for rate limiting and HITL."""

    async def increment(self, key: str, window_seconds: int, limit: int) -> tuple[bool, int]:
        """Sliding window counter. Returns (allowed, current_count)."""
        ...

    async def set_with_ttl(self, key: str, value: str, ttl_seconds: int) -> None: ...

    async def get(self, key: str) -> str | None: ...

    async def delete(self, key: str) -> None: ...

    async def publish(self, channel: str, message: str) -> None: ...

    async def subscribe(self, channel: str) -> AsyncIterator[str]:
        """Subscribe to a pub/sub channel and return an async iterator of messages.

        IMPORTANT: This is a coroutine, not an async generator. The
        registration / network handshake happens synchronously when the
        coroutine is awaited; iteration only consumes messages from the
        already-registered subscription. Callers must use::

            sub = await state.subscribe("channel")
            async for msg in sub:
                ...

        This shape was chosen deliberately to avoid the publish-before-
        subscribe race that an async-generator design suffers — see audit
        v1.0 M1 for the original bug.
        """
        ...


class _SlidingWindow:
    """Thread-safe asyncio sliding window counter backed by a deque of timestamps."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._timestamps: collections.deque[float] = collections.deque()

    async def increment(self, window_seconds: int, limit: int) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - window_seconds
        async with self._lock:
            # Remove expired entries
            while self._timestamps and self._timestamps[0] <= cutoff:
                self._timestamps.popleft()
            count = len(self._timestamps)
            if count >= limit:
                return False, count
            self._timestamps.append(now)
            return True, count + 1


class InProcessBackend:
    """Asyncio-native StateBackend with no external dependencies.

    Rate limit windows reset on process restart — acceptable for single-process
    deployments. Does not support pub/sub (HITL requires DragonflyBackend).
    """

    def __init__(self) -> None:
        self._windows: dict[str, _SlidingWindow] = {}
        self._store: dict[str, tuple[str, float | None]] = {}  # key → (value, expires_at)
        self._pubsub: dict[str, list[asyncio.Queue[str]]] = {}
        self._lock = asyncio.Lock()

    async def increment(self, key: str, window_seconds: int, limit: int) -> tuple[bool, int]:
        async with self._lock:
            if key not in self._windows:
                self._windows[key] = _SlidingWindow()
        return await self._windows[key].increment(window_seconds, limit)

    async def set_with_ttl(self, key: str, value: str, ttl_seconds: int) -> None:
        expires_at = time.monotonic() + ttl_seconds
        async with self._lock:
            self._store[key] = (value, expires_at)

    async def get(self, key: str) -> str | None:
        async with self._lock:
            entry = self._store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at is not None and time.monotonic() > expires_at:
            async with self._lock:
                self._store.pop(key, None)
            return None
        return value

    async def delete(self, key: str) -> None:
        async with self._lock:
            self._store.pop(key, None)

    async def publish(self, channel: str, message: str) -> None:
        async with self._lock:
            queues = list(self._pubsub.get(channel, []))
        for q in queues:
            await q.put(message)

    async def subscribe(self, channel: str) -> AsyncIterator[str]:
        """Register the subscription synchronously, then return an iterator."""
        q: asyncio.Queue[str] = asyncio.Queue()
        async with self._lock:
            self._pubsub.setdefault(channel, []).append(q)

        async def _iter() -> AsyncIterator[str]:
            try:
                while True:
                    yield await q.get()
            finally:
                async with self._lock:
                    with contextlib.suppress(KeyError, ValueError):
                        self._pubsub[channel].remove(q)

        return _iter()


def build_state_backend(
    backend_type: str,
    url: str | None = None,
    agent_id: str | None = None,
) -> StateBackend:
    """Factory: return the appropriate StateBackend from manifest config.

    Raises ConfigError if type is 'dragonfly' but redis-py is not installed.
    """
    if backend_type == "in_process":
        return InProcessBackend()

    if backend_type == "dragonfly":
        try:
            from .state_dragonfly import DragonflyBackend
        except ImportError as e:
            from .exceptions import ConfigError

            raise ConfigError(
                "state_backend.type is 'dragonfly' but the [dragonfly] extra is not installed. "
                "Run: pip install scoped-mcp[dragonfly]"
            ) from e

        if not url:
            from .exceptions import ConfigError

            raise ConfigError("state_backend.url is required when type is 'dragonfly'")

        return DragonflyBackend(url=url, agent_id=agent_id or "default")

    from .exceptions import ConfigError

    raise ConfigError(f"Unknown state_backend.type: {backend_type!r}")


__all__ = [
    "InProcessBackend",
    "StateBackend",
    "_sanitize_key_component",
    "build_state_backend",
]
