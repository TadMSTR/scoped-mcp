"""Tests for StateBackend implementations.

InProcessBackend runs unconditionally. DragonflyBackend tests are skipped if
a Dragonfly/Redis instance is not available on localhost:6379.
"""

from __future__ import annotations

import asyncio
import socket
import time

import pytest

from scoped_mcp.state import InProcessBackend, _sanitize_key_component


def _dragonfly_reachable() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 6379), timeout=1):
            return True
    except OSError:
        return False


_skip_no_dragonfly = pytest.mark.skipif(
    not _dragonfly_reachable(), reason="Dragonfly not available on localhost:6379"
)


# ---------------------------------------------------------------------------
# Key sanitization
# ---------------------------------------------------------------------------


def test_sanitize_strips_colons() -> None:
    assert _sanitize_key_component("files:read") == "files|read"


def test_sanitize_strips_control_chars() -> None:
    assert _sanitize_key_component("bad\x00key") == "bad_key"
    assert _sanitize_key_component("bad\nkey") == "bad_key"
    assert _sanitize_key_component("bad\rkey") == "bad_key"


def test_sanitize_normal_passthrough() -> None:
    assert _sanitize_key_component("filesystem.write_file") == "filesystem.write_file"
    assert _sanitize_key_component("mcp_proxy.*") == "mcp_proxy.*"


# ---------------------------------------------------------------------------
# InProcessBackend — sliding window
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inprocess_allows_up_to_limit() -> None:
    b = InProcessBackend()
    for i in range(5):
        allowed, count = await b.increment("key", window_seconds=60, limit=5)
        assert allowed, f"call {i + 1} should be allowed"
        assert count == i + 1


@pytest.mark.asyncio
async def test_inprocess_rejects_over_limit() -> None:
    b = InProcessBackend()
    for _ in range(5):
        await b.increment("key", window_seconds=60, limit=5)
    allowed, count = await b.increment("key", window_seconds=60, limit=5)
    assert not allowed
    assert count == 5


@pytest.mark.asyncio
async def test_inprocess_window_reset() -> None:
    """Entries outside the window are evicted on the next call."""
    b = InProcessBackend()
    for _ in range(3):
        await b.increment("key", window_seconds=60, limit=3)
    allowed, _ = await b.increment("key", window_seconds=60, limit=3)
    assert not allowed

    # Backdate all timestamps so they fall outside the window
    import time as _time

    window = b._windows["key"]
    old_ts = _time.monotonic() - 120
    window._timestamps.clear()
    window._timestamps.extend([old_ts, old_ts, old_ts])

    allowed, count = await b.increment("key", window_seconds=60, limit=3)
    assert allowed
    assert count == 1


@pytest.mark.asyncio
async def test_inprocess_independent_keys() -> None:
    b = InProcessBackend()
    for _ in range(3):
        await b.increment("key_a", window_seconds=60, limit=3)
    allowed_a, _ = await b.increment("key_a", window_seconds=60, limit=3)
    assert not allowed_a

    allowed_b, count_b = await b.increment("key_b", window_seconds=60, limit=3)
    assert allowed_b
    assert count_b == 1


# ---------------------------------------------------------------------------
# InProcessBackend — set/get/delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inprocess_set_get() -> None:
    b = InProcessBackend()
    await b.set_with_ttl("k", "v", ttl_seconds=60)
    assert await b.get("k") == "v"


@pytest.mark.asyncio
async def test_inprocess_get_missing_returns_none() -> None:
    b = InProcessBackend()
    assert await b.get("nonexistent") is None


@pytest.mark.asyncio
async def test_inprocess_ttl_expiry() -> None:
    b = InProcessBackend()
    await b.set_with_ttl("k", "v", ttl_seconds=10)
    # Manually backdate the expiry
    stored_val, _ = b._store["k"]
    b._store["k"] = (stored_val, time.monotonic() - 1)
    assert await b.get("k") is None


@pytest.mark.asyncio
async def test_inprocess_delete() -> None:
    b = InProcessBackend()
    await b.set_with_ttl("k", "v", ttl_seconds=60)
    await b.delete("k")
    assert await b.get("k") is None


# ---------------------------------------------------------------------------
# InProcessBackend — pub/sub
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_inprocess_pubsub() -> None:
    b = InProcessBackend()
    received: list[str] = []

    # subscribe() is a coroutine: registration happens synchronously when
    # awaited, so the publish below cannot beat us to the channel.
    sub = await b.subscribe("chan")

    async def subscriber() -> None:
        async for msg in sub:
            received.append(msg)
            break

    task = asyncio.create_task(subscriber())
    await b.publish("chan", "hello")
    await task

    assert received == ["hello"]


@pytest.mark.asyncio
async def test_inprocess_pubsub_publish_before_iteration_is_received() -> None:
    """Audit v1.0 M1 regression: a publish that lands AFTER subscribe()
    awaits but BEFORE the iteration starts must still be delivered. The
    old async-generator design lost messages here."""
    b = InProcessBackend()

    sub = await b.subscribe("chan")
    # Publish BEFORE any iteration begins — the queue must already be
    # registered behind the subscription.
    await b.publish("chan", "race-test")

    # Now iterate: the message must be waiting in the queue.
    async for msg in sub:
        assert msg == "race-test"
        break


# ---------------------------------------------------------------------------
# DragonflyBackend — requires running Dragonfly on localhost:6379
# ---------------------------------------------------------------------------


@pytest.fixture
def dragonfly_backend():
    if not _dragonfly_reachable():
        pytest.skip("Dragonfly not available on localhost:6379")
    try:
        from scoped_mcp.state_dragonfly import DragonflyBackend
    except ImportError:
        pytest.skip("redis-py not installed — install scoped-mcp[dragonfly]")
    return DragonflyBackend(url="redis://localhost:6379/15", agent_id="test-agent")


@pytest.mark.asyncio
@_skip_no_dragonfly
async def test_dragonfly_ping(dragonfly_backend) -> None:
    result = await dragonfly_backend._client.ping()
    assert result


@pytest.mark.asyncio
@_skip_no_dragonfly
async def test_dragonfly_sliding_window(dragonfly_backend) -> None:
    key = "rate:testwin"
    await dragonfly_backend._client.delete(dragonfly_backend._key(key))

    for i in range(3):
        allowed, _count = await dragonfly_backend.increment(key, 60, 3)
        assert allowed, f"call {i + 1} should be allowed"

    allowed, _ = await dragonfly_backend.increment(key, 60, 3)
    assert not allowed

    await dragonfly_backend._client.delete(dragonfly_backend._key(key))


@pytest.mark.asyncio
@_skip_no_dragonfly
async def test_dragonfly_cross_agent_isolation(dragonfly_backend) -> None:
    if not _dragonfly_reachable():
        pytest.skip("Dragonfly not available")
    from scoped_mcp.state_dragonfly import DragonflyBackend

    other = DragonflyBackend(url="redis://localhost:6379/15", agent_id="other-agent")
    key = "rate:isolation-test"

    await dragonfly_backend._client.delete(dragonfly_backend._key(key))
    await other._client.delete(other._key(key))

    for _ in range(3):
        await dragonfly_backend.increment(key, 60, 3)
    allowed, _ = await dragonfly_backend.increment(key, 60, 3)
    assert not allowed

    # other agent is independent
    allowed, count = await other.increment(key, 60, 3)
    assert allowed
    assert count == 1

    await dragonfly_backend._client.delete(dragonfly_backend._key(key))
    await other._client.delete(other._key(key))
    await other.close()


@pytest.mark.asyncio
@_skip_no_dragonfly
async def test_dragonfly_adversarial_agent_id() -> None:
    """agent_id with colons/path chars must not contaminate key namespace."""
    if not _dragonfly_reachable():
        pytest.skip("Dragonfly not available")
    try:
        from scoped_mcp.state_dragonfly import DragonflyBackend
    except ImportError:
        pytest.skip("redis-py not installed")

    b = DragonflyBackend(url="redis://localhost:6379/15", agent_id="evil:agent/../other")
    # _prefix format is "scoped-mcp:{sanitized_agent_id}:"
    # The agent_id portion (between the two colons) must not itself contain colons
    inner = b._prefix.removeprefix("scoped-mcp:").removesuffix(":")
    assert ":" not in inner, f"Sanitized agent_id must not contain colons, got: {inner!r}"
    await b.close()


@pytest.mark.asyncio
@_skip_no_dragonfly
async def test_dragonfly_set_get_delete(dragonfly_backend) -> None:
    await dragonfly_backend.set_with_ttl("test-key", "test-value", 60)
    assert await dragonfly_backend.get("test-key") == "test-value"
    await dragonfly_backend.delete("test-key")
    assert await dragonfly_backend.get("test-key") is None
