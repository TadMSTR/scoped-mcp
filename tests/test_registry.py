"""Tests for registry.py — module discovery, mode filtering, manifest enforcement."""

from __future__ import annotations

import asyncio
from typing import ClassVar

import pytest

from scoped_mcp.exceptions import ManifestError
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import Manifest, ModuleConfig
from scoped_mcp.modules._base import ToolModule, tool
from scoped_mcp.registry import (
    _discover_module_classes,
    _register_signing_hook_if_available,
    build_server,
)

# ── Module discovery ──────────────────────────────────────────────────────────


def test_discover_finds_builtin_modules() -> None:
    """After Phase 2+ adds real modules, this number will grow."""
    discovered = _discover_module_classes()
    # In Phase 1, no tool modules exist yet — this verifies discovery runs without error.
    assert isinstance(discovered, dict)


# ── build_server rejects unknown modules ──────────────────────────────────────


def test_build_server_unknown_module_raises(agent_ctx: AgentContext) -> None:
    manifest = Manifest(
        agent_type="test",
        modules={"nonexistent_module": ModuleConfig(mode="read")},
    )
    with pytest.raises(ManifestError, match="nonexistent_module"):
        build_server(agent_ctx, manifest)


# ── ToolModule.get_tool_methods mode filtering ────────────────────────────────


class _MockModule(ToolModule):
    name = "_test_mock"
    scoping = None
    required_credentials: ClassVar[list[str]] = []

    @tool(mode="read")
    async def read_thing(self) -> str:
        return "read"

    @tool(mode="write")
    async def write_thing(self) -> str:
        return "write"


def _make_mock(agent_ctx: AgentContext) -> _MockModule:
    return _MockModule(agent_ctx=agent_ctx, credentials={}, config={})


def test_get_tool_methods_read_mode(agent_ctx: AgentContext) -> None:
    mod = _make_mock(agent_ctx)
    methods = mod.get_tool_methods("read")
    names = [m.__name__ for m in methods]
    assert "read_thing" in names
    assert "write_thing" not in names


def test_get_tool_methods_write_mode(agent_ctx: AgentContext) -> None:
    mod = _make_mock(agent_ctx)
    methods = mod.get_tool_methods("write")
    names = [m.__name__ for m in methods]
    assert "read_thing" in names
    assert "write_thing" in names


def test_get_tool_methods_none_mode(agent_ctx: AgentContext) -> None:
    mod = _make_mock(agent_ctx)
    methods = mod.get_tool_methods(None)
    names = [m.__name__ for m in methods]
    assert "read_thing" in names
    assert "write_thing" in names


# ── type: field dispatch tests ────────────────────────────────────────────────


from unittest.mock import MagicMock, patch  # noqa: E402


def _mock_module_cls():
    """Return a mock module class whose instances report no tools."""
    mock_cls = MagicMock()
    mock_cls.required_credentials = []
    mock_cls.optional_credentials = []
    mock_instance = mock_cls.return_value
    mock_instance.get_tool_methods.return_value = []
    return mock_cls


def test_type_field_dispatches_to_correct_class(agent_ctx: AgentContext) -> None:
    """Manifest key 'task-queue' with type: mcp_proxy instantiates the mcp_proxy class."""
    mock_cls = _mock_module_cls()

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {
                "task-queue": {"type": "mcp_proxy", "config": {"url": "http://localhost/mcp"}}
            },
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes", return_value={"mcp_proxy": mock_cls}
    ):
        build_server(agent_ctx, manifest)

    mock_cls.assert_called_once()
    call_kwargs = mock_cls.call_args.kwargs
    assert call_kwargs["agent_ctx"] is agent_ctx


def test_unknown_type_raises_manifest_error(agent_ctx: AgentContext) -> None:
    """Registry raises ManifestError when type: references an unknown module class."""
    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {"thing": {"type": "nonexistent_module"}},
        }
    )

    with patch("scoped_mcp.registry._discover_module_classes", return_value={}):
        with pytest.raises(ManifestError, match="nonexistent_module"):
            build_server(agent_ctx, manifest)


def test_type_field_none_uses_key_name(agent_ctx: AgentContext) -> None:
    """When type is absent, the manifest key itself is used as the class name."""
    mock_matrix_cls = _mock_module_cls()

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {"matrix": {"config": {"allowed_rooms": ["!abc:test"]}}},
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value={"matrix": mock_matrix_cls},
    ):
        build_server(agent_ctx, manifest)

    mock_matrix_cls.assert_called_once()


# ── Lifespan wiring tests ─────────────────────────────────────────────────────


from unittest.mock import AsyncMock  # noqa: E402

from scoped_mcp.registry import _make_module_lifespan  # noqa: E402


@pytest.mark.asyncio
async def test_registry_lifespan_calls_startup_on_all_modules(agent_ctx: AgentContext) -> None:
    """Registry lifespan calls startup() on each loaded module after server starts."""
    mock_instance = MagicMock()
    mock_instance.name = "matrix"
    mock_instance.startup = AsyncMock()
    mock_instance.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([mock_instance])
    async with lifespan(server=None):
        mock_instance.startup.assert_awaited_once()


@pytest.mark.asyncio
async def test_registry_lifespan_calls_shutdown_in_reverse(agent_ctx: AgentContext) -> None:
    """Registry lifespan calls shutdown() on modules in reverse manifest order."""
    call_order: list[str] = []

    mock_a = MagicMock()
    mock_a.name = "mod_a"
    mock_a.startup = AsyncMock()
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("a"))

    mock_b = MagicMock()
    mock_b.name = "mod_b"
    mock_b.startup = AsyncMock()
    mock_b.shutdown = AsyncMock(side_effect=lambda: call_order.append("b"))

    lifespan = _make_module_lifespan([mock_a, mock_b])
    async with lifespan(server=None):
        pass  # triggers shutdown on exit

    assert call_order == ["b", "a"]


@pytest.mark.asyncio
async def test_lifespan_partial_startup_cleans_up_started_modules() -> None:
    """If module N raises in startup(), modules 0..N-1 that started still get shutdown().

    With append-before-await, the failing module is also in started — shutdown() is called
    on it but is a no-op because its handle was never set (shutdown guard: _client_handle is
    not None).
    """
    call_order: list[str] = []

    mock_a = MagicMock()
    mock_a.name = "mod_a"
    mock_a.startup = AsyncMock(side_effect=lambda: call_order.append("start_a"))
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("shutdown_a"))

    mock_b = MagicMock()
    mock_b.name = "mod_b"
    mock_b.startup = AsyncMock(side_effect=RuntimeError("startup failed"))
    mock_b.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([mock_a, mock_b])
    with pytest.raises(RuntimeError, match="startup failed"):
        async with lifespan(server=None):
            pass  # should never be reached

    assert "start_a" in call_order
    assert "shutdown_a" in call_order
    mock_b.shutdown.assert_awaited_once()


@pytest.mark.asyncio
async def test_lifespan_shutdown_error_does_not_skip_remaining() -> None:
    """If mod.shutdown() raises, remaining modules still get shutdown()."""
    call_order: list[str] = []

    mock_a = MagicMock()
    mock_a.name = "mod_a"
    mock_a.startup = AsyncMock()
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("shutdown_a"))

    mock_b = MagicMock()
    mock_b.name = "mod_b"
    mock_b.startup = AsyncMock()
    mock_b.shutdown = AsyncMock(side_effect=RuntimeError("shutdown failed"))

    # mod_b is reversed-first (index 1 shuts down before index 0)
    lifespan = _make_module_lifespan([mock_a, mock_b])
    async with lifespan(server=None):
        pass

    # mod_a shutdown must still run despite mod_b raising
    assert "shutdown_a" in call_order


@pytest.mark.asyncio
async def test_lifespan_starts_modules_concurrently() -> None:
    """All modules start in parallel — total elapsed ≈ one sleep unit, not N units."""
    import time

    N = 4
    SLEEP = 0.05  # 50ms; serial would be 200ms

    async def slow_startup():
        await asyncio.sleep(SLEEP)

    mocks = []
    for i in range(N):
        m = MagicMock()
        m.name = f"mod_{i}"
        m.startup = slow_startup
        m.shutdown = AsyncMock()
        mocks.append(m)

    lifespan = _make_module_lifespan(mocks)
    t0 = time.monotonic()
    async with lifespan(server=None):
        pass
    elapsed = time.monotonic() - t0

    assert elapsed < SLEEP * 2, (
        f"startup took {elapsed:.3f}s — expected < {SLEEP * 2:.3f}s "
        f"for parallel startup of {N} modules x {SLEEP}s each"
    )


@pytest.mark.asyncio
async def test_lifespan_parallel_startup_failure_cleans_up_started_modules() -> None:
    """Startup failure propagates; modules that finished startup concurrently get shutdown()."""
    call_order: list[str] = []
    mod_a_ready = asyncio.Event()

    mock_a = MagicMock()
    mock_a.name = "mod_a"

    async def a_startup():
        call_order.append("start_a")
        mod_a_ready.set()

    mock_a.startup = a_startup
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("shutdown_a"))

    mock_b = MagicMock()
    mock_b.name = "mod_b"

    async def b_startup():
        await mod_a_ready.wait()  # yield until mod_a has started
        raise RuntimeError("b startup failed")

    mock_b.startup = b_startup
    mock_b.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([mock_a, mock_b])
    with pytest.raises(RuntimeError, match="b startup failed"):
        async with lifespan(server=None):
            pass

    assert "start_a" in call_order
    assert "shutdown_a" in call_order
    # mod_b is appended before its startup runs, so finally calls shutdown on it too.
    # In practice this is a no-op: mcp_proxy.shutdown() guards with _client_handle is not None.
    mock_b.shutdown.assert_awaited_once()


@pytest.mark.asyncio
async def test_lifespan_mid_startup_module_gets_shutdown_called() -> None:
    """A module that is mid-startup when a sibling fails still gets shutdown() called.

    With append-before-await, the module is in started before the gather raises, so the
    finally block reaches it even when it never finished startup().
    """
    call_order: list[str] = []
    a_in_startup = asyncio.Event()

    mock_a = MagicMock()
    mock_a.name = "mod_a"
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("shutdown_a"))

    async def a_startup():
        a_in_startup.set()
        await asyncio.sleep(3600)  # stays mid-startup until the test ends

    mock_a.startup = a_startup

    mock_b = MagicMock()
    mock_b.name = "mod_b"

    async def b_startup():
        await a_in_startup.wait()  # wait until mod_a is mid-startup
        raise RuntimeError("b startup failed")

    mock_b.startup = b_startup
    mock_b.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([mock_a, mock_b])
    with pytest.raises(RuntimeError, match="b startup failed"):
        async with lifespan(server=None):
            pass

    # mod_a was appended before its startup ran — finally calls shutdown even though
    # a_startup never completed.
    assert "shutdown_a" in call_order


# ── _register_signing_hook_if_available ───────────────────────────────────────


def test_register_signing_hook_no_keys_does_nothing() -> None:
    from scoped_mcp.hooks import _registry, clear_hooks

    clear_hooks()
    try:
        _register_signing_hook_if_available({}, None)
        assert ("agent-bus", "log_event") not in _registry
    finally:
        clear_hooks()


def test_register_signing_hook_missing_public_key_does_nothing() -> None:
    from scoped_mcp.hooks import _registry, clear_hooks

    clear_hooks()
    try:
        _register_signing_hook_if_available({"signing_private_key": "abc"}, None)
        assert ("agent-bus", "log_event") not in _registry
    finally:
        clear_hooks()


def test_register_signing_hook_with_valid_keys_registers_hook() -> None:
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from scoped_mcp.hooks import _registry, clear_hooks

    private_key = Ed25519PrivateKey.generate()
    priv_b64 = base64.b64encode(private_key.private_bytes_raw()).decode()
    pub_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()

    clear_hooks()
    try:
        import structlog

        ops = structlog.get_logger("ops")
        _register_signing_hook_if_available(
            {"signing_private_key": priv_b64, "signing_public_key": pub_b64},
            ops,
        )
        assert len(_registry.get(("agent-bus", "log_event"), [])) == 1
    finally:
        clear_hooks()


# ── Tool name prefix regression test ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_tool_names_are_single_prefixed(agent_ctx: AgentContext) -> None:
    """Tools must be registered as '{module}_{method}' — not '{module}_{module}_{method}'.

    server.mount(prefix=module_name) applies the prefix, so child.tool() must receive
    the bare method name only. Double-registration caused HITL and rate-limit patterns
    to never match on forge.
    """
    from unittest.mock import patch

    mock_cls = MagicMock()
    mock_cls.required_credentials = []
    mock_cls.optional_credentials = []

    mock_instance = _make_mock(agent_ctx)
    mock_cls.return_value = mock_instance

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {
                "my-module": {
                    "type": "_test_mock",
                    "mode": "read",
                    "config": {},
                }
            },
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value={"_test_mock": type(mock_instance)},
    ):
        server = build_server(agent_ctx, manifest)

    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    assert tool_names, "expected at least one tool to be registered"
    for name in tool_names:
        # No tool should start with the doubled prefix
        assert not name.startswith("my-module_my-module_"), f"double prefix detected: {name!r}"
        # All tools should start with the single module prefix
        assert name.startswith("my-module_"), f"expected single prefix in: {name!r}"
