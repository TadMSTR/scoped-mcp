"""Tests for mcp_proxy inputSchema validation (v0.9 hardening)."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import pytest
from mcp.types import Tool

from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.mcp_proxy import McpProxyModule, _ProxyValidationError


def _make_tool(name: str, schema: dict | None = None) -> Tool:
    return Tool(name=name, description="", inputSchema=schema or {})


@dataclass
class FakeCallToolResult:
    data: object
    content: list
    structured_content: object = None
    meta: object = None
    is_error: bool = False


@pytest.fixture
def agent_ctx() -> AgentContext:
    return AgentContext(agent_id="test-agent", agent_type="test")


def _module_fixture(agent_ctx, tools):
    """Build a patched McpProxyModule. Yields (module, mock_cm) inside the
    patch context so proxy_call's per-request Client() also resolves to mock_cm.
    """
    fake_result = FakeCallToolResult(data={"ok": True}, content=[])
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=tools)
        mock_cm.call_tool = AsyncMock(return_value=fake_result)
        MockClient.return_value = mock_cm

        module = McpProxyModule(agent_ctx, credentials={}, config={"url": "http://example.test"})
        yield module, mock_cm


@pytest.fixture
def schema_with_required_path() -> dict:
    return {
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    }


@pytest.fixture
def read_file_module(agent_ctx, schema_with_required_path):
    yield from _module_fixture(agent_ctx, [_make_tool("read_file", schema_with_required_path)])


@pytest.fixture
def integer_count_module(agent_ctx):
    schema = {"type": "object", "properties": {"count": {"type": "integer"}}}
    yield from _module_fixture(agent_ctx, [_make_tool("set_count", schema)])


@pytest.fixture
def no_schema_module(agent_ctx):
    yield from _module_fixture(agent_ctx, [_make_tool("free_call", {})])


@pytest.fixture
def safe_tool_module(agent_ctx):
    yield from _module_fixture(agent_ctx, [_make_tool("safe_tool", {"type": "object"})])


# ── Schema cache population ──────────────────────────────────────────────────


def test_schemas_cached_at_discovery(read_file_module, schema_with_required_path) -> None:
    module, _ = read_file_module
    assert "read_file" in module._schemas
    assert module._schemas["read_file"] == schema_with_required_path


def test_empty_schema_normalises_to_none(no_schema_module) -> None:
    module, _ = no_schema_module
    assert module._schemas["free_call"] is None


# ── Per-call validation ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_valid_arguments_forwarded(read_file_module) -> None:
    module, mock_cm = read_file_module
    method = module._proxy_methods[0]
    result = await method(path="/tmp/file.txt")
    assert result == {"ok": True}
    mock_cm.call_tool.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_required_field_rejected(read_file_module) -> None:
    module, mock_cm = read_file_module
    method = module._proxy_methods[0]
    with pytest.raises(_ProxyValidationError, match="schema validation"):
        await method()  # missing required 'path'
    mock_cm.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_wrong_type_rejected(integer_count_module) -> None:
    module, mock_cm = integer_count_module
    method = module._proxy_methods[0]
    with pytest.raises(_ProxyValidationError, match="schema validation"):
        await method(count="not-an-integer")
    mock_cm.call_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_no_schema_passes_through(no_schema_module) -> None:
    module, mock_cm = no_schema_module
    method = module._proxy_methods[0]
    result = await method(anything="goes", count=42)
    assert result == {"ok": True}
    mock_cm.call_tool.assert_awaited_once()


@pytest.mark.asyncio
async def test_validation_logs_argument_keys_not_values(
    read_file_module, caplog: pytest.LogCaptureFixture
) -> None:
    module, _ = read_file_module
    method = module._proxy_methods[0]
    with pytest.raises(_ProxyValidationError):
        await method(secret_value="hunter2-do-not-log")
    log_text = " ".join(r.getMessage() for r in caplog.records)
    assert "hunter2-do-not-log" not in log_text


# ── Allowlist / denylist enforcement on refresh ──────────────────────────────


@pytest.mark.asyncio
async def test_refresh_filters_through_allowlist(safe_tool_module) -> None:
    """A refreshed schema cache must respect the operator's allowlist —
    a malicious upstream cannot widen the exposed tool surface by serving
    new tools after startup."""
    module, _ = safe_tool_module
    module._tool_allowlist = {"safe_tool"}

    refreshed = [
        _make_tool("safe_tool", {"type": "object"}),
        _make_tool("malicious_new_tool", {"type": "object"}),
    ]
    fake_client = AsyncMock()
    fake_client.list_tools = AsyncMock(return_value=refreshed)

    await module._refresh_schemas_from_client(fake_client)

    assert "safe_tool" in module._schemas
    assert "malicious_new_tool" not in module._schemas


@pytest.mark.asyncio
async def test_refresh_failure_keeps_existing_cache(read_file_module) -> None:
    """If refresh fails (upstream down), the existing cache must be preserved
    — fail-safe to stale-but-restrictive over no validation at all."""
    module, _ = read_file_module
    original_cache = dict(module._schemas)

    fake_client = AsyncMock()
    fake_client.list_tools = AsyncMock(side_effect=ConnectionError("upstream down"))

    await module._refresh_schemas_from_client(fake_client)

    assert module._schemas == original_cache
