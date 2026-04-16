"""Tests for audit.py — structured logging, sanitization, and @audited decorator."""

from __future__ import annotations

import pytest

from scoped_mcp.audit import _sanitize_value, audited
from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext

# ── _sanitize_value ───────────────────────────────────────────────────────────


def test_sanitize_token_key() -> None:
    assert _sanitize_value("supersecret", "MY_TOKEN") == "<redacted>"


def test_sanitize_password_key() -> None:
    assert _sanitize_value("hunter2", "DB_PASSWORD") == "<redacted>"


def test_sanitize_secret_key() -> None:
    assert _sanitize_value("s3cr3t", "OAUTH_SECRET") == "<redacted>"


def test_sanitize_binary() -> None:
    result = _sanitize_value(b"\x00\x01\x02")
    assert result == "<binary 3 bytes>"


def test_sanitize_long_string() -> None:
    long_str = "a" * 600
    result = _sanitize_value(long_str)
    assert isinstance(result, str)
    assert "truncated" in result
    assert len(result) < 600


def test_sanitize_normal_string() -> None:
    assert _sanitize_value("hello world") == "hello world"


def test_sanitize_dict_recurses() -> None:
    data = {"MY_TOKEN": "secret", "message": "hello"}
    result = _sanitize_value(data)
    assert result["MY_TOKEN"] == "<redacted>"
    assert result["message"] == "hello"


def test_sanitize_list_recurses() -> None:
    data = ["normal", b"\xff\xfe"]
    result = _sanitize_value(data)
    assert result[0] == "normal"
    assert "<binary" in result[1]


# ── @audited decorator ────────────────────────────────────────────────────────


class _MockModule:
    """Minimal mock of a ToolModule instance for decorator tests."""

    def __init__(self, agent_ctx: AgentContext) -> None:
        self.agent_ctx = agent_ctx


async def _make_tool(module: _MockModule, raise_exc: Exception | None = None) -> str:
    async def _tool(self: _MockModule, value: str) -> str:
        if raise_exc:
            raise raise_exc
        return f"ok:{value}"

    _tool.__name__ = "test_tool"
    wrapped = audited("test_module_test_tool")(_tool)
    return await wrapped(module, value="hello")


@pytest.mark.asyncio
async def test_audited_returns_result(agent_ctx: AgentContext) -> None:
    module = _MockModule(agent_ctx)
    result = await _make_tool(module)
    assert result == "ok:hello"


@pytest.mark.asyncio
async def test_audited_reraises_scope_violation(agent_ctx: AgentContext) -> None:
    module = _MockModule(agent_ctx)
    with pytest.raises(ScopeViolation):
        await _make_tool(module, raise_exc=ScopeViolation("out of scope"))


@pytest.mark.asyncio
async def test_audited_reraises_general_exception(agent_ctx: AgentContext) -> None:
    module = _MockModule(agent_ctx)
    with pytest.raises(ValueError, match="bad input"):
        await _make_tool(module, raise_exc=ValueError("bad input"))
