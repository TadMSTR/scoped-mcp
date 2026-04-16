"""Tests for audit.py — structured logging, sanitization, and @audited decorator."""

from __future__ import annotations

import pytest

from scoped_mcp.audit import _sanitize_processor, _sanitize_value, audited
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
    # Use a non-hex char so the long-hex pattern redactor (L1) doesn't consume it.
    long_str = "z" * 600
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


# ── L1: expanded redaction ────────────────────────────────────────────────────


def test_sanitize_authorization_key() -> None:
    assert _sanitize_value("Bearer abc", "authorization") == "<redacted>"


def test_sanitize_cookie_key() -> None:
    assert _sanitize_value("sid=xyz", "cookie") == "<redacted>"


def test_sanitize_pwd_suffix() -> None:
    assert _sanitize_value("hunter2", "DB_PWD") == "<redacted>"


def test_sanitize_pass_suffix() -> None:
    assert _sanitize_value("hunter2", "USER_PASS") == "<redacted>"


def test_sanitize_auth_suffix() -> None:
    assert _sanitize_value("abc", "HTTP_AUTH") == "<redacted>"


def test_sanitize_jwt_pattern_in_error_message() -> None:
    msg = "upstream rejected: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghij"
    result = _sanitize_value(msg)
    assert "eyJ" not in result
    assert "<redacted-jwt>" in result


def test_sanitize_bearer_pattern_in_error_message() -> None:
    msg = "401 from api: Bearer sk-abcd1234efgh5678"
    result = _sanitize_value(msg)
    assert "sk-abcd1234efgh5678" not in result
    assert "<redacted-bearer>" in result


def test_sanitize_long_hex_in_message() -> None:
    msg = "session cookie was aabbccddeeff00112233445566778899aabbccdd"
    result = _sanitize_value(msg)
    assert "aabbccddeeff00112233445566778899aabbccdd" not in result
    assert "<redacted-hex>" in result


def test_sanitize_processor_walks_whole_event() -> None:
    event = {
        "event": "tool_call",
        "tool": "foo_bar",
        "error": "Bearer sk-supersecret-token-abcdef",
        "detail": {"MY_TOKEN": "leak"},
    }
    result = _sanitize_processor(None, "info", event)
    assert result["event"] == "tool_call"  # preserved
    assert result["tool"] == "foo_bar"  # preserved (not key-match, no patterns)
    assert "sk-supersecret-token-abcdef" not in result["error"]
    assert result["detail"]["MY_TOKEN"] == "<redacted>"


def test_sanitize_processor_preserves_event_field_even_if_sensitive_looking() -> None:
    # The literal string 'scope_violation' in event must not be accidentally redacted.
    event = {"event": "scope_violation", "level": "warning"}
    result = _sanitize_processor(None, "warning", event)
    assert result["event"] == "scope_violation"


# ── H3: @audited signature no longer accepts scope_strategy ──────────────────


def test_audited_rejects_scope_strategy_kwarg() -> None:
    """The scope_strategy param was removed per 2026-04-16 audit finding H3.

    Modules are responsible for calling ``self.scoping.enforce`` themselves.
    A caller that was relying on the decorator to do that needs to know
    immediately, not silently get an un-enforced tool.
    """
    with pytest.raises(TypeError):
        audited("foo_tool", scope_strategy=object())  # type: ignore[call-arg]
