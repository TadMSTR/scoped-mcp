"""Tests for the SMCP-15 long-lived HTTP transport surface.

Covers the four testable acceptance criteria:
  AC2 — bearer auth: unauthenticated requests are rejected before dispatch.
  AC3 — per-connection session identity: concurrent connections get distinct session ids.
  AC4 — upstream self-heal: a dead persistent stdio transport reconnects once and retries.
  AC1 — transport wiring: --transport/--host/--port/--path parse; stdio stays the default.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import anyio
import pytest
import structlog
from fastmcp import FastMCP
from mcp.types import Tool

from scoped_mcp.audit import audited
from scoped_mcp.http_auth import BearerTokenVerifier
from scoped_mcp.identity import (
    AgentContext,
    RequestIdentity,
    _normalize_session_id,
    resolve_request_identity,
)
from scoped_mcp.modules.mcp_proxy import McpProxyModule, _is_reconnectable

# ── AC2: bearer token verifier ────────────────────────────────────────────────


async def _verify(verifier: BearerTokenVerifier, token: str):
    return await verifier.verify_token(token)


@pytest.mark.asyncio
async def test_bearer_verifier_accepts_matching_token_and_carries_agent_id() -> None:
    v = BearerTokenVerifier(expected_token="s3cret", agent_id="research")
    tok = await _verify(v, "s3cret")
    assert tok is not None
    # forward-compat guardrail: identity travels as both client_id and a claim.
    assert tok.client_id == "research"
    assert tok.claims.get("agent_id") == "research"


@pytest.mark.asyncio
async def test_bearer_verifier_rejects_wrong_and_empty_token() -> None:
    v = BearerTokenVerifier(expected_token="s3cret", agent_id="research")
    assert await _verify(v, "wrong") is None
    assert await _verify(v, "") is None


def test_bearer_verifier_refuses_empty_secret() -> None:
    with pytest.raises(ValueError, match="non-empty token"):
        BearerTokenVerifier(expected_token="", agent_id="research")


def test_http_app_rejects_unauthenticated_requests() -> None:
    """A TokenVerifier-protected streamable-http app 401s a request with no/invalid bearer,
    and lets a valid bearer past auth (subsequent 406 is content negotiation, not auth)."""
    from starlette.testclient import TestClient

    server = FastMCP("scoped-mcp/test", auth=BearerTokenVerifier("secret", "research"))
    app = server.http_app(path="/mcp")
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    with TestClient(app) as client:
        assert client.post("/mcp", json=body).status_code == 401
        assert (
            client.post("/mcp", json=body, headers={"Authorization": "Bearer wrong"}).status_code
            == 401
        )
        good = client.post("/mcp", json=body, headers={"Authorization": "Bearer secret"})
        assert good.status_code != 401  # past auth


# ── AC3: per-connection session identity ──────────────────────────────────────


@contextmanager
def _fake_request(session_id: str | None = None, agent_id_claim: str | None = None):
    """Patch the FastMCP per-request dependencies the resolver reads lazily."""
    ctx = None if session_id is None else type("Ctx", (), {"session_id": session_id})()
    token = None
    if agent_id_claim is not None:
        token = type("Tok", (), {"claims": {"agent_id": agent_id_claim}})()
    with (
        patch("fastmcp.server.dependencies.get_context", return_value=ctx),
        patch("fastmcp.server.dependencies.get_access_token", return_value=token),
    ):
        yield


def test_resolve_identity_falls_back_to_process_defaults() -> None:
    # No active FastMCP context (stdio / unit test) → defaults, no raise.
    assert resolve_request_identity("dev", "proc-sess") == RequestIdentity("proc-sess", "dev")


def test_resolve_identity_uses_context_session_id() -> None:
    with _fake_request(session_id="conn-A"):
        ident = resolve_request_identity("dev", "proc-sess")
    # Raw MCP session id is normalized to a stable UUID, not used verbatim.
    assert ident.session_id == _normalize_session_id("conn-A")
    assert ident.session_id != "conn-A"
    assert ident.agent_id == "dev"  # no token claim → default agent id


def test_resolve_identity_uses_token_agent_id_claim() -> None:
    with _fake_request(session_id="conn-A", agent_id_claim="research-07"):
        ident = resolve_request_identity("dev", "proc-sess")
    assert ident.agent_id == "research-07"  # forward-compat: per-connection agent id


def test_two_connections_get_distinct_session_ids() -> None:
    with _fake_request(session_id="conn-A"):
        a = resolve_request_identity("dev", "proc-sess")
    with _fake_request(session_id="conn-B"):
        b = resolve_request_identity("dev", "proc-sess")
    assert a.session_id != b.session_id  # distinct connections → distinct audit ids


def test_normalized_session_id_survives_audit_sanitizer() -> None:
    """Regression: a 32-hex MCP session id would be redacted to <redacted-hex>, collapsing
    all sessions. The normalized UUID must pass through the sanitizer unchanged."""
    from scoped_mcp.audit import _sanitize_value

    raw_hex = "0f9c2a7b4d1e4c8fa3b6e5d2c1084f7e"  # 32 hex chars — the redaction trigger
    assert _sanitize_value(raw_hex, "session_id") == "<redacted-hex>"  # proves the hazard
    normalized = _normalize_session_id(raw_hex)
    assert _sanitize_value(normalized, "session_id") == normalized  # survives intact


class _MockModule:
    def __init__(self, agent_ctx: AgentContext) -> None:
        self.agent_ctx = agent_ctx


@pytest.mark.asyncio
async def test_audited_stamps_per_connection_session_id() -> None:
    """The @audited log line carries the per-connection session id, not the process global."""

    async def _tool(self: _MockModule, value: str) -> str:
        return f"ok:{value}"

    _tool.__name__ = "test_tool"
    wrapped = audited("test_module_test_tool")(_tool)
    module = _MockModule(AgentContext(agent_id="dev", agent_type="research"))

    with _fake_request(session_id="conn-XYZ"), structlog.testing.capture_logs() as logs:
        await wrapped(module, value="hi")

    expected = _normalize_session_id("conn-XYZ")
    assert any(r.get("session_id") == expected for r in logs)
    assert not any(r.get("session_id") == "proc-sess" for r in logs)


# ── AC4: upstream transparent reconnect + retry ───────────────────────────────


def test_is_reconnectable_matches_dead_transport_errors() -> None:
    assert _is_reconnectable(anyio.BrokenResourceError())
    assert _is_reconnectable(anyio.ClosedResourceError())
    assert _is_reconnectable(ConnectionResetError())
    assert _is_reconnectable(ExceptionGroup("g", [anyio.ClosedResourceError()]))


def test_is_reconnectable_ignores_normal_and_cancellation() -> None:
    import asyncio

    assert not _is_reconnectable(ValueError("bad args"))
    assert not _is_reconnectable(asyncio.CancelledError())


def _make_tool_desc(name: str) -> Tool:
    return Tool(name=name, description="", inputSchema={})


@dataclass
class _Result:
    data: object
    content: list


@pytest.fixture
def stdio_module():
    agent_ctx = AgentContext(agent_id="dev", agent_type="research")
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        disc = AsyncMock()
        disc.__aenter__ = AsyncMock(return_value=disc)
        disc.__aexit__ = AsyncMock(return_value=None)
        disc.list_tools = AsyncMock(return_value=[_make_tool_desc("log_event")])
        MockClient.return_value = disc
        yield McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"command": "/path/to/python3", "args": ["server.py"]},
        )


@pytest.mark.asyncio
async def test_proxy_reconnects_and_retries_on_dead_transport(stdio_module) -> None:
    # Persistent client whose call_tool fails with a dead-transport error.
    dead = AsyncMock()
    dead.__aenter__ = AsyncMock(return_value=dead)
    dead.__aexit__ = AsyncMock(return_value=None)
    dead.list_tools = AsyncMock(return_value=[])
    dead.call_tool = AsyncMock(side_effect=anyio.BrokenResourceError())

    # Fresh client opened by the reconnect; its call_tool succeeds.
    fresh = AsyncMock()
    fresh.__aenter__ = AsyncMock(return_value=fresh)
    fresh.__aexit__ = AsyncMock(return_value=None)
    fresh.list_tools = AsyncMock(return_value=[_make_tool_desc("log_event")])
    fresh.call_tool = AsyncMock(return_value=_Result(data={"ok": True}, content=[]))

    with patch("scoped_mcp.modules.mcp_proxy.Client", return_value=dead):
        await stdio_module.startup()

    method = stdio_module.get_tool_methods(mode=None)[0]
    with patch("scoped_mcp.modules.mcp_proxy.Client", return_value=fresh):
        result = await method()

    assert result == {"ok": True}
    dead.call_tool.assert_called_once()  # first attempt hit the dead transport
    fresh.call_tool.assert_called_once_with("log_event", arguments={})  # retry succeeded
    assert stdio_module._persistent_client is fresh


@pytest.mark.asyncio
async def test_proxy_does_not_reconnect_on_normal_tool_error(stdio_module) -> None:
    persistent = AsyncMock()
    persistent.__aenter__ = AsyncMock(return_value=persistent)
    persistent.__aexit__ = AsyncMock(return_value=None)
    persistent.list_tools = AsyncMock(return_value=[])
    persistent.call_tool = AsyncMock(side_effect=ValueError("upstream rejected"))

    with patch("scoped_mcp.modules.mcp_proxy.Client", return_value=persistent):
        await stdio_module.startup()

    stdio_module._reconnect_persistent = AsyncMock()  # spy — must NOT be called
    method = stdio_module.get_tool_methods(mode=None)[0]
    with pytest.raises(ValueError, match="upstream rejected"):
        await method()
    stdio_module._reconnect_persistent.assert_not_called()


# ── AC1: transport CLI wiring ─────────────────────────────────────────────────


def test_parse_args_http_flags() -> None:
    from scoped_mcp.server import parse_args

    a = parse_args(["run", "--manifest", "m.yaml", "--transport", "http", "--port", "8471"])
    assert (a.transport, a.host, a.port, a.path) == ("http", "127.0.0.1", 8471, "/mcp")


def test_parse_args_defaults_to_stdio() -> None:
    from scoped_mcp.server import parse_args

    a = parse_args(["run", "--manifest", "m.yaml"])
    assert a.transport == "stdio"
