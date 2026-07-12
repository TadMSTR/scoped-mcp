"""Tests for ops_alert.py — Vault-independent operational alerting."""

from __future__ import annotations

import pytest

from scoped_mcp.ops_alert import (
    _format_body,
    alerting_configured,
    send_ops_alert,
)

_MATRIX_ENV = {
    "SCOPED_MCP_ALERT_MATRIX_HOMESERVER": "https://matrix.example.com",
    "SCOPED_MCP_ALERT_MATRIX_TOKEN": "alert-token",
    "SCOPED_MCP_ALERT_MATRIX_ROOM": "!alerts:example.com",
}


def _set_matrix_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in _MATRIX_ENV.items():
        monkeypatch.setenv(key, value)


def _clear_matrix_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _MATRIX_ENV:
        monkeypatch.delenv(key, raising=False)


# ── configuration detection ───────────────────────────────────────────────────


def test_alerting_configured_true_when_all_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_matrix_env(monkeypatch)
    assert alerting_configured() is True


def test_alerting_configured_false_when_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_matrix_env(monkeypatch)
    monkeypatch.setenv("SCOPED_MCP_ALERT_MATRIX_HOMESERVER", "https://matrix.example.com")
    # token + room missing
    assert alerting_configured() is False


def test_alerting_configured_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_matrix_env(monkeypatch)
    assert alerting_configured() is False


# ── body formatting ───────────────────────────────────────────────────────────


def test_format_body_includes_event_and_detail() -> None:
    body = _format_body("vault_credentials_degraded", {"agent_id": "research", "failures": 3})
    assert body.startswith("[scoped-mcp] vault_credentials_degraded")
    assert "agent_id: research" in body
    assert "failures: 3" in body


# ── send_ops_alert ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_ops_alert_noop_when_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_matrix_env(monkeypatch)
    # Never raises, returns False when there is no configured sink.
    assert await send_ops_alert("some_event", {"x": 1}) is False


@pytest.mark.asyncio
async def test_send_ops_alert_posts_to_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_matrix_env(monkeypatch)
    captured: dict = {}

    class _FakeResp:
        def raise_for_status(self) -> None:
            return None

    class _FakeClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> _FakeClient:
            return self

        async def __aexit__(self, *args) -> bool:
            return False

        async def put(self, url, json, headers) -> _FakeResp:
            captured["url"] = url
            captured["json"] = json
            captured["headers"] = headers
            return _FakeResp()

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)

    ok = await send_ops_alert("vault_credentials_degraded", {"agent_id": "research"})
    assert ok is True
    assert "/_matrix/client/v3/rooms/" in captured["url"]
    assert captured["json"]["msgtype"] == "m.text"
    assert captured["json"]["body"].startswith("[scoped-mcp] vault_credentials_degraded")
    assert captured["headers"]["Authorization"] == "Bearer alert-token"


@pytest.mark.asyncio
async def test_send_ops_alert_swallows_matrix_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_matrix_env(monkeypatch)

    class _BoomClient:
        def __init__(self, *args, **kwargs) -> None:
            pass

        async def __aenter__(self) -> _BoomClient:
            return self

        async def __aexit__(self, *args) -> bool:
            return False

        async def put(self, url, json, headers):
            raise RuntimeError("network down")

    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", _BoomClient)

    # A sink failure must never propagate — returns False, swallowed and logged.
    assert await send_ops_alert("vault_credentials_degraded", {}) is False
