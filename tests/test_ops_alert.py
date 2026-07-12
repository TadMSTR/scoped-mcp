"""Tests for ops_alert.py — Vault-independent operational alerting."""

from __future__ import annotations

from typing import ClassVar

import pytest

from scoped_mcp.ops_alert import (
    _format_body,
    _ntfy_config,
    alerting_configured,
    send_ops_alert,
)

_MATRIX_ENV = {
    "SCOPED_MCP_ALERT_MATRIX_HOMESERVER": "https://matrix.example.com",
    "SCOPED_MCP_ALERT_MATRIX_TOKEN": "alert-token",
    "SCOPED_MCP_ALERT_MATRIX_ROOM": "!alerts:example.com",
}

_NTFY_ENV = {
    "SCOPED_MCP_ALERT_NTFY_URL": "https://ntfy.example.com/forge",
    "SCOPED_MCP_ALERT_NTFY_TOKEN": "ntfy-token",
}


def _set_matrix_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in _MATRIX_ENV.items():
        monkeypatch.setenv(key, value)


def _clear_matrix_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _MATRIX_ENV:
        monkeypatch.delenv(key, raising=False)


def _set_ntfy_env(monkeypatch: pytest.MonkeyPatch, with_token: bool = True) -> None:
    monkeypatch.setenv("SCOPED_MCP_ALERT_NTFY_URL", _NTFY_ENV["SCOPED_MCP_ALERT_NTFY_URL"])
    if with_token:
        monkeypatch.setenv("SCOPED_MCP_ALERT_NTFY_TOKEN", _NTFY_ENV["SCOPED_MCP_ALERT_NTFY_TOKEN"])
    else:
        monkeypatch.delenv("SCOPED_MCP_ALERT_NTFY_TOKEN", raising=False)


def _clear_ntfy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _NTFY_ENV:
        monkeypatch.delenv(key, raising=False)


class _SinkRecorder:
    """Fake httpx.AsyncClient that records Matrix PUTs and ntfy POSTs.

    ``matrix_ok`` / ``ntfy_ok`` control whether each verb succeeds or raises, so a single
    fake drives all Matrix-primary / ntfy-fallback delivery permutations.
    """

    calls: ClassVar[list[str]] = []
    matrix_ok: ClassVar[bool] = True
    ntfy_ok: ClassVar[bool] = True
    last_ntfy: ClassVar[dict | None] = None

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self) -> _SinkRecorder:
        return self

    async def __aexit__(self, *args) -> bool:
        return False

    class _Resp:
        def raise_for_status(self) -> None:
            return None

    async def put(self, url, json=None, headers=None) -> _SinkRecorder._Resp:
        type(self).calls.append("matrix")
        if not type(self).matrix_ok:
            raise RuntimeError("matrix down")
        return self._Resp()

    async def post(self, url, content=None, headers=None) -> _SinkRecorder._Resp:
        type(self).calls.append("ntfy")
        type(self).last_ntfy = {"url": url, "content": content, "headers": headers}
        if not type(self).ntfy_ok:
            raise RuntimeError("ntfy down")
        return self._Resp()


def _install_recorder(
    monkeypatch: pytest.MonkeyPatch, *, matrix_ok: bool = True, ntfy_ok: bool = True
) -> type[_SinkRecorder]:
    import httpx

    rec = type("_Rec", (_SinkRecorder,), {})
    rec.calls = []
    rec.matrix_ok = matrix_ok
    rec.ntfy_ok = ntfy_ok
    rec.last_ntfy = None
    monkeypatch.setattr(httpx, "AsyncClient", rec)
    return rec


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


# ── ntfy fallback (SMCP-27) ───────────────────────────────────────────────────


def test_alerting_configured_true_when_only_ntfy_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_matrix_env(monkeypatch)
    _set_ntfy_env(monkeypatch)
    assert alerting_configured() is True


def test_ntfy_config_requires_url_token_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_ntfy_env(monkeypatch)
    assert _ntfy_config() is None
    _set_ntfy_env(monkeypatch, with_token=False)
    assert _ntfy_config() == ("https://ntfy.example.com/forge", "")


@pytest.mark.asyncio
async def test_matrix_ok_does_not_call_ntfy(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_matrix_env(monkeypatch)
    _set_ntfy_env(monkeypatch)
    rec = _install_recorder(monkeypatch, matrix_ok=True)

    ok = await send_ops_alert("vault_credentials_degraded", {"agent_id": "research"})
    assert ok is True
    # Fallback, not fan-out: Matrix succeeded, so ntfy is never contacted.
    assert rec.calls == ["matrix"]


@pytest.mark.asyncio
async def test_matrix_fail_falls_back_to_ntfy(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_matrix_env(monkeypatch)
    _set_ntfy_env(monkeypatch)
    rec = _install_recorder(monkeypatch, matrix_ok=False, ntfy_ok=True)

    ok = await send_ops_alert("vault_credentials_degraded", {"agent_id": "research"})
    assert ok is True
    assert rec.calls == ["matrix", "ntfy"]
    assert rec.last_ntfy["url"] == "https://ntfy.example.com/forge"
    assert rec.last_ntfy["headers"]["Authorization"] == "Bearer ntfy-token"
    assert rec.last_ntfy["headers"]["Title"].startswith("scoped-mcp: vault_credentials_degraded")


@pytest.mark.asyncio
async def test_ntfy_used_when_matrix_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_matrix_env(monkeypatch)
    _set_ntfy_env(monkeypatch, with_token=False)
    rec = _install_recorder(monkeypatch, ntfy_ok=True)

    ok = await send_ops_alert("vault_credentials_degraded", {})
    assert ok is True
    # Matrix unconfigured → straight to ntfy, no Matrix attempt.
    assert rec.calls == ["ntfy"]
    # Unauthenticated topic: no Authorization header.
    assert "Authorization" not in rec.last_ntfy["headers"]


@pytest.mark.asyncio
async def test_noop_when_neither_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_matrix_env(monkeypatch)
    _clear_ntfy_env(monkeypatch)
    rec = _install_recorder(monkeypatch)

    assert await send_ops_alert("some_event", {"x": 1}) is False
    assert rec.calls == []


@pytest.mark.asyncio
async def test_ntfy_withholds_token_over_non_https(monkeypatch: pytest.MonkeyPatch) -> None:
    # INFO-1: a misconfigured http:// endpoint must not carry the bearer token in cleartext.
    # The alert is still attempted (best-effort), just unauthenticated.
    _clear_matrix_env(monkeypatch)
    monkeypatch.setenv("SCOPED_MCP_ALERT_NTFY_URL", "http://ntfy.insecure.example/forge")
    monkeypatch.setenv("SCOPED_MCP_ALERT_NTFY_TOKEN", "ntfy-token")
    rec = _install_recorder(monkeypatch, ntfy_ok=True)

    ok = await send_ops_alert("vault_credentials_degraded", {})
    assert ok is True
    assert rec.calls == ["ntfy"]
    assert "Authorization" not in rec.last_ntfy["headers"]


@pytest.mark.asyncio
async def test_ntfy_network_error_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    # Matrix down AND ntfy down — both attempted, both swallowed, never raises.
    _set_matrix_env(monkeypatch)
    _set_ntfy_env(monkeypatch)
    rec = _install_recorder(monkeypatch, matrix_ok=False, ntfy_ok=False)

    assert await send_ops_alert("vault_credentials_degraded", {}) is False
    assert rec.calls == ["matrix", "ntfy"]
