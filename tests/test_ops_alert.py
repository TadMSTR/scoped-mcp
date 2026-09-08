"""Tests for ops_alert.py — Vault-independent operational alerting."""

from __future__ import annotations

from typing import ClassVar

import pytest

from scoped_mcp import ops_alert
from scoped_mcp.ops_alert import (
    _format_body,
    _ntfy_config,
    alerting_configured,
    send_ops_alert,
)

# Every environment variable ops_alert reads, derived from the module's own name
# constants rather than restated here. ops_alert reads config fresh from os.environ
# on every call, so anything left set by the operator's shell is live config for
# these tests — and 7 of the agent .env files export SCOPED_MCP_ALERT_NTFY_URL.
# Sourcing one before running the suite turned two passing tests red on unmodified
# code (vikunja#604). CI never saw it: the runner's environment is clean, so the
# disagreement always presented as "green in CI, red locally", the shape most
# easily dismissed as the operator's problem rather than a test bug.
#
# Derived, not hand-listed, so a sixth alert variable cannot be added to ops_alert
# and silently escape isolation — the failure mode would look exactly like this one.
_ALERT_ENV_VARS: frozenset[str] = frozenset(
    value
    for name, value in vars(ops_alert).items()
    if name.endswith("_ENV") and isinstance(value, str)
)


@pytest.fixture(autouse=True)
def _isolate_alert_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clear every alert variable before each test, so each declares what it needs.

    Autouse and unconditional: the tests that assert on a variable's ABSENCE are
    the ones that break, and those are exactly the tests that would never think to
    ask for isolation.
    """
    for var in _ALERT_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


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


# ── the isolation itself (vikunja#604) ──────────────────────────────────────


def test_alert_env_roster_covers_every_variable_ops_alert_reads() -> None:
    """The isolated set must be the complete set the module actually reads.

    _ALERT_ENV_VARS is derived from ops_alert's own constants, so this asserts the
    derivation still finds them — if the naming convention changes, isolation would
    silently shrink to nothing and the autouse fixture would become a no-op while
    still looking present.
    """
    assert _ALERT_ENV_VARS >= set(_MATRIX_ENV) | set(_NTFY_ENV)
    assert len(_ALERT_ENV_VARS) == 5, sorted(_ALERT_ENV_VARS)


def test_ambient_alert_env_does_not_reach_a_test(monkeypatch: pytest.MonkeyPatch) -> None:
    """No alert variable is visible at test start, whatever the operator's shell holds.

    This is the regression guard for #604 itself. Without the autouse fixture,
    test_alerting_configured_false_when_partial and _when_unset fail under a shell
    that exported SCOPED_MCP_ALERT_NTFY_URL.
    """
    import os

    leaked = sorted(v for v in _ALERT_ENV_VARS if v in os.environ)
    assert leaked == [], f"ambient alert config reached the test: {leaked}"
