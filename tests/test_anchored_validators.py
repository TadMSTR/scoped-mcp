"""Anchored validators reject a trailing newline (vikunja#1219).

``re.match`` with a pattern ending in ``$`` accepts ``"dev\\n"``: ``$`` also matches just
before a final newline. Every ``^...$`` validator in ``src/`` now uses ``fullmatch``.
The token-claim path is the one that mattered: its value is not stripped, and
``agent_id`` is interpolated into filesystem paths and bucket prefixes.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from scoped_mcp.identity import AgentContext, resolve_request_identity

_TRAILING = ["\n", "\r", " ", "\r\n", "\t"]


@pytest.mark.parametrize("suffix", _TRAILING)
def test_token_claim_with_trailing_whitespace_is_ignored(suffix: str) -> None:
    token = type("Tok", (), {"claims": {"agent_id": f"dev{suffix}"}})()
    with (
        patch("fastmcp.server.dependencies.get_context", side_effect=RuntimeError),
        patch("fastmcp.server.dependencies.get_access_token", return_value=token),
    ):
        ident = resolve_request_identity("env-agent", "proc-sess")
    assert ident.agent_id == "env-agent"


def test_token_claim_valid_is_still_used() -> None:
    token = type("Tok", (), {"claims": {"agent_id": "dev"}})()
    with (
        patch("fastmcp.server.dependencies.get_context", side_effect=RuntimeError),
        patch("fastmcp.server.dependencies.get_access_token", return_value=token),
    ):
        assert resolve_request_identity("env-agent", "proc-sess").agent_id == "dev"


@pytest.mark.parametrize("suffix", _TRAILING)
def test_env_identity_never_keeps_trailing_whitespace(
    monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    """The env path strips first, so the value is normalised rather than refused."""
    monkeypatch.setenv("AGENT_ID", f"dev{suffix}")
    monkeypatch.setenv("AGENT_TYPE", f"developer{suffix}")
    ctx = AgentContext.from_env()
    assert (ctx.agent_id, ctx.agent_type) == ("dev", "developer")


# ── Manifest validators ──────────────────────────────────────────────────────


def test_manifest_agent_type_rejects_trailing_newline() -> None:
    from scoped_mcp.manifest import Manifest

    modules = {"filesystem": {"mode": "read", "config": {"base_path": "/tmp/agents"}}}
    assert Manifest.model_validate({"agent_type": "research", "modules": modules})
    with pytest.raises(ValidationError, match="agent_type"):
        Manifest.model_validate({"agent_type": "research\n", "modules": modules})


def test_rate_limit_rejects_trailing_newline() -> None:
    from scoped_mcp.manifest import RateLimitsConfig

    with pytest.raises(ValidationError):
        RateLimitsConfig.model_validate({"global": "10/minute\n"})
    with pytest.raises(ValidationError):
        RateLimitsConfig.model_validate({"per_tool": {"x_*": "10/minute\n"}})


def test_notify_topic_and_room_reject_trailing_newline() -> None:
    from scoped_mcp.manifest import NotifyConfig

    with pytest.raises(ValidationError):
        NotifyConfig.model_validate({"type": "ntfy", "topic": "approvals\n"})
    with pytest.raises(ValidationError):
        NotifyConfig.model_validate({"type": "matrix", "room": "!abc:example.org\n"})


# ── Module argument validators ───────────────────────────────────────────────


def test_grafana_validators_reject_trailing_newline() -> None:
    from scoped_mcp.modules.grafana import _validate_datasource_name, _validate_uid

    with pytest.raises(ValueError):
        _validate_uid("abc123\n")
    with pytest.raises(ValueError):
        _validate_datasource_name("prometheus\n")


def test_influxdb_validators_reject_trailing_newline() -> None:
    from scoped_mcp.modules._influxdb_validators import (
        _validate_identifier,
        _validate_measurement,
    )

    with pytest.raises(ValueError):
        _validate_measurement("cpu\n")
    with pytest.raises(ValueError):
        _validate_identifier("host\n")
