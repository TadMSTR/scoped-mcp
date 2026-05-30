"""Tests for HITL middleware (v1.1 — reject-then-wait).

Flow:
  1. First call to an approval-required tool returns HitlRejectedError
     immediately, containing the approval ID.
  2. Operator runs ``scoped-mcp hitl approve <id>``, which writes a one-time
     pre-approval token to state.
  3. Agent retries the tool call; middleware finds the token, consumes it,
     and forwards the call upstream.

Uses InProcessBackend for state since it faithfully emulates the
DragonflyBackend contract for set/get/delete. Production HITL still
requires DragonflyBackend (enforced at manifest load).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from scoped_mcp.exceptions import HitlRejectedError, ManifestError
from scoped_mcp.hitl import (
    PREAPPROVAL_TTL_SECONDS,
    HitlMiddleware,
    _build_arguments_summary,
    _generate_approval_id,
    _preapproval_key,
)
from scoped_mcp.hitl_cli import _key_for, _parse_approval_id, run_hitl_command
from scoped_mcp.manifest import load_manifest
from scoped_mcp.state import InProcessBackend


class _RecordingNotifier:
    """Notifier that records calls instead of sending anywhere."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def notify(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


async def _passthrough() -> str:
    return "EXECUTED"


def _make_middleware(
    state: InProcessBackend,
    notifier: _RecordingNotifier | None = None,
    approval_required: list[str] | None = None,
    shadow: list[str] | None = None,
    agent_id: str = "research-01",
) -> HitlMiddleware:
    return HitlMiddleware(
        state=state,
        agent_id=agent_id,
        agent_type="research",
        approval_required=approval_required if approval_required is not None else ["*"],
        shadow=shadow if shadow is not None else [],
        timeout_seconds=300,
        notifier=notifier or _RecordingNotifier(),
    )


# ── Reject-then-wait core flow ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_first_call_raises_immediately_with_approval_id() -> None:
    """First call to an approval-required tool always raises HitlRejectedError
    immediately and includes the approval ID in the message."""
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    mw = _make_middleware(state, notifier, approval_required=["filesystem.delete_file"])

    with pytest.raises(HitlRejectedError, match="approval ID:") as exc_info:
        await mw(
            agent_ctx=None,
            tool_name="filesystem.delete_file",
            kwargs={"path": "/tmp/x"},
            call_next=_passthrough,
        )

    # Message contains enough to act on
    msg = str(exc_info.value)
    assert "filesystem.delete_file" in msg
    assert "research-01." in msg  # approval_id embedded

    # Notifier was called
    assert len(notifier.calls) == 1
    assert notifier.calls[0]["tool_name"] == "filesystem.delete_file"


@pytest.mark.asyncio
async def test_retry_with_preapproval_token_succeeds() -> None:
    """After the operator writes a pre-approval token, the next call proceeds."""
    state = InProcessBackend()
    mw = _make_middleware(state, approval_required=["filesystem.delete_file"])

    # First call — get the rejection and extract the approval_id
    with pytest.raises(HitlRejectedError) as exc_info:
        await mw(
            agent_ctx=None,
            tool_name="filesystem.delete_file",
            kwargs={"path": "/tmp/x"},
            call_next=_passthrough,
        )
    msg = str(exc_info.value)
    # Extract approval_id from the error message (format: "research-01.<hex12>")
    import re

    approval_id_match = re.search(r"research-01\.[0-9a-f]{12}", msg)
    assert approval_id_match, f"approval_id not found in: {msg}"

    # Operator writes pre-approval token (simulates CLI approve)
    pre_key = _preapproval_key("filesystem.delete_file")
    await state.set_with_ttl(pre_key, "approved", PREAPPROVAL_TTL_SECONDS)

    # Retry — should proceed
    result = await mw(
        agent_ctx=None,
        tool_name="filesystem.delete_file",
        kwargs={"path": "/tmp/x"},
        call_next=_passthrough,
    )
    assert result == "EXECUTED"


@pytest.mark.asyncio
async def test_preapproval_token_is_one_time_use() -> None:
    """Pre-approval token is consumed on first successful retry. A third call
    without a new token is rejected again."""
    state = InProcessBackend()
    mw = _make_middleware(state, approval_required=["some_tool"])

    # First call — rejected
    with pytest.raises(HitlRejectedError):
        await mw(agent_ctx=None, tool_name="some_tool", kwargs={}, call_next=_passthrough)

    # Write pre-approval token
    pre_key = _preapproval_key("some_tool")
    await state.set_with_ttl(pre_key, "approved", PREAPPROVAL_TTL_SECONDS)

    # Second call — succeeds, token consumed
    result = await mw(agent_ctx=None, tool_name="some_tool", kwargs={}, call_next=_passthrough)
    assert result == "EXECUTED"

    # Third call — no token, rejected again
    with pytest.raises(HitlRejectedError):
        await mw(agent_ctx=None, tool_name="some_tool", kwargs={}, call_next=_passthrough)


@pytest.mark.asyncio
async def test_reject_does_not_write_preapproval() -> None:
    """If the operator rejects (no pre-approval token written), retry is also rejected."""
    state = InProcessBackend()
    mw = _make_middleware(state, approval_required=["some_tool"])

    # First call — rejected (no pre-approval token written)
    with pytest.raises(HitlRejectedError):
        await mw(agent_ctx=None, tool_name="some_tool", kwargs={}, call_next=_passthrough)

    # Retry — still rejected
    with pytest.raises(HitlRejectedError):
        await mw(agent_ctx=None, tool_name="some_tool", kwargs={}, call_next=_passthrough)


@pytest.mark.asyncio
async def test_pending_payload_written_to_state() -> None:
    """On rejection, a payload is written to state so the CLI can list and approve it."""
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    mw = _make_middleware(state, notifier, approval_required=["some_tool"])

    with pytest.raises(HitlRejectedError):
        await mw(
            agent_ctx=None,
            tool_name="some_tool",
            kwargs={"arg": "value"},
            call_next=_passthrough,
        )

    # Payload exists in state
    approval_id = notifier.calls[0]["approval_id"]
    raw = await state.get(f"hitl:{approval_id}")
    assert raw is not None
    payload = json.loads(raw)
    assert payload["tool"] == "some_tool"
    assert payload["agent_id"] == "research-01"
    assert payload["approval_id"] == approval_id


# ── Non-approval paths ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_non_matching_tool_passes_through() -> None:
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    mw = _make_middleware(
        state, notifier, approval_required=["filesystem.delete_file"], agent_id="a1"
    )
    result = await mw(
        agent_ctx=None,
        tool_name="filesystem.read_file",
        kwargs={},
        call_next=_passthrough,
    )
    assert result == "EXECUTED"
    assert notifier.calls == []


# ── Shadow mode ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_shadow_returns_synthetic_response_without_calling_upstream() -> None:
    state = InProcessBackend()
    upstream = AsyncMock(side_effect=AssertionError("upstream MUST NOT be called in shadow"))
    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="research",
        approval_required=[],
        shadow=["mcp_proxy.*"],
        timeout_seconds=300,
        notifier=_RecordingNotifier(),
    )

    result = await mw(
        agent_ctx=None,
        tool_name="mcp_proxy.dangerous_op",
        kwargs={"target": "prod"},
        call_next=upstream,
    )
    assert result["shadow"] is True
    upstream.assert_not_called()


@pytest.mark.asyncio
async def test_shadow_takes_precedence_over_approval() -> None:
    """If a tool matches both shadow and approval_required, shadow wins."""
    state = InProcessBackend()
    upstream = AsyncMock(side_effect=AssertionError("MUST NOT be called"))
    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="research",
        approval_required=["*"],
        shadow=["*"],
        timeout_seconds=300,
        notifier=_RecordingNotifier(),
    )
    result = await mw(
        agent_ctx=None,
        tool_name="any_tool",
        kwargs={},
        call_next=upstream,
    )
    assert result["shadow"] is True
    upstream.assert_not_called()


# ── Glob pattern matching ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_glob_pattern_matches_in_approval_required() -> None:
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="r",
        approval_required=["mcp_proxy.*"],
        shadow=[],
        timeout_seconds=300,
        notifier=notifier,
    )
    with pytest.raises(HitlRejectedError):
        await mw(
            agent_ctx=None,
            tool_name="mcp_proxy.delete_resource",
            kwargs={},
            call_next=_passthrough,
        )
    assert len(notifier.calls) == 1


# ── Argument redaction ───────────────────────────────────────────────────────


def test_arguments_summary_redacts_sensitive_keys() -> None:
    summary = _build_arguments_summary(
        {
            "path": "/data/foo.txt",
            "API_TOKEN": "supersecret",
            "password": "hunter2",
        }
    )
    assert summary["path"] == "/data/foo.txt"
    assert summary["API_TOKEN"] == "<redacted>"
    assert summary["password"] == "<redacted>"


@pytest.mark.asyncio
async def test_state_payload_does_not_contain_raw_sensitive_values() -> None:
    """The JSON payload stored in the state backend must contain only the
    sanitised summary — operator-side display draws from this payload."""
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    mw = _make_middleware(state, notifier, agent_id="a1")

    with pytest.raises(HitlRejectedError):
        await mw(
            agent_ctx=None,
            tool_name="some_tool",
            kwargs={"API_TOKEN": "this-must-not-leak-anywhere", "path": "/safe"},
            call_next=_passthrough,
        )

    for key, (value, _ttl) in state._store.items():
        assert "this-must-not-leak-anywhere" not in value, (
            f"sensitive value leaked into state key {key!r}"
        )


# ── Notifier failures ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_notifier_exception_swallowed_middleware_still_rejects() -> None:
    """A buggy notifier must NOT propagate — error is logged and the call is
    still rejected with HitlRejectedError (never RuntimeError)."""
    state = InProcessBackend()

    class BrokenNotifier:
        async def notify(self, **kwargs: Any) -> None:
            raise RuntimeError("notifier exploded")

    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="r",
        approval_required=["*"],
        shadow=[],
        timeout_seconds=300,
        notifier=BrokenNotifier(),
    )
    upstream = AsyncMock()
    with pytest.raises(HitlRejectedError):
        await mw(
            agent_ctx=None,
            tool_name="x",
            kwargs={},
            call_next=upstream,
        )
    upstream.assert_not_called()


@pytest.mark.asyncio
async def test_notifier_failure_does_not_prevent_retry() -> None:
    """Even when the notifier fails, the pending payload is still written to
    state, so the operator can find and approve it via ``hitl list``."""
    state = InProcessBackend()
    captured_id: dict[str, str] = {}

    class BrokenNotifier:
        async def notify(self, approval_id: str, **kwargs: Any) -> None:
            captured_id["id"] = approval_id
            raise RuntimeError("transport down")

    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="r",
        approval_required=["*"],
        shadow=[],
        timeout_seconds=300,
        notifier=BrokenNotifier(),
    )

    with pytest.raises(HitlRejectedError):
        await mw(agent_ctx=None, tool_name="x", kwargs={}, call_next=_passthrough)

    # Payload written despite notifier failure
    assert "id" in captured_id
    raw = await state.get(f"hitl:{captured_id['id']}")
    assert raw is not None

    # Operator writes pre-approval token, retry succeeds
    pre_key = _preapproval_key("x")
    await state.set_with_ttl(pre_key, "approved", PREAPPROVAL_TTL_SECONDS)
    result = await mw(agent_ctx=None, tool_name="x", kwargs={}, call_next=_passthrough)
    assert result == "EXECUTED"


# ── State backend errors ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_state_write_failure_raises_hitl_rejected() -> None:
    """If the state backend fails to write the pending payload, HITL fails
    closed — HitlRejectedError, not the underlying backend exception."""

    class BrokenState(InProcessBackend):
        async def set_with_ttl(self, key: str, value: str, ttl_seconds: int) -> None:
            raise OSError("dragonfly unreachable")

    state = BrokenState()
    mw = _make_middleware(state, agent_id="a1")

    with pytest.raises(HitlRejectedError, match="state backend unavailable"):
        await mw(agent_ctx=None, tool_name="x", kwargs={}, call_next=_passthrough)


# ── Approval ID format and CLI parsing ───────────────────────────────────────


def test_approval_id_format() -> None:
    aid = _generate_approval_id("research-01")
    assert aid.startswith("research-01.")
    suffix = aid.split(".", 1)[1]
    assert len(suffix) == 12
    int(suffix, 16)  # all hex chars


def test_cli_parse_approval_id_well_formed() -> None:
    parsed = _parse_approval_id("research-01.abc123def456")
    assert parsed == ("research-01", "abc123def456")


def test_cli_parse_approval_id_with_dots_in_agent_id() -> None:
    """rsplit ensures the suffix is always the last component."""
    parsed = _parse_approval_id("foo.bar.abc123")
    assert parsed == ("foo.bar", "abc123")


def test_cli_parse_approval_id_malformed() -> None:
    assert _parse_approval_id("no-dot-here") is None
    assert _parse_approval_id(".no-agent") is None
    assert _parse_approval_id("no-suffix.") is None


def test_cli_key_for_uses_agent_prefix() -> None:
    key = _key_for("research-01.abc123def456")
    assert key == "scoped-mcp:research-01:hitl:research-01.abc123def456"


def test_cli_key_for_rejects_malformed() -> None:
    with pytest.raises(ValueError, match="malformed"):
        _key_for("not-an-approval-id")


def test_preapproval_key_format() -> None:
    key = _preapproval_key("pm2-mcp__restart_service")
    assert key == "hitl:preapproved:pm2-mcp__restart_service"


# ── Manifest-level validation: HITL requires dragonfly ───────────────────────


def test_manifest_hitl_with_in_process_backend_rejected() -> None:
    yaml_content = """
agent_type: research
modules:
  filesystem:
    mode: read
    config:
      base_path: /tmp/x
hitl:
  approval_required:
    - filesystem.write_file
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        path = f.name
    try:
        with pytest.raises(ManifestError):
            load_manifest(path)
    finally:
        Path(path).unlink()


def test_manifest_hitl_with_dragonfly_backend_accepts() -> None:
    yaml_content = """
agent_type: research
modules:
  filesystem:
    mode: read
    config:
      base_path: /tmp/x
state_backend:
  type: dragonfly
  url: redis://localhost:6379
hitl:
  approval_required:
    - filesystem.write_file
  timeout_seconds: 60
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        path = f.name
    try:
        m = load_manifest(path)
        assert m.hitl is not None
        assert m.hitl.approval_required == ["filesystem.write_file"]
        assert m.hitl.timeout_seconds == 60
    finally:
        Path(path).unlink()


def test_manifest_hitl_empty_lists_with_in_process_ok() -> None:
    yaml_content = """
agent_type: research
modules:
  filesystem:
    mode: read
    config:
      base_path: /tmp/x
hitl:
  approval_required: []
  shadow: []
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        path = f.name
    try:
        m = load_manifest(path)
        assert m.hitl is not None
    finally:
        Path(path).unlink()


# ── Notify config validation ─────────────────────────────────────────────────


def test_notify_ntfy_requires_topic() -> None:
    yaml_content = """
agent_type: research
modules:
  filesystem:
    mode: read
    config:
      base_path: /tmp/x
state_backend:
  type: dragonfly
  url: redis://localhost:6379
hitl:
  approval_required: ["*"]
  notify:
    type: ntfy
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        path = f.name
    try:
        with pytest.raises(ManifestError):
            load_manifest(path)
    finally:
        Path(path).unlink()


def test_notify_webhook_requires_url() -> None:
    yaml_content = """
agent_type: research
modules:
  filesystem:
    mode: read
    config:
      base_path: /tmp/x
state_backend:
  type: dragonfly
  url: redis://localhost:6379
hitl:
  approval_required: ["*"]
  notify:
    type: webhook
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        path = f.name
    try:
        with pytest.raises(ManifestError):
            load_manifest(path)
    finally:
        Path(path).unlink()


def test_notify_extra_field_rejected() -> None:
    yaml_content = """
agent_type: research
modules:
  filesystem:
    mode: read
    config:
      base_path: /tmp/x
state_backend:
  type: dragonfly
  url: redis://localhost:6379
hitl:
  approval_required: ["*"]
  notify:
    type: log
    unknown_field: yes
"""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
        f.write(yaml_content)
        path = f.name
    try:
        with pytest.raises(ManifestError):
            load_manifest(path)
    finally:
        Path(path).unlink()


# ── L3 regression: NotifyConfig field-format validators ─────────────────────


@pytest.mark.parametrize(
    "topic",
    [
        "valid-topic_123",
        "alphanumeric",
        "X" * 64,
    ],
)
def test_notify_topic_valid(topic: str) -> None:
    from scoped_mcp.manifest import NotifyConfig

    cfg = NotifyConfig(type="ntfy", topic=topic)
    assert cfg.topic == topic


@pytest.mark.parametrize(
    "topic",
    [
        "with spaces",
        "X" * 65,
        "../traversal",
        "with/slash",
        "with.dot",
    ],
)
def test_notify_topic_invalid(topic: str) -> None:
    from pydantic import ValidationError

    from scoped_mcp.manifest import NotifyConfig

    with pytest.raises(ValidationError, match="topic"):
        NotifyConfig(type="ntfy", topic=topic)


@pytest.mark.parametrize(
    "room",
    [
        "!abc:matrix.org",
        "#alias:example.com",
        "!room.id_with-chars:home.server",
    ],
)
def test_notify_room_valid(room: str) -> None:
    from scoped_mcp.manifest import NotifyConfig

    cfg = NotifyConfig(type="matrix", room=room)
    assert cfg.room == room


@pytest.mark.parametrize(
    "room",
    [
        "no-prefix:matrix.org",
        "!no-server",
        "@user:matrix.org",
        "/etc/passwd",
    ],
)
def test_notify_room_invalid(room: str) -> None:
    from pydantic import ValidationError

    from scoped_mcp.manifest import NotifyConfig

    with pytest.raises(ValidationError, match="room"):
        NotifyConfig(type="matrix", room=room)


@pytest.mark.parametrize(
    "url",
    ["http://example.com/hook", "https://example.com/hook"],
)
def test_notify_url_valid(url: str) -> None:
    from scoped_mcp.manifest import NotifyConfig

    cfg = NotifyConfig(type="webhook", url=url)
    assert cfg.url == url


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "javascript:alert(1)",
        "/relative/path",
        "example.com/no-scheme",
    ],
)
def test_notify_url_invalid(url: str) -> None:
    from pydantic import ValidationError

    from scoped_mcp.manifest import NotifyConfig

    with pytest.raises(ValidationError, match="url"):
        NotifyConfig(type="webhook", url=url)


# ── HITL CLI dispatch (no Dragonfly required for these paths) ────────────────


def _write_manifest(yaml_content: str) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
    f.write(yaml_content)
    f.close()
    return f.name


def test_hitl_cli_rejects_in_process_backend() -> None:
    import argparse

    path = _write_manifest(
        """
agent_type: research
modules:
  filesystem:
    mode: read
    config:
      base_path: /tmp/x
"""
    )
    try:
        ns = argparse.Namespace(manifest=path, hitl_command="list")
        rc = run_hitl_command(ns)
        assert rc == 1
    finally:
        Path(path).unlink()


def test_hitl_cli_rejects_invalid_manifest() -> None:
    import argparse

    path = _write_manifest("not: a: valid: manifest:\n")
    try:
        ns = argparse.Namespace(manifest=path, hitl_command="list")
        rc = run_hitl_command(ns)
        assert rc == 1
    finally:
        Path(path).unlink()


def test_server_parse_args_hitl_list() -> None:
    from scoped_mcp.server import parse_args

    ns = parse_args(["hitl", "--manifest", "/path/to/m.yml", "list"])
    assert ns.command == "hitl"
    assert ns.hitl_command == "list"
    assert ns.manifest == "/path/to/m.yml"


def test_server_parse_args_hitl_approve() -> None:
    from scoped_mcp.server import parse_args

    ns = parse_args(["hitl", "--manifest", "/m.yml", "approve", "research-01.abcdef123456"])
    assert ns.hitl_command == "approve"
    assert ns.approval_id == "research-01.abcdef123456"


def test_server_parse_args_hitl_reject_with_reason() -> None:
    from scoped_mcp.server import parse_args

    ns = parse_args(["hitl", "--manifest", "/m.yml", "reject", "a.b", "policy-violation"])
    assert ns.hitl_command == "reject"
    assert ns.approval_id == "a.b"
    assert ns.reason == "policy-violation"


# Suppress unused-import warning
_ = json
