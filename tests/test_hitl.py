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
    _canonical_args_hash,
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

    # Operator writes pre-approval token (simulates CLI approve).
    # Token is bound to (tool_name, args_hash) so the retry must use the same args.
    kwargs_to_retry = {"path": "/tmp/x"}
    pre_key = _preapproval_key("filesystem.delete_file", _canonical_args_hash(kwargs_to_retry))
    await state.set_with_ttl(pre_key, "approved", PREAPPROVAL_TTL_SECONDS)

    # Retry — should proceed
    result = await mw(
        agent_ctx=None,
        tool_name="filesystem.delete_file",
        kwargs=kwargs_to_retry,
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

    # Write pre-approval token bound to (tool, args)
    pre_key = _preapproval_key("some_tool", _canonical_args_hash({}))
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


def test_preapproval_key_not_matched_by_list_filter() -> None:
    """F1 regression: preapproval keys must not appear in hitl list output.
    The `:preapproved:` substring filter correctly excludes them even when
    the tool name contains a dot (which would otherwise match the *.*  pattern)."""
    from scoped_mcp.hitl_cli import _preapproval_key_for

    dotted_tool = "mcp_proxy.delete_file"
    args_hash = "deadbeef12345678"
    full_key = (
        f"scoped-mcp:research-01:hitl:"
        f"{_preapproval_key_for('research-01', dotted_tool, args_hash)}"
    )
    # The *:preapproved:* filter must catch this
    assert ":preapproved:" in full_key


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
    pre_key = _preapproval_key("x", _canonical_args_hash({}))
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
    args_hash = _canonical_args_hash({"service": "pm2"})
    key = _preapproval_key("pm2-mcp__restart_service", args_hash)
    assert key == f"hitl:preapproved:pm2-mcp__restart_service:{args_hash}"


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


# ── hitl_notify.py coverage ───────────────────────────────────────────────────


class TestFormatMessage:
    def test_contains_approval_id(self) -> None:
        from scoped_mcp.hitl_notify import _format_message

        msg = _format_message("agent-1.abc123", "my_tool", "agent-1", "sysadmin", {}, 60)
        assert "agent-1.abc123" in msg

    def test_contains_tool_name(self) -> None:
        from scoped_mcp.hitl_notify import _format_message

        msg = _format_message("a.b", "my_tool", "a", "t", {"x": "y"}, 30)
        assert "my_tool" in msg

    def test_args_rendered(self) -> None:
        from scoped_mcp.hitl_notify import _format_message

        msg = _format_message("a.b", "t", "a", "tp", {"key": "val"}, 30)
        assert "key: val" in msg

    def test_no_args_shows_placeholder(self) -> None:
        from scoped_mcp.hitl_notify import _format_message

        msg = _format_message("a.b", "t", "a", "tp", {}, 30)
        assert "(none)" in msg

    def test_approve_reject_commands_present(self) -> None:
        from scoped_mcp.hitl_notify import _format_message

        msg = _format_message("a.b", "t", "a", "tp", {}, 30)
        assert "approve a.b" in msg
        assert "reject a.b" in msg


@pytest.mark.asyncio
async def test_log_notifier_calls_structlog(capfd) -> None:
    from scoped_mcp.hitl_notify import LogNotifier

    notifier = LogNotifier()
    # Should not raise; output goes to structlog
    await notifier.notify("a.b", "tool", "a", "tp", {"x": "1"}, 60)


@pytest.mark.asyncio
async def test_ntfy_notifier_sends_request() -> None:
    respx = pytest.importorskip("respx")
    from httpx import Response

    from scoped_mcp.hitl_notify import NtfyNotifier

    notifier = NtfyNotifier(url="http://ntfy.test", topic="alerts")
    with respx.mock:
        route = respx.post("http://ntfy.test/alerts").mock(return_value=Response(200))
        await notifier.notify("a.b", "tool", "a", "tp", {}, 30)
    assert route.called


@pytest.mark.asyncio
async def test_ntfy_notifier_swallows_transport_error() -> None:
    respx = pytest.importorskip("respx")
    from httpx import ConnectError

    from scoped_mcp.hitl_notify import NtfyNotifier

    notifier = NtfyNotifier(url="http://ntfy.test", topic="alerts")
    with respx.mock:
        respx.post("http://ntfy.test/alerts").mock(side_effect=ConnectError("down"))
        # Must not raise
        await notifier.notify("a.b", "tool", "a", "tp", {}, 30)


def test_ntfy_notifier_requires_topic() -> None:
    from scoped_mcp.hitl_notify import NtfyNotifier

    with pytest.raises(ValueError, match="topic"):
        NtfyNotifier(url="http://ntfy.test", topic="")


@pytest.mark.asyncio
async def test_webhook_notifier_posts_json() -> None:
    respx = pytest.importorskip("respx")
    from httpx import Response

    from scoped_mcp.hitl_notify import WebhookNotifier

    notifier = WebhookNotifier(url="http://hooks.test/hook")
    with respx.mock:
        route = respx.post("http://hooks.test/hook").mock(return_value=Response(200))
        await notifier.notify("a.b", "tool", "a", "tp", {"k": "v"}, 30)
    assert route.called
    import json as _json

    payload = _json.loads(route.calls[0].request.content)
    assert payload["approval_id"] == "a.b"
    assert payload["tool"] == "tool"


@pytest.mark.asyncio
async def test_webhook_notifier_swallows_error() -> None:
    respx = pytest.importorskip("respx")
    from httpx import ConnectError

    from scoped_mcp.hitl_notify import WebhookNotifier

    notifier = WebhookNotifier(url="http://hooks.test/hook")
    with respx.mock:
        respx.post("http://hooks.test/hook").mock(side_effect=ConnectError("down"))
        await notifier.notify("a.b", "tool", "a", "tp", {}, 30)


def test_webhook_notifier_requires_url() -> None:
    from scoped_mcp.hitl_notify import WebhookNotifier

    with pytest.raises(ValueError, match="url"):
        WebhookNotifier(url="")


@pytest.mark.asyncio
async def test_matrix_notifier_skips_when_no_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    from scoped_mcp.hitl_notify import MatrixNotifier

    monkeypatch.delenv("MATRIX_HOMESERVER", raising=False)
    monkeypatch.delenv("MATRIX_ACCESS_TOKEN", raising=False)
    notifier = MatrixNotifier(room="!room:matrix.test")
    # Should not raise — logs warning and returns
    await notifier.notify("a.b", "tool", "a", "tp", {}, 30)


@pytest.mark.asyncio
async def test_matrix_notifier_sends_request(monkeypatch: pytest.MonkeyPatch) -> None:
    respx = pytest.importorskip("respx")
    from httpx import Response

    from scoped_mcp.hitl_notify import MatrixNotifier

    monkeypatch.setenv("MATRIX_HOMESERVER", "http://matrix.test")
    monkeypatch.setenv("MATRIX_ACCESS_TOKEN", "tok-example")
    notifier = MatrixNotifier(room="!room:matrix.test")
    with respx.mock:
        route = respx.post(
            url__regex=r"http://matrix\.test/_matrix/client/v3/rooms/.+/send/.+"
        ).mock(return_value=Response(200, json={"event_id": "$x"}))
        await notifier.notify("a.b", "tool", "a", "tp", {}, 30)
    assert route.called


def test_matrix_notifier_requires_room() -> None:
    from scoped_mcp.hitl_notify import MatrixNotifier

    with pytest.raises(ValueError, match="room"):
        MatrixNotifier(room="")


def test_build_notifier_log() -> None:
    from unittest.mock import MagicMock

    from scoped_mcp.hitl_notify import LogNotifier, build_notifier

    cfg = MagicMock()
    cfg.type = "log"
    assert isinstance(build_notifier(cfg), LogNotifier)


def test_build_notifier_ntfy() -> None:
    from unittest.mock import MagicMock

    from scoped_mcp.hitl_notify import NtfyNotifier, build_notifier

    cfg = MagicMock()
    cfg.type = "ntfy"
    cfg.url = "http://ntfy.test"
    cfg.topic = "alerts"
    assert isinstance(build_notifier(cfg), NtfyNotifier)


def test_build_notifier_webhook() -> None:
    from unittest.mock import MagicMock

    from scoped_mcp.hitl_notify import WebhookNotifier, build_notifier

    cfg = MagicMock()
    cfg.type = "webhook"
    cfg.url = "http://hooks.test/hook"
    assert isinstance(build_notifier(cfg), WebhookNotifier)


def test_build_notifier_matrix() -> None:
    from unittest.mock import MagicMock

    from scoped_mcp.hitl_notify import MatrixNotifier, build_notifier

    cfg = MagicMock()
    cfg.type = "matrix"
    cfg.room = "!r:matrix.test"
    assert isinstance(build_notifier(cfg), MatrixNotifier)


def test_build_notifier_unknown_type_raises() -> None:
    from unittest.mock import MagicMock

    from scoped_mcp.hitl_notify import build_notifier

    cfg = MagicMock()
    cfg.type = "unknown_channel"
    with pytest.raises(Exception):
        build_notifier(cfg)
