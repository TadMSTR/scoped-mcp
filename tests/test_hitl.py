"""Tests for HITL middleware (v1.0).

Uses InProcessBackend for pub/sub since it's a faithful in-process emulation
of the Dragonfly contract. Production HITL still requires DragonflyBackend
(enforced at manifest load).
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

from scoped_mcp.exceptions import HitlRejectedError, ManifestError
from scoped_mcp.hitl import HitlMiddleware, _build_arguments_summary, _generate_approval_id
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


async def _publish_after(state, channel: str, message: str, delay: float = 0.05) -> None:
    """Helper: publish a decision to the channel after a short delay so the
    awaiting middleware can register its subscription first."""
    await asyncio.sleep(delay)
    await state.publish(channel, message)


# ── Approval flow ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_approve_runs_underlying_call() -> None:
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    mw = HitlMiddleware(
        state=state,
        agent_id="research-01",
        agent_type="research",
        approval_required=["filesystem.delete_file"],
        shadow=[],
        timeout_seconds=2,
        notifier=notifier,
    )

    # Capture the approval_id from the notifier so we can publish to its channel
    async def call_with_publisher() -> Any:
        # Give the middleware a moment to write the key + notify, then publish approve
        async def publisher() -> None:
            for _ in range(50):
                await asyncio.sleep(0.01)
                if notifier.calls:
                    approval_id = notifier.calls[0]["approval_id"]
                    await state.publish(f"hitl:{approval_id}", "approve")
                    return

        publisher_task = asyncio.create_task(publisher())
        try:
            return await mw(
                agent_ctx=None,
                tool_name="filesystem.delete_file",
                kwargs={"path": "/tmp/x"},
                call_next=_passthrough,
            )
        finally:
            await publisher_task

    result = await call_with_publisher()
    assert result == "EXECUTED"
    assert len(notifier.calls) == 1
    assert notifier.calls[0]["tool_name"] == "filesystem.delete_file"
    assert notifier.calls[0]["agent_id"] == "research-01"


@pytest.mark.asyncio
async def test_reject_raises_hitl_rejected() -> None:
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    mw = HitlMiddleware(
        state=state,
        agent_id="research-01",
        agent_type="research",
        approval_required=["*"],
        shadow=[],
        timeout_seconds=2,
        notifier=notifier,
    )

    upstream = AsyncMock(return_value="UPSTREAM_RESULT")

    async def driver() -> Any:
        async def publisher() -> None:
            for _ in range(50):
                await asyncio.sleep(0.01)
                if notifier.calls:
                    approval_id = notifier.calls[0]["approval_id"]
                    await state.publish(f"hitl:{approval_id}", "reject:not-today")
                    return

        publisher_task = asyncio.create_task(publisher())
        try:
            return await mw(
                agent_ctx=None,
                tool_name="any_tool",
                kwargs={},
                call_next=upstream,
            )
        finally:
            await publisher_task

    with pytest.raises(HitlRejectedError, match="HITL approval policy"):
        await driver()
    upstream.assert_not_called()


@pytest.mark.asyncio
async def test_timeout_auto_rejects() -> None:
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    mw = HitlMiddleware(
        state=state,
        agent_id="research-01",
        agent_type="research",
        approval_required=["*"],
        shadow=[],
        timeout_seconds=1,  # short timeout for the test
        notifier=notifier,
    )
    upstream = AsyncMock()

    with pytest.raises(HitlRejectedError):
        await mw(
            agent_ctx=None,
            tool_name="any_tool",
            kwargs={},
            call_next=upstream,
        )
    upstream.assert_not_called()


@pytest.mark.asyncio
async def test_non_matching_tool_passes_through() -> None:
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="research",
        approval_required=["filesystem.delete_file"],
        shadow=[],
        timeout_seconds=2,
        notifier=notifier,
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
    notifier = _RecordingNotifier()
    upstream = AsyncMock(side_effect=AssertionError("upstream MUST NOT be called in shadow"))
    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="research",
        approval_required=[],
        shadow=["mcp_proxy.*"],
        timeout_seconds=300,
        notifier=notifier,
    )

    result = await mw(
        agent_ctx=None,
        tool_name="mcp_proxy.dangerous_op",
        kwargs={"target": "prod"},
        call_next=upstream,
    )
    assert result["shadow"] is True
    upstream.assert_not_called()
    # Shadow does NOT trigger a notification — it's logged-only.
    assert notifier.calls == []


@pytest.mark.asyncio
async def test_shadow_takes_precedence_over_approval() -> None:
    """If a tool matches both shadow and approval_required, shadow wins so no
    operator approval can ever cause it to be forwarded upstream."""
    state = InProcessBackend()
    notifier = _RecordingNotifier()
    upstream = AsyncMock(side_effect=AssertionError("MUST NOT be called"))
    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="research",
        approval_required=["*"],
        shadow=["*"],
        timeout_seconds=300,
        notifier=notifier,
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
        timeout_seconds=1,
        notifier=notifier,
    )
    # Should suspend → timeout → reject
    with pytest.raises(HitlRejectedError):
        await mw(
            agent_ctx=None,
            tool_name="mcp_proxy.delete_resource",
            kwargs={},
            call_next=_passthrough,
        )
    # And the notifier must have been called
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
    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="r",
        approval_required=["*"],
        shadow=[],
        timeout_seconds=1,
        notifier=notifier,
    )

    async def driver() -> Any:
        return await mw(
            agent_ctx=None,
            tool_name="some_tool",
            kwargs={"API_TOKEN": "this-must-not-leak-anywhere", "path": "/safe"},
            call_next=_passthrough,
        )

    with pytest.raises(HitlRejectedError):
        await driver()

    # Walk every stored value and confirm the secret never landed
    # in the payload.
    for key, (value, _ttl) in state._store.items():
        assert "this-must-not-leak-anywhere" not in value, (
            f"sensitive value leaked into state key {key!r}"
        )


# ── Notifier failures don't break approval loop ──────────────────────────────


@pytest.mark.asyncio
async def test_notifier_exception_swallowed_and_middleware_continues() -> None:
    """Audit v1.0 L1 regression: a buggy notifier must NOT propagate out of
    the middleware. The error is logged and the approval loop continues; the
    call eventually times out → HitlRejectedError, never RuntimeError."""
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
        timeout_seconds=1,
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
async def test_notifier_exception_does_not_block_approve_decision() -> None:
    """L1 follow-up: even when the notifier raises, an operator decision
    arriving via another channel still drives the call to its conclusion."""
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
        timeout_seconds=2,
        notifier=BrokenNotifier(),
    )

    async def publisher() -> None:
        for _ in range(50):
            await asyncio.sleep(0.01)
            if "id" in captured_id:
                await state.publish(f"hitl:{captured_id['id']}", "approve")
                return

    publisher_task = asyncio.create_task(publisher())
    try:
        result = await mw(
            agent_ctx=None,
            tool_name="x",
            kwargs={},
            call_next=_passthrough,
        )
    finally:
        await publisher_task
    assert result == "EXECUTED"


# ── M1 regression: fast operator approval during notify() is not lost ────────


@pytest.mark.asyncio
async def test_fast_operator_approval_during_notify_is_received() -> None:
    """Audit v1.0 M1 regression: a notifier that publishes the approval
    INSIDE its notify() call (a fast operator who decides instantaneously)
    must not lose the message. The middleware must have its subscription
    registered synchronously BEFORE notify() runs."""
    state = InProcessBackend()

    class FastOperatorNotifier:
        def __init__(self, backend: InProcessBackend) -> None:
            self._backend = backend

        async def notify(self, approval_id: str, **kwargs: Any) -> None:
            await self._backend.publish(f"hitl:{approval_id}", "approve")

    mw = HitlMiddleware(
        state=state,
        agent_id="a1",
        agent_type="r",
        approval_required=["*"],
        shadow=[],
        timeout_seconds=2,
        notifier=FastOperatorNotifier(state),
    )
    result = await mw(
        agent_ctx=None,
        tool_name="x",
        kwargs={},
        call_next=_passthrough,
    )
    assert result == "EXECUTED"


# ── Approval ID format and CLI parsing ───────────────────────────────────────


def test_approval_id_format() -> None:
    aid = _generate_approval_id("research-01")
    assert aid.startswith("research-01.")
    suffix = aid.split(".", 1)[1]
    assert len(suffix) == 12
    # all hex chars
    int(suffix, 16)


def test_cli_parse_approval_id_well_formed() -> None:
    parsed = _parse_approval_id("research-01.abc123def456")
    assert parsed == ("research-01", "abc123def456")


def test_cli_parse_approval_id_with_dots_in_agent_id() -> None:
    """If for some reason agent_id had dots (it can't, validated upstream),
    rsplit ensures the suffix is parsed correctly."""
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


# ── Manifest-level validation: HITL requires dragonfly ───────────────────────


def test_manifest_hitl_with_in_process_backend_rejected() -> None:
    """HITL needs cross-process state — manifest load must fail when paired
    with the in-process backend."""
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
        with pytest.raises(ManifestError, match="dragonfly"):
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
    """An empty hitl block with no approval_required and no shadow rules is a
    no-op — should not require dragonfly. Avoids surprising operators who add
    an empty section as a placeholder."""
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
        with pytest.raises(ManifestError, match="topic"):
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
        with pytest.raises(ManifestError, match="url"):
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
        "X" * 64,  # max length
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
        "X" * 65,  # too long
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
        "@user:matrix.org",  # user id, not a room
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


# Suppress the unused json warning by using it indirectly
_ = json


# ── HITL CLI dispatch (no Dragonfly required for these paths) ────────────────


def _write_manifest(yaml_content: str) -> str:
    f = tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False)
    f.write(yaml_content)
    f.close()
    return f.name


def test_hitl_cli_rejects_in_process_backend() -> None:
    """The CLI must refuse to talk to an in-process backend — there is no
    server-side state to reach via this path."""
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
