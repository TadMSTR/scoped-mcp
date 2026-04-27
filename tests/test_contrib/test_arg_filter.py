"""Tests for ArgumentFilterMiddleware (v0.9 hardening)."""

from __future__ import annotations

import base64
import urllib.parse

import pytest

from scoped_mcp.contrib.arg_filter import ArgumentFilterMiddleware
from scoped_mcp.exceptions import ConfigError


async def _passthrough() -> str:
    return "OK"


# ── Plain-text matches ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_block_pattern_in_plain_text() -> None:
    mw = ArgumentFilterMiddleware(
        rules=[{"name": "creds", "pattern": "password", "fields": ["*"], "action": "block"}],
        agent_id="a1",
    )
    with pytest.raises(ConfigError, match="creds"):
        await mw(
            agent_ctx=None,
            tool_name="filesystem_write_file",
            kwargs={"text": "my password is hunter2"},
            call_next=_passthrough,
        )


@pytest.mark.asyncio
async def test_warn_lets_call_through(caplog: pytest.LogCaptureFixture) -> None:
    mw = ArgumentFilterMiddleware(
        rules=[{"name": "warn-creds", "pattern": "password", "fields": ["*"], "action": "warn"}],
        agent_id="a1",
    )
    result = await mw(
        agent_ctx=None,
        tool_name="filesystem_write_file",
        kwargs={"text": "my password"},
        call_next=_passthrough,
    )
    assert result == "OK"


@pytest.mark.asyncio
async def test_no_match_passes_through() -> None:
    mw = ArgumentFilterMiddleware(
        rules=[{"name": "creds", "pattern": "password", "fields": ["*"], "action": "block"}],
        agent_id="a1",
    )
    result = await mw(
        agent_ctx=None,
        tool_name="filesystem_read_file",
        kwargs={"path": "/tmp/safe.txt"},
        call_next=_passthrough,
    )
    assert result == "OK"


# ── Field scoping ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_field_scope_limits_inspection() -> None:
    """Pattern in a non-listed field is ignored."""
    mw = ArgumentFilterMiddleware(
        rules=[{"name": "trav", "pattern": r"\.\./", "fields": ["path"], "action": "block"}],
        agent_id="a1",
    )
    # Pattern is in 'description', not 'path' — should pass
    result = await mw(
        agent_ctx=None,
        tool_name="filesystem_write_file",
        kwargs={"path": "/tmp/safe.txt", "description": "use ../../../"},
        call_next=_passthrough,
    )
    assert result == "OK"


@pytest.mark.asyncio
async def test_field_scope_blocks_when_in_listed_field() -> None:
    mw = ArgumentFilterMiddleware(
        rules=[{"name": "trav", "pattern": r"\.\./", "fields": ["path"], "action": "block"}],
        agent_id="a1",
    )
    with pytest.raises(ConfigError, match="trav"):
        await mw(
            agent_ctx=None,
            tool_name="filesystem_read_file",
            kwargs={"path": "../../etc/passwd"},
            call_next=_passthrough,
        )


# ── Encoding-aware matching ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_base64_decode_match() -> None:
    payload = base64.b64encode(b"my password leaked").decode()
    mw = ArgumentFilterMiddleware(
        rules=[
            {
                "name": "b64-creds",
                "pattern": "password",
                "fields": ["*"],
                "action": "block",
                "decode": ["base64"],
            }
        ],
        agent_id="a1",
    )
    with pytest.raises(ConfigError, match="b64-creds"):
        await mw(
            agent_ctx=None,
            tool_name="some_tool",
            kwargs={"data": payload},
            call_next=_passthrough,
        )


@pytest.mark.asyncio
async def test_url_decode_match() -> None:
    payload = urllib.parse.quote("password=hunter2")
    mw = ArgumentFilterMiddleware(
        rules=[
            {
                "name": "url-creds",
                "pattern": "password",
                "fields": ["*"],
                "action": "block",
                "decode": ["url"],
            }
        ],
        agent_id="a1",
    )
    with pytest.raises(ConfigError, match="url-creds"):
        await mw(
            agent_ctx=None,
            tool_name="some_tool",
            kwargs={"q": payload},
            call_next=_passthrough,
        )


@pytest.mark.asyncio
async def test_decode_failure_falls_back_to_raw_match() -> None:
    """If base64 decode fails, the raw string is still matched."""
    mw = ArgumentFilterMiddleware(
        rules=[
            {
                "name": "creds",
                "pattern": "password",
                "fields": ["*"],
                "action": "block",
                "decode": ["base64"],
            }
        ],
        agent_id="a1",
    )
    # 'my password' is not valid base64 — decode fails, raw match still triggers
    with pytest.raises(ConfigError, match="creds"):
        await mw(
            agent_ctx=None,
            tool_name="some_tool",
            kwargs={"data": "my password"},
            call_next=_passthrough,
        )


# ── Decode size cap ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oversized_base64_skips_decode_path() -> None:
    """A base64 input that would decode to >64 KiB must not be decoded —
    the raw text is still scanned, but decode is bypassed for size."""
    big = base64.b64encode(b"X" * 100_000).decode()  # ~133 KB raw, ~100 KB decoded
    mw = ArgumentFilterMiddleware(
        rules=[
            {
                "name": "creds",
                "pattern": "X" * 50,  # only matches in decoded form
                "fields": ["*"],
                "action": "block",
                "decode": ["base64"],
            }
        ],
        agent_id="a1",
    )
    # Pattern only matches in decoded form, but decode is skipped due to size.
    # Raw base64 string contains no consecutive 'X' runs of length 50,
    # so the call should NOT be blocked.
    result = await mw(
        agent_ctx=None,
        tool_name="some_tool",
        kwargs={"data": big},
        call_next=_passthrough,
    )
    assert result == "OK"


# ── Block-before-warn ordering ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_block_evaluated_before_warn() -> None:
    """When both a block and a warn rule match, the block wins (short-circuit).
    This guarantees a violating call cannot 'warn-only' through the middleware
    when an explicit block rule also covers it."""
    mw = ArgumentFilterMiddleware(
        rules=[
            {"name": "warn-only", "pattern": "secret", "fields": ["*"], "action": "warn"},
            {"name": "blocker", "pattern": "secret", "fields": ["*"], "action": "block"},
        ],
        agent_id="a1",
    )
    with pytest.raises(ConfigError, match="blocker"):
        await mw(
            agent_ctx=None,
            tool_name="some_tool",
            kwargs={"text": "the secret value"},
            call_next=_passthrough,
        )


# ── Value-not-logged invariant ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_value_never_appears_in_log(caplog: pytest.LogCaptureFixture) -> None:
    """Block log entry must contain field name and rule name, but never the
    matched value — preserves audit log redaction guarantees."""
    mw = ArgumentFilterMiddleware(
        rules=[{"name": "creds", "pattern": "password", "fields": ["*"], "action": "block"}],
        agent_id="a1",
    )
    secret = "hunter2-do-not-log-this-anywhere"
    with pytest.raises(ConfigError):
        await mw(
            agent_ctx=None,
            tool_name="some_tool",
            kwargs={"text": f"my password is {secret}"},
            call_next=_passthrough,
        )
    log_text = " ".join(r.getMessage() for r in caplog.records)
    assert secret not in log_text


# ── Construction-time validation ─────────────────────────────────────────────


def test_invalid_pattern_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="not a valid regex"):
        ArgumentFilterMiddleware(
            rules=[{"name": "bad", "pattern": "[unclosed", "fields": ["*"], "action": "block"}],
            agent_id="a1",
        )


def test_invalid_action_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="action"):
        ArgumentFilterMiddleware(
            rules=[{"name": "x", "pattern": ".*", "fields": ["*"], "action": "kill-the-process"}],
            agent_id="a1",
        )


def test_invalid_decode_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="decode"):
        ArgumentFilterMiddleware(
            rules=[
                {
                    "name": "x",
                    "pattern": ".*",
                    "fields": ["*"],
                    "action": "block",
                    "decode": ["rot13"],
                }
            ],
            agent_id="a1",
        )


def test_empty_fields_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="fields"):
        ArgumentFilterMiddleware(
            rules=[{"name": "x", "pattern": ".*", "fields": [], "action": "block"}],
            agent_id="a1",
        )


# ── Case sensitivity ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_case_insensitive_match() -> None:
    mw = ArgumentFilterMiddleware(
        rules=[
            {
                "name": "creds",
                "pattern": "password",
                "fields": ["*"],
                "action": "block",
                "case_insensitive": True,
            }
        ],
        agent_id="a1",
    )
    with pytest.raises(ConfigError, match="creds"):
        await mw(
            agent_ctx=None,
            tool_name="some_tool",
            kwargs={"text": "my PASSWORD is hunter2"},
            call_next=_passthrough,
        )


@pytest.mark.asyncio
async def test_case_sensitive_default() -> None:
    mw = ArgumentFilterMiddleware(
        rules=[{"name": "creds", "pattern": "password", "fields": ["*"], "action": "block"}],
        agent_id="a1",
    )
    # Default is case-sensitive — uppercase variant should pass through
    result = await mw(
        agent_ctx=None,
        tool_name="some_tool",
        kwargs={"text": "my PASSWORD is fine"},
        call_next=_passthrough,
    )
    assert result == "OK"


# ── Non-string args ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_non_string_args_are_skipped() -> None:
    """Filter only inspects top-level string args; ints/dicts are ignored."""
    mw = ArgumentFilterMiddleware(
        rules=[{"name": "creds", "pattern": "password", "fields": ["*"], "action": "block"}],
        agent_id="a1",
    )
    result = await mw(
        agent_ctx=None,
        tool_name="some_tool",
        kwargs={"count": 42, "options": {"nested": "password"}},  # nested not walked
        call_next=_passthrough,
    )
    assert result == "OK"
