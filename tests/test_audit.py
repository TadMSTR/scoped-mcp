"""Tests for audit.py — structured logging, sanitization, and @audited decorator."""

from __future__ import annotations

import asyncio
import pathlib

import pytest
import structlog.testing

from scoped_mcp.audit import (
    SESSION_ID,
    _sanitize_processor,
    _sanitize_value,
    audited,
    configure_audit,
)
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


def test_sanitize_modern_vault_sst_with_underscores_and_dashes() -> None:
    # Real-format SST: base64url payload contains _ and -
    token = "hvs.CAESIJ_9aZ-Bk-hQVXYZ_dGhlcmU0NTY3ODkwAAAAAAA"  # gitleaks:allow
    result = _sanitize_value(f"auth failed: token={token} expired")
    assert token not in result
    assert "<redacted-vault-token>" in result


def test_sanitize_modern_vault_batch_token() -> None:
    token = "hvb.AbcDefGhi_jKlMnOpQrStUvWxYz0123456789"  # gitleaks:allow
    result = _sanitize_value(f"using {token} for batch op")
    assert token not in result
    assert "<redacted-vault-token>" in result


def test_sanitize_legacy_vault_service_token() -> None:
    token = "s.abcdef0123456789ABCDEF01"  # gitleaks:allow
    result = _sanitize_value(f"got token {token} back")
    assert token not in result
    assert "<redacted-vault-token>" in result


def test_sanitize_legacy_vault_batch_token() -> None:
    token = "b.abcdef0123456789ABCDEF01"  # gitleaks:allow
    result = _sanitize_value(f"batch {token} ok")
    assert token not in result
    assert "<redacted-vault-token>" in result


def test_sanitize_legacy_vault_recovery_token() -> None:
    token = "r.abcdef0123456789ABCDEF01"  # gitleaks:allow
    result = _sanitize_value(f"recovery {token} ok")
    assert token not in result
    assert "<redacted-vault-token>" in result


def test_sanitize_secret_id_key_redacted() -> None:
    # L2 fix: secret_id and role_id must be in _SENSITIVE_KEYS
    assert _sanitize_value("d3b0c442-98fc-1c14-9af8-decafe000001", "secret_id") == "<redacted>"
    assert _sanitize_value("e9c1d442-98fc-1c14-9af8-decafe000002", "role_id") == "<redacted>"


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


# ── Phase 1a: session_id + log_args ──────────────────────────────────────────


def test_session_id_is_a_uuid() -> None:
    import re

    assert re.match(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        SESSION_ID,
    )


@pytest.mark.asyncio
async def test_audited_includes_session_id_in_log(agent_ctx: AgentContext) -> None:
    module = _MockModule(agent_ctx)
    with structlog.testing.capture_logs() as logs:
        await _make_tool(module)
    assert any(r.get("session_id") == SESSION_ID for r in logs)


@pytest.mark.asyncio
async def test_audited_includes_args_by_default(agent_ctx: AgentContext) -> None:
    configure_audit(log_args=True)
    module = _MockModule(agent_ctx)
    with structlog.testing.capture_logs() as logs:
        await _make_tool(module)
    assert any("args" in r for r in logs)


@pytest.mark.asyncio
async def test_audited_omits_args_when_log_args_false(agent_ctx: AgentContext) -> None:
    configure_audit(log_args=False)
    module = _MockModule(agent_ctx)
    try:
        with structlog.testing.capture_logs() as logs:
            await _make_tool(module)
        assert all("args" not in r for r in logs)
    finally:
        configure_audit(log_args=True)  # restore default


# ── Phase 1d: response filter hook in @audited ────────────────────────────────


@pytest.mark.asyncio
async def test_audited_applies_response_filter(agent_ctx: AgentContext) -> None:
    from scoped_mcp.contrib.response_filter import ResponseFilter

    rf = ResponseFilter(
        rules=[{"name": "strip-secret", "pattern": "ok:", "action": "redact"}],
        agent_id=agent_ctx.agent_id,
    )
    configure_audit(response_filter=rf)
    module = _MockModule(agent_ctx)
    try:
        result = await _make_tool(module)
        assert "ok:" not in result
        assert "[REDACTED]" in result
    finally:
        configure_audit(response_filter=None)


# ── Phase 1a: agent-bus fire-and-forget emission ──────────────────────────────


@pytest.mark.asyncio
async def test_audited_emits_agent_bus_event(
    agent_ctx: AgentContext, tmp_path: pathlib.Path
) -> None:
    import json

    configure_audit(agent_bus_emit=True, agent_bus_comms_dir=str(tmp_path))
    module = _MockModule(agent_ctx)
    try:
        await _make_tool(module)
        # Yield twice so the create_task coroutine starts, then give the
        # run_in_executor thread enough wall time to complete the write.
        await asyncio.sleep(0)
        await asyncio.sleep(0.05)

        log_files = list((tmp_path / "logs").glob("*-session.jsonl"))
        assert log_files, "no session JSONL written"
        events = [json.loads(line) for line in log_files[0].read_text().splitlines()]
        assert any(e["event"] == "tool.called" for e in events)
        tool_events = [e for e in events if e["event"] == "tool.called"]
        assert tool_events[0]["metadata"]["session_id"] == SESSION_ID
        assert tool_events[0]["metadata"]["outcome"] == "ok"
    finally:
        configure_audit(agent_bus_emit=False, agent_bus_comms_dir=None)


def test_audited_rejects_scope_strategy_kwarg() -> None:
    """The scope_strategy param was removed per 2026-04-16 audit finding H3.

    Modules are responsible for calling ``self.scoping.enforce`` themselves.
    A caller that was relying on the decorator to do that needs to know
    immediately, not silently get an un-enforced tool.
    """
    with pytest.raises(TypeError):
        audited("foo_tool", scope_strategy=object())  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_agent_bus_expands_tilde_in_comms_dir(agent_ctx: AgentContext) -> None:
    """agent_bus_comms_dir values starting with '~' must be expanded to the home dir.

    Without .expanduser(), Path("~/.claude/comms") resolves relative to CWD,
    writing events to e.g. /home/ted/.claude/projects/sysadmin/~/.claude/comms/.
    """
    import json
    import shutil
    import tempfile

    # Create a temp dir inside the actual home so tilde expansion is verifiable.
    home = pathlib.Path.home()
    target = pathlib.Path(tempfile.mkdtemp(dir=home, prefix=".scoped-mcp-test-"))
    tilde_path = "~/" + target.name

    configure_audit(agent_bus_emit=True, agent_bus_comms_dir=tilde_path)
    try:
        await _make_tool(_MockModule(agent_ctx))
        await asyncio.sleep(0)
        await asyncio.sleep(0.05)

        log_files = list((target / "logs").glob("*-session.jsonl"))
        assert log_files, (
            f"no JSONL written to expanded path {target}/logs — tilde was likely not expanded"
        )
        events = [json.loads(line) for line in log_files[0].read_text().splitlines()]
        assert any(e["event"] == "tool.called" for e in events)
    finally:
        configure_audit(agent_bus_emit=False, agent_bus_comms_dir=None)
        shutil.rmtree(target, ignore_errors=True)


# ── configure_logging file sinks + error-path agent-bus emit ──────────────────


def test_configure_logging_attaches_rotating_file_sinks(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """audit_log / ops_log paths attach a size-based RotatingFileHandler to each stream."""
    import logging
    import logging.handlers

    import structlog

    from scoped_mcp.audit import configure_logging

    monkeypatch.setenv("SCOPED_MCP_LOG_MAX_BYTES", "2048")
    monkeypatch.setenv("SCOPED_MCP_LOG_BACKUPS", "2")

    # configure_logging reconfigures structlog and the root handler globally; snapshot and
    # restore everything so this test can't perturb sibling tests' log capture.
    saved_structlog = structlog.get_config()
    root = logging.getLogger()
    saved_root_handlers = list(root.handlers)
    audit_logger = logging.getLogger("audit")
    ops_logger = logging.getLogger("ops")
    before = {id(h) for h in audit_logger.handlers + ops_logger.handlers}
    try:
        configure_logging(audit_log=str(tmp_path / "audit.log"), ops_log=str(tmp_path / "ops.log"))
        assert any(
            isinstance(h, logging.handlers.RotatingFileHandler) for h in audit_logger.handlers
        )
        assert any(isinstance(h, logging.handlers.RotatingFileHandler) for h in ops_logger.handlers)
    finally:
        structlog.configure(**saved_structlog)
        root.handlers[:] = saved_root_handlers
        for lg in (audit_logger, ops_logger):
            for h in list(lg.handlers):
                if id(h) not in before:
                    lg.removeHandler(h)
                    h.close()


@pytest.mark.asyncio
async def test_audited_emits_agent_bus_error_event(
    agent_ctx: AgentContext, tmp_path: pathlib.Path
) -> None:
    """A failing tool still fires an agent-bus event, tagged outcome=error."""
    import json

    configure_audit(agent_bus_emit=True, agent_bus_comms_dir=str(tmp_path))
    module = _MockModule(agent_ctx)
    try:
        with pytest.raises(RuntimeError):
            await _make_tool(module, raise_exc=RuntimeError("boom"))
        await asyncio.sleep(0)
        await asyncio.sleep(0.05)

        log_files = list((tmp_path / "logs").glob("*-session.jsonl"))
        assert log_files, "no session JSONL written"
        events = [json.loads(line) for line in log_files[0].read_text().splitlines()]
        err_events = [e for e in events if e["metadata"]["outcome"] == "error"]
        assert err_events
        assert err_events[0]["metadata"]["error"] == "RuntimeError"
    finally:
        configure_audit(agent_bus_emit=False, agent_bus_comms_dir=None)
