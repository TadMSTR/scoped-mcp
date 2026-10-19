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


async def _make_tool(
    module: _MockModule, raise_exc: Exception | None = None, value: str = "hello"
) -> str:
    async def _tool(self: _MockModule, value: str) -> str:
        if raise_exc:
            raise raise_exc
        return f"ok:{value}"

    _tool.__name__ = "test_tool"
    wrapped = audited("test_module_test_tool")(_tool)
    return await wrapped(module, value=value)


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


# ── Private audit/ops/event files (vikunja#1075 item 3) ──────────────────────


@pytest.fixture
def permissive_umask():
    """PM2's umask. Without it the tests would pass on a 077 workstation and prove nothing."""
    import os

    old = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(old)


def _mode(path: pathlib.Path) -> int:
    return path.stat().st_mode & 0o777


def _private_handler(path: pathlib.Path, max_bytes: int = 0):
    import logging

    from scoped_mcp.audit import _PrivateRotatingFileHandler

    handler = _PrivateRotatingFileHandler(str(path), maxBytes=max_bytes, backupCount=2)
    handler.setFormatter(logging.Formatter("%(message)s"))
    return handler


def _record(msg: str):
    import logging

    return logging.LogRecord("audit", logging.INFO, __file__, 1, msg, None, None)


def test_log_file_is_created_0600_under_a_permissive_umask(
    tmp_path: pathlib.Path, permissive_umask: None
) -> None:
    path = tmp_path / "audit.jsonl"
    handler = _private_handler(path)
    try:
        handler.emit(_record("x"))
    finally:
        handler.close()
    assert _mode(path) == 0o600


def test_rotated_and_new_log_files_stay_0600(
    tmp_path: pathlib.Path, permissive_umask: None
) -> None:
    path = tmp_path / "audit.jsonl"
    handler = _private_handler(path, max_bytes=64)
    try:
        for _ in range(10):
            handler.emit(_record("y" * 40))
    finally:
        handler.close()
    rotated = tmp_path / "audit.jsonl.1"
    assert rotated.exists(), "the handler never rotated, so the test proves nothing"
    assert _mode(rotated) == 0o600
    assert _mode(path) == 0o600


def test_configure_logging_creates_missing_dirs_0700_and_files_0600(
    tmp_path: pathlib.Path, permissive_umask: None
) -> None:
    import logging

    import structlog

    from scoped_mcp.audit import configure_logging, get_audit_logger

    audit_log = tmp_path / "agent" / "audit" / "audit.jsonl"
    ops_log = tmp_path / "agent" / "ops" / "ops.jsonl"
    saved_structlog = structlog.get_config()
    root = logging.getLogger()
    saved_root_handlers = list(root.handlers)
    loggers = (logging.getLogger("audit"), logging.getLogger("ops"))
    before = {id(h) for lg in loggers for h in lg.handlers}
    try:
        configure_logging(audit_log=str(audit_log), ops_log=str(ops_log))
        get_audit_logger().info("probe")
    finally:
        structlog.configure(**saved_structlog)
        root.handlers[:] = saved_root_handlers
        for lg in loggers:
            for h in list(lg.handlers):
                if id(h) not in before:
                    lg.removeHandler(h)
                    h.close()
    assert _mode(audit_log.parent) == 0o700
    assert _mode(ops_log.parent) == 0o700
    assert _mode(audit_log) == 0o600
    assert _mode(ops_log) == 0o600


def test_an_existing_log_dir_keeps_its_mode(tmp_path: pathlib.Path) -> None:
    from scoped_mcp.audit import _ensure_private_dir

    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o750)
    _ensure_private_dir(str(shared / "audit.jsonl"))
    assert _mode(shared) == 0o750


def test_agent_bus_event_file_is_created_0600(
    tmp_path: pathlib.Path, permissive_umask: None
) -> None:
    from scoped_mcp.audit import _sync_append_event

    path = tmp_path / "2026-10-19-session.jsonl"
    _sync_append_event(str(path), '{"a": 1}\n')
    _sync_append_event(str(path), '{"a": 2}\n')
    assert _mode(path) == 0o600
    assert path.read_text() == '{"a": 1}\n{"a": 2}\n'


def test_agent_bus_event_file_another_writer_created_keeps_its_mode(
    tmp_path: pathlib.Path, permissive_umask: None
) -> None:
    """The session JSONL is shared with agent-bus. Appending must not re-mode its file."""
    from scoped_mcp.audit import _sync_append_event

    path = tmp_path / "2026-10-19-session.jsonl"
    path.write_text("")
    path.chmod(0o664)
    _sync_append_event(str(path), "{}\n")
    assert _mode(path) == 0o664


@pytest.mark.asyncio
async def test_agent_bus_logs_dir_is_created_0700(
    agent_ctx: AgentContext, tmp_path: pathlib.Path, permissive_umask: None
) -> None:
    configure_audit(agent_bus_emit=True, agent_bus_comms_dir=str(tmp_path))
    module = _MockModule(agent_ctx)
    try:
        await _make_tool(module)
        await asyncio.sleep(0)
        await asyncio.sleep(0.05)
    finally:
        configure_audit(agent_bus_emit=False, agent_bus_comms_dir=None)
    logs = tmp_path / "logs"
    assert _mode(logs) == 0o700
    assert all(_mode(f) == 0o600 for f in logs.iterdir())
    assert list(logs.iterdir()), "no event file written"


# ── By-value redaction (vikunja#1075 item 3) ─────────────────────────────────

# Shaped like nothing the patterns know: not a JWT, bearer, PAT, Vault token or hex run.
_SHAPELESS = "dk-Q7wLmZ2pXv9RtYc"
_NTFY_URL = "https://ntfy.example.net/forge-alerts-3kq9vz"


def test_shapeless_secret_passes_the_pattern_redaction() -> None:
    """The premise: without by-value redaction this value reaches the log verbatim."""
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    configure_value_redaction(environ={})
    assert _redact_string(f"curl -H 'X-Api-Key: {_SHAPELESS}'") == (
        f"curl -H 'X-Api-Key: {_SHAPELESS}'"
    )


def test_sensitive_named_env_value_is_redacted_by_value() -> None:
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    configure_value_redaction(environ={"DOCKHAND_API_TOKEN": _SHAPELESS})
    out = _redact_string(f"curl -H 'X-Api-Key: {_SHAPELESS}' http://dockhand")
    assert _SHAPELESS not in out
    assert "<redacted-value:DOCKHAND_API_TOKEN>" in out


def test_value_is_redacted_inside_a_longer_token() -> None:
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    configure_value_redaction(environ={"DOCKHAND_API_TOKEN": _SHAPELESS})
    assert _SHAPELESS not in _redact_string(f"x=abc{_SHAPELESS}def")


def test_short_value_is_not_redacted() -> None:
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    assert configure_value_redaction(environ={"FOO_TOKEN": "short-val"}) == 0
    assert _redact_string("a short-val here") == "a short-val here"


def test_twelve_character_value_is_redacted() -> None:
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    configure_value_redaction(environ={"FOO_TOKEN": "abcdefghijkl"})
    assert _redact_string("abcdefghijkl") == "<redacted-value:FOO_TOKEN>"


def test_insensitive_env_names_are_not_collected() -> None:
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    configure_value_redaction(environ={"HOME": "/home/someone-long"})
    assert _redact_string("/home/someone-long") == "/home/someone-long"


def test_manifest_referenced_name_is_redacted_whatever_it_is_called() -> None:
    """DOCKHAND_MCP_BEARER does not look sensitive; a manifest reference makes it count."""
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    env = {"DOCKHAND_MCP_BEARER": _SHAPELESS}
    configure_value_redaction(environ=env)
    assert _redact_string(_SHAPELESS) == _SHAPELESS
    configure_value_redaction(["DOCKHAND_MCP_BEARER"], environ=env)
    assert _redact_string(_SHAPELESS) == "<redacted-value:DOCKHAND_MCP_BEARER>"


def test_alert_ntfy_topic_url_is_redacted_whole() -> None:
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    configure_value_redaction(environ={"SCOPED_MCP_ALERT_NTFY_URL": _NTFY_URL})
    out = _redact_string(f"curl -d hi {_NTFY_URL}")
    assert out == "curl -d hi <redacted-value:SCOPED_MCP_ALERT_NTFY_URL>"


@pytest.mark.parametrize(
    ("value", "redacted"),
    [
        ("https://vault.example.net:8200", False),
        ("https://vault.example.net:8200/", False),
        ("redis://:hunter2hunter2@127.0.0.1:6379", True),
        ("https://hooks.example.net/T0/B0", True),
        ("https://api.example.net/?key=abc", True),
        ("123456789012345", False),
    ],
)
def test_non_secret_values_are_skipped(value: str, redacted: bool) -> None:
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    configure_value_redaction(["SOME_REF"], environ={"SOME_REF": value})
    assert (_redact_string(f"x {value} y") != f"x {value} y") is redacted


def test_longest_value_wins_when_one_contains_another() -> None:
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    configure_value_redaction(
        environ={"BASE_TOKEN": _SHAPELESS, "FULL_TOKEN": _SHAPELESS + "-extended"}
    )
    assert _redact_string(_SHAPELESS + "-extended") == "<redacted-value:FULL_TOKEN>"
    assert _redact_string(_SHAPELESS) == "<redacted-value:BASE_TOKEN>"


def test_values_are_redacted_before_patterns() -> None:
    """A long hex run inside a known secret must not split it before the value pass."""
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    secret = "tok-" + "ab" * 20
    configure_value_redaction(environ={"HEXY_TOKEN": secret})
    assert _redact_string(secret) == "<redacted-value:HEXY_TOKEN>"


def test_regex_metacharacters_in_a_value_are_literal() -> None:
    from scoped_mcp.audit import _redact_string, configure_value_redaction

    configure_value_redaction(environ={"ODD_PASSWORD": "a.b*c+d(e)f|g"})
    assert _redact_string("a.b*c+d(e)f|g") == "<redacted-value:ODD_PASSWORD>"
    assert _redact_string("aXbbbcdddefg") == "aXbbbcdddefg"


def test_value_count_is_distinct_values() -> None:
    from scoped_mcp.audit import configure_value_redaction

    env = {"A_TOKEN": _SHAPELESS, "B_TOKEN": _SHAPELESS, "C_SECRET": "another-secret-1"}
    assert configure_value_redaction(environ=env) == 2


def test_sanitize_processor_redacts_values_in_args_and_error_fields() -> None:
    from scoped_mcp.audit import _sanitize_processor, configure_value_redaction

    configure_value_redaction(environ={"DOCKHAND_API_TOKEN": _SHAPELESS})
    event = {
        "event": "tool_call",
        "args": {"command": f"curl -H 'X-Api-Key: {_SHAPELESS}'", "argv": ["-k", _SHAPELESS]},
        "error": f"401 for key {_SHAPELESS}",
    }
    out = _sanitize_processor(None, "info", event)
    assert _SHAPELESS not in str(out)
    assert out["args"]["argv"][1] == "<redacted-value:DOCKHAND_API_TOKEN>"


def test_stdlib_records_are_redacted_by_value() -> None:
    import logging

    from scoped_mcp.audit import _RedactionFilter, configure_value_redaction

    configure_value_redaction(environ={"DOCKHAND_API_TOKEN": _SHAPELESS})
    record = logging.LogRecord("uvicorn", logging.INFO, __file__, 1, "hdr %s", (_SHAPELESS,), None)
    _RedactionFilter().filter(record)
    assert record.getMessage() == "hdr <redacted-value:DOCKHAND_API_TOKEN>"


@pytest.mark.asyncio
async def test_audit_file_never_holds_an_env_secret_value(
    agent_ctx: AgentContext, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: env -> configure_logging -> @audited -> the audit file on disk."""
    import logging

    import structlog

    from scoped_mcp.audit import configure_logging

    monkeypatch.setenv("DOCKHAND_API_TOKEN", _SHAPELESS)
    audit_log = tmp_path / "audit.jsonl"
    saved_structlog = structlog.get_config()
    root = logging.getLogger()
    saved_root_handlers = list(root.handlers)
    audit_logger = logging.getLogger("audit")
    before = {id(h) for h in audit_logger.handlers}
    try:
        configure_logging(audit_log=str(audit_log))
        await _make_tool(_MockModule(agent_ctx), value=f"curl -H 'X-Api-Key: {_SHAPELESS}'")
    finally:
        structlog.configure(**saved_structlog)
        root.handlers[:] = saved_root_handlers
        for h in list(audit_logger.handlers):
            if id(h) not in before:
                audit_logger.removeHandler(h)
                h.close()
    text = audit_log.read_text()
    assert "tool_call" in text, "the tool call was not logged, so the test proves nothing"
    assert _SHAPELESS not in text
    assert "<redacted-value:DOCKHAND_API_TOKEN>" in text
