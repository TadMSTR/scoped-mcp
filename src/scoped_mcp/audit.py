"""Structured audit logging for scoped-mcp.

Two log streams:
  - audit: tool calls, scope checks, scope violations
  - ops:   startup, shutdown, module loading, credential resolution

The @audited decorator wraps every tool call for logging. It is applied by
the registry at registration time — module authors do not apply it manually,
and must not suppress or bypass it. @audited does NOT enforce scope; each
module is responsible for calling its own ``scoping.enforce()`` (or an
equivalent allowlist / validation check) inside every tool method. See
``AGENTS.md`` for the module-author enforcement checklist.

Argument sanitization runs as a structlog processor and cannot be bypassed
by module code. Credential values are redacted; large payloads are truncated.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import logging
import logging.handlers
import os
import re
import sys
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from .identity import resolve_request_identity

# ── Session ID ───────────────────────────────────────────────────────────────

SESSION_ID: str = str(uuid.uuid4())
"""UUID generated at process start. Injected into every audit record and OTel span.
Enables cross-tool-call reconstruction by session key instead of timestamp ranging."""

# ── Runtime audit configuration ──────────────────────────────────────────────
# Defaults apply until configure_audit() is called from server.py at startup.

_log_args: bool = True
_agent_bus_emit: bool = False
_agent_bus_comms_dir: str | None = None
_response_filter: Any = None  # ResponseFilter instance or None


def configure_audit(
    *,
    log_args: bool = True,
    agent_bus_emit: bool = False,
    agent_bus_comms_dir: str | None = None,
    response_filter: Any = None,
) -> None:
    """Set audit runtime config from the manifest. Call once at server startup."""
    global _log_args, _agent_bus_emit, _agent_bus_comms_dir, _response_filter
    _log_args = log_args
    _agent_bus_emit = agent_bus_emit
    _agent_bus_comms_dir = agent_bus_comms_dir
    _response_filter = response_filter


# ── Agent-bus JSONL emission ─────────────────────────────────────────────────


# Audit, ops and event files are created owner-only, whatever the process umask (PM2's
# is 022). They record tool arguments, so a 0644 file under a traversable dir let any
# local UID read them (vikunja#1075). An existing file keeps its mode: a shared file
# another writer created is not ours to tighten.
_LOG_FILE_MODE = 0o600
_LOG_DIR_MODE = 0o700


def _open_private_append(path: str, **kwargs: Any) -> Any:
    """Open ``path`` for appending, creating it 0600 if it does not exist."""
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, _LOG_FILE_MODE)
    return open(fd, "a", **kwargs)


def _sync_append_event(log_path: str, line: str) -> None:
    """Sync JSONL append. Runs in an executor to avoid blocking the event loop."""
    with _open_private_append(log_path) as f:
        f.write(line)


async def _emit_agent_bus_event(
    tool_name: str,
    agent_id: str,
    outcome: str,
    elapsed_ms: float,
    session_id: str,
    error: str | None = None,
) -> None:
    """Write a tool.called event to the agent-bus JSONL log. Never raises."""
    if not _agent_bus_comms_dir:
        return
    try:
        logs_dir = Path(_agent_bus_comms_dir).expanduser() / "logs"
        logs_dir.mkdir(mode=_LOG_DIR_MODE, parents=True, exist_ok=True)

        date = datetime.now(UTC).strftime("%Y-%m-%d")
        log_path = str(logs_dir / f"{date}-session.jsonl")

        event = {
            "id": str(uuid.uuid4()),
            "ts": datetime.now(UTC).isoformat(),
            "event": "tool.called",
            "scope": "session",
            "source": agent_id,
            "target": None,
            "artifact_path": None,
            "summary": f"{tool_name} — {outcome} in {elapsed_ms}ms",
            "hostname": os.uname().nodename,
            "metadata": {
                "tool": tool_name,
                "outcome": outcome,
                "latency_ms": elapsed_ms,
                "session_id": session_id,
                "error": error,
            },
        }
        line = json.dumps(event, ensure_ascii=False) + "\n"

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _sync_append_event, log_path, line)
    except Exception:
        pass  # never let emission errors crash the tool call


# ── OTel session injection ───────────────────────────────────────────────────


def _inject_session_id_to_current_span(session_id: str) -> None:
    """Set scoped_mcp.session on the active OTel span, if one is recording.

    Called at the start of every @audited wrapper so the per-connection session ID
    is stamped on the span created by OtelMiddleware before the tool body runs.
    """
    try:
        from opentelemetry import trace as _otel

        span = _otel.get_current_span()
        if span.is_recording():
            span.set_attribute("scoped_mcp.session", session_id)
    except ImportError:
        pass


# ── Sanitization processor ──────────────────────────────────────────────────

_MAX_ARG_LEN = 500  # characters; longer strings are truncated
_SENSITIVE_SUFFIXES = (
    "_TOKEN",
    "_PASSWORD",
    "_SECRET",
    "_KEY",
    "_CREDENTIALS",
    "_PWD",
    "_PASS",
    "_AUTH",
)
_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "session",
        "bearer",
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        # Vault-specific fields
        "lease_id",
        "accessor",
        "secret_id",
        "role_id",
    }
)
# Log-event top-level keys whose value is operational metadata, not user-supplied
# data, and must never be redacted by the key-match pass (e.g. a log record whose
# ``event`` field is literally ``"scope_violation"`` or an arg named ``token``
# labelled via ``key``).
_PRESERVE_KEYS = frozenset({"event", "logger", "level", "timestamp", "status"})

# Pattern-based redaction — applied to every string value regardless of key name.
# Keeps tokens out of logs when they appear embedded in error strings,
# user-supplied URLs, free-form messages, etc.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
_GH_PAT_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
# Vault service tokens (new hvs./hvb./hvr. format and legacy s./b./r. format).
# Modern SSTs use base64url, which contains _ and -; \b cannot terminate before _, so
# the modern arm has no trailing \b. The legacy arm covers all three legacy prefixes.
_VAULT_TOKEN_RE = re.compile(r"\b(?:hvs|hvb|hvr)\.[A-Za-z0-9_-]+|\b[sbr]\.[A-Za-z0-9]{24,}\b")


# ── By-value redaction (vikunja#1075 item 3) ─────────────────────────────────
# The patterns above only catch secrets with a recognisable shape. A Dockhand API token
# or an ntfy topic URL has none, and both reached the audit log verbatim. So the broker
# also redacts the actual secret values it holds: the values in its own environment
# (the launcher sources the agent .env into it) whose names look sensitive, and whatever
# the manifest's ${VAR} references resolved to.
#
# SECURITY: the value set is never logged, nor its size distribution or hashes. Only a
# count goes to ops.

# Shorter values are too likely to occur by chance in ordinary text.
_MIN_REDACT_VALUE_LEN = 12
# Secret by path, so the sensitive-name heuristic cannot see it: the topic is the
# credential (vikunja#1075).
_SECRET_ENV_NAMES = frozenset({"SCOPED_MCP_ALERT_NTFY_URL"})
# Name shapes that hold a secret but are not in _SENSITIVE_SUFFIXES, measured on a live
# broker's env (VAULT_SECRET_ID, VAULT_ROLE_ID, AGENT_REGISTRY_DSN, DOCKHAND_MCP_BEARER,
# RENOVATE_BOT_PAT). For value collection only: widening _SENSITIVE_SUFFIXES would also
# change which tool-argument keys are blanked.
_VALUE_NAME_SUFFIXES = (
    "_SECRET_ID",
    "_ROLE_ID",
    "_DSN",
    "_BEARER",
    "_PAT",
    "_WEBHOOK",
    "_WEBHOOK_URL",
)
_URL_RE = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://")

# (pattern, value -> name). One tuple, rebound in a single assignment, so a concurrent
# reader never pairs a new pattern with the old names (which would raise inside the
# substitution and, in _RedactionFilter, let the record through unredacted).
_value_redaction: tuple[re.Pattern[str], dict[str, str]] | None = None


def _url_has_userinfo(value: str) -> bool:
    if not _URL_RE.match(value):
        return False
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return bool(parts.username or parts.password)


def _name_holds_secret(name: str) -> bool:
    return _key_looks_sensitive(name) or name.upper().endswith(_VALUE_NAME_SUFFIXES)


def _is_redactable_value(value: str) -> bool:
    """False for values that are not secrets and would only redact ordinary text."""
    if len(value) < _MIN_REDACT_VALUE_LEN or value.isdigit():
        return False
    if _URL_RE.match(value):
        # A bare origin (scheme://host[:port][/]) names a service, it does not grant
        # access to one. Userinfo, a query or a path can carry a credential: the ntfy
        # topic URL is secret by its path. Those are kept.
        from urllib.parse import urlsplit

        try:
            parts = urlsplit(value)
        except ValueError:
            return True
        return bool(parts.username or parts.password or parts.query or parts.path.strip("/"))
    return True


def configure_value_redaction(
    extra_names: Iterable[str] = (), environ: Mapping[str, str] | None = None
) -> int:
    """(Re)build the by-value redaction set from the process environment.

    Collects every variable whose name looks sensitive, every URL value carrying
    userinfo (a password in a DSN, whatever the variable is called), the names in
    ``_SECRET_ENV_NAMES``, and ``extra_names`` (the manifest's ${VAR} references,
    whatever they are called). Rebuilt from scratch on each call. Returns how many
    distinct values are redacted, the one thing about the set that may be logged.
    """
    global _value_redaction
    env = os.environ if environ is None else environ
    wanted = (
        {n for n, v in env.items() if _name_holds_secret(n) or _url_has_userinfo(v)}
        | _SECRET_ENV_NAMES
        | set(extra_names)
    )
    names: dict[str, str] = {}
    # Sorted so that two names sharing a value always report the same one.
    for name in sorted(wanted):
        value = env.get(name)
        if value and _is_redactable_value(value):
            names.setdefault(value, name)
    if not names:
        _value_redaction = None
        return 0
    # One compiled alternation, longest value first: at any position the longest secret
    # wins, so a value that contains another is replaced whole.
    alternatives = sorted(names, key=len, reverse=True)
    _value_redaction = (re.compile("|".join(re.escape(v) for v in alternatives)), names)
    return len(names)


def _redact_values(s: str) -> str:
    current = _value_redaction
    if current is None:
        return s
    pattern, names = current
    return pattern.sub(lambda m: f"<redacted-value:{names[m.group(0)]}>", s)


def _redact_string(s: str) -> str:
    """Apply value-based, then pattern-based, redaction to a single string.

    Values first: a pattern pass could rewrite part of a known secret (a hex run inside
    it, say) and leave the rest unmatched.
    """
    s = _redact_values(s)
    s = _JWT_RE.sub("<redacted-jwt>", s)
    s = _BEARER_RE.sub("<redacted-bearer>", s)
    s = _GH_PAT_RE.sub("<redacted-gh-token>", s)
    s = _VAULT_TOKEN_RE.sub("<redacted-vault-token>", s)
    s = _LONG_HEX_RE.sub("<redacted-hex>", s)
    return s


def _key_looks_sensitive(key: str) -> bool:
    lower = key.lower()
    upper = key.upper()
    if lower in _SENSITIVE_KEYS:
        return True
    return any(upper.endswith(s) for s in _SENSITIVE_SUFFIXES)


def _sanitize_value(value: Any, key: str = "") -> Any:
    """Redact or truncate a single argument value."""
    if key and _key_looks_sensitive(key):
        return "<redacted>"
    if isinstance(value, bytes):
        return f"<binary {len(value)} bytes>"
    if isinstance(value, str):
        redacted = _redact_string(value)
        if len(redacted) > _MAX_ARG_LEN:
            return redacted[:_MAX_ARG_LEN] + f"...<truncated {len(redacted.encode())} bytes>"
        return redacted
    if isinstance(value, dict):
        return {k: _sanitize_value(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    return value


def _sanitize_processor(logger: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor that sanitizes every field in log events.

    Applied to the whole event_dict, not just the ``args`` sub-mapping, so
    credential values leaking into ``error``, ``detail``, or any other key
    are still caught. ``event``/``level``/``logger``/``timestamp``/``status``
    are preserved so they cannot be silently clobbered.
    """
    for k, v in list(event_dict.items()):
        if k in _PRESERVE_KEYS:
            continue
        event_dict[k] = _sanitize_value(v, k)
    return event_dict


# ── Logger configuration ─────────────────────────────────────────────────────


class _RedactionFilter(logging.Filter):
    """Apply value and pattern redaction to stdlib log records on the stderr handler (F-05).

    The structlog ``_sanitize_processor`` only scrubs records emitted through structlog
    loggers. Third-party libraries (uvicorn / starlette / fastmcp) log via plain stdlib
    logging, bypassing it — and under the long-lived HTTP process their stderr is captured
    persistently by PM2. A dependency that logs an ``Authorization: Bearer <token>`` header at
    DEBUG would otherwise persist the secret. This filter runs the same pattern redaction over
    every formatted stderr record so a leaked bearer/token never reaches the log.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = _redact_string(record.getMessage())
            record.args = ()
        except Exception:
            pass  # never let redaction drop a log record
        return True


class _PrivateRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """A RotatingFileHandler whose files are 0600, including after a rollover.

    ``doRollover`` renames the current file, which keeps its mode, and calls ``_open``
    for the new one, so overriding ``_open`` covers both. A process-wide ``os.umask``
    would do the same for every file every module writes, which is not ours to change.

    Unlike the shared agent-bus file, this one is scoped-mcp's own, so an existing file
    this process owns is tightened to 0600 as well (a log written by an older version, or
    reused across a restart). One owned by someone else is left alone.
    """

    def _open(self) -> Any:
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_APPEND | os.O_CREAT, _LOG_FILE_MODE)
        try:
            st = os.fstat(fd)
            if st.st_uid == os.geteuid() and st.st_mode & 0o077:
                os.fchmod(fd, _LOG_FILE_MODE)
        except OSError:
            pass  # never let a mode fix stop logging
        return self._builtin_open(fd, self.mode, encoding=self.encoding, errors=self.errors)


def _ensure_private_dir(path: str) -> None:
    """Create the log file's directory 0700 if it is missing. An existing one is left as is.

    In production the launcher creates it first (``mkdir -m 0700``); this covers every
    other way of starting scoped-mcp. Never loosens: ``mkdir`` does not touch a
    directory that already exists. Nor does it tighten one: ``--audit-log ~/audit.log``
    would otherwise chmod the home directory.
    """
    Path(path).parent.mkdir(mode=_LOG_DIR_MODE, parents=True, exist_ok=True)


def configure_logging(audit_log: str | None = None, ops_log: str | None = None) -> None:
    """Configure structlog. Call once at server startup.

    Args:
        audit_log: optional file path for audit stream output.
        ops_log:   optional file path for ops stream output.

    File sinks use a size-based ``RotatingFileHandler`` so a long-lived HTTP process
    (SMCP-15) cannot grow a single audit/ops file without bound. Under the legacy
    stdio-per-turn launcher each short-lived process writes a small per-pid file that
    never reaches the rotation threshold, so behaviour there is unchanged. Tunable via
    ``SCOPED_MCP_LOG_MAX_BYTES`` (default 50 MiB) and ``SCOPED_MCP_LOG_BACKUPS``
    (default 5); set max-bytes to 0 to disable rotation.
    """
    # Route through stdlib so file handlers can be attached per named logger.
    # JSONRenderer already serialises the event; %(message)s preserves it as-is.
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            _sanitize_processor,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )

    # Before the first record is written, so even the startup lines are covered. server.py
    # extends it with the manifest's ${VAR} names once the manifest is loaded.
    configure_value_redaction()

    _json_fmt = logging.Formatter("%(message)s")

    # All log output goes to stderr — stdout is the stdio JSON-RPC wire.
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(_json_fmt)
    stderr_handler.addFilter(_RedactionFilter())  # F-05: scrub stdlib/dep logs on stderr
    root.addHandler(stderr_handler)

    # Rotation knobs — bound disk for a long-lived process; no-op for tiny stdio files.
    max_bytes = int(os.environ.get("SCOPED_MCP_LOG_MAX_BYTES", str(50 * 1024 * 1024)))
    backups = int(os.environ.get("SCOPED_MCP_LOG_BACKUPS", "5"))

    def _file_handler(path: str) -> logging.Handler:
        # maxBytes=0 disables rotation (stdlib RotatingFileHandler semantics).
        _ensure_private_dir(path)
        fh = _PrivateRotatingFileHandler(
            path, maxBytes=max(max_bytes, 0), backupCount=max(backups, 0)
        )
        fh.setFormatter(_json_fmt)
        return fh

    # Optional file sinks: named loggers propagate to root (stderr) AND write to file.
    if audit_log:
        logging.getLogger("audit").addHandler(_file_handler(audit_log))

    if ops_log:
        logging.getLogger("ops").addHandler(_file_handler(ops_log))


def get_audit_logger() -> structlog.stdlib.BoundLogger:
    return structlog.get_logger("audit")


def get_ops_logger() -> structlog.stdlib.BoundLogger:
    return structlog.get_logger("ops")


# ── @audited decorator ───────────────────────────────────────────────────────


def audited(tool_name: str) -> Callable:
    """Decorator factory that wraps a tool handler with audit logging.

    Applied by the registry — module authors do not call this directly.
    Scope enforcement is the module's responsibility (see ``AGENTS.md``);
    ``@audited`` does not call ``scope_strategy.enforce()``.

    Args:
        tool_name: the namespaced tool name (e.g. "filesystem_read_file").
    """

    def decorator(fn: Callable) -> Callable:
        # Capture agent_ctx at decoration time from the bound method's __self__.
        # get_tool_methods() returns bound methods, so __self__ is the module instance.
        # Falling back to args[0] at call time handles the unbound case in tests.
        _bound_self = getattr(fn, "__self__", None)
        _agent_ctx_from_binding = getattr(_bound_self, "agent_ctx", None)

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            logger = get_audit_logger()
            start = time.monotonic()

            agent_ctx = _agent_ctx_from_binding or (
                getattr(args[0], "agent_ctx", None) if args else None
            )
            default_agent_id = agent_ctx.agent_id if agent_ctx else "unknown"

            # Per-connection identity: session_id (and, forward-compat, agent_id) come from
            # the in-flight request context, not the process globals — so one long-lived HTTP
            # process keeps distinct session ids across concurrent clients. Falls back to the
            # process SESSION_ID / env agent_id on stdio or outside a request.
            identity = resolve_request_identity(default_agent_id, SESSION_ID)
            agent_id = identity.agent_id
            session_id = identity.session_id

            _inject_session_id_to_current_span(session_id)

            log_kwargs: dict[str, Any] = {
                "tool": tool_name,
                "agent_id": agent_id,
                "session_id": session_id,
            }
            if _log_args:
                log_kwargs["args"] = kwargs

            try:
                result = await fn(*args, **kwargs)
                elapsed_ms = round((time.monotonic() - start) * 1000, 2)

                if _response_filter is not None:
                    result = _response_filter.filter_response(result, tool_name, agent_id)

                logger.info("tool_call", status="ok", elapsed_ms=elapsed_ms, **log_kwargs)

                if _agent_bus_emit and _agent_bus_comms_dir:
                    with contextlib.suppress(RuntimeError):
                        _t = asyncio.create_task(
                            _emit_agent_bus_event(tool_name, agent_id, "ok", elapsed_ms, session_id)
                        )
                        _t.add_done_callback(lambda _: None)

                return result
            except Exception as exc:
                from .exceptions import ScopeViolation  # avoid circular at module level

                elapsed_ms = round((time.monotonic() - start) * 1000, 2)
                if isinstance(exc, ScopeViolation):
                    logger.warning(
                        "scope_violation",
                        status="blocked",
                        error=str(exc),
                        elapsed_ms=elapsed_ms,
                        **log_kwargs,
                    )
                else:
                    logger.error(
                        "tool_error",
                        status="error",
                        error=type(exc).__name__,
                        elapsed_ms=elapsed_ms,
                        **log_kwargs,
                    )

                if _agent_bus_emit and _agent_bus_comms_dir:
                    with contextlib.suppress(RuntimeError):
                        _t = asyncio.create_task(
                            _emit_agent_bus_event(
                                tool_name,
                                agent_id,
                                "error",
                                elapsed_ms,
                                session_id,
                                type(exc).__name__,
                            )
                        )
                        _t.add_done_callback(lambda _: None)

                raise

        return wrapper

    return decorator
