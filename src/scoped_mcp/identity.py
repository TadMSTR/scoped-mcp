"""Agent identity — reads AGENT_ID and AGENT_TYPE from the environment.

Security model (2026-04-16 audit, finding M5):
``agent_id`` is interpolated into filesystem paths, bucket prefixes, folder
titles, and log fields across the codebase. Anything containing ``/``, ``..``,
whitespace, or shell metacharacters breaks the trust boundary. ``from_env``
validates both identifiers against a conservative pattern before constructing
the ``AgentContext`` — callers that build one directly are responsible for
passing pre-validated values.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass

from .exceptions import ConfigError

_AGENT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_AGENT_TYPE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

# Fixed namespace for deriving audit session ids from raw MCP session ids. Must stay
# constant across processes so the same connection maps to the same correlation id.
_SESSION_ID_NAMESPACE = uuid.UUID("6f3e2b5a-8c1d-4e7f-9a2b-1c0d5e4f3a2b")


def _normalize_session_id(raw: str) -> str:
    """Map a raw MCP session id to a stable, non-sensitive, dash-formatted UUID.

    Streamable-http session ids are 32-char hex strings. Two problems if used verbatim as
    the audit ``session_id``: (1) the audit sanitizer's long-hex redaction rewrites them to
    ``<redacted-hex>``, collapsing every session to one indistinguishable token; (2) the raw
    id is effectively a session secret that should not be written to logs at all. A ``uuid5``
    over a fixed namespace is deterministic (same connection → same id), injective in
    practice (distinct connections → distinct ids), dash-formatted (survives sanitization),
    and non-reversible (the raw session token never reaches a log).
    """
    return str(uuid.uuid5(_SESSION_ID_NAMESPACE, raw))


def _connection_session_id(default_session_id: str) -> str:
    """Per-connection audit id for a stateless HTTP client that negotiated no session id.

    F-03 / SMCP-16: under the long-lived HTTP transport a client that presents no MCP
    session id would otherwise fall back to the process-global ``SESSION_ID`` — so every
    such client shares one audit ``session_id`` and their trails merge. Derive the id from
    the TCP peer (client ``host:port``) of the in-flight request instead: distinct
    concurrent connections get distinct ids, and a kept-alive connection stays stable
    across calls. The peer address is run through the same ``uuid5`` mapping as a real
    session id, so nothing connection-level leaks into a log. Falls back to the process
    default when no peer address is resolvable (e.g. stdio, or a request with no client).
    """
    try:
        from fastmcp.server.dependencies import get_http_request

        client = getattr(get_http_request(), "client", None)
        host = getattr(client, "host", None)
        port = getattr(client, "port", None)
        if host is not None and port is not None:
            return _normalize_session_id(f"conn:{host}:{port}")
    except Exception:
        pass  # no HTTP request in context (stdio) — fall through to the process default
    return default_session_id


@dataclass(frozen=True)
class AgentContext:
    """Immutable identity for the running agent.

    Created once at startup and passed to every module. All scope decisions
    are keyed on agent_id; agent_type drives manifest selection conventions.
    """

    agent_id: str
    agent_type: str

    @classmethod
    def from_env(cls) -> AgentContext:
        """Build an AgentContext from environment variables.

        Raises ConfigError if AGENT_ID or AGENT_TYPE is missing, empty, or
        does not match the allowed identifier pattern.
        """
        agent_id = os.environ.get("AGENT_ID", "").strip()
        agent_type = os.environ.get("AGENT_TYPE", "").strip()

        pairs = [("AGENT_ID", agent_id), ("AGENT_TYPE", agent_type)]
        missing = [name for name, val in pairs if not val]
        if missing:
            raise ConfigError(f"Required environment variable(s) not set: {', '.join(missing)}")

        if not _AGENT_ID_PATTERN.match(agent_id):
            raise ConfigError(
                f"AGENT_ID {agent_id!r} does not match required pattern "
                f"{_AGENT_ID_PATTERN.pattern}. Must be 1-63 characters of "
                f"lowercase a-z / digits / hyphen and start with a letter or digit."
            )
        if not _AGENT_TYPE_PATTERN.match(agent_type):
            raise ConfigError(
                f"AGENT_TYPE {agent_type!r} does not match required pattern "
                f"{_AGENT_TYPE_PATTERN.pattern}. Must be 1-63 characters of "
                f"lowercase a-z / digits / hyphen / underscore and start with a "
                f"letter or digit."
            )

        return cls(agent_id=agent_id, agent_type=agent_type)


@dataclass(frozen=True)
class RequestIdentity:
    """Per-connection identity resolved at tool-call time.

    A single long-lived HTTP process serves many concurrent client connections
    (many turns / sessions), so identity can no longer come solely from the
    process-global ``AgentContext`` + ``SESSION_ID``. This struct carries BOTH
    the ``session_id`` and the ``agent_id`` for the *current* request.

    Forward-compat guardrail (clone pool): today ``agent_id`` still resolves to the
    process's fixed ``AGENT_ID`` (the bearer-token claim equals the env identity), so
    behaviour is unchanged. When the pooled-agent design lands, ``agent_id`` becomes a
    genuine per-connection value carried in the token claim — swapping the resolver, not
    rewriting the audit/scope path.
    """

    session_id: str
    agent_id: str


def resolve_request_identity(default_agent_id: str, default_session_id: str) -> RequestIdentity:
    """Resolve the identity for the in-flight request, falling back to process defaults.

    - ``session_id`` is read from the FastMCP per-connection context
      (``Context.session_id`` — populated for all transports). On stdio, or outside a
      request, it falls back to the process-global ``default_session_id``.
    - ``agent_id`` is read from the authenticated bearer token's ``agent_id`` claim
      when present, else falls back to ``default_agent_id`` (the env-derived identity).

    Never raises — any lookup failure yields the corresponding default so audit logging
    and stdio behaviour are unaffected.
    """
    session_id = default_session_id
    agent_id = default_agent_id

    try:
        from fastmcp.server.dependencies import get_context

        sid = getattr(get_context(), "session_id", None)
        if sid:
            session_id = _normalize_session_id(str(sid))
        else:
            # Stateless HTTP client with no MCP session id — derive a per-connection id so
            # distinct clients don't collapse onto the shared process default (F-03 / SMCP-16).
            session_id = _connection_session_id(default_session_id)
    except Exception:
        pass  # no active FastMCP context (stdio / unit test) — keep default

    try:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
        if token is not None:
            claim = (getattr(token, "claims", None) or {}).get("agent_id")
            # F-01: only trust a claim that satisfies the agent-id trust boundary — agent_id
            # is interpolated into filesystem paths, bucket prefixes, and log fields, so an
            # unvalidated value containing '/', '..', or whitespace escapes scope. An invalid
            # or malformed claim is ignored, keeping the validated default. Not reachable while
            # the only issuer stamps the validated env AGENT_ID, but the guard ships with the
            # trusting code so the clone-pool token issuer cannot introduce a traversal sink.
            if claim and _AGENT_ID_PATTERN.match(claim):
                agent_id = claim
    except Exception:
        pass  # unauthenticated transport (stdio) — keep default

    return RequestIdentity(session_id=session_id, agent_id=agent_id)
