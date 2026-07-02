"""Bearer-token authentication for the HTTP (streamable-http) transport.

stdio transport has implicit isolation: each spawn is a private stdin/stdout pipe
owned by one client process. The HTTP transport replaces that pipe with a localhost
TCP port, which *any* local process can reach — so it MUST authenticate every request
before a tool is dispatched.

``BearerTokenVerifier`` is a FastMCP ``TokenVerifier`` (resource-server model, no OAuth
server): it constant-time-compares the presented bearer token against a single per-agent
secret sourced from the ``SCOPED_MCP_BEARER_TOKEN`` environment variable. A missing or
mismatched token makes ``verify_token`` return ``None``, which FastMCP turns into a 401
before any tool handler runs.

Forward-compat guardrail (clone pool, plan items 2 & 3): the returned ``AccessToken``
carries the caller's ``agent_id`` both as ``client_id`` and in ``claims["agent_id"]``.
Today one process = one fixed ``AGENT_ID``, so the claim equals the process identity and
nothing downstream changes. When the pooled-agent design lands, a verifier that maps many
tokens → many ``agent_id`` values is a drop-in replacement — the per-connection identity
resolver (``identity.resolve_request_identity``) already reads the claim, so no audit/scope
rewrite is required.
"""

from __future__ import annotations

import hmac
from typing import Any

from fastmcp.server.auth import AccessToken, TokenVerifier


class BearerTokenVerifier(TokenVerifier):
    """Verify a static per-agent bearer token in constant time.

    Args:
        expected_token: the shared secret the client must present. Must be non-empty —
            an empty configured token would authenticate every request and is rejected
            at construction time.
        agent_id: identity stamped onto the returned AccessToken (client_id + claim).
    """

    def __init__(self, expected_token: str, agent_id: str) -> None:
        super().__init__()
        if not expected_token:
            raise ValueError(
                "BearerTokenVerifier requires a non-empty token "
                "(set SCOPED_MCP_BEARER_TOKEN); refusing to run HTTP transport unauthenticated"
            )
        self._expected_token = expected_token
        self._agent_id = agent_id

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an AccessToken on exact match, else None (→ 401 before dispatch)."""
        # F-04: compare as UTF-8 bytes. hmac.compare_digest on two str operands raises
        # TypeError if either holds non-ASCII — a non-ASCII bearer would 500 instead of a
        # clean 401. Bytes are always comparable, keeping the path fail-closed and quiet.
        if not token or not hmac.compare_digest(token.encode(), self._expected_token.encode()):
            return None
        claims: dict[str, Any] = {"agent_id": self._agent_id}
        return AccessToken(
            token=token,
            client_id=self._agent_id,
            scopes=[],
            expires_at=None,
            claims=claims,
        )
