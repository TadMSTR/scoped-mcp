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

import asyncio
import hmac
import time
from collections import deque
from typing import Any

import structlog
from fastmcp.server.auth import AccessToken, TokenVerifier

_log = structlog.get_logger("ops")


class BearerTokenVerifier(TokenVerifier):
    """Verify a static per-agent bearer token in constant time.

    Args:
        expected_token: the shared secret the client must present. Must be non-empty —
            an empty configured token would authenticate every request and is rejected
            at construction time.
        agent_id: identity stamped onto the returned AccessToken (client_id + claim).
        agent_type: identity type, included in the 401-burst ops alert.

    401-burst detection (SMCP-28): a misconfigured client (unresolved bearer env var)
    hammers /mcp with 401s while calling no tool — so a session-start scoped_mcp_status
    check can never catch it (the client is rejected at the bearer before any tool
    dispatch). This verifier counts recent auth failures in a sliding window and fires
    one Vault-independent ops alert when the count crosses a threshold, rate-limited by
    a cooldown so a noisy client cannot storm the alert channel.
    """

    _BURST_WINDOW_SECONDS = 60.0
    _BURST_THRESHOLD = 5
    _BURST_COOLDOWN_SECONDS = 300.0
    # Hard cap on tracked 401 timestamps (defense-in-depth, audit INFO-1): under a
    # sustained loopback flood the window would otherwise hold ~(rate x window) entries.
    # Any value well above _BURST_THRESHOLD preserves detection while bounding memory.
    _BURST_MAX_TRACKED = 256

    def __init__(self, expected_token: str, agent_id: str, agent_type: str = "unknown") -> None:
        super().__init__()
        if not expected_token:
            raise ValueError(
                "BearerTokenVerifier requires a non-empty token "
                "(set SCOPED_MCP_BEARER_TOKEN); refusing to run HTTP transport unauthenticated"
            )
        self._expected_token = expected_token
        self._agent_id = agent_id
        self._agent_type = agent_type
        self._recent_401s: deque[float] = deque(maxlen=self._BURST_MAX_TRACKED)
        self._last_alert_monotonic: float | None = None
        # Strong references to in-flight alert tasks so a detached best-effort send
        # cannot be garbage-collected before it runs.
        self._alert_tasks: set[asyncio.Task] = set()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an AccessToken on exact match, else None (→ 401 before dispatch)."""
        # F-04: compare as UTF-8 bytes. hmac.compare_digest on two str operands raises
        # TypeError if either holds non-ASCII — a non-ASCII bearer would 500 instead of a
        # clean 401. Bytes are always comparable, keeping the path fail-closed and quiet.
        if not token or not hmac.compare_digest(token.encode(), self._expected_token.encode()):
            if self._register_failure_and_check(time.monotonic()):
                self._fire_burst_alert(len(self._recent_401s))
            return None
        claims: dict[str, Any] = {"agent_id": self._agent_id}
        return AccessToken(
            token=token,
            client_id=self._agent_id,
            scopes=[],
            expires_at=None,
            claims=claims,
        )

    def _register_failure_and_check(self, now: float) -> bool:
        """Record a 401 at ``now`` and return True iff a rate-limited alert should fire.

        Pure and synchronous (monotonic clock injected) so the burst logic is unit
        testable without real time or network. Prunes the sliding window, tests the
        threshold, and enforces the cooldown — updating the last-alert stamp only when
        it returns True.
        """
        self._recent_401s.append(now)
        cutoff = now - self._BURST_WINDOW_SECONDS
        while self._recent_401s and self._recent_401s[0] < cutoff:
            self._recent_401s.popleft()

        if len(self._recent_401s) < self._BURST_THRESHOLD:
            return False
        if (
            self._last_alert_monotonic is not None
            and now - self._last_alert_monotonic < self._BURST_COOLDOWN_SECONDS
        ):
            return False
        self._last_alert_monotonic = now
        return True

    def _fire_burst_alert(self, count: int) -> None:
        """Schedule a best-effort ops alert without blocking the 401 response.

        Fire-and-forget: send_ops_alert swallows all its own errors, so the detached
        task can never surface an unhandled exception.
        """
        _log.warning(
            "bearer_auth_401_burst",
            agent_id=self._agent_id,
            count_in_window=count,
            window_seconds=self._BURST_WINDOW_SECONDS,
        )
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no loop (shouldn't happen under http transport) — skip

        async def _send() -> None:
            from .ops_alert import send_ops_alert

            await send_ops_alert(
                "bearer_auth_401_burst",
                {
                    "agent_id": self._agent_id,
                    "agent_type": self._agent_type,
                    "count_in_window": count,
                    "window_seconds": self._BURST_WINDOW_SECONDS,
                },
            )

        task = loop.create_task(_send())
        self._alert_tasks.add(task)
        task.add_done_callback(self._alert_tasks.discard)
