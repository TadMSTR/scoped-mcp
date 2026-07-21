"""HTTP surface for the in-session HITL approval flow (SMCP-14, Phase B).

Registers ``POST /hitl/approve``, ``POST /hitl/deny`` and ``GET /hitl/pending``
on the agent's scoped-mcp HTTP server. The matrix-hitl-bot calls these after a
gated tool is rejected, so the operator can approve by replying in Matrix
without the requesting agent ever touching the approval path.

SECURITY — these routes authenticate themselves. FastMCP ``custom_route``
handlers are *unauthenticated by design* (see ``_register_health_route``): the
``BearerTokenVerifier`` only guards ``/mcp`` tool dispatch, so it does NOT cover
custom routes. Each handler therefore enforces its own bearer check against a
**dedicated** secret, ``SCOPED_MCP_HITL_TOKEN`` — distinct from the MCP tool
bearer. Only the trusted bot/courier holds it; the requesting agent never does.
The endpoint is reachable only on the loopback bind the HTTP transport already
enforces.

Fail-closed: a missing endpoint secret returns 503; any unexpected error returns
503 (deny). The handler never falls through to an approval on error.
"""

from __future__ import annotations

import hmac
import os
import re
from typing import TYPE_CHECKING, Any

import structlog

from . import hitl_endpoint
from .state import StateBackend

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from .identity import AgentContext

_log = structlog.get_logger("audit")

_HITL_TOKEN_ENV = "SCOPED_MCP_HITL_TOKEN"

# endpoint result status -> HTTP status code
_STATUS_CODES = {
    "approved": 200,
    "denied": 200,
    "not_found": 404,
    "already_decided": 409,
    "invalid_otp": 403,
}

# SMCP-37: deployed AGENT_ID carries a forward-compat clone-pool suffix
# (e.g. "sysadmin-01") that matrix-hitl-bot's config doesn't know about.
# Strip it before comparing so config can use the stable bare name.
_CLONE_SUFFIX_RE = re.compile(r"-\d+$")


def _normalize_agent_id(agent_id: str) -> str:
    """Strip a trailing clone-pool numeric suffix (e.g. "-01") for alias comparison."""
    return _CLONE_SUFFIX_RE.sub("", agent_id)


def _check_bearer(request: Any) -> tuple[bool, int]:
    """Validate the endpoint bearer. Returns (ok, http_status_on_failure).

    (True, 200) on success; (False, 503) when the endpoint secret is unset
    (misconfigured => fail-closed); (False, 401) on a missing/bad token.
    """
    expected = os.environ.get(_HITL_TOKEN_ENV, "").strip()
    if not expected:
        return False, 503
    header = request.headers.get("authorization", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        return False, 401
    presented = header[len(prefix) :].strip()
    if not presented or not hmac.compare_digest(presented.encode(), expected.encode()):
        return False, 401
    # SECURITY[accepted]: the 401 here is a stale/unused status on the success path —
    # the caller (_authed) discards the second tuple element when ok=True, so it never
    # reaches a response. Cosmetic only, no auth impact.
    # Audit: 2026-07-17/hitl-approval-flow-2026-07.
    return True, 401


def register_hitl_routes(server: FastMCP, state: StateBackend, agent_ctx: AgentContext) -> None:
    """Attach the /hitl/* routes to the HTTP server for this agent."""
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    if not os.environ.get(_HITL_TOKEN_ENV, "").strip():
        # Register anyway (so requests get a clean 503, not a 404) but warn loudly:
        # HITL is configured yet the approve endpoint has no secret, so the bot
        # cannot approve until the operator sets SCOPED_MCP_HITL_TOKEN.
        _log.warning(
            "hitl_endpoint_token_unset",
            detail=f"{_HITL_TOKEN_ENV} not set — approve endpoint will 503",
        )

    agent_id = agent_ctx.agent_id

    async def _authed(request: Request) -> JSONResponse | None:
        ok, code = _check_bearer(request)
        if not ok:
            if code == 503:
                _log.error("hitl_endpoint_misconfigured", detail=f"{_HITL_TOKEN_ENV} unset")
            return JSONResponse({"error": "unauthorized"}, status_code=code)
        return None

    @server.custom_route("/hitl/approve", methods=["POST"])
    async def hitl_approve(request: Request) -> JSONResponse:
        denied = await _authed(request)
        if denied is not None:
            return denied
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        approval_id = (body or {}).get("approval_id", "")
        otp = (body or {}).get("otp")  # None => Phase 1 trusted-bot form
        if not approval_id or not isinstance(approval_id, str):
            return JSONResponse({"error": "approval_id required"}, status_code=400)
        try:
            # Tag the audit channel: an OTP means the Phase 2 courier form, its
            # absence the Phase 1 trusted matrix-hitl-bot. Either way it is the
            # real out-of-band path, distinct from interactive_self_service.
            via = "courier" if otp else "matrix_bot"
            result = await hitl_endpoint.approve(
                state, agent_id, approval_id, otp=otp, resolved_via=via
            )
        except Exception as e:  # fail-closed — a backend error must deny, never approve
            _log.error(
                "hitl_approve_backend_error", approval_id=approval_id, error=type(e).__name__
            )
            return JSONResponse({"error": "backend_unavailable"}, status_code=503)
        return JSONResponse(result, status_code=_STATUS_CODES.get(result["status"], 500))

    @server.custom_route("/hitl/deny", methods=["POST"])
    async def hitl_deny(request: Request) -> JSONResponse:
        denied = await _authed(request)
        if denied is not None:
            return denied
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid_json"}, status_code=400)
        approval_id = (body or {}).get("approval_id", "")
        if not approval_id or not isinstance(approval_id, str):
            return JSONResponse({"error": "approval_id required"}, status_code=400)
        try:
            result = await hitl_endpoint.deny(
                state, agent_id, approval_id, resolved_via="matrix_bot"
            )
        except Exception as e:  # fail-closed
            _log.error("hitl_deny_backend_error", approval_id=approval_id, error=type(e).__name__)
            return JSONResponse({"error": "backend_unavailable"}, status_code=503)
        return JSONResponse(result, status_code=_STATUS_CODES.get(result["status"], 500))

    @server.custom_route("/hitl/pending", methods=["GET"])
    async def hitl_pending(request: Request) -> JSONResponse:
        denied = await _authed(request)
        if denied is not None:
            return denied
        # agent_id query param is advisory — this process serves one agent, and
        # list_pending filters to it regardless. A mismatch yields an empty list.
        # SMCP-37: accept either an exact match or a match after stripping each
        # side's clone-pool suffix, so a caller using the bare alias still lines up.
        want = request.query_params.get("agent_id")
        if want and want != agent_id and _normalize_agent_id(want) != _normalize_agent_id(agent_id):
            return JSONResponse({"agent_id": agent_id, "pending": []}, status_code=200)
        try:
            pending = await hitl_endpoint.list_pending(state, agent_id)
        except Exception as e:  # fail-closed
            _log.error("hitl_pending_backend_error", error=type(e).__name__)
            return JSONResponse({"error": "backend_unavailable"}, status_code=503)
        return JSONResponse({"agent_id": agent_id, "pending": pending}, status_code=200)

    _log.info(
        "hitl_endpoint_registered",
        agent_id=agent_id,
        routes=["/hitl/approve", "/hitl/deny", "/hitl/pending"],
    )


__all__ = ["register_hitl_routes"]
