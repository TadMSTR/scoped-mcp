"""Transport-agnostic HITL approval logic.

This is the core of the in-session approval path (SMCP-14). It operates on a
:class:`~scoped_mcp.state.StateBackend` and is deliberately independent of HTTP
so it can be unit-tested with an ``InProcessBackend``. The thin Starlette layer
in ``hitl_http.py`` handles bearer auth and maps these result dicts to status
codes.

Two callers are supported:

* **Phase 1 — the matrix-hitl-bot** presents ``{approval_id}`` after
  authenticating with the endpoint bearer. It is a *trusted actor*; it does not
  present an OTP. The requesting agent is never in this loop.
* **Phase 2 (deferred) — a CloudCLI courier** presents ``{approval_id, otp}``.
  The OTP is an unforgeable capability delivered out-of-band on a channel the
  requesting agent is not a member of. The endpoint verifies it before acting.

One-time semantics come from :meth:`StateBackend.get_delete` (GETDEL): the
pending record is claimed atomically, so a second approve of the same
``approval_id`` — or a concurrent race — resolves to ``already_decided``.

Fail-closed: the token operations run against the state backend directly. If the
backend raises, the exception propagates to ``hitl_http`` which returns 503
(deny) — it never falls through to writing a pre-approval token. The Postgres
audit update is the only fail-open part (best-effort, wrapped).
"""

from __future__ import annotations

import contextlib
import hmac
import json
import time
from typing import Any

import structlog

from . import hitl_events
from .hitl import (
    ISSUED_MARKER_DECIDED,
    ISSUED_MARKER_GRACE_SECONDS,
    PREAPPROVAL_TTL_SECONDS,
    _issued_key,
    _otp_key,
    _preapproval_key,
    is_side_key,
)
from .state import StateBackend

_log = structlog.get_logger("audit")

# Returned with status "expired", so every consumer (the interactive confirm tool, the
# HTTP endpoint) tells the agent the same next step.
EXPIRED_DETAIL = (
    "the approval request expired before it was decided; re-issue the original tool call "
    "to get a new approval id, then ask the operator again"
)

# A pending key's TTL and this process's clock are read independently; allow this much
# skew before calling a lapsed request expired.
_EXPIRY_SKEW_SECONDS = 1.0


def _pending_key(approval_id: str) -> str:
    return f"hitl:{approval_id}"


def _belongs_to_agent(approval_id: str, agent_id: str) -> bool:
    """Approval IDs are ``{agent_id}.{uuid}`` — reject IDs for another agent.

    Each scoped-mcp process serves exactly one agent, so an approval_id whose
    prefix is not this agent's is either a typo or a cross-agent probe; treat it
    as not-found rather than touching another namespace.
    """
    return "." in approval_id and approval_id.rsplit(".", 1)[0] == agent_id


def _expired() -> dict[str, Any]:
    return {"status": "expired", "detail": EXPIRED_DETAIL}


async def _lapsed_status(state: StateBackend, approval_id: str) -> str:
    """Why this agent's pending record for ``approval_id`` is gone.

    - ``already_decided``: the deny tombstone or the marker says someone decided it, or
      the record went before its time was up (only a decision removes it early);
    - ``expired``: the marker says it ran out its time undecided;
    - ``not_found``: nothing is known (a wrong id, a marker past its grace period, or a
      request issued before markers existed).

    Only ever called after _belongs_to_agent, so it never looks at another agent's ids.
    """
    from .hitl_events import deny_tombstone_key

    if await state.get(deny_tombstone_key(approval_id)) is not None:
        return "already_decided"
    raw = await state.get(_issued_key(approval_id))
    if raw is None:
        return "not_found"
    try:
        marker = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return "not_found"
    if not isinstance(marker, dict):
        return "not_found"
    if marker.get("decided"):
        return "already_decided"
    expires_at = marker.get("expires_at")
    if not isinstance(expires_at, int | float) or isinstance(expires_at, bool):
        return "not_found"
    if time.time() + _EXPIRY_SKEW_SECONDS >= expires_at:
        return "expired"
    return "already_decided"


async def _mark_decided(state: StateBackend, approval_id: str) -> None:
    """Best-effort: record that the request was decided, so a later approve says so."""
    try:
        await state.set_with_ttl(
            _issued_key(approval_id), ISSUED_MARKER_DECIDED, ISSUED_MARKER_GRACE_SECONDS
        )
    except Exception as e:
        _log.warning(
            "hitl_issued_marker_write_failed", approval_id=approval_id, error=type(e).__name__
        )


async def _resolve_audit(approval_id: str, state: str, resolved_via: str | None = None) -> None:
    """Best-effort audit state update (fail-open)."""
    try:
        from .registry_db import get_registry

        registry = await get_registry()
        await registry.resolve_hitl_approval(approval_id, state, resolved_via=resolved_via)
    except Exception as e:  # fail-open
        _log.warning("hitl_audit_resolve_failed", approval_id=approval_id, error=type(e).__name__)


async def approve(
    state: StateBackend,
    agent_id: str,
    approval_id: str,
    otp: str | None = None,
    resolved_via: str = "operator_endpoint",
) -> dict[str, Any]:
    """Approve a pending request. Returns a result dict with a ``status`` key.

    status ∈ {approved, expired, not_found, already_decided, invalid_otp}.

    ``not_found`` covers an unknown id and another agent's id alike, and the ownership
    check runs first, so a response never shows that another agent's id exists.
    ``expired`` (with ``detail`` saying to re-issue the call) means this agent issued the
    id and it ran out its time undecided, or its record cannot be bound to a call.
    ``already_decided`` means someone approved or denied it already.

    ``resolved_via`` tags the audit row with the resolution channel so a later
    audit can tell the real out-of-band path (``matrix_bot`` / ``courier``) apart
    from the in-session ``interactive_self_service`` shortcut. It changes only the
    audit label — the peek/claim/token-write logic is identical for every caller,
    so the interactive tool reuses this function rather than duplicating it.

    Backend errors are NOT caught here — they propagate so the HTTP layer fails
    closed with a 503. Only the audit write is best-effort.
    """
    if not _belongs_to_agent(approval_id, agent_id):
        return {"status": "not_found"}

    # Peek (without consuming) to learn the tool + args binding and confirm the
    # request still exists. For the courier path we verify the OTP BEFORE claiming
    # the pending record, so a bad guess cannot destroy a legitimate pending item.
    raw = await state.get(_pending_key(approval_id))
    if raw is None:
        lapsed = await _lapsed_status(state, approval_id)
        return _expired() if lapsed == "expired" else {"status": lapsed}
    try:
        payload = json.loads(raw)
        tool_name = payload.get("tool", "")
        args_hash = payload.get("args_hash", "")
    except (json.JSONDecodeError, AttributeError):
        tool_name, args_hash = "", ""

    if otp is not None:
        # Phase 2 courier form: consume the OTP (single-use) and constant-time
        # compare. Any mismatch/absence denies — fail-closed.
        # SECURITY[deferred]: get_delete consumes the OTP before the compare, so a
        # wrong guess burns the valid token (self-grief, not a bypass). Dead code
        # until Phase 2 (Phase 1 bot never sends otp). Fix before Phase 2 ships:
        # peek-then-claim or restore-on-mismatch. Target: SMCP-35.
        # Audit: 2026-07-17/hitl-approval-flow-2026-07.
        stored_otp = await state.get_delete(_otp_key(approval_id))
        if stored_otp is None or not hmac.compare_digest(otp, stored_otp):
            await _resolve_audit(approval_id, "denied", resolved_via=resolved_via)
            _log.warning("hitl_approve_invalid_otp", approval_id=approval_id, agent_id=agent_id)
            return {"status": "invalid_otp"}

    # Atomically claim the pending record — this is the one-time gate. If we lose
    # a race (or it was already decided), get_delete returns None.
    claimed = await state.get_delete(_pending_key(approval_id))
    if claimed is None:
        # Lost a race with another decision, or the TTL ran out between the peek and the
        # claim. Without a marker, the old answer stands.
        if await _lapsed_status(state, approval_id) == "expired":
            return _expired()
        return {"status": "already_decided"}

    # Phase 1 bot form never presented the OTP; invalidate it now so it can never
    # be used afterwards (a consumed approval must leave no live token behind).
    if otp is None:
        await state.delete(_otp_key(approval_id))

    if not tool_name or not args_hash:
        # Cannot bind a pre-approval token without both — refuse rather than write
        # a token the middleware will never match (which would silently never
        # approve). Audited as expired, and reported as expired too: the request can no
        # longer be approved, and re-issuing the call is the way out.
        _log.warning("hitl_approve_missing_binding", approval_id=approval_id, agent_id=agent_id)
        await _resolve_audit(approval_id, "expired", resolved_via=resolved_via)
        return _expired()

    # Write the one-time pre-approval token the middleware consumes on retry.
    # The approval_id rides along in the token value (not just "approved") so
    # the middleware can resolve the audit row to "consumed" once the token is
    # actually used (SMCP-39) — otherwise hitl_approvals.state sticks at
    # "approved" forever and a later reconcile pass re-nudges a resolved session.
    #
    # The audit row is written BEFORE the token (round 2 R2-04). In the other order, an
    # agent redeeming the token in between had its consume recorded first, and this
    # write then put the row back to "approved". If the token write fails, the row is
    # moved on to "expired" so it never claims an approval that cannot be used; the
    # exception still propagates and the HTTP layer fails closed.
    await _resolve_audit(approval_id, "approved", resolved_via=resolved_via)
    try:
        await state.set_with_ttl(
            _preapproval_key(tool_name, args_hash),
            json.dumps({"status": "approved", "approval_id": approval_id}),
            PREAPPROVAL_TTL_SECONDS,
        )
    except Exception:
        await _resolve_audit(approval_id, "expired", resolved_via=resolved_via)
        raise
    await _mark_decided(state, approval_id)
    _log.warning(
        "hitl_approved_via_endpoint",
        approval_id=approval_id,
        agent_id=agent_id,
        tool=tool_name,
        courier=otp is not None,
        resolved_via=resolved_via,
    )
    return {"status": "approved", "tool": tool_name, "agent_id": agent_id}


async def deny(
    state: StateBackend,
    agent_id: str,
    approval_id: str,
    resolved_via: str = "operator_endpoint",
) -> dict[str, Any]:
    """Deny a pending request: drop the pending record and the OTP.

    ``resolved_via`` tags the audit row with the resolution channel (see
    :func:`approve`).
    """
    if not _belongs_to_agent(approval_id, agent_id):
        return {"status": "not_found"}
    claimed = await state.get_delete(_pending_key(approval_id))
    await state.delete(_otp_key(approval_id))
    if claimed is None:
        lapsed = await _lapsed_status(state, approval_id)
        return _expired() if lapsed == "expired" else {"status": lapsed}
    await _mark_decided(state, approval_id)
    tool_name = ""
    with contextlib.suppress(json.JSONDecodeError, AttributeError):
        tool_name = json.loads(claimed).get("tool", "")
    await _resolve_audit(approval_id, "denied", resolved_via=resolved_via)
    _log.warning(
        "hitl_denied_via_endpoint",
        approval_id=approval_id,
        agent_id=agent_id,
        tool=tool_name,
        resolved_via=resolved_via,
    )
    # Resolved in-process, so it is emitted here; the reconcile skips rows that are no
    # longer pending.
    await hitl_events.closed(
        approval_id=approval_id, agent_id=agent_id, tool=tool_name, outcome="denied"
    )
    return {"status": "denied", "tool": tool_name, "agent_id": agent_id}


async def list_pending(state: StateBackend, agent_id: str) -> list[dict[str, Any]]:
    """List this agent's pending approvals (approval_id, agent_id, tool).

    Excludes the side keys (pre-approval and OTP tokens, deny tombstones, issued
    markers) that share the ``hitl:`` namespace but are not pending approvals.
    """
    out: list[dict[str, Any]] = []
    for key, value in await state.scan("hitl:*.*"):
        if is_side_key(key):
            continue
        try:
            payload = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        aid = payload.get("approval_id", "")
        if not _belongs_to_agent(aid, agent_id):
            continue
        out.append(
            {
                "approval_id": aid,
                "agent_id": payload.get("agent_id", agent_id),
                "tool": payload.get("tool", ""),
            }
        )
    return out


__all__ = ["approve", "deny", "list_pending"]
