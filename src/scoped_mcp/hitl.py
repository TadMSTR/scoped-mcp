"""Human-in-the-loop approval middleware (v1.1 — reject-then-wait).

When an agent calls a tool whose name matches an ``approval_required`` glob
pattern, the proxy rejects the call immediately, writes a payload to the
shared state backend, and sends a notification to the configured operator
channel. The agent receives a ``HitlRejectedError`` containing the approval
ID and retry instructions.

The operator approves via the CLI (``scoped-mcp hitl approve <id>``), which
writes a one-time pre-approval token to state. On the agent's next call to
the same tool, the middleware finds the token, consumes it (deletes it), and
forwards the call upstream.

This replaces the v1.0 suspend-and-wait design, which blocked the MCP
connection while waiting for a pub/sub decision. In a Claude session, the
blocked tool call prevented any other tools from running — including the
CLI approval command — causing a session deadlock.

When the tool name matches a ``shadow`` pattern, the call is logged with a
sanitised argument summary and returns a synthetic empty-success response
without ever reaching the underlying module — useful for observing what an
agent would do before enabling a tool.

Approval ID format: ``"{agent_id}.{uuid_hex_12}"``. Encoding the agent_id
into the user-visible ID lets the operator CLI find the agent's prefix in
Dragonfly without a separate lookup key. The UUID portion makes the ID
unguessable.

State keys (under the agent-scoped prefix in DragonflyBackend):
- ``hitl:{approval_id}`` — JSON payload, TTL = ``timeout_seconds``
- ``hitl:preapproved:{tool_name}:{args_hash}`` — one-time approval token,
  TTL = ``PREAPPROVAL_TTL_SECONDS``

Security invariants:
- Argument values pass through ``audit._sanitize_value`` before notification
  or storage. Operators see redacted summaries, never raw values.
- The agent-facing rejection message is generic — it does not reveal which
  pattern matched or any operator-side reasoning beyond the approval ID.
- HITL fails closed: backend errors during ``set_with_ttl`` bubble up to the
  agent as a ``HitlRejectedError`` rather than silently forwarding the call.
- Pre-approval tokens are one-time-use: consumed on first matching retry.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import secrets
import time
import uuid
from collections.abc import Callable
from typing import Any

import structlog

from .audit import _sanitize_value
from .exceptions import HitlRejectedError
from .hitl_notify import Notifier
from .state import StateBackend

_log = structlog.get_logger("audit")

# Length of the random portion of the approval ID — short enough to be
# easily quoted in a notification, long enough (48 bits) to be unguessable
# under the lifetime of a single approval window.
_APPROVAL_ID_HEX_LEN = 12

# TTL for the pre-approval token written by the CLI on approve. Must be long
# enough for the agent to retry after receiving the approval notification,
# but short enough that stale tokens don't accumulate.
# Set to 300 s (matching the default hitl.timeout_seconds) so the agent has
# the full approval window to retry — 60 s was too short for a Claude session
# where the agent may do several reasoning steps before retrying.
PREAPPROVAL_TTL_SECONDS = 300

# Synthetic response returned for shadow-mode calls.
_SHADOW_RESPONSE: dict[str, Any] = {
    "shadow": True,
    "message": "tool call shadowed — no upstream invocation",
}


def _build_arguments_summary(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Apply audit redaction to every argument value for operator-facing display.

    Reuses the structlog sanitiser to honour the same redaction rules as the
    rest of the audit pipeline (sensitive keys redacted, long strings
    truncated, JWT/bearer/vault tokens stripped from free text).
    """
    return {k: _sanitize_value(v, k) for k, v in kwargs.items()}


def _generate_approval_id(agent_id: str) -> str:
    suffix = uuid.uuid4().hex[:_APPROVAL_ID_HEX_LEN]
    return f"{agent_id}.{suffix}"


def _canonical_args_hash(kwargs: dict[str, Any]) -> str:
    """Stable 16-char hex hash of tool call arguments for pre-approval binding.

    Binds the pre-approval token to the exact arguments the operator saw, so
    approving ``run_command(command="ls")`` cannot authorize a later call with
    different arguments during the 60-second TTL window (H-01).

    Uses sorted keys for stability and ``default=str`` to handle non-JSON-serializable
    values deterministically. Fails to "unhashable" on serialisation error — callers
    treat this as a cache miss and re-trigger approval.
    """
    try:
        canonical = json.dumps(kwargs, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]
    except Exception:
        return "unhashable"


def _preapproval_key(tool_name: str, args_hash: str) -> str:
    """State key for a one-time pre-approval token bound to (tool, args)."""
    return f"hitl:preapproved:{tool_name}:{args_hash}"


# Entropy for the one-time approval token (OTP). token_urlsafe(32) is 256 bits,
# well above the 128-bit floor in the plan, and URL-safe so a courier can paste
# it into CloudCLI without escaping (Phase 2).
_OTP_BYTES = 32


def _otp_key(approval_id: str) -> str:
    """State key for the one-time approval token bound to an approval_id.

    The plaintext OTP lives ONLY here (Dragonfly, agent-scoped, short TTL). It is
    never placed in the operator notification, because the requesting agent can
    read its own notify room — the single most important invariant of the design.
    Only its hash is persisted to the Postgres audit row.
    """
    return f"hitl:otp:{approval_id}"


def _generate_otp() -> str:
    return secrets.token_urlsafe(_OTP_BYTES)


class HitlMiddleware:
    """Tool-call middleware enforcing approval and shadow-mode policy."""

    def __init__(
        self,
        state: StateBackend,
        agent_id: str,
        agent_type: str,
        approval_required: list[str],
        shadow: list[str],
        timeout_seconds: int,
        notifier: Notifier,
    ) -> None:
        self._state = state
        self._agent_id = agent_id
        self._agent_type = agent_type
        self._approval_patterns = list(approval_required)
        self._shadow_patterns = list(shadow)
        self._timeout = timeout_seconds
        self._notifier = notifier

    @staticmethod
    def _matches(tool_name: str, patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(tool_name, p) for p in patterns)

    async def __call__(
        self,
        agent_ctx: Any,
        tool_name: str,
        kwargs: dict[str, Any],
        call_next: Callable[[], Any],
    ) -> Any:
        # Shadow takes precedence — if a tool is shadowed AND in approval_required,
        # we never want to forward the call regardless of the operator decision.
        if self._matches(tool_name, self._shadow_patterns):
            return await self._handle_shadow(tool_name, kwargs)

        if self._matches(tool_name, self._approval_patterns):
            return await self._handle_approval(tool_name, kwargs, call_next)

        return await call_next()

    async def _handle_shadow(self, tool_name: str, kwargs: dict[str, Any]) -> Any:
        summary = _build_arguments_summary(kwargs)
        _log.warning(
            "hitl_shadowed",
            agent_id=self._agent_id,
            tool=tool_name,
            arguments_summary=summary,
        )
        return _SHADOW_RESPONSE

    async def _handle_approval(
        self,
        tool_name: str,
        kwargs: dict[str, Any],
        call_next: Callable[[], Any],
    ) -> Any:
        # Check for a pre-approval token written by the operator CLI after
        # approving a previous rejected call for this tool.
        # The token is bound to (tool_name, args_hash) so approving one call
        # cannot authorize a different call with different arguments (H-01).
        args_hash = _canonical_args_hash(kwargs)
        pre_key = _preapproval_key(tool_name, args_hash)
        preapproved = await self._state.get(pre_key)
        if preapproved is not None:
            # Consume the token — one-time use only.
            await self._state.delete(pre_key)
            _log.warning(
                "hitl_preapproved",
                agent_id=self._agent_id,
                tool=tool_name,
            )
            return await call_next()

        # No pre-approval found — register the request and reject immediately.
        approval_id = _generate_approval_id(self._agent_id)
        approval_key = f"hitl:{approval_id}"
        summary = _build_arguments_summary(kwargs)

        payload = json.dumps(
            {
                "tool": tool_name,
                "agent_id": self._agent_id,
                "agent_type": self._agent_type,
                "arguments_summary": summary,
                "args_hash": args_hash,
                "approval_id": approval_id,
                "timestamp": time.time(),
                "timeout_seconds": self._timeout,
            }
        )

        # Mint the one-time approval token (OTP). It is written to the SAME
        # backend, inside the same fail-closed try, so a backend outage denies the
        # call rather than leaving an approvable request with no token. The OTP is
        # stored server-side only; it is NEVER sent to the notification channel.
        otp = _generate_otp()
        otp_key = _otp_key(approval_id)

        try:
            await self._state.set_with_ttl(approval_key, payload, self._timeout)
            await self._state.set_with_ttl(otp_key, otp, self._timeout)
        except Exception as e:
            _log.error(
                "hitl_state_write_failed",
                approval_id=approval_id,
                error=type(e).__name__,
            )
            # Don't chain via ``from e`` — the underlying exception type is an
            # operational fingerprint we should not surface to the agent.
            raise HitlRejectedError("approval rejected: state backend unavailable") from None

        # Best-effort audit row (fail-open): only the OTP *hash* is persisted, so
        # the audit table can never be used to replay an approval. A DB outage must
        # not turn a correct reject into an error — the security decision is already
        # enforced by the Dragonfly OTP above.
        try:
            from .registry_db import get_registry, hash_otp

            registry = await get_registry()
            await registry.insert_hitl_approval(
                approval_id=approval_id,
                agent_id=self._agent_id,
                tool_name=tool_name,
                state="pending",
                token_hash=hash_otp(otp),
                ttl_seconds=self._timeout,
            )
        except Exception as e:  # fail-open — audit must never block the reject
            _log.warning("hitl_audit_write_failed", approval_id=approval_id, error=type(e).__name__)

        _log.warning(
            "hitl_approval_pending",
            approval_id=approval_id,
            agent_id=self._agent_id,
            tool=tool_name,
            arguments_summary=summary,
            timeout_seconds=self._timeout,
        )

        # Notify the operator. A buggy or third-party notifier that raises must
        # not propagate out of the middleware — log and continue to the rejection.
        try:
            await self._notifier.notify(
                approval_id=approval_id,
                tool_name=tool_name,
                agent_id=self._agent_id,
                agent_type=self._agent_type,
                arguments_summary=summary,
                timeout_seconds=self._timeout,
            )
        except Exception as e:
            _log.error(
                "hitl_notifier_failed",
                approval_id=approval_id,
                error=type(e).__name__,
            )

        # Reject immediately — do not block the MCP connection waiting for
        # a pub/sub decision. The agent should surface the approval_id to the
        # operator, wait for the approval notification, then retry the call.
        raise HitlRejectedError(
            f"Tool call to {tool_name!r} requires operator approval "
            f"(approval ID: {approval_id}). "
            f"Run: scoped-mcp hitl approve {approval_id} — then retry this tool call."
        )


def build_hitl_middleware(
    hitl_cfg: Any,
    state: StateBackend,
    agent_id: str,
    agent_type: str,
) -> HitlMiddleware:
    """Construct a HitlMiddleware from manifest config + runtime context.

    hitl_cfg is the validated HitlConfig pydantic model.
    """
    from .hitl_notify import build_notifier

    return HitlMiddleware(
        state=state,
        agent_id=agent_id,
        agent_type=agent_type,
        approval_required=hitl_cfg.approval_required,
        shadow=hitl_cfg.shadow,
        timeout_seconds=hitl_cfg.timeout_seconds,
        notifier=build_notifier(hitl_cfg.notify),
    )
