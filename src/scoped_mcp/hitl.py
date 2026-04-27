"""Human-in-the-loop approval middleware (v1.0).

When an agent calls a tool whose name matches an ``approval_required`` glob
pattern, the proxy suspends the call, writes a payload to the shared state
backend, sends a notification to the configured operator channel, and waits
for an ``approve``/``reject`` decision over pub/sub. Auto-rejects after
``timeout_seconds`` with no decision.

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
- pub/sub channel: ``hitl:{approval_id}`` (same name as the storage key)

Security invariants:
- Argument values pass through ``audit._sanitize_value`` before notification
  or storage. Operators see redacted summaries, never raw values.
- The agent-facing rejection message is generic — it does not reveal which
  pattern matched or any operator-side reasoning.
- HITL fails closed: backend errors during ``set_with_ttl`` or ``publish``
  bubble up to the agent as a ``HitlRejectedError`` rather than silently
  forwarding the call.
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import json
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
            return await self._await_approval(tool_name, kwargs, call_next)

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

    async def _await_approval(
        self,
        tool_name: str,
        kwargs: dict[str, Any],
        call_next: Callable[[], Any],
    ) -> Any:
        approval_id = _generate_approval_id(self._agent_id)
        approval_key = f"hitl:{approval_id}"
        summary = _build_arguments_summary(kwargs)

        payload = json.dumps(
            {
                "tool": tool_name,
                "agent_id": self._agent_id,
                "agent_type": self._agent_type,
                "arguments_summary": summary,
                "approval_id": approval_id,
                "timestamp": time.time(),
                "timeout_seconds": self._timeout,
            }
        )

        # Subscribe BEFORE writing the key, so a fast operator decision cannot
        # arrive between the publish and our subscribe call.
        sub = self._state.subscribe(approval_key)

        try:
            await self._state.set_with_ttl(approval_key, payload, self._timeout)
        except Exception as e:
            _log.error(
                "hitl_state_write_failed",
                approval_id=approval_id,
                error=type(e).__name__,
            )
            raise HitlRejectedError(
                f"approval rejected: state backend unavailable ({type(e).__name__})"
            ) from e

        _log.warning(
            "hitl_approval_pending",
            approval_id=approval_id,
            agent_id=self._agent_id,
            tool=tool_name,
            arguments_summary=summary,
            timeout_seconds=self._timeout,
        )

        # Notify the operator. Notifier failures are logged inside the notifier
        # and do not interrupt the approval loop.
        await self._notifier.notify(
            approval_id=approval_id,
            tool_name=tool_name,
            agent_id=self._agent_id,
            agent_type=self._agent_type,
            arguments_summary=summary,
            timeout_seconds=self._timeout,
        )

        decision = await self._wait_for_decision(approval_id, sub)

        # Always clean up the approval key — TTL would handle eventually, but
        # explicit delete keeps `hitl list` tidy after a decision.
        with contextlib.suppress(Exception):
            await self._state.delete(approval_key)

        if decision == "approve":
            _log.warning(
                "hitl_approved",
                approval_id=approval_id,
                agent_id=self._agent_id,
                tool=tool_name,
            )
            return await call_next()

        # decision is "reject", "reject:<reason>", or "timeout"
        _log.warning(
            "hitl_rejected",
            approval_id=approval_id,
            agent_id=self._agent_id,
            tool=tool_name,
            decision=decision,
        )
        # Generic agent-facing message — operator-side reasoning stays in the audit log.
        raise HitlRejectedError(f"tool call to {tool_name!r} rejected by HITL approval policy")

    async def _wait_for_decision(self, approval_id: str, sub: Any) -> str:
        """Consume the subscribe stream until a decision message arrives or timeout."""
        try:
            async with asyncio.timeout(self._timeout):
                async for msg in sub:
                    if msg == "approve" or msg == "reject" or msg.startswith("reject:"):
                        return msg
                    # Unknown messages are ignored — defends against stray
                    # publishes on the channel.
                # Generator exhausted without a decision (shouldn't happen for
                # an indefinite stream, but treat as rejection).
                return "timeout"
        except TimeoutError:
            return "timeout"
        finally:
            # Best-effort close on the async generator. Some backends
            # (DragonflyBackend) need explicit aclose() to release the pubsub.
            with _suppress_all():
                await sub.aclose()  # type: ignore[union-attr]


class _suppress_all:
    """Context manager that swallows any exception — used for best-effort cleanup."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return True


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
