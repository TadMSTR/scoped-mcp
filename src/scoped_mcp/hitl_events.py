"""HITL lifecycle events for agent-bus: requested, approved, refused, closed.

Off by default. Turned on by ``audit.agent_bus_hitl_emit: true`` (which requires
``audit.agent_bus_comms_dir``). When on, each event is one JSON file written to
``<agent_bus_comms_dir>/outbox/scoped-mcp/``. agent-bus drains that directory into its
hash-chained cross-agent log (agent-bus README, "Producer Outboxes"). This package does not
depend on agent-bus: the file contract is six fields, and this module is one of its
independent writers.

WHY AN OUTBOX AND NOT ``audit._emit_agent_bus_event``. That function appends a raw line
to the *session* log with no lock and no hash chain. It is fine for ``tool.called``, which
is session-scoped and high-volume. A cross-agent event written that way would break
agent-bus's ``verify_chain``. The outbox keeps agent-bus as the only writer of its chained
log.

NO ARGUMENT VALUES, EVER. At the request site, ``kwargs``, the redacted summary and the
signed record's canonical ``arguments`` are all in scope. The emit helpers below take only
the named primitive fields; none accepts a mapping, a summary or a record. The
request event carries ``args_sha256_prefix`` (12 hex), enough to tell two requests apart and
nothing more. ``tests/test_hitl_events.py`` drives request, approve, consume, deny and
reconcile with a sentinel argument value under signing ``off``, ``observe`` and
``enforce``, and asserts the sentinel's bytes are in no outbox file.

A FAILED EMIT NEVER CHANGES THE GATE'S DECISION. Every helper swallows its own errors and
returns None. The write runs in an executor so a slow disk cannot stall the event loop.

BUS EVENTS ARE DISPLAY-ONLY. Any process running as the bus's uid can write an outbox file.
Nothing may approve from ``hitl.requested``: an approval comes from the pending record in
the state backend and a signed statement (``hitl_signing``), never from the bus.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import threading
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog

_log = structlog.get_logger("audit")

SOURCE = "scoped-mcp"
OUTBOX_SUBDIR = ("outbox", "scoped-mcp")
SUMMARY_CHARS = 300
FIELD_CHARS = 128
ARGS_PREFIX_CHARS = 12

# Written by the approver on deny, read by the reconcile. TTL long enough to outlive any
# pending request (default timeout 300 s, plus the signed-token grace below).
DENY_TOMBSTONE_TTL_SECONDS = 3600

# A request still `pending` after its timeout may have been approved and signed at the last
# moment; the signed token then stays valid for up to hitl_signing.MAX_LIFETIME_SECONDS
# (120 s). Reconcile waits that long past the timeout before calling it expired, so it never
# closes a request whose approval is still redeemable.
EXPIRY_GRACE_SECONDS = 120

RECONCILE_INTERVAL_SECONDS = 30

_outbox: Path | None = None
_stamp_lock = threading.Lock()
_last_stamp: datetime | None = None


def deny_tombstone_key(approval_id: str) -> str:
    """State key the approver sets on deny, so a deny is distinguishable from expiry."""
    return f"hitl:denied:{approval_id}"


def configure_hitl_events(*, enabled: bool, comms_dir: str | None) -> None:
    """Set the outbox from the manifest. Call once at startup, before the middleware."""
    global _outbox
    if enabled and comms_dir:
        _outbox = Path(comms_dir).expanduser().joinpath(*OUTBOX_SUBDIR)
    else:
        _outbox = None


def is_enabled() -> bool:
    return _outbox is not None


def _short(value: Any) -> Any:
    if isinstance(value, str) and len(value) > FIELD_CHARS:
        return value[:FIELD_CHARS]
    return value


def _next_stamp() -> datetime:
    """Strictly increasing within the process, so drain order is emit order."""
    global _last_stamp
    with _stamp_lock:
        now = datetime.now(UTC)
        if _last_stamp is not None and now <= _last_stamp:
            now = _last_stamp + timedelta(microseconds=1)
        _last_stamp = now
        return now


def _write(outbox: Path, event: str, summary: str, metadata: dict[str, Any]) -> None:
    outbox.mkdir(mode=0o700, parents=True, exist_ok=True)
    now = _next_stamp()
    eid = str(uuid.uuid4())
    body = {
        "id": eid,
        "ts": now.isoformat(),
        "event": event,
        "source": SOURCE,
        "target": None,
        "summary": summary[:SUMMARY_CHARS],
        "metadata": {k: _short(v) for k, v in metadata.items() if v is not None},
    }
    tmp = outbox / f".tmp-{eid}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(body, f, ensure_ascii=False)
    os.rename(tmp, outbox / f"{now.strftime('%Y%m%dT%H%M%S.%f')}-{eid}.json")


async def _emit(event: str, summary: str, metadata: dict[str, Any]) -> None:
    outbox = _outbox
    if outbox is None:
        return
    try:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _write, outbox, event, summary, metadata)
    except Exception as e:  # never let emission touch the gate
        _log.warning("hitl_event_emit_failed", hitl_event=event, error=type(e).__name__)


# ── the four events: fixed fields only ──────────────────────────────────────


async def requested(
    *,
    approval_id: str,
    agent_id: str,
    agent_type: str,
    tool: str,
    args_sha256: str,
    timeout_seconds: int,
    signing_mode: str,
) -> None:
    expires_at = (datetime.now(UTC) + timedelta(seconds=timeout_seconds)).isoformat()
    await _emit(
        "hitl.requested",
        f"HITL approval requested: {tool} ({agent_id})",
        {
            "approval_id": approval_id,
            "agent_id": agent_id,
            "agent_type": agent_type,
            "tool": tool,
            "args_sha256_prefix": args_sha256[:ARGS_PREFIX_CHARS],
            "expires_at": expires_at,
            "signing_mode": signing_mode,
        },
    )


# hitl._generate_approval_id's shape, as hitl_approver.parse_approval_id checks it. On the
# unsigned (off/observe) path the id comes out of a token value the agent could have
# written, so anything else is dropped rather than carried into an event.
_APPROVAL_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\.[0-9a-f]{12}\Z")


async def approved(*, approval_id: str | None, agent_id: str, tool: str, signing_mode: str) -> None:
    if not (isinstance(approval_id, str) and _APPROVAL_ID_RE.match(approval_id)):
        approval_id = None
    await _emit(
        "hitl.approved",
        f"HITL approval used: {tool} ({agent_id})",
        {
            "approval_id": approval_id,
            "agent_id": agent_id,
            "tool": tool,
            "signing_mode": signing_mode,
        },
    )


async def refused(
    *, agent_id: str, tool: str, reason: str, accepted: bool, signing_mode: str
) -> None:
    """A presented approval token failed verification. No approval_id: it is unverified."""
    await _emit(
        "hitl.refused",
        f"HITL approval token refused ({reason}): {tool} ({agent_id})",
        {
            "agent_id": agent_id,
            "tool": tool,
            "reason": reason,
            "accepted": accepted,
            "signing_mode": signing_mode,
        },
    )


async def closed(*, approval_id: str, agent_id: str, tool: str, outcome: str) -> None:
    """A request that will never be used: ``denied`` or ``expired``."""
    await _emit(
        "hitl.closed",
        f"HITL request {outcome}: {tool} ({agent_id})",
        {"approval_id": approval_id, "agent_id": agent_id, "tool": tool, "outcome": outcome},
    )


# ── reconcile: the only way a deny-by-approver or an expiry becomes visible ──


class HitlReconciler:
    """Close this agent's stale ``pending`` audit rows and say so.

    Until this existed, expiry was the state backend's TTL silently removing keys. A deny
    through ``scoped-mcp-approve --deny`` deleted keys from another uid and told the broker
    nothing. In both cases the ``hitl_approvals`` row stayed ``pending`` for ever.

    Every RECONCILE_INTERVAL_SECONDS, for this agent only:
      - a pending row with a deny tombstone is resolved ``denied``, at once;
      - a pending row older than its timeout plus EXPIRY_GRACE_SECONDS is ``expired``.
    The update is guarded on ``state = 'pending'``. Two processes serving one agent (the
    stdio launcher) therefore cannot both resolve a row, and only the one that did emits
    ``hitl.closed``. Requires the registry (``AGENT_REGISTRY_DSN``); without it there are
    no rows and nothing to do.
    """

    def __init__(
        self,
        state: Any,
        agent_id: str,
        interval: float = RECONCILE_INTERVAL_SECONDS,
        registry_getter: Any = None,
    ) -> None:
        self._state = state
        self._agent_id = agent_id
        self._interval = interval
        self._registry_getter = registry_getter
        self._task: asyncio.Task | None = None

    async def _registry(self) -> Any:
        if self._registry_getter is not None:
            return await self._registry_getter()
        from .registry_db import get_registry

        return await get_registry()

    async def reconcile_once(self) -> int:
        """One pass. Returns the number of rows this process closed."""
        registry = await self._registry()
        if not registry.enabled:
            return 0
        rows = await registry.list_pending_hitl(self._agent_id, EXPIRY_GRACE_SECONDS)
        closed_count = 0
        for row in rows:
            approval_id = row["approval_id"]
            denied = False
            with contextlib.suppress(Exception):
                denied = await self._state.get(deny_tombstone_key(approval_id)) is not None
            if denied:
                outcome, via = "denied", "signed_approver"
            elif row["overdue"]:
                outcome, via = "expired", "reconcile"
            else:
                continue
            if await registry.resolve_hitl_approval(
                approval_id, outcome, expected_state="pending", resolved_via=via
            ):
                closed_count += 1
                await closed(
                    approval_id=approval_id,
                    agent_id=self._agent_id,
                    tool=row["tool_name"],
                    outcome=outcome,
                )
        return closed_count

    async def _run(self) -> None:
        while True:
            # Sleep first: the loop starts on a tool call, and that call's own request
            # cannot be stale yet.
            await asyncio.sleep(self._interval)
            try:
                await self.reconcile_once()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                _log.warning("hitl_reconcile_failed", error=type(e).__name__)

    def ensure_started(self) -> None:
        """Start the loop on the running event loop, once. Safe to call on every tool call."""
        if self._task is not None and not self._task.done():
            return
        try:
            self._task = asyncio.get_running_loop().create_task(
                self._run(), name="scoped-mcp-hitl-reconcile"
            )
        except RuntimeError:
            self._task = None  # no running loop (sync test path); try again next call

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None
