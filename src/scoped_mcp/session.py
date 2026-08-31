"""Session attribution — tie a tool call to the run that launched the agent.

The session registry (``registry_db``) keys everything on ``sessions.session_id``.
That id is the **run id** that ``task-dispatcher`` mints per launch
(``uuid.uuid4()``) and injects into the launched agent's environment as
``FORGE_RUN_ID``. This module is how that id reaches scoped-mcp.

Why a header and not ``os.environ``
-----------------------------------
Under the deployed HTTP transport, scoped-mcp is **not** a per-session process.
``run-scoped-mcp-http.sh`` starts one long-lived PM2 process per agent, at boot,
which then serves every run that agent ever performs. ``FORGE_RUN_ID`` lives in
the environment of the ``claude`` CLI child, on the far side of a TCP socket —
reading ``os.environ`` here would find nothing, forever.

So the CLI forwards it per-request: each agent's ``.mcp.json`` sets

    "headers": {"X-Forge-Run-Id": "${FORGE_RUN_ID}",
                "X-Forge-Task-Id": "${FORGE_TASK_ID}"}

and the CLI interpolates those from the child environment, the same mechanism
``SCOPED_MCP_BEARER_TOKEN`` already rides. The ``os.environ`` fallback below is
kept for the stdio transport, where the broker *is* per-session and does inherit
the variable.

Validation is a security control, not tidiness
----------------------------------------------
**When the variable is unset the CLI sends the literal string
``${FORGE_RUN_ID}``** — not an empty header, not an absent one. Measured, not
assumed. Without the UUID check below, every interactive (non-dispatcher)
session would register one shared ``sessions`` row literally named
``${FORGE_RUN_ID}`` and every interactive approval would join to it. That turns
"unknown" into "known and wrong" in an audit column, which is exactly what the
build plan forbids for the historical backfill. ``run-steward.sh`` already
UUID-validates the same value before exporting it; this matches that.

An id that does not validate means **no launcher-minted identity**. Register
nothing, attribute nothing, leave the column NULL. Never invent an id: a
self-generated UUID is indistinguishable in the table from a real one while
carrying none of the guarantee, which converts an audit control into
self-attestation.

What is and is not trusted
--------------------------
``agent_id`` is **never** taken from a header. It stays the broker's own
``AGENT_ID`` — root-controlled via the manifest, pinned by a per-agent port and
bearer token — so *who acted* remains non-spoofable. Only the session
*correlation* rides the header, at the same trust level the launcher's
environment injection already has.

That is not sufficient on its own, and the second half of the control lives in
``registry_db.upsert_session``. A well-formed UUID is not proof of ownership:
real run ids are readable out of ``~/.claude/comms/artifacts/task-launches/``
by any agent running as the same user, and sessions are never closed, so any
historical id stays a live target. The upsert therefore refuses to relabel or
refresh a session row owned by a different ``agent_id``, and returns False —
which lands here as "not attributable" and stores NULL. See that method's
docstring for why preserving the owner alone would not have closed it.

Fail-open, like everything else in the registry path: any failure here is
logged and swallowed. Attribution is a paper trail and must never block a tool
call.
"""

from __future__ import annotations

import os
import re
import time
from collections import OrderedDict

import structlog

_log = structlog.get_logger("ops")

# Header names are matched case-insensitively; Starlette's Headers mapping is
# already case-insensitive, and these are the lowercase forms on the wire.
RUN_ID_HEADER = "x-forge-run-id"
TASK_ID_HEADER = "x-forge-task-id"

# Canonical dashed UUID. Deliberately strict: the whole point is to reject the
# literal "${FORGE_RUN_ID}" an interactive session sends, along with empty
# values and anything else that is not a launcher-minted id.
_UUID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)

# How long a registration is cached before the row is refreshed. This does two
# jobs at once: it keeps the upsert to roughly once per run rather than once per
# tool call, and it advances ``sessions.last_seen_at`` over the life of a long
# run (the liveness signal the registry previously never got — every existing
# row had last_seen_at == started_at, one of them since 2026-07-17).
REFRESH_SECONDS = 60.0

# Bound on the memo. The broker is long-lived and sees an unbounded number of
# runs over weeks, so this cannot be an unbounded set. Evicting an entry costs
# one redundant upsert, which is idempotent — there is no correctness risk in
# the eviction, only in letting the dict grow forever.
_MEMO_MAX = 512

# run_id -> monotonic timestamp of the last successful upsert.
_seen: OrderedDict[str, float] = OrderedDict()
# (run_id, task_id) pairs already linked in this process.
_linked: OrderedDict[tuple[str, str], float] = OrderedDict()


def _valid_uuid(value: str | None) -> str | None:
    """Return ``value`` if it is a canonical UUID, else None.

    Returns None for the literal ``${FORGE_RUN_ID}``, for an empty string, and
    for anything else that is not launcher-minted. See the module docstring for
    why that specific literal is the case that matters.
    """
    if not value:
        return None
    value = value.strip()
    return value if _UUID_RE.match(value) else None


def _header(name: str) -> str | None:
    """Read a header from the in-flight HTTP request, or None outside one.

    ``identity.py`` already reaches into the request context this way; the
    import is local and the failure is swallowed because there is no HTTP
    request under the stdio transport, which is a normal condition rather than
    an error.
    """
    try:
        from fastmcp.server.dependencies import get_http_request

        return get_http_request().headers.get(name)
    except Exception:
        return None


def read_run_identity() -> tuple[str | None, str | None]:
    """Return the validated ``(run_id, task_id)`` for the current call.

    Header first — that is the HTTP transport, which is what is deployed. Falls
    back to the process environment for the stdio transport, where the broker is
    spawned per session and does inherit ``FORGE_RUN_ID`` directly.

    Either element is None when absent or malformed. A malformed value is not an
    error to report to the agent; it simply means this call is not attributable.
    """
    run_id = _valid_uuid(_header(RUN_ID_HEADER)) or _valid_uuid(os.environ.get("FORGE_RUN_ID"))
    task_id = _valid_uuid(_header(TASK_ID_HEADER)) or _valid_uuid(os.environ.get("FORGE_TASK_ID"))
    return run_id, task_id


def _remember(memo: OrderedDict, key, now: float) -> None:
    memo[key] = now
    memo.move_to_end(key)
    while len(memo) > _MEMO_MAX:
        memo.popitem(last=False)


def _due(memo: OrderedDict, key, now: float, interval: float) -> bool:
    last = memo.get(key)
    return last is None or (now - last) >= interval


async def attribute_current_call(agent_id: str) -> str | None:
    """Register the current run as a session and return its id, or None.

    Returns the run id **only after** its ``sessions`` row has been written, so a
    caller can hand the value straight to a foreign key. Returns None when there
    is no launcher-minted identity (an interactive session), when the registry is
    disabled, or when the upsert failed — in every one of those cases the correct
    stored value is NULL.

    Safe to call on every tool call: the upsert is rate-limited to once per
    ``REFRESH_SECONDS`` per run id.
    """
    try:
        run_id, task_id = read_run_identity()
        if run_id is None:
            return None

        from .registry_db import get_registry

        registry = await get_registry()
        if not registry.enabled:
            return None

        now = time.monotonic()
        first_sight = run_id not in _seen
        if _due(_seen, run_id, now, REFRESH_SECONDS):
            # The bool matters. upsert_session is fail-open and swallows its own
            # errors, so without an explicit answer a failed write would still
            # yield a run id here — and the FK would then reject the approval
            # INSERT that carries it. A failed upsert degrades to None.
            if not await registry.upsert_session(
                session_id=run_id,
                agent_id=agent_id,
                transport="headless",
                status="active",
            ):
                return None
            _remember(_seen, run_id, now)
            if first_sight:
                # Once per run, not once per call — the ops log is a queried
                # artifact, and a long run makes hundreds of tool calls.
                _log.info(
                    "session_attribution_registered",
                    session_id=run_id,
                    agent_id=agent_id,
                    task_id=task_id,
                )

        # Phase 5 — link the session to the task it was launched for. Gated on the
        # session row existing (above), because session_tasks carries the same FK.
        # build_name is deliberately not passed. It is derivable only by parsing a
        # build-plan path out of the task's context_refs, and the plan is explicit
        # that a path should not be parsed into a schema column — NULL beats a
        # guess. Only memoise on a confirmed write, so a transient failure is
        # retried on the next call rather than recorded as done.
        link_due = task_id is not None and _due(_linked, (run_id, task_id), now, float("inf"))
        if link_due and await registry.insert_session_task(
            session_id=run_id, task_id=task_id, role="target"
        ):
            _remember(_linked, (run_id, task_id), now)

        return run_id
    except Exception as e:  # fail-open — attribution must never block a tool call
        _log.warning("session_attribution_failed", error=type(e).__name__)
        return None


class SessionAttributionMiddleware:
    """Register the launching run as a session on every tool call.

    Placed **after rate-limit and arg-filter, before HITL** — see
    ``server._build_middleware``, which is what actually governs the position;
    this docstring is not the source of truth for it. Both halves matter. Before
    HITL because the foreign key needs it: HITL mints its approval downstream of
    this, and an approval carrying an id with no session row would be rejected by
    ``hitl_approvals_session_id_fkey``. After the rate limiter because this
    middleware performs a database write, and running it first would put an
    unmetered write ahead of the only thing bounding call volume.

    Registering here rather than only at the HITL gate is deliberate. Most runs
    never trigger a gated call, and a registry that only learns about the runs
    that happened to need an approval could not answer "what has this agent been
    doing" — nor would ``session_tasks`` ever be populated for an ordinary build.

    Cost on the hot path is a dict lookup and a clock read; the database write is
    rate-limited to once per ``REFRESH_SECONDS`` per run, and an interactive
    session with no launcher-minted id returns before touching the registry at
    all. Never raises: ``attribute_current_call`` swallows everything.
    """

    async def __call__(self, agent_ctx, tool_name, kwargs, call_next):
        await attribute_current_call(agent_ctx.agent_id)
        return await call_next()


def _reset_for_tests() -> None:
    """Clear the process-local memos. Tests only."""
    _seen.clear()
    _linked.clear()


__all__ = [
    "RUN_ID_HEADER",
    "TASK_ID_HEADER",
    "SessionAttributionMiddleware",
    "attribute_current_call",
    "read_run_identity",
]
