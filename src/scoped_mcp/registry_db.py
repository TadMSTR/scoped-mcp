"""Agent session registry — asyncpg data-access layer (fail-open).

A thin DAL over the ``agent-postgres`` session registry (see
``migrations/0001_agent_session_registry.sql``). scoped-mcp is the first
runtime consumer: it writes an *audit* row to ``hitl_approvals`` when a gated
call is rejected and updates that row's ``state`` when the approval is
resolved. The plaintext OTP is never written here — only a hash.

**Fail-open contract.** Every method in this module is best-effort. A missing
``[postgres]`` extra, an unset DSN, or any database error is caught, logged at
warning, and swallowed — it MUST NOT raise into the caller. The registry is an
observability/audit sidecar; it can never block a tool call, an approval
decision, or a memory write.

This is deliberately the opposite of the HITL *gate*, whose token lives in
Dragonfly and is fail-*closed* (a backend error there denies the call, per
security-patterns rule M1). The split is intentional: the security decision is
enforced by the Dragonfly token; this table is only the paper trail.

Configuration:
- ``AGENT_REGISTRY_DSN`` — Postgres DSN (e.g.
  ``postgresql://registry:***@127.0.0.1:5433/agent_registry``). Unset ⇒ the
  registry is disabled and every call is a no-op. Off by default, matching the
  forge MCP telemetry convention.

The P2/P3 tables (``session_tasks``, ``session_usage``, ``memory_artifacts``)
have no writer in this build; their insert helpers exist so future consumers
wire in without a schema change.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from typing import Any

import structlog

_log = structlog.get_logger("ops")

# Module-level singleton. ``_init_lock`` guards concurrent first-use so the pool
# is created exactly once even under a burst of simultaneous approvals.
_registry: RegistryDB | None = None
_init_lock: asyncio.Lock | None = None


def hash_otp(otp: str) -> str:
    """Return the hex sha256 of an OTP for audit-only storage.

    The plaintext OTP never leaves Dragonfly; only this digest is persisted, so
    the audit table cannot be used to replay an approval.
    """
    return hashlib.sha256(otp.encode()).hexdigest()


class RegistryDB:
    """asyncpg-backed session registry DAL. All writes are fail-open.

    Construct via :func:`get_registry`, which handles lazy pool creation and
    caches the singleton. A ``RegistryDB`` whose ``pool`` is ``None`` is a
    valid *disabled* instance — every method no-ops — so callers never branch
    on configuration state.
    """

    def __init__(self, pool: Any | None) -> None:
        self._pool = pool

    @property
    def enabled(self) -> bool:
        return self._pool is not None

    # -- session registry ---------------------------------------------------

    async def upsert_session(
        self,
        session_id: str,
        agent_id: str,
        transport: str,
        room_id: str | None = None,
        project_dir: str | None = None,
        scoped_mcp_url: str | None = None,
        status: str = "active",
    ) -> bool:
        """Insert or refresh a session row (used for approve-routing).

        Returns True only when this agent owns the row afterwards. The caller
        needs that answer rather than a silent no-op: ``hitl_approvals.session_id``
        and ``session_tasks.session_id`` both carry a real foreign key to this
        table, so treating a *failed* upsert as success would hand a downstream
        INSERT a dangling id. A failure must degrade to NULL, never to a dangling
        id.

        **A session id you do not already own is not your identity.**
        ``session_id`` is a bare TEXT primary key with no binding to an agent, and
        the run id reaches us in a request header validated only as a well-formed
        UUID — not as *belonging to the caller*. Real run ids are readable from
        ``~/.claude/comms/artifacts/task-launches/*.json`` by any agent running as
        the same user, and sessions are never closed, so every historical id stays
        a live target. Two consequences, both closed here:

        1. ``agent_id`` is **not** in the ``DO UPDATE SET`` list, so a second agent
           presenting the same id cannot relabel whose session it is.
        2. The update is guarded by ``WHERE sessions.agent_id = EXCLUDED.agent_id``
           and the statement ``RETURNING``s the id, so a mismatched caller gets no
           row back and this returns False. Preserving the owner alone would not
           be enough — the caller would still be handed the id and would stamp its
           own approvals with a session belonging to somebody else, which is the
           same misattribution running the other way.

        A mismatch is never legitimate: a run id is minted per launch for exactly
        one agent. It is logged at WARNING because it means a collision, a reused
        id, or an attempt to claim another agent's session.

        Refreshing ``last_seen_at`` on every call is what makes ``status`` mean
        anything. **Staleness rule:** a session whose ``last_seen_at`` has not
        advanced for longer than the HITL approval timeout is not live — its
        process is gone and the row was never closed. Nothing sweeps those yet:
        a terminal ``status`` needs the launcher's exit signal, which lives in
        task-dispatcher's run records (``run_id``/``ended``/``reaped``) and is
        tracked separately. Until then, read ``active`` as "last seen at
        ``last_seen_at``", never as "running now".
        """
        if self._pool is None:
            return False
        try:
            async with self._pool.acquire() as conn:
                owned = await conn.fetchval(
                    """
                    INSERT INTO sessions (
                        session_id, agent_id, transport, room_id, project_dir,
                        scoped_mcp_url, status, last_seen_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, now())
                    ON CONFLICT (session_id) DO UPDATE SET
                        transport      = EXCLUDED.transport,
                        room_id        = COALESCE(EXCLUDED.room_id, sessions.room_id),
                        project_dir    = COALESCE(EXCLUDED.project_dir, sessions.project_dir),
                        scoped_mcp_url = COALESCE(EXCLUDED.scoped_mcp_url, sessions.scoped_mcp_url),
                        status         = EXCLUDED.status,
                        last_seen_at   = now()
                      WHERE sessions.agent_id = EXCLUDED.agent_id
                    RETURNING session_id
                    """,
                    session_id,
                    agent_id,
                    transport,
                    room_id,
                    project_dir,
                    scoped_mcp_url,
                    status,
                )
            if owned is None:
                # The row exists and belongs to a different agent. Not an error to
                # the caller — it degrades to an unattributed approval — but it is
                # never legitimate, so say so loudly.
                _log.warning(
                    "registry_session_owner_mismatch",
                    session_id=session_id,
                    claimed_by=agent_id,
                )
                return False
            return True
        except Exception as e:  # fail-open
            _log.warning("registry_upsert_session_failed", error=type(e).__name__)
            return False

    # -- HITL audit ---------------------------------------------------------

    async def insert_hitl_approval(
        self,
        approval_id: str,
        agent_id: str,
        tool_name: str,
        state: str,
        token_hash: str | None = None,
        ttl_seconds: int | None = None,
        session_id: str | None = None,
    ) -> None:
        """Record a pending HITL approval (audit trail; token_hash only).

        Idempotent on ``approval_id`` — a retried reject that re-registers the
        same id refreshes the row rather than erroring.

        ``session_id`` is resolved through a subselect rather than inserted
        directly, so an id with no ``sessions`` row lands as NULL instead of
        raising. This is not defensive tidiness: ``hitl_approvals.session_id``
        has a real foreign key, a plain INSERT of an unknown id raises
        ``hitl_approvals_session_id_fkey``, and the fail-open ``except`` below
        would then swallow **the entire audit row** — losing the approval
        record, not merely its attribution. Verified against the live schema.
        NULL correctly means "not attributable"; a missing row means nothing at
        all was written down.
        """
        if self._pool is None:
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO hitl_approvals (
                        approval_id, session_id, agent_id, tool_name,
                        token_hash, state, ttl_seconds
                    ) VALUES (
                        $1,
                        (SELECT session_id FROM sessions WHERE session_id = $2),
                        $3, $4, $5, $6, $7
                    )
                    ON CONFLICT (approval_id) DO UPDATE SET
                        token_hash  = EXCLUDED.token_hash,
                        state       = EXCLUDED.state,
                        ttl_seconds = EXCLUDED.ttl_seconds
                    """,
                    approval_id,
                    session_id,
                    agent_id,
                    tool_name,
                    token_hash,
                    state,
                    ttl_seconds,
                )
        except Exception as e:  # fail-open
            _log.warning("registry_insert_approval_failed", error=type(e).__name__)

    async def resolve_hitl_approval(
        self,
        approval_id: str,
        state: str,
        expected_state: str | None = None,
        resolved_via: str | None = None,
    ) -> None:
        """Mark an approval resolved (approved | denied | consumed | expired).

        ``expected_state``, when given, adds a ``WHERE state = expected_state`` guard
        so this transition only applies from that specific prior state — a caller that
        transitions from a known state (e.g. hitl.py's consume-time approved->consumed)
        should always pass it, so a race against some other resolution of the same row
        becomes a logged no-op instead of silently clobbering a terminal state.
        Left unguarded (None, the default) for callers that legitimately resolve from
        the initial "pending" state without knowing it in advance (hitl_endpoint.py's
        approve/deny paths) — passing "pending" there would be redundant with the
        Dragonfly get_delete claim that already makes that transition exactly-once.

        ``resolved_via``, when given, records the resolution channel (e.g.
        ``matrix_bot``, ``courier``, ``interactive_self_service``) in the audit row.
        Left None (the default) for callers that don't know or don't want to change it
        — notably hitl.py's approved->consumed transition, which must preserve the
        channel recorded at approve time — so the column is only written when a caller
        explicitly supplies it, never clobbered back to NULL on a later transition.
        """
        if self._pool is None:
            return
        try:
            async with self._pool.acquire() as conn:
                # Build the base SET/WHERE + params, then append resolved_via only
                # when supplied — a NULL param would overwrite the approve-time
                # channel on a later consume/expire transition.
                params: list[Any] = [approval_id, state]
                where = "approval_id = $1"
                if expected_state is not None:
                    params.append(expected_state)
                    where += f" AND state = ${len(params)}"
                via_clause = ""
                if resolved_via is not None:
                    params.append(resolved_via)
                    via_clause = f", resolved_via = ${len(params)}"
                result = await conn.execute(
                    f"""
                    UPDATE hitl_approvals
                       SET state = $2, resolved_at = now(){via_clause}
                     WHERE {where}
                    """,
                    *params,
                )
                if expected_state is not None and result == "UPDATE 0":
                    _log.warning(
                        "registry_resolve_approval_state_mismatch",
                        approval_id=approval_id,
                        target_state=state,
                        expected_state=expected_state,
                    )
        except Exception as e:  # fail-open
            _log.warning("registry_resolve_approval_failed", error=type(e).__name__)

    # -- P2/P3 (no writer yet; present for forward consumers) ---------------

    async def insert_session_task(
        self,
        session_id: str,
        task_id: str,
        role: str,
        build_name: str | None = None,
    ) -> bool:
        """Link a session to the task it was launched for. Returns True on write.

        Idempotent by ``NOT EXISTS`` rather than by ``ON CONFLICT``: the table has
        no unique constraint on ``(session_id, task_id)`` and this build must not
        add schema, so the guard lives in the statement. That makes the link
        survive a broker restart without duplicating, which an in-process memo
        alone would not. Two concurrent inserts of the same pair could still race
        past the check — harmless for an audit sidecar with one broker process per
        agent, and a duplicate row here misleads nobody.
        """
        if self._pool is None:
            return False
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO session_tasks (session_id, task_id, role, build_name)
                    SELECT $1, $2, $3, $4
                     WHERE NOT EXISTS (
                           SELECT 1 FROM session_tasks
                            WHERE session_id = $1 AND task_id = $2
                     )
                    """,
                    session_id,
                    task_id,
                    role,
                    build_name,
                )
            return True
        except Exception as e:  # fail-open
            _log.warning("registry_insert_session_task_failed", error=type(e).__name__)
            return False

    async def insert_memory_artifact(
        self,
        session_id: str,
        artifact_type: str,
        ref: str,
        tier: str | None = None,
    ) -> None:
        if self._pool is None:
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO memory_artifacts (session_id, artifact_type, ref, tier)
                    VALUES ($1, $2, $3, $4)
                    """,
                    session_id,
                    artifact_type,
                    ref,
                    tier,
                )
        except Exception as e:  # fail-open
            _log.warning("registry_insert_memory_artifact_failed", error=type(e).__name__)

    async def close(self) -> None:
        if self._pool is None:
            return
        try:
            await self._pool.close()
        except Exception as e:  # fail-open
            _log.warning("registry_close_failed", error=type(e).__name__)
        finally:
            self._pool = None


async def _build_pool(dsn: str) -> Any | None:
    """Create an asyncpg pool, or return None on any failure (fail-open)."""
    try:
        import asyncpg  # local import — optional [postgres] extra
    except ImportError:
        _log.warning(
            "registry_disabled_missing_dep",
            detail="asyncpg not installed; install scoped-mcp[postgres]",
        )
        return None
    try:
        return await asyncpg.create_pool(dsn, min_size=1, max_size=5, command_timeout=5.0)
    except Exception as e:  # fail-open — a down DB must not stop startup
        _log.warning("registry_pool_init_failed", error=type(e).__name__)
        return None


def registry_health() -> dict[str, Any]:
    """Return a database-independent snapshot of registry state.

    Modelled on ``credentials_vault.credential_health()``, which solved this same
    problem once already: an optional dependency that fails open, whose failure
    was therefore invisible. The pool builder returns None on a missing
    ``asyncpg``, an unset DSN, or an unreachable database — logged once at
    WARNING, after which every writer silently no-ops. The fail-open choice is
    correct (a down database must never block a HITL-gated tool call); its
    *invisibility* is what this fixes. "Is attribution actually recording?"
    should be answerable from ``scoped_mcp_status`` without reading logs.

    ``state`` is the field to read:

    ``disabled``    — no ``AGENT_REGISTRY_DSN``. Off by design, nothing is wrong.
    ``uninitialised`` — configured, but no writer has run yet in this process.
                      The pool is built lazily on first use.
    ``unavailable`` — configured and initialised, but the pool could not be
                      built. **Approvals are not being attributed.** This is the
                      state that used to be silent.
    ``recording``   — configured, pool live, writes are landing.

    Never raises and never touches the database — a diagnostic that can hang or
    throw is worse than none. Reports booleans and a state word only: the DSN
    carries a password and must never appear here.
    """
    configured = bool(os.environ.get("AGENT_REGISTRY_DSN", "").strip())
    if not configured:
        return {"configured": False, "enabled": False, "state": "disabled"}
    if _registry is None:
        return {"configured": True, "enabled": False, "state": "uninitialised"}
    enabled = _registry.enabled
    return {
        "configured": True,
        "enabled": enabled,
        "state": "recording" if enabled else "unavailable",
    }


async def get_registry() -> RegistryDB:
    """Return the process-wide registry DAL, creating the pool on first use.

    Always returns a ``RegistryDB``: a disabled one (``pool=None``) when
    ``AGENT_REGISTRY_DSN`` is unset or the pool cannot be built, so callers can
    invoke methods unconditionally.
    """
    global _registry, _init_lock
    if _registry is not None:
        return _registry
    if _init_lock is None:
        _init_lock = asyncio.Lock()
    async with _init_lock:
        if _registry is not None:  # lost the race
            return _registry
        dsn = os.environ.get("AGENT_REGISTRY_DSN", "").strip()
        pool = await _build_pool(dsn) if dsn else None
        if dsn and pool is None:
            _log.warning("registry_enabled_but_unavailable")
        _registry = RegistryDB(pool)
        return _registry


__all__ = ["RegistryDB", "get_registry", "hash_otp", "registry_health"]
