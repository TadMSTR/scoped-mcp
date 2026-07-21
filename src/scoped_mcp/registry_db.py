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
    ) -> None:
        """Insert or refresh a session row (used for approve-routing)."""
        if self._pool is None:
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO sessions (
                        session_id, agent_id, transport, room_id, project_dir,
                        scoped_mcp_url, status, last_seen_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, now())
                    ON CONFLICT (session_id) DO UPDATE SET
                        agent_id       = EXCLUDED.agent_id,
                        transport      = EXCLUDED.transport,
                        room_id        = COALESCE(EXCLUDED.room_id, sessions.room_id),
                        project_dir    = COALESCE(EXCLUDED.project_dir, sessions.project_dir),
                        scoped_mcp_url = COALESCE(EXCLUDED.scoped_mcp_url, sessions.scoped_mcp_url),
                        status         = EXCLUDED.status,
                        last_seen_at   = now()
                    """,
                    session_id,
                    agent_id,
                    transport,
                    room_id,
                    project_dir,
                    scoped_mcp_url,
                    status,
                )
        except Exception as e:  # fail-open
            _log.warning("registry_upsert_session_failed", error=type(e).__name__)

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
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7)
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
    ) -> None:
        if self._pool is None:
            return
        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO session_tasks (session_id, task_id, role, build_name)
                    VALUES ($1, $2, $3, $4)
                    """,
                    session_id,
                    task_id,
                    role,
                    build_name,
                )
        except Exception as e:  # fail-open
            _log.warning("registry_insert_session_task_failed", error=type(e).__name__)

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


__all__ = ["RegistryDB", "get_registry", "hash_otp"]
