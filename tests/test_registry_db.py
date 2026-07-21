"""Tests for the agent session registry DAL (registry_db.py).

These cover the fail-open contract without requiring a live Postgres: a
disabled registry (no DSN) no-ops on every method, a registry whose pool
raises on acquire swallows the error, and OTP hashing is stable.
"""

from __future__ import annotations

import hashlib

from scoped_mcp import registry_db
from scoped_mcp.registry_db import RegistryDB, hash_otp


def test_hash_otp_matches_sha256():
    otp = "s3cret-one-time-token"
    assert hash_otp(otp) == hashlib.sha256(otp.encode()).hexdigest()
    assert len(hash_otp(otp)) == 64  # hex sha256


def test_hash_otp_differs_per_input():
    assert hash_otp("a") != hash_otp("b")


def test_disabled_registry_reports_not_enabled():
    reg = RegistryDB(pool=None)
    assert reg.enabled is False


async def test_disabled_registry_writes_are_noops():
    """Every write method must return cleanly when the pool is None."""
    reg = RegistryDB(pool=None)
    # None of these should raise despite there being no database at all.
    await reg.upsert_session("s1", "developer", "matrix")
    await reg.insert_hitl_approval("developer.abc", "developer", "gitea_pr_merge", "pending")
    await reg.resolve_hitl_approval("developer.abc", "approved")
    await reg.insert_session_task("s1", "task-1", "parent")
    await reg.insert_memory_artifact("s1", "note", "/path/to/note.md")
    await reg.close()


class _RaisingPool:
    """A pool whose acquire() always raises — simulates a down/broken DB."""

    def acquire(self):
        raise RuntimeError("connection refused")

    async def close(self):
        raise RuntimeError("already closed")


async def test_registry_swallows_db_errors():
    """A broken pool must never surface an exception to the caller (fail-open)."""
    reg = RegistryDB(pool=_RaisingPool())
    assert reg.enabled is True
    # acquire() raises synchronously inside each method — all must be swallowed.
    await reg.upsert_session("s1", "developer", "matrix")
    await reg.insert_hitl_approval("developer.abc", "developer", "gitea_pr_merge", "pending")
    await reg.resolve_hitl_approval("developer.abc", "approved")
    await reg.insert_session_task("s1", "task-1", "parent")
    await reg.insert_memory_artifact("s1", "note", "/path/to/note.md")
    await reg.close()  # close() also swallows


async def test_get_registry_disabled_without_dsn(monkeypatch):
    """With no AGENT_REGISTRY_DSN, get_registry returns a disabled instance."""
    monkeypatch.delenv("AGENT_REGISTRY_DSN", raising=False)
    # Reset the module singleton so the fixture-free call re-evaluates env.
    monkeypatch.setattr(registry_db, "_registry", None)
    monkeypatch.setattr(registry_db, "_init_lock", None)
    reg = await registry_db.get_registry()
    assert reg.enabled is False


# ── resolve_hitl_approval expected_state guard (audit LOW, scoped-mcp-fixes-batch-2026-07) ──


class _FakeConn:
    """Records executed queries; returns a configurable asyncpg-style status string."""

    def __init__(self, status: str = "UPDATE 1") -> None:
        self.status = status
        self.calls: list[tuple[str, ...]] = []

    async def execute(self, query: str, *args: str) -> str:
        self.calls.append((query, *args))
        return self.status


class _FakeAcquireCtx:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    async def __aenter__(self) -> _FakeConn:
        return self._conn

    async def __aexit__(self, *exc: object) -> None:
        return None


class _FakePool:
    def __init__(self, conn: _FakeConn) -> None:
        self._conn = conn

    def acquire(self) -> _FakeAcquireCtx:
        return _FakeAcquireCtx(self._conn)


async def test_resolve_without_expected_state_is_unguarded():
    """Default (no expected_state) behavior is unchanged — the pending->approved/
    denied/expired transitions used by hitl_endpoint.py must not gain a guard clause,
    since the row's current state there is "pending", not the target state."""
    conn = _FakeConn(status="UPDATE 1")
    reg = RegistryDB(pool=_FakePool(conn))

    await reg.resolve_hitl_approval("developer.abc", "approved")

    assert len(conn.calls) == 1
    query, *params = conn.calls[0]
    assert "AND state" not in query
    assert params == ["developer.abc", "approved"]


async def test_resolve_with_matching_expected_state_applies_guarded_update():
    conn = _FakeConn(status="UPDATE 1")
    reg = RegistryDB(pool=_FakePool(conn))

    await reg.resolve_hitl_approval("developer.abc", "consumed", expected_state="approved")

    assert len(conn.calls) == 1
    query, *params = conn.calls[0]
    assert "AND state = $3" in query
    assert params == ["developer.abc", "consumed", "approved"]


async def test_resolve_with_mismatched_expected_state_logs_and_does_not_raise():
    """Audit LOW: a race where the row already moved to some other terminal state
    (e.g. expired/denied) must not be silently clobbered — zero rows affected is
    logged, not raised (fail-open contract preserved)."""
    conn = _FakeConn(status="UPDATE 0")  # simulates no row matched the WHERE clause
    reg = RegistryDB(pool=_FakePool(conn))

    # Must not raise.
    await reg.resolve_hitl_approval("developer.abc", "consumed", expected_state="approved")

    assert len(conn.calls) == 1


async def test_resolve_expected_state_guard_swallows_db_errors():
    """The guarded path must remain fail-open, same as the unguarded path."""
    reg = RegistryDB(pool=_RaisingPool())
    await reg.resolve_hitl_approval("developer.abc", "consumed", expected_state="approved")


# ── resolved_via channel tag (hitl interactive mode) ──────────────────────────


async def test_resolve_with_resolved_via_unguarded_appends_column():
    """resolved_via, when supplied on the unguarded path, is appended as $3."""
    conn = _FakeConn(status="UPDATE 1")
    reg = RegistryDB(pool=_FakePool(conn))

    await reg.resolve_hitl_approval(
        "developer.abc", "approved", resolved_via="interactive_self_service"
    )

    assert len(conn.calls) == 1
    query, *params = conn.calls[0]
    assert "resolved_via = $3" in query
    assert "AND state" not in query
    assert params == ["developer.abc", "approved", "interactive_self_service"]


async def test_resolve_with_resolved_via_and_expected_state_numbers_params():
    """With both guards, expected_state is $3 and resolved_via becomes $4."""
    conn = _FakeConn(status="UPDATE 1")
    reg = RegistryDB(pool=_FakePool(conn))

    await reg.resolve_hitl_approval(
        "developer.abc", "consumed", expected_state="approved", resolved_via="matrix_bot"
    )

    assert len(conn.calls) == 1
    query, *params = conn.calls[0]
    assert "AND state = $3" in query
    assert "resolved_via = $4" in query
    assert params == ["developer.abc", "consumed", "approved", "matrix_bot"]


async def test_resolve_without_resolved_via_omits_column():
    """No resolved_via => the UPDATE never touches the column (preserves the
    approve-time channel across a later consume/expire transition)."""
    conn = _FakeConn(status="UPDATE 1")
    reg = RegistryDB(pool=_FakePool(conn))

    await reg.resolve_hitl_approval("developer.abc", "consumed", expected_state="approved")

    query, *_ = conn.calls[0]
    assert "resolved_via" not in query
