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


# -- session attribution (vikunja#596) ----------------------------------------


class _RecordingConn:
    """Captures every statement and its parameters."""

    def __init__(self, calls, fetchval_result):
        self._calls = calls
        self._fetchval_result = fetchval_result

    async def execute(self, sql, *params):
        self._calls.append((sql, params))
        return "INSERT 0 1"

    async def fetchval(self, sql, *params):
        self._calls.append((sql, params))
        return self._fetchval_result


class _RecordingPool:
    """A working pool. ``fetchval_result=None`` emulates the ownership guard
    rejecting the upsert (RETURNING yielded no row)."""

    def __init__(self, fetchval_result="session-id"):
        self.calls: list[tuple] = []
        self._fetchval_result = fetchval_result

    def acquire(self):
        calls = self.calls
        result = self._fetchval_result

        class _Ctx:
            async def __aenter__(self):
                return _RecordingConn(calls, result)

            async def __aexit__(self, *a):
                return False

        return _Ctx()


async def test_approval_resolves_session_id_through_a_subselect():
    """An unknown session must degrade to NULL, not raise.

    hitl_approvals.session_id carries a real FK. A plain INSERT of an id with no
    sessions row raises hitl_approvals_session_id_fkey, and the fail-open except
    would then swallow the whole audit row — losing the approval record, not just
    its attribution. The subselect is what makes the row survive.
    """
    pool = _RecordingPool()
    reg = RegistryDB(pool=pool)
    await reg.insert_hitl_approval(
        "developer-01.abc", "developer", "gitea_pr_merge", "pending", session_id="s-1"
    )
    sql, params = pool.calls[0]
    normalized = " ".join(sql.split())
    assert "SELECT session_id FROM sessions WHERE session_id = $2" in normalized, (
        "session_id must be resolved through a subselect so an unknown id "
        "degrades to NULL instead of destroying the audit row"
    )
    assert "VALUES ($1, $2, $3" not in normalized, "raw $2 insert reintroduces the FK raise"
    assert params[1] == "s-1"


async def test_approval_still_written_without_a_session():
    """NULL session_id is the correct value for an unattributable approval."""
    pool = _RecordingPool()
    reg = RegistryDB(pool=pool)
    await reg.insert_hitl_approval("developer-01.abc", "developer", "t", "pending")
    assert len(pool.calls) == 1
    assert pool.calls[0][1][1] is None


async def test_upsert_session_reports_success_and_failure():
    """The caller needs the bool — a swallowed failure must not read as success."""
    assert await RegistryDB(pool=_RecordingPool()).upsert_session("s1", "developer", "headless")
    assert not await RegistryDB(pool=_RaisingPool()).upsert_session("s1", "developer", "headless")
    assert not await RegistryDB(pool=None).upsert_session("s1", "developer", "headless")


async def test_insert_session_task_reports_success_and_failure():
    assert await RegistryDB(pool=_RecordingPool()).insert_session_task("s1", "t1", "target")
    assert not await RegistryDB(pool=_RaisingPool()).insert_session_task("s1", "t1", "target")
    assert not await RegistryDB(pool=None).insert_session_task("s1", "t1", "target")


async def test_session_task_link_is_idempotent_in_sql():
    """No unique constraint exists and this build adds no schema, so the guard
    has to be in the statement — an in-process memo alone would duplicate the
    link after a broker restart."""
    pool = _RecordingPool()
    await RegistryDB(pool=pool).insert_session_task("s1", "t1", "target")
    normalized = " ".join(pool.calls[0][0].split())
    assert "WHERE NOT EXISTS" in normalized
    assert "SELECT 1 FROM session_tasks WHERE session_id = $1 AND task_id = $2" in normalized


# -- registry_health (Phase 4) ------------------------------------------------


def test_registry_health_disabled_without_dsn(monkeypatch):
    monkeypatch.delenv("AGENT_REGISTRY_DSN", raising=False)
    assert registry_db.registry_health() == {
        "configured": False,
        "enabled": False,
        "state": "disabled",
    }


def test_registry_health_uninitialised(monkeypatch):
    monkeypatch.setenv("AGENT_REGISTRY_DSN", "postgresql://u:p@127.0.0.1:5433/db")
    monkeypatch.setattr(registry_db, "_registry", None)
    health = registry_db.registry_health()
    assert health["configured"] is True
    assert health["state"] == "uninitialised"


def test_registry_health_unavailable_is_visible(monkeypatch):
    """The whole point of Phase 4: a configured-but-down registry must SAY so.

    This is the state that used to be silent — one WARNING at startup, then every
    writer no-oping forever with approvals landing unattributed.
    """
    monkeypatch.setenv("AGENT_REGISTRY_DSN", "postgresql://u:p@127.0.0.1:5433/db")
    monkeypatch.setattr(registry_db, "_registry", RegistryDB(pool=None))
    health = registry_db.registry_health()
    assert health == {"configured": True, "enabled": False, "state": "unavailable"}


def test_registry_health_recording(monkeypatch):
    monkeypatch.setenv("AGENT_REGISTRY_DSN", "postgresql://u:p@127.0.0.1:5433/db")
    monkeypatch.setattr(registry_db, "_registry", RegistryDB(pool=_RecordingPool()))
    assert registry_db.registry_health()["state"] == "recording"


def test_registry_health_never_leaks_the_dsn(monkeypatch):
    """The DSN carries a password and this payload lands in an agent's context."""
    monkeypatch.setenv("AGENT_REGISTRY_DSN", "postgresql://user:hunter2@127.0.0.1:5433/db")
    monkeypatch.setattr(registry_db, "_registry", RegistryDB(pool=_RecordingPool()))
    rendered = repr(registry_db.registry_health())
    assert "hunter2" not in rendered
    assert "127.0.0.1" not in rendered
    assert "postgresql" not in rendered


# -- session ownership (audit HIGH, 2026-08-31) -------------------------------


async def test_upsert_does_not_overwrite_agent_id_on_conflict():
    """A second agent presenting the same run id must not relabel the row.

    session_id is a bare TEXT primary key with no binding to an agent, and the id
    arrives in a header validated only as a well-formed UUID. Real run ids are
    readable from ~/.claude/comms/artifacts/task-launches/ by any agent running as
    the same user, and sessions are never closed — so every historical id is a live
    target. If agent_id were in the SET list, whoever presented the id last would
    own the row.
    """
    pool = _RecordingPool()
    await RegistryDB(pool=pool).upsert_session("s1", "developer", "headless")
    normalized = " ".join(pool.calls[0][0].split())
    set_clause = normalized.split("DO UPDATE SET", 1)[1]
    assert "agent_id" not in set_clause.split("WHERE")[0], (
        "agent_id must not be reassignable on conflict — that is session hijacking"
    )


async def test_upsert_is_guarded_by_owner_and_returns_the_id():
    """Preserving the owner is necessary but NOT sufficient.

    With only `agent_id = sessions.agent_id`, a mismatched caller still gets a
    successful upsert, is handed the run id back, and stamps its own approvals with
    a session belonging to someone else — the same misattribution running the other
    way. The WHERE guard plus RETURNING is what makes the mismatch observable.
    """
    pool = _RecordingPool()
    await RegistryDB(pool=pool).upsert_session("s1", "developer", "headless")
    normalized = " ".join(pool.calls[0][0].split())
    assert "WHERE sessions.agent_id = EXCLUDED.agent_id" in normalized
    assert "RETURNING session_id" in normalized


async def test_owner_mismatch_reports_failure():
    """No row returned ⇒ someone else owns it ⇒ this call is not attributable."""
    assert not await RegistryDB(pool=_RecordingPool(fetchval_result=None)).upsert_session(
        "s1", "developer", "headless"
    )


async def test_owner_match_reports_success():
    assert await RegistryDB(pool=_RecordingPool(fetchval_result="s1")).upsert_session(
        "s1", "developer", "headless"
    )
