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
