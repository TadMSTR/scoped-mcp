"""Tests for modules/sqlite.py — schema isolation, SQL validation, injection prevention.

Note: these tests exercise the SQL validation layer directly via _validate_sql.
End-to-end database tests require aiosqlite and run against a temp file.
"""

from __future__ import annotations

import pytest

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.sqlite import SqliteModule


@pytest.fixture
def db_module(tmp_path, agent_ctx: AgentContext) -> SqliteModule:
    db_file = tmp_path / "test.db"
    return SqliteModule(
        agent_ctx=agent_ctx,
        credentials={},
        config={"db_path": str(db_file)},
    )


# ── SQL validation — read-only mode ──────────────────────────────────────────


def test_valid_select_passes(db_module: SqliteModule) -> None:
    db_module._validate_sql("SELECT * FROM my_table", read_only=True)


def test_insert_in_read_mode_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation, match="Read-only mode"):
        db_module._validate_sql("INSERT INTO my_table (col) VALUES ('x')", read_only=True)


def test_update_in_read_mode_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation, match="Read-only mode"):
        db_module._validate_sql("UPDATE my_table SET col = 1", read_only=True)


def test_delete_in_read_mode_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation, match="Read-only mode"):
        db_module._validate_sql("DELETE FROM my_table WHERE id = 1", read_only=True)


# ── SQL validation — write mode ───────────────────────────────────────────────


def test_valid_insert_passes(db_module: SqliteModule) -> None:
    db_module._validate_sql("INSERT INTO my_table (col) VALUES ('hello')", read_only=False)


def test_valid_update_passes(db_module: SqliteModule) -> None:
    db_module._validate_sql("UPDATE my_table SET col = 'x' WHERE id = 1", read_only=False)


# ── Blocked statement types ───────────────────────────────────────────────────


def test_pragma_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation):
        db_module._validate_sql("PRAGMA journal_mode=WAL", read_only=False)


def test_attach_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation):
        db_module._validate_sql("ATTACH DATABASE '/etc/passwd' AS evil", read_only=False)


def test_detach_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation):
        db_module._validate_sql("DETACH DATABASE other_db", read_only=False)


# ── Multi-statement batch prevention ─────────────────────────────────────────


def test_multi_statement_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation, match="Multi-statement"):
        db_module._validate_sql(
            "SELECT * FROM t1; DROP TABLE t1",
            read_only=False,
        )


# ── Cross-schema reference prevention ────────────────────────────────────────


def test_cross_schema_reference_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation):
        db_module._validate_sql("SELECT * FROM other_agent.some_table", read_only=True)


# ── create_table input validation ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_table_invalid_name(db_module: SqliteModule) -> None:
    with pytest.raises(ValueError, match="Invalid table name"):
        await db_module.create_table("bad name!", {"id": "INTEGER"})


# ── Config validation ─────────────────────────────────────────────────────────


def test_missing_db_path_raises(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="db_path"):
        SqliteModule(agent_ctx=agent_ctx, credentials={}, config={})
