"""Tests for modules/sqlite.py — per-agent file isolation, SQL validation,
create_table input validation.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiosqlite")

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.sqlite import SqliteModule


@pytest.fixture
def db_module(tmp_path, agent_ctx: AgentContext) -> SqliteModule:
    return SqliteModule(
        agent_ctx=agent_ctx,
        credentials={},
        config={"db_dir": str(tmp_path)},
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


def test_with_select_passes_in_read_mode(db_module: SqliteModule) -> None:
    db_module._validate_sql("WITH x AS (SELECT 1) SELECT * FROM x", read_only=True)


# A write that opens with a read-looking CTE. The guard relies on sqlglot returning the
# write's node type at the top, not a Select/With; a parser change that did otherwise
# would turn read-only mode into read-write. Re-run on every sqlglot bump.
@pytest.mark.parametrize(
    "sql",
    [
        "WITH x AS (SELECT 1) DELETE FROM my_table",
        "WITH x AS (SELECT 1) INSERT INTO my_table SELECT * FROM x",
        "WITH x AS (SELECT 1) UPDATE my_table SET col = 1",
        "INSERT OR REPLACE INTO my_table (col) VALUES ('x')",
        "DELETE FROM my_table RETURNING *",
    ],
)
def test_write_disguised_as_read_blocked(db_module: SqliteModule, sql: str) -> None:
    with pytest.raises(ScopeViolation, match="Read-only mode"):
        db_module._validate_sql(sql, read_only=True)


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


def test_drop_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation):
        db_module._validate_sql("DROP TABLE my_table", read_only=False)


# ── Multi-statement batch prevention ─────────────────────────────────────────


def test_multi_statement_blocked(db_module: SqliteModule) -> None:
    with pytest.raises(ScopeViolation, match="Multi-statement"):
        db_module._validate_sql(
            "SELECT * FROM t1; DROP TABLE t1",
            read_only=False,
        )


# The separator hidden behind a comment or a string must still split. A parser that
# swallowed the second statement into the first would pass the batch as one Select.
@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1 /* ; */; DROP TABLE t1",
        "SELECT ';'; DROP TABLE t1",
        "SELECT 1 -- x\n; DELETE FROM t1",
        "BEGIN; DELETE FROM t1; COMMIT",
    ],
)
@pytest.mark.parametrize("read_only", [True, False])
def test_multi_statement_hidden_separator_blocked(
    db_module: SqliteModule, sql: str, read_only: bool
) -> None:
    with pytest.raises(ScopeViolation, match="Multi-statement"):
        db_module._validate_sql(sql, read_only=read_only)


def test_trailing_semicolon_is_one_statement(db_module: SqliteModule) -> None:
    db_module._validate_sql("SELECT 1;", read_only=True)


# ── create_table input validation (M7) ───────────────────────────────────────


@pytest.mark.asyncio
async def test_create_table_invalid_name(db_module: SqliteModule) -> None:
    with pytest.raises(ValueError, match="Invalid table name"):
        await db_module.create_table("bad name!", {"id": "INTEGER"})


@pytest.mark.asyncio
async def test_create_table_invalid_column_name(db_module: SqliteModule) -> None:
    with pytest.raises(ValueError, match="Invalid column name"):
        await db_module.create_table("t", {"id; DROP TABLE users;--": "INTEGER"})


@pytest.mark.asyncio
async def test_create_table_invalid_column_type(db_module: SqliteModule) -> None:
    with pytest.raises(ValueError, match="Invalid column type"):
        await db_module.create_table("t", {"id": "INTEGER); DROP TABLE foo;--"})


@pytest.mark.asyncio
async def test_create_table_valid_types_accepted(db_module: SqliteModule) -> None:
    await db_module.create_table("t", {"id": "INTEGER PRIMARY KEY", "name": "TEXT NOT NULL"})
    tables = await db_module.list_tables()
    assert "t" in tables


# ── Config validation ─────────────────────────────────────────────────────────


def test_missing_db_dir_raises(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="db_dir"):
        SqliteModule(agent_ctx=agent_ctx, credentials={}, config={})


def test_deprecated_db_path_raises(tmp_path, agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match=r"db_path.*no longer supported"):
        SqliteModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"db_path": str(tmp_path / "shared.db")},
        )


# ── C1: per-agent file isolation ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_two_agents_cannot_see_each_others_data(
    tmp_path, agent_ctx: AgentContext, other_agent_ctx: AgentContext
) -> None:
    """Two agents with the same db_dir get distinct files; data is invisible across."""
    db_dir = tmp_path / "shared_db_dir"
    mod_a = SqliteModule(agent_ctx=agent_ctx, credentials={}, config={"db_dir": str(db_dir)})
    mod_b = SqliteModule(agent_ctx=other_agent_ctx, credentials={}, config={"db_dir": str(db_dir)})

    await mod_a.create_table("secrets", {"id": "INTEGER PRIMARY KEY", "value": "TEXT"})
    await mod_a.execute("INSERT INTO secrets (value) VALUES ('agent-a-only')")

    # Agent A sees its own data.
    tables_a = await mod_a.list_tables()
    rows_a = await mod_a.query("SELECT value FROM secrets")
    assert "secrets" in tables_a
    assert rows_a == [{"value": "agent-a-only"}]

    # Agent B sees no tables at all in its own file.
    tables_b = await mod_b.list_tables()
    assert tables_b == []


@pytest.mark.asyncio
async def test_agent_data_persists_across_module_instances(
    tmp_path, agent_ctx: AgentContext
) -> None:
    """A fresh module instance with the same agent_id + db_dir sees prior state."""
    db_dir = tmp_path / "shared_db_dir"
    mod_1 = SqliteModule(agent_ctx=agent_ctx, credentials={}, config={"db_dir": str(db_dir)})
    await mod_1.create_table("state", {"id": "INTEGER PRIMARY KEY", "value": "TEXT"})
    await mod_1.execute("INSERT INTO state (value) VALUES ('persisted')")

    mod_2 = SqliteModule(agent_ctx=agent_ctx, credentials={}, config={"db_dir": str(db_dir)})
    rows = await mod_2.query("SELECT value FROM state")
    assert rows == [{"value": "persisted"}]


def test_db_dir_created_with_restrictive_mode(tmp_path, agent_ctx: AgentContext) -> None:
    """db_dir is created with mode 0o700 when it does not already exist."""
    db_dir = tmp_path / "new_dir"
    assert not db_dir.exists()
    SqliteModule(agent_ctx=agent_ctx, credentials={}, config={"db_dir": str(db_dir)})
    assert db_dir.exists()
    assert (db_dir.stat().st_mode & 0o777) == 0o700
