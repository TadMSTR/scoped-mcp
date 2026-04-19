"""SQLite module — per-agent database file isolation.

Each agent gets its own SQLite file at ``{db_dir}/agent_{agent_id}.db``. Agents
cannot read or write each other's files regardless of SQL shape — isolation is
a filesystem property, not a SQL property. SQL parsing via sqlglot still enforces
SELECT-only for reads and blocks PRAGMA/ATTACH/DETACH/DROP/multi-statement batches
as defense in depth.

Config:
    db_dir (str): required — directory holding per-agent DB files. Created with
        mode 0o700 if it does not exist.

Required credentials: none (SQLite uses a local file).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import aiosqlite
import sqlglot
import sqlglot.expressions as exp

from ..exceptions import ScopeViolation
from ._base import ToolModule, tool

_BLOCKED_STATEMENT_TYPES = (
    exp.Command,
    exp.Pragma,
    exp.Attach,
    exp.Detach,
    exp.Drop,
)

_ALLOWED_COL_TYPES = {
    "INTEGER",
    "TEXT",
    "REAL",
    "BLOB",
    "NUMERIC",
    "BOOLEAN",
    "INTEGER PRIMARY KEY",
    "INTEGER PRIMARY KEY AUTOINCREMENT",
    "TEXT PRIMARY KEY",
    "INTEGER NOT NULL",
    "TEXT NOT NULL",
    "REAL NOT NULL",
    "INTEGER UNIQUE",
    "TEXT UNIQUE",
    "INTEGER DEFAULT 0",
    "TEXT DEFAULT ''",
}


class SqliteModule(ToolModule):
    name: ClassVar[str] = "sqlite"
    required_credentials: ClassVar[list[str]] = []

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        db_dir = config.get("db_dir")
        if not db_dir and config.get("db_path"):
            raise ValueError(
                "sqlite module: 'db_path' is no longer supported. Use 'db_dir' — a "
                "directory; each agent gets its own {db_dir}/agent_{agent_id}.db file. "
                "See CHANGELOG for migration notes."
            )
        if not db_dir:
            raise ValueError("sqlite module requires 'db_dir' in config")

        dir_path = Path(db_dir)
        dir_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._db_dir = dir_path
        self._db_file = dir_path / f"agent_{agent_ctx.agent_id}.db"

    def _validate_sql(self, sql: str, read_only: bool) -> None:
        """Parse and validate SQL. Raises ScopeViolation on policy violations.

        Checks:
        - No ATTACH, DETACH, PRAGMA, DROP, or unknown Command statements
        - No multi-statement batches
        - Read-only mode: only SELECT/WITH...SELECT allowed
        """
        statements = sqlglot.parse(sql, dialect="sqlite")

        if len(statements) > 1:
            raise ScopeViolation("Multi-statement SQL batches are not allowed")

        if not statements or statements[0] is None:
            raise ScopeViolation("Empty or unparseable SQL statement")

        stmt = statements[0]

        if isinstance(stmt, _BLOCKED_STATEMENT_TYPES):
            raise ScopeViolation(f"{type(stmt).__name__} statements are not allowed")

        for node in stmt.walk():
            if isinstance(node, exp.Command):
                cmd_name = str(node.this).upper()
                if cmd_name in ("PRAGMA", "ATTACH", "DETACH"):
                    raise ScopeViolation(f"{cmd_name} statements are not allowed")

        if read_only and not isinstance(stmt, exp.Select | exp.With):
            raise ScopeViolation(
                f"Read-only mode: only SELECT statements are allowed, got {type(stmt).__name__}"
            )

    async def _execute(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        async with aiosqlite.connect(self._db_file) as conn:
            conn.row_factory = aiosqlite.Row
            cursor = await conn.execute(sql, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def _execute_write(self, sql: str, params: tuple = ()) -> int:
        async with aiosqlite.connect(self._db_file) as conn:
            cursor = await conn.execute(sql, params)
            await conn.commit()
            return cursor.rowcount

    @tool(mode="read")
    async def query(self, sql: str) -> list[dict[str, Any]]:
        """Execute a SELECT query against this agent's database file.

        Args:
            sql: A SELECT statement.

        Returns:
            List of result rows as dicts.
        """
        self._validate_sql(sql, read_only=True)
        return await self._execute(sql)

    @tool(mode="read")
    async def list_tables(self) -> list[str]:
        """List tables in this agent's database file.

        Returns:
            List of table names.
        """
        async with aiosqlite.connect(self._db_file) as conn:
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            rows = await cursor.fetchall()
            return [row[0] for row in rows]

    @tool(mode="write")
    async def execute(self, sql: str) -> int:
        """Execute an INSERT, UPDATE, or DELETE against this agent's database file.

        Args:
            sql: An INSERT/UPDATE/DELETE statement.

        Returns:
            Number of rows affected.
        """
        self._validate_sql(sql, read_only=False)
        return await self._execute_write(sql)

    @tool(mode="write")
    async def create_table(self, name: str, columns: dict[str, str]) -> bool:
        """Create a table in this agent's database file.

        Args:
            name: Table name. Must be a valid Python identifier.
            columns: Dict mapping column names (identifiers) to types from the
                allowlist. Unknown types are rejected.

        Returns:
            True on success.
        """
        if not name.isidentifier():
            raise ValueError(f"Invalid table name: {name!r}")

        for col_name, col_type in columns.items():
            if not col_name.isidentifier():
                raise ValueError(f"Invalid column name: {col_name!r}")
            normalized = " ".join(col_type.upper().split())
            if normalized not in _ALLOWED_COL_TYPES:
                raise ValueError(
                    f"Invalid column type: {col_type!r}. Allowed types: "
                    f"{sorted(_ALLOWED_COL_TYPES)}"
                )

        col_defs = ", ".join(
            f"{col_name} {' '.join(col_type.upper().split())}"
            for col_name, col_type in columns.items()
        )
        sql = f"CREATE TABLE IF NOT EXISTS {name} ({col_defs})"
        await self._execute_write(sql)
        return True
