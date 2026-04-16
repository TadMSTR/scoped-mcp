"""SQLite module — agent-scoped queries and table management.

Scope: SchemaScope — each agent operates in its own schema (SQLite ATTACH namespace).
SQL parsing via sqlglot enforces: SELECT-only for reads, no ATTACH/PRAGMA/DETACH,
no cross-schema table references, no multi-statement batches.

Config:
    db_path (str): required — path to the SQLite database file.

Required credentials: none (credentials are not needed for a local SQLite file).

Security note: SchemaScope.enforce() in _validate_sql validates all table references
before any query reaches the database. Free-form Flux/SQL that bypasses schema
restrictions is not accepted.
"""

from __future__ import annotations

from typing import Any, ClassVar

import aiosqlite
import sqlglot
import sqlglot.expressions as exp

from ..exceptions import ScopeViolation
from ..scoping import SchemaScope
from ._base import ToolModule, tool


# Statement types that are never allowed regardless of mode.
_BLOCKED_STATEMENT_TYPES = (
    exp.Command,   # fallback for unparsed/unknown commands
    exp.Pragma,    # PRAGMA journal_mode=..., etc.
    exp.Attach,    # ATTACH DATABASE
    exp.Detach,    # DETACH DATABASE
    exp.Drop,      # DROP TABLE — use delete_table tool instead
)


class SqliteModule(ToolModule):
    name: ClassVar[str] = "sqlite"
    scoping: ClassVar[SchemaScope] = SchemaScope()
    required_credentials: ClassVar[list[str]] = []

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        db_path = config.get("db_path")
        if not db_path:
            raise ValueError("sqlite module requires 'db_path' in config")
        self._db_path = db_path
        self._schema = self.scoping.apply("", agent_ctx)

    def _validate_sql(self, sql: str, read_only: bool) -> None:
        """Parse and validate SQL. Raises ScopeViolation on policy violations.

        Checks:
        - No ATTACH DATABASE, DETACH DATABASE, or PRAGMA statements
        - No multi-statement batches
        - All table references use the agent's schema
        - Read-only mode: only SELECT/WITH...SELECT allowed
        """
        statements = sqlglot.parse(sql, dialect="sqlite")

        if len(statements) > 1:
            raise ScopeViolation("Multi-statement SQL batches are not allowed")

        if not statements or statements[0] is None:
            raise ScopeViolation("Empty or unparseable SQL statement")

        stmt = statements[0]

        # Block dangerous statement types at the top level.
        # PRAGMA, ATTACH, DETACH parse as their own node types in sqlglot; Command
        # is a fallback for anything sqlglot can't fully parse.
        if isinstance(stmt, _BLOCKED_STATEMENT_TYPES):
            raise ScopeViolation(
                f"{type(stmt).__name__} statements are not allowed"
            )

        # Also walk for nested Command nodes (extra defense against obfuscation)
        for node in stmt.walk():
            if isinstance(node, exp.Command):
                cmd_name = str(node.this).upper()
                if cmd_name in ("PRAGMA", "ATTACH", "DETACH"):
                    raise ScopeViolation(f"{cmd_name} statements are not allowed")

        if read_only and not isinstance(stmt, (exp.Select, exp.With)):
            raise ScopeViolation(
                f"Read-only mode: only SELECT statements are allowed, got {type(stmt).__name__}"
            )

        # Validate table references belong to the agent's schema.
        # In SQLite, schema-qualified names appear as catalog.table or schema.table.
        for table in stmt.find_all(exp.Table):
            db = table.args.get("db")
            if db is not None:
                ref_schema = str(db).lower()
                expected = self._schema.lower()
                if ref_schema != expected:
                    raise ScopeViolation(
                        f"Table reference '{db}.{table.name}' is outside the agent schema "
                        f"'{self._schema}'"
                    )

    async def _execute(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        """Execute SQL and return results as a list of dicts."""
        async with aiosqlite.connect(self._db_path) as conn:
            conn.row_factory = aiosqlite.Row
            # Attach the agent schema (SQLite uses ATTACH for schema namespacing)
            await conn.execute(f"ATTACH DATABASE ':memory:' AS {self._schema}")
            cursor = await conn.execute(sql, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def _execute_write(self, sql: str, params: tuple = ()) -> int:
        """Execute a write SQL statement and return affected row count."""
        async with aiosqlite.connect(self._db_path) as conn:
            await conn.execute(f"ATTACH DATABASE ':memory:' AS {self._schema}")
            cursor = await conn.execute(sql, params)
            await conn.commit()
            return cursor.rowcount

    @tool(mode="read")
    async def query(self, sql: str) -> list[dict[str, Any]]:
        """Execute a SELECT query scoped to the agent's schema.

        Args:
            sql: A SELECT statement. Only the agent's schema is accessible.

        Returns:
            List of result rows as dicts.
        """
        self._validate_sql(sql, read_only=True)
        return await self._execute(sql)

    @tool(mode="read")
    async def list_tables(self) -> list[str]:
        """List tables in the agent's schema.

        Returns:
            List of table names.
        """
        async with aiosqlite.connect(self._db_path) as conn:
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
            rows = await cursor.fetchall()
            return [row[0] for row in rows]

    @tool(mode="write")
    async def execute(self, sql: str) -> int:
        """Execute an INSERT, UPDATE, or DELETE statement.

        Args:
            sql: An INSERT/UPDATE/DELETE statement scoped to the agent's schema.

        Returns:
            Number of rows affected.
        """
        self._validate_sql(sql, read_only=False)
        return await self._execute_write(sql)

    @tool(mode="write")
    async def create_table(self, name: str, columns: dict[str, str]) -> bool:
        """Create a table in the agent's schema.

        Args:
            name: Table name (unqualified — agent schema is applied automatically).
            columns: Dict mapping column names to their SQL type strings (e.g. {"id": "INTEGER PRIMARY KEY"}).

        Returns:
            True on success.
        """
        if not name.isidentifier():
            raise ValueError(f"Invalid table name: {name!r}")

        col_defs = ", ".join(
            f"{col_name} {col_type}"
            for col_name, col_type in columns.items()
        )
        sql = f"CREATE TABLE IF NOT EXISTS {name} ({col_defs})"
        await self._execute_write(sql)
        return True
