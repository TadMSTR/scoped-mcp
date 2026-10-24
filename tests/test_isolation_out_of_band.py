"""Out-of-band isolation and audit-identity tests (GitHub #83, vikunja#1219).

The module-level isolation tests ask the module what it can see. These open the backend
directly — plain ``sqlite3`` and ``pathlib``, never ``SqliteModule`` or
``FilesystemModule`` — so a database keyed on the wrong identity, a file written in the
wrong place, or a write that reached another agent's backend is caught even when the
module's own view looks consistent.

The two agents share an ``agent_type`` and differ only in ``agent_id``. The shared
``agent_ctx`` / ``other_agent_ctx`` fixtures differ in both, which is what let a database
keyed on ``agent_type`` pass the existing isolation test.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("aiosqlite")

from fastmcp import Client

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import Manifest
from scoped_mcp.modules.filesystem import FilesystemModule
from scoped_mcp.modules.sqlite import SqliteModule
from scoped_mcp.registry import build_server

AGENT_A = AgentContext(agent_id="iso-agent-a", agent_type="research")
AGENT_B = AgentContext(agent_id="iso-agent-b", agent_type="research")


# ── Independent backend readers ──────────────────────────────────────────────


def _sqlite_rows(db_file: Path, table: str) -> list[str]:
    """Read every ``value`` in ``table`` over a fresh connection, opened read-only."""
    conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    try:
        return [row[0] for row in conn.execute(f"SELECT value FROM {table} ORDER BY value")]
    finally:
        conn.close()


def _sqlite_schema(db_file: Path) -> list[tuple[str, str]]:
    """Every schema object in the file, as (type, name), over a fresh connection."""
    conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    try:
        return list(conn.execute("SELECT type, name FROM sqlite_master ORDER BY type, name"))
    finally:
        conn.close()


def _tree(root: Path) -> dict[str, str]:
    """Every regular file under ``root``, relative path → content, read with os.walk."""
    out: dict[str, str] = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            full = Path(dirpath) / name
            out[str(full.relative_to(root))] = full.read_text(encoding="utf-8")
    return out


# ── 1. sqlite: one file per agent_id, checked on disk ────────────────────────


async def test_sqlite_each_agent_writes_only_its_own_file(tmp_path: Path) -> None:
    db_dir = tmp_path / "db"
    mod_a = SqliteModule(agent_ctx=AGENT_A, credentials={}, config={"db_dir": str(db_dir)})
    mod_b = SqliteModule(agent_ctx=AGENT_B, credentials={}, config={"db_dir": str(db_dir)})

    for mod, marker in ((mod_a, "marker-from-a"), (mod_b, "marker-from-b")):
        await mod.create_table("notes", {"id": "INTEGER PRIMARY KEY", "value": "TEXT"})
        await mod.execute(f"INSERT INTO notes (value) VALUES ('{marker}')")

    assert sorted(p.name for p in db_dir.iterdir()) == [
        "agent_iso-agent-a.db",
        "agent_iso-agent-b.db",
    ]
    assert _sqlite_rows(db_dir / "agent_iso-agent-a.db", "notes") == ["marker-from-a"]
    assert _sqlite_rows(db_dir / "agent_iso-agent-b.db", "notes") == ["marker-from-b"]


# ── 2. sqlite: read-only and statement policy on the public tools ────────────


@pytest.fixture
def seeded_sqlite(tmp_path: Path) -> tuple[SqliteModule, Path]:
    db_dir = tmp_path / "db"
    mod = SqliteModule(agent_ctx=AGENT_A, credentials={}, config={"db_dir": str(db_dir)})
    db_file = db_dir / "agent_iso-agent-a.db"
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE keep (value TEXT)")
    conn.execute("INSERT INTO keep (value) VALUES ('original')")
    conn.commit()
    conn.close()
    return mod, db_file


@pytest.mark.parametrize(
    "sql",
    [
        "CREATE TABLE planted (value TEXT)",
        "DROP TABLE keep",
        "INSERT INTO keep (value) VALUES ('planted')",
    ],
)
async def test_sqlite_query_refuses_non_select(
    seeded_sqlite: tuple[SqliteModule, Path], sql: str
) -> None:
    mod, db_file = seeded_sqlite
    before = _sqlite_schema(db_file)

    with pytest.raises(ScopeViolation):
        await mod.query(sql)

    assert _sqlite_schema(db_file) == before
    assert _sqlite_rows(db_file, "keep") == ["original"]


@pytest.mark.parametrize(
    "sql",
    [
        "PRAGMA journal_mode = DELETE",
        "PRAGMA user_version = 7",
        "ATTACH DATABASE 'other.db' AS other",
        "DROP TABLE keep",
        "INSERT INTO keep (value) VALUES ('a'); DROP TABLE keep",
    ],
)
async def test_sqlite_execute_refuses_blocked_statements(
    seeded_sqlite: tuple[SqliteModule, Path], sql: str
) -> None:
    mod, db_file = seeded_sqlite
    before = _sqlite_schema(db_file)

    with pytest.raises(ScopeViolation):
        await mod.execute(sql)

    assert _sqlite_schema(db_file) == before
    assert _sqlite_rows(db_file, "keep") == ["original"]
    conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
    try:
        assert conn.execute("PRAGMA user_version").fetchone() == (0,)
    finally:
        conn.close()
    # ATTACH would create the target file next to the agent's own.
    assert sorted(p.name for p in db_file.parent.iterdir()) == [db_file.name]


# ── 3. filesystem: writes land under the agent root, checked on disk ─────────


@pytest.fixture
def two_fs_agents(tmp_path: Path) -> tuple[FilesystemModule, Path, Path]:
    base = tmp_path / "fs"
    mod_a = FilesystemModule(agent_ctx=AGENT_A, credentials={}, config={"base_path": str(base)})
    # B is created only so its root exists; every B file below is planted on disk directly.
    FilesystemModule(agent_ctx=AGENT_B, credentials={}, config={"base_path": str(base)})
    root_a = base.resolve() / "agents" / "iso-agent-a"
    root_b = base.resolve() / "agents" / "iso-agent-b"
    (root_b / "notes.txt").write_text("b-private", encoding="utf-8")
    return mod_a, root_a, root_b


async def test_filesystem_write_lands_under_own_root_only(
    two_fs_agents: tuple[FilesystemModule, Path, Path],
) -> None:
    mod_a, root_a, root_b = two_fs_agents
    b_before = _tree(root_b)

    await mod_a.write_file("notes.txt", "a-private")

    assert _tree(root_a) == {"notes.txt": "a-private"}
    assert _tree(root_b) == b_before == {"notes.txt": "b-private"}


def _escape_paths(root_b: Path) -> list[str]:
    return [
        "/etc",
        "/etc/hostname",
        "../iso-agent-b",
        "../iso-agent-b/notes.txt",
        str(root_b),
        str(root_b / "notes.txt"),
    ]


@pytest.mark.parametrize("index", range(6))
async def test_filesystem_every_tool_refuses_escape(
    two_fs_agents: tuple[FilesystemModule, Path, Path], index: int
) -> None:
    mod_a, _root_a, root_b = two_fs_agents
    path = _escape_paths(root_b)[index]
    b_before = _tree(root_b)

    with pytest.raises(ScopeViolation):
        await mod_a.read_file(path)
    with pytest.raises(ScopeViolation):
        await mod_a.list_dir(path)
    with pytest.raises(ScopeViolation):
        await mod_a.write_file(path, "planted")
    with pytest.raises(ScopeViolation):
        await mod_a.delete_file(path)

    assert (root_b / "notes.txt").read_text(encoding="utf-8") == "b-private"
    assert _tree(root_b) == b_before


# ── 4. Audit identity matches the backend actually touched ───────────────────


@pytest.fixture
def audit_file(tmp_path: Path) -> Iterator[Path]:
    """Configure the real audit file sink, then restore the global logging state."""
    import structlog

    from scoped_mcp.audit import configure_logging

    path = tmp_path / "audit.jsonl"
    saved_structlog = structlog.get_config()
    root = logging.getLogger()
    saved_root_handlers = list(root.handlers)
    audit_logger = logging.getLogger("audit")
    before = {id(h) for h in audit_logger.handlers}
    try:
        configure_logging(audit_log=str(path))
        yield path
    finally:
        structlog.configure(**saved_structlog)
        root.handlers[:] = saved_root_handlers
        for h in list(audit_logger.handlers):
            if id(h) not in before:
                audit_logger.removeHandler(h)
                h.close()


def _audit_records(path: Path, tool: str) -> list[dict]:
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [r for r in records if r.get("event") == "tool_call" and r.get("tool") == tool]


def _sqlite_manifest(db_dir: Path) -> Manifest:
    return Manifest.model_validate(
        {
            "agent_type": "research",
            "modules": {"sqlite": {"mode": "write", "config": {"db_dir": str(db_dir)}}},
        }
    )


def _fs_manifest(base: Path) -> Manifest:
    return Manifest.model_validate(
        {
            "agent_type": "research",
            "modules": {"filesystem": {"mode": "write", "config": {"base_path": str(base)}}},
        }
    )


async def test_audit_identity_matches_sqlite_backend_touched(
    tmp_path: Path, audit_file: Path
) -> None:
    db_dir = tmp_path / "db"
    manifest = _sqlite_manifest(db_dir)

    # A then B in one process, so a stale or process-global identity is caught.
    for ctx in (AGENT_A, AGENT_B):
        server = build_server(ctx, manifest)
        async with Client(server) as client:
            await client.call_tool(
                "sqlite_create_table",
                {"name": "notes", "columns": {"id": "INTEGER PRIMARY KEY", "value": "TEXT"}},
            )
            await client.call_tool(
                "sqlite_execute",
                {"sql": f"INSERT INTO notes (value) VALUES ('written-by-{ctx.agent_id}')"},
            )

    records = _audit_records(audit_file, "sqlite_execute")
    assert [r["agent_id"] for r in records] == ["iso-agent-a", "iso-agent-b"]
    for record in records:
        agent_id = record["agent_id"]
        # The backend that changed is the one the audit record names, and only that one.
        assert _sqlite_rows(db_dir / f"agent_{agent_id}.db", "notes") == [f"written-by-{agent_id}"]


async def test_audit_identity_matches_filesystem_backend_touched(
    tmp_path: Path, audit_file: Path
) -> None:
    base = tmp_path / "fs"
    manifest = _fs_manifest(base)

    for ctx in (AGENT_A, AGENT_B):
        server = build_server(ctx, manifest)
        async with Client(server) as client:
            await client.call_tool(
                "filesystem_write_file",
                {"path": "notes.txt", "content": f"written-by-{ctx.agent_id}"},
            )

    records = _audit_records(audit_file, "filesystem_write_file")
    assert [r["agent_id"] for r in records] == ["iso-agent-a", "iso-agent-b"]
    agents_dir = base.resolve() / "agents"
    assert sorted(p.name for p in agents_dir.iterdir()) == ["iso-agent-a", "iso-agent-b"]
    for record in records:
        agent_id = record["agent_id"]
        assert _tree(agents_dir / agent_id) == {"notes.txt": f"written-by-{agent_id}"}


async def test_audit_records_a_scope_violation_against_the_calling_agent(
    tmp_path: Path, audit_file: Path
) -> None:
    """A refused cross-agent write is logged under the agent that attempted it."""
    base = tmp_path / "fs"
    manifest = _fs_manifest(base)
    FilesystemModule(agent_ctx=AGENT_B, credentials={}, config={"base_path": str(base)})
    root_b = base.resolve() / "agents" / "iso-agent-b"

    server = build_server(AGENT_A, manifest)
    async with Client(server) as client:
        result = await client.call_tool(
            "filesystem_write_file",
            {"path": str(root_b / "planted.txt"), "content": "x"},
            raise_on_error=False,
        )
    assert result.is_error

    records = [json.loads(line) for line in audit_file.read_text().splitlines() if line.strip()]
    violations = [r for r in records if r.get("event") == "scope_violation"]
    assert [(r["tool"], r["agent_id"]) for r in violations] == [
        ("filesystem_write_file", "iso-agent-a")
    ]
    assert _tree(root_b) == {}
