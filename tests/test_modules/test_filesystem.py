"""Tests for modules/filesystem.py — PrefixScope enforcement, read/write/delete."""

from __future__ import annotations

from pathlib import Path

import pytest

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.filesystem import FilesystemModule


@pytest.fixture
def base_path(tmp_path: Path) -> Path:
    return tmp_path


@pytest.fixture
def fs_module(base_path: Path, agent_ctx: AgentContext) -> FilesystemModule:
    return FilesystemModule(
        agent_ctx=agent_ctx,
        credentials={},
        config={"base_path": str(base_path)},
    )


@pytest.fixture
def other_fs_module(base_path: Path, other_agent_ctx: AgentContext) -> FilesystemModule:
    return FilesystemModule(
        agent_ctx=other_agent_ctx,
        credentials={},
        config={"base_path": str(base_path)},
    )


# ── Happy-path read/write/delete ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_write_and_read_file(fs_module: FilesystemModule) -> None:
    result = await fs_module.write_file("hello.txt", "hello world")
    assert result is True
    content = await fs_module.read_file("hello.txt")
    assert content == "hello world"


@pytest.mark.asyncio
async def test_list_dir_after_write(fs_module: FilesystemModule) -> None:
    await fs_module.write_file("a.txt", "a")
    await fs_module.write_file("b.txt", "b")
    entries = await fs_module.list_dir()
    assert "a.txt" in entries
    assert "b.txt" in entries


@pytest.mark.asyncio
async def test_write_creates_parent_dirs(fs_module: FilesystemModule) -> None:
    await fs_module.write_file("subdir/nested/file.txt", "nested content")
    content = await fs_module.read_file("subdir/nested/file.txt")
    assert content == "nested content"


@pytest.mark.asyncio
async def test_delete_file(fs_module: FilesystemModule) -> None:
    await fs_module.write_file("to_delete.txt", "bye")
    result = await fs_module.delete_file("to_delete.txt")
    assert result is True
    with pytest.raises(FileNotFoundError):
        await fs_module.read_file("to_delete.txt")


@pytest.mark.asyncio
async def test_read_nonexistent_raises(fs_module: FilesystemModule) -> None:
    with pytest.raises(FileNotFoundError):
        await fs_module.read_file("nonexistent.txt")


@pytest.mark.asyncio
async def test_delete_nonexistent_raises(fs_module: FilesystemModule) -> None:
    with pytest.raises(FileNotFoundError):
        await fs_module.delete_file("ghost.txt")


# ── Cross-agent isolation ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cross_agent_read_blocked(
    fs_module: FilesystemModule,
    other_fs_module: FilesystemModule,
    base_path: Path,
    other_agent_ctx: AgentContext,
) -> None:
    """Agent 1 cannot read a file written by agent 2."""
    await other_fs_module.write_file("secret.txt", "agent2 data")
    other_root = base_path / "agents" / "test-agent-2" / "secret.txt"
    with pytest.raises(ScopeViolation):
        await fs_module.read_file(str(other_root))


@pytest.mark.asyncio
async def test_cross_agent_write_blocked(
    fs_module: FilesystemModule,
    base_path: Path,
) -> None:
    other_target = str(base_path / "agents" / "test-agent-2" / "evil.txt")
    with pytest.raises(ScopeViolation):
        await fs_module.write_file(other_target, "injection")


# ── Traversal attack prevention ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dotdot_traversal_blocked(
    fs_module: FilesystemModule,
    base_path: Path,
    agent_ctx: AgentContext,
) -> None:
    traversal = str(base_path / "agents" / "test-agent-1" / ".." / ".." / "etc" / "passwd")
    with pytest.raises(ScopeViolation):
        await fs_module.read_file(traversal)


@pytest.mark.asyncio
async def test_absolute_escape_blocked(fs_module: FilesystemModule) -> None:
    with pytest.raises(ScopeViolation):
        await fs_module.read_file("/etc/passwd")


@pytest.mark.asyncio
async def test_symlink_escape_blocked(
    fs_module: FilesystemModule,
    base_path: Path,
    agent_ctx: AgentContext,
) -> None:
    agent_root = base_path / "agents" / "test-agent-1"
    outside = base_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("outside data")
    link = agent_root / "escape"
    link.symlink_to(outside)
    with pytest.raises(ScopeViolation):
        await fs_module.read_file(str(link / "secret.txt"))


# ── Config validation ─────────────────────────────────────────────────────────

def test_missing_base_path_raises(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="base_path"):
        FilesystemModule(agent_ctx=agent_ctx, credentials={}, config={})
