"""Filesystem module — file read/write scoped to the agent's directory prefix.

Scope: PrefixScope with base_path from config. All paths are resolved to
agents/{agent_id}/ under the base_path. Traversal attacks and symlink
escapes are blocked by PrefixScope.enforce() before any I/O.

Config:
    base_path (str): required — root directory under which agent subdirs live.

Required credentials: none.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import ClassVar

from ..scoping import PrefixScope
from ._base import ToolModule, tool


class FilesystemModule(ToolModule):
    name: ClassVar[str] = "filesystem"
    scoping: ClassVar[PrefixScope | None] = None  # instantiated in __init__
    required_credentials: ClassVar[list[str]] = []

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        base_path = config.get("base_path")
        if not base_path:
            raise ValueError("filesystem module requires 'base_path' in config")
        self._scope = PrefixScope(str(base_path))
        # Ensure agent directory exists
        agent_root = Path(self._scope.apply("", agent_ctx))
        agent_root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, path: str) -> str:
        """Resolve a relative path to an absolute scoped path and enforce scope."""
        if os.path.isabs(path):
            absolute = path
        else:
            absolute = self._scope.apply(path, self.agent_ctx)
        self._scope.enforce(absolute, self.agent_ctx)
        return absolute

    @tool(mode="read")
    async def read_file(self, path: str) -> str:
        """Read the contents of a file within the agent's scoped directory.

        Args:
            path: relative path from the agent root, or absolute path within scope.

        Returns:
            File contents as a string.
        """
        absolute = self._resolve(path)
        try:
            return Path(absolute).read_text(encoding="utf-8")
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {path}")
        except IsADirectoryError:
            raise IsADirectoryError(f"Path is a directory, not a file: {path}")

    @tool(mode="read")
    async def list_dir(self, path: str = "") -> list[str]:
        """List the contents of a directory within the agent's scoped directory.

        Args:
            path: relative path from the agent root, or empty string for the root.

        Returns:
            List of entry names (files and directories) in the directory.
        """
        absolute = self._resolve(path) if path else self._scope.apply("", self.agent_ctx)
        if path:
            self._scope.enforce(absolute, self.agent_ctx)
        target = Path(absolute)
        if not target.exists():
            raise FileNotFoundError(f"Directory not found: {path!r}")
        if not target.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {path!r}")
        return sorted(entry.name for entry in target.iterdir())

    @tool(mode="write")
    async def write_file(self, path: str, content: str) -> bool:
        """Write content to a file within the agent's scoped directory.

        Creates parent directories if they don't exist.

        Args:
            path: relative path from the agent root, or absolute path within scope.
            content: string content to write.

        Returns:
            True on success.
        """
        absolute = self._resolve(path)
        target = Path(absolute)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return True

    @tool(mode="write")
    async def delete_file(self, path: str) -> bool:
        """Delete a file within the agent's scoped directory.

        Args:
            path: relative path from the agent root, or absolute path within scope.

        Returns:
            True on success.
        """
        absolute = self._resolve(path)
        target = Path(absolute)
        if not target.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if target.is_dir():
            raise IsADirectoryError(f"Path is a directory; cannot delete with delete_file: {path}")
        target.unlink()
        return True
