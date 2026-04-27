"""ToolModule base class — the public contract for all tool modules.

Third-party modules subclass ToolModule and implement the tool contract.
The registry discovers ToolModule subclasses, instantiates them with
agent context and credentials, and registers their tools with FastMCP.

Do NOT change the ToolModule interface without a major version bump — it
is the extension point that third-party module authors depend on.
"""

from __future__ import annotations

import functools
from abc import ABC
from typing import Any, ClassVar, Literal

from ..scoping import ScopeStrategy

# ── @tool decorator ──────────────────────────────────────────────────────────


def tool(mode: Literal["read", "write"]) -> Any:
    """Mark a ToolModule method as an MCP tool with the given mode.

    Usage:
        class MyModule(ToolModule):
            @tool(mode="read")
            async def my_read_tool(self, arg: str) -> str: ...

            @tool(mode="write")
            async def my_write_tool(self, arg: str) -> bool: ...
    """

    def decorator(fn: Any) -> Any:
        fn._tool_mode = mode
        fn._is_tool = True

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await fn(*args, **kwargs)

        wrapper._tool_mode = mode  # type: ignore[attr-defined]
        wrapper._is_tool = True  # type: ignore[attr-defined]
        return wrapper

    return decorator


# ── ToolModule base class ─────────────────────────────────────────────────────


class ToolModule(ABC):
    """Base class for all scoped-mcp tool modules.

    Subclass this and implement tool methods decorated with @tool(mode=...).
    The registry handles instantiation, credential injection, and FastMCP registration.

    Class variables to declare in subclasses:
        name: unique module identifier used in manifests and tool name prefixes.
        scoping: the ScopeStrategy to apply, or None for no scoping (e.g. webhooks).
        required_credentials: list of credential key names the module cannot
            start without — registry raises CredentialError if any are missing.
        optional_credentials: list of credential key names that are loaded if
            present but do not block startup if absent. Values are resolved by
            the same source (env or file) as required_credentials; if absent
            the key is simply missing from ``self.credentials`` at runtime.
    """

    name: ClassVar[str]
    scoping: ClassVar[ScopeStrategy | None] = None
    required_credentials: ClassVar[list[str]] = []
    optional_credentials: ClassVar[list[str]] = []

    def __init__(
        self,
        agent_ctx: Any,  # AgentContext — typed as Any to avoid circular import at class level
        credentials: dict[str, str],
        config: dict[str, Any],
    ) -> None:
        self.agent_ctx = agent_ctx
        self.credentials = credentials
        self.config = config

    async def startup(self) -> None:  # noqa: B027
        """Called once after the server event loop starts. Override to open
        persistent resources (connections, subprocesses, pools)."""

    async def shutdown(self) -> None:  # noqa: B027
        """Called once on graceful server stop. Override to release resources
        opened in startup()."""

    def get_tool_methods(self, mode: Literal["read", "write"] | None) -> list[Any]:
        """Return tool methods matching the requested mode.

        mode="read"  → only @tool(mode="read") methods
        mode="write" → both read and write methods
        mode=None    → all methods (used for write-only modules like notifiers)
        """
        methods = []
        for attr_name in dir(self):
            attr = getattr(type(self), attr_name, None)
            if attr is None:
                continue
            if not getattr(attr, "_is_tool", False):
                continue
            tool_mode: str = getattr(attr, "_tool_mode", "")
            if mode is None or (mode == "read" and tool_mode == "read"):
                methods.append(getattr(self, attr_name))
            elif mode == "write":
                # write mode includes both read and write tools
                methods.append(getattr(self, attr_name))
        return methods
