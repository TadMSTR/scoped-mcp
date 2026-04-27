"""MCP server proxy module — forward tool calls to any upstream MCP server.

Supports HTTP (streamable-http) and stdio transports. Tools are discovered
at startup via MCP tools/list and registered dynamically. The manifest key
becomes the tool name prefix; tool_allowlist/tool_denylist filter which
upstream tools are exposed.

Security note: unlike http_proxy, this module does NOT block loopback or
RFC1918 addresses. mcp_proxy is explicitly for proxying local services
declared by the operator in the manifest. The URL is operator-controlled,
not user-supplied. See docs/threat-model.md for the distinction.

Config:
    url (str): URL of an HTTP streamable-http MCP server.
        XOR
    command (str): Executable path for a stdio MCP server.
    args (list[str]): Arguments to pass to the command.

    tool_allowlist (list[str]): If set, only these tools are exposed.
        Empty list or absent = all tools exposed.
    tool_denylist (list[str]): Tools in this list are never exposed.
        Applied after allowlist filtering.
    discovery_timeout_seconds (float): Timeout for the initial tools/list
        call at startup. Default: 10.0.

Note: the manifest mode: field has no effect for mcp_proxy — use
tool_allowlist/tool_denylist for access control instead.

Required credentials: none (upstream credentials stay in the upstream service)
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, ClassVar

from fastmcp import Client

from ._base import ToolModule


class McpProxyModule(ToolModule):
    name: ClassVar[str] = "mcp_proxy"
    scoping = None
    required_credentials: ClassVar[list[str]] = []

    def __init__(self, agent_ctx: Any, credentials: dict, config: dict) -> None:
        super().__init__(agent_ctx, credentials, config)

        self._url: str | None = config.get("url")
        self._command: str | None = config.get("command")
        self._args: list[str] = config.get("args", [])

        if not self._url and not self._command:
            raise ValueError("mcp_proxy requires either 'url' or 'command' in config")
        if self._url and self._command:
            raise ValueError("mcp_proxy: specify 'url' OR 'command', not both")

        allowlist = config.get("tool_allowlist", [])
        denylist = config.get("tool_denylist", [])
        self._tool_allowlist: set[str] = set(allowlist) if allowlist else set()
        self._tool_denylist: set[str] = set(denylist)
        self._discovery_timeout: float = float(config.get("discovery_timeout_seconds", 10.0))

        # Discover tools synchronously at init time (before event loop starts).
        self._proxy_methods: list[Any] = asyncio.run(
            asyncio.wait_for(self._discover_tools(), timeout=self._discovery_timeout)
        )

    def _transport(self) -> str | dict:
        """Return a fastmcp.Client-compatible transport spec."""
        if self._url:
            return self._url
        return {"command": self._command, "args": self._args}

    async def _discover_tools(self) -> list[Any]:
        """Connect to upstream, enumerate tools, build proxy callables."""
        async with Client(self._transport()) as client:
            upstream_tools = await client.list_tools()

        methods = []
        seen_safe: set[str] = set()
        for upstream_tool in upstream_tools:
            tool_name: str = upstream_tool.name

            if self._tool_allowlist and tool_name not in self._tool_allowlist:
                continue
            if tool_name in self._tool_denylist:
                continue

            safe = re.sub(r"[^a-zA-Z0-9_]", "_", tool_name)
            if safe and safe[0].isdigit():
                safe = f"tool_{safe}"
            if safe in seen_safe:
                raise ValueError(
                    f"mcp_proxy: upstream tool '{tool_name}' normalizes to '{safe}', "
                    f"which collides with an earlier tool — use tool_allowlist to exclude one"
                )
            seen_safe.add(safe)

            method = self._make_proxy_method(tool_name)
            methods.append(method)

        return methods

    def _make_proxy_method(self, upstream_tool_name: str) -> Any:
        """Create an async callable that forwards a single tool call upstream."""
        module = self

        async def proxy_call(**kwargs: Any) -> Any:
            async with Client(module._transport()) as client:
                result = await client.call_tool(upstream_tool_name, arguments=kwargs)
            if result.data is not None:
                return result.data
            texts = [block.text for block in result.content if hasattr(block, "text")]
            return "\n".join(texts) if texts else result.content

        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", upstream_tool_name)
        if safe_name and safe_name[0].isdigit():
            safe_name = f"tool_{safe_name}"
        proxy_call.__name__ = safe_name

        # Required by _base.get_tool_methods() — marks this as a tool.
        proxy_call._is_tool = True
        proxy_call._tool_mode = "write"  # upstream tools have no mode metadata

        # Required by @audited — it uses fn.__self__ to find agent_ctx.
        proxy_call.__self__ = module

        return proxy_call

    def get_tool_methods(self, mode: Any) -> list[Any]:
        """Override: return pre-built proxy callables, ignoring mode filter.

        Mode filtering doesn't apply to proxied tools — the upstream server
        defines its own access semantics. Use tool_allowlist/tool_denylist
        in config for tool-level access control.
        """
        return self._proxy_methods
