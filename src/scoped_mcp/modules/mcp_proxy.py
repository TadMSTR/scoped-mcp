"""MCP server proxy module — forward tool calls to any upstream MCP server.

Supports HTTP (streamable-http) and stdio transports. Tools are discovered
at startup via MCP tools/list and registered dynamically. The manifest key
becomes the tool name prefix; tool_allowlist/tool_denylist filter which
upstream tools are exposed.

HTTP transport: a new connection is opened per tool call (cheap, stateless).

stdio transport: two subprocess spawns occur per module lifetime:
  1. A short-lived subprocess during __init__ for tool discovery (tools/list).
  2. A persistent subprocess opened in startup() and reused for all tool calls.
The persistent subprocess is closed in shutdown() when the server stops.

Security note: unlike http_proxy, this module does NOT block loopback or
RFC1918 addresses. mcp_proxy is explicitly for proxying local services
declared by the operator in the manifest. The URL is operator-controlled,
not user-supplied. See docs/threat-model.md for the distinction.

Config:
    url (str): URL of an HTTP streamable-http MCP server.
        XOR
    command (str): Executable path for a stdio MCP server.
    args (list[str]): Arguments to pass to the command.

    headers (dict[str, str]): Optional HTTP headers to send with every request
        to the upstream MCP server. Only applies to HTTP (url) transport — has
        no effect on stdio transport. Header values support ${VAR_NAME}
        substitution via the manifest credentials block (resolved before this
        module is instantiated). Sensitive header values (e.g. Authorization)
        are automatically redacted by the structlog sanitize processor.

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
import inspect
import keyword
import re
from typing import Any, ClassVar

import jsonschema
import structlog
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from ._base import ToolModule

_log = structlog.get_logger("audit")


def _coerce_schema(raw: Any) -> dict[str, Any] | None:
    """Return raw if it is a usable JSON Schema dict, else None.

    fastmcp tool descriptors sometimes carry pydantic models or empty dicts —
    only a non-empty dict is a real schema worth validating against.
    """
    if isinstance(raw, dict) and raw:
        return raw
    return None


class _ProxyValidationError(ValueError):
    """Raised when proxied arguments fail upstream inputSchema validation."""


class McpProxyModule(ToolModule):
    name: ClassVar[str] = "mcp_proxy"
    scoping = None
    required_credentials: ClassVar[list[str]] = []

    def __init__(self, agent_ctx: Any, credentials: dict, config: dict) -> None:
        super().__init__(agent_ctx, credentials, config)

        # Set by the registry after instantiation to the manifest key (e.g. "agent-bus").
        # Used as the server key for hook lookups in run_before_hooks().
        self._manifest_key: str = ""

        self._url: str | None = config.get("url")
        self._command: str | None = config.get("command")
        self._args: list[str] = config.get("args", [])
        self._headers: dict[str, str] = config.get("headers") or {}

        if not self._url and not self._command:
            raise ValueError("mcp_proxy requires either 'url' or 'command' in config")
        if self._url and self._command:
            raise ValueError("mcp_proxy: specify 'url' OR 'command', not both")
        if self._headers and self._command:
            _log.warning(
                "mcp_proxy_headers_ignored",
                reason="headers config has no effect on stdio transport",
            )

        allowlist = config.get("tool_allowlist", [])
        denylist = config.get("tool_denylist", [])
        self._tool_allowlist: set[str] = set(allowlist) if allowlist else set()
        self._tool_denylist: set[str] = set(denylist)
        self._discovery_timeout: float = float(config.get("discovery_timeout_seconds", 10.0))
        self._client_handle: Any | None = None  # outer Client for stdio — retained for __aexit__
        self._persistent_client: Any | None = None  # return value of __aenter__; used for calls

        # {upstream_tool_name: inputSchema_dict | None} — populated at discovery, refreshed
        # on stdio reconnect via _refresh_schemas(). Used by proxy_call to validate arguments
        # against the upstream-declared JSON Schema before forwarding the call.
        self._schemas: dict[str, dict[str, Any] | None] = {}

        # Discover tools synchronously at init time (before event loop starts).
        self._proxy_methods: list[Any] = asyncio.run(
            asyncio.wait_for(self._discover_tools(), timeout=self._discovery_timeout)
        )

    def _transport(self) -> str | dict | StreamableHttpTransport:
        """Return a fastmcp.Client-compatible transport spec."""
        if self._url:
            if self._headers:
                return StreamableHttpTransport(url=self._url, headers=self._headers)
            return self._url
        return {"mcpServers": {"upstream": {"command": self._command, "args": self._args}}}

    async def _discover_tools(self) -> list[Any]:
        """Connect to upstream, enumerate tools, build proxy callables.

        Also populates ``self._schemas`` with each upstream tool's ``inputSchema``
        for use by per-call argument validation.
        """
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

            self._schemas[tool_name] = _coerce_schema(getattr(upstream_tool, "inputSchema", None))

            method = self._make_proxy_method(tool_name)
            methods.append(method)

        return methods

    async def _refresh_schemas_from_client(self, client: Any) -> None:
        """Re-fetch tools/list from an already-open client and update the schema cache.

        Filters via the same allowlist/denylist as ``_discover_tools`` so a
        refresh can never widen the exposed tool surface — a malicious or
        misconfigured upstream that suddenly advertises new tools cannot use a
        refresh to bypass the operator's allowlist.

        Update semantics — never demote validation:
        - Tools that disappear from the refresh response keep their existing
          schema. The proxy method built at __init__ remains callable, so we
          must never silently downgrade validation for it (audit M1).
        - A tool that returns from the refresh with no schema (None) does NOT
          overwrite an existing non-None schema. Strict-stays-strict.
        - A tool that returns with a new schema overwrites the prior one.

        Refresh failures are logged at warning and leave the existing cache
        intact (fail-safe: stale-but-restrictive over no validation at all).
        """
        try:
            upstream_tools = await client.list_tools()
        except Exception as e:
            _log.warning(
                "mcp_proxy_schema_refresh_failed",
                module=self.name,
                error=type(e).__name__,
            )
            return

        for t in upstream_tools:
            tool_name = t.name
            if self._tool_allowlist and tool_name not in self._tool_allowlist:
                continue
            if tool_name in self._tool_denylist:
                continue
            new_schema = _coerce_schema(getattr(t, "inputSchema", None))
            # Never demote a known-strict schema to None.
            if new_schema is None and self._schemas.get(tool_name) is not None:
                continue
            self._schemas[tool_name] = new_schema

    async def startup(self) -> None:
        if self._command:  # stdio transport — open persistent subprocess
            self._client_handle = Client(self._transport())
            self._persistent_client = await self._client_handle.__aenter__()
            # Refresh schemas against the live persistent connection so a
            # restart of this server picks up any upstream-side schema changes
            # that landed between __init__ discovery and lifespan startup.
            await self._refresh_schemas_from_client(self._persistent_client)

    async def shutdown(self) -> None:
        if self._client_handle is not None:
            await self._client_handle.__aexit__(None, None, None)
            self._client_handle = None
            self._persistent_client = None

    def _validate_arguments(self, upstream_tool_name: str, kwargs: dict[str, Any]) -> None:
        """Validate kwargs against the cached upstream inputSchema.

        On schema mismatch raises ``_ProxyValidationError``. Logs a warning to
        the audit stream with the tool name, the validation error message, and
        the *names* of the supplied arguments — never the values.
        """
        schema = self._schemas.get(upstream_tool_name)
        if schema is None:
            _log.debug(
                "mcp_proxy_no_schema",
                module=self.name,
                tool=upstream_tool_name,
            )
            return
        try:
            jsonschema.validate(kwargs, schema)
        except jsonschema.ValidationError as e:
            _log.warning(
                "mcp_proxy_schema_validation_failed",
                module=self.name,
                tool=upstream_tool_name,
                validation_error=e.message,
                argument_keys=sorted(kwargs.keys()),
            )
            raise _ProxyValidationError(
                f"mcp_proxy: arguments to {upstream_tool_name!r} failed schema validation: "
                f"{e.message}"
            ) from e

    @staticmethod
    def _signature_from_schema(
        schema: dict[str, Any] | None,
    ) -> tuple[inspect.Signature, dict[str, str]]:
        """Build an explicit inspect.Signature from an MCP inputSchema.

        fastmcp rejects tool functions whose signature contains **kwargs, so each
        proxied tool gets a synthesized signature derived from the upstream-declared
        inputSchema properties. The proxy body keeps **kwargs and receives args as
        keywords at call time; strict per-call validation still runs against the full
        schema in _validate_arguments(), so a lossy type mapping here is safe.

        Returns (signature, rename_map) where rename_map maps a sanitized Python
        parameter name back to the original upstream property name. Upstream names
        that are not valid Python identifiers or are reserved keywords are sanitized;
        proxy_call un-renames before forwarding.
        """
        json_py = {
            "string": str,
            "integer": int,
            "number": float,
            "boolean": bool,
            "array": list,
            "object": dict,
        }

        def py_type(prop: dict) -> Any:
            t = prop.get("type")
            if isinstance(t, list):
                non_null = [x for x in t if x != "null"]
                t = non_null[0] if non_null else None
            elif t is None:
                # anyOf: [{type: X}, {type: null}] — emitted by pydantic/FastMCP 2.x
                # for Optional[T] fields instead of type: [X, null].
                any_of = prop.get("anyOf", [])
                non_null = [
                    x.get("type")
                    for x in any_of
                    if isinstance(x, dict) and x.get("type") not in ("null", None)
                ]
                t = non_null[0] if non_null else None
            return json_py.get(t, Any)

        rename: dict[str, str] = {}
        used: set[str] = set()

        def safe_param(name: str) -> str:
            base = re.sub(r"[^a-zA-Z0-9_]", "_", name)
            if not base or base[0].isdigit():
                base = f"p_{base}"
            while keyword.iskeyword(base) or not base.isidentifier() or base in used:
                base = f"{base}_"
            used.add(base)
            if base != name:
                rename[base] = name
            return base

        empty = inspect.Signature(parameters=[]), rename
        if not isinstance(schema, dict):
            return empty
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            return empty
        required = set(schema.get("required", []) or [])

        params: list[inspect.Parameter] = []
        # required (no default) must precede optional for POSITIONAL_OR_KEYWORD
        for name, prop in props.items():
            if name in required:
                params.append(
                    inspect.Parameter(
                        safe_param(name),
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        annotation=py_type(prop if isinstance(prop, dict) else {}),
                    )
                )
        for name, prop in props.items():
            if name not in required:
                prop = prop if isinstance(prop, dict) else {}
                params.append(
                    inspect.Parameter(
                        safe_param(name),
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                        annotation=py_type(prop),
                        default=prop.get("default", None),
                    )
                )
        return inspect.Signature(parameters=params), rename

    def _make_proxy_method(self, upstream_tool_name: str) -> Any:
        """Create an async callable that forwards a single tool call upstream."""
        module = self
        _sig, _rename = self._signature_from_schema(self._schemas.get(upstream_tool_name))

        async def proxy_call(**kwargs: Any) -> Any:
            if _rename:
                kwargs = {_rename.get(k, k): v for k, v in kwargs.items()}
            kwargs = {k: v for k, v in kwargs.items() if v is not None}
            module._validate_arguments(upstream_tool_name, kwargs)

            if module._manifest_key:
                from ..hooks import run_before_hooks

                kwargs = await run_before_hooks(module._manifest_key, upstream_tool_name, kwargs)

            if module._persistent_client is not None:
                # stdio: reuse the persistent subprocess opened in startup()
                result = await module._persistent_client.call_tool(
                    upstream_tool_name, arguments=kwargs
                )
            else:
                # HTTP: open a connection per call (cheap, stateless)
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
        proxy_call.__signature__ = _sig
        proxy_call.__annotations__ = {
            p.name: (p.annotation if p.annotation is not inspect.Parameter.empty else Any)
            for p in _sig.parameters.values()
        }
        proxy_call.__annotations__["return"] = Any

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
