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

    env (dict[str, str]): Optional environment variables for a spawned stdio
        child. Only applies to stdio (command) transport — has no effect on HTTP
        transport, which spawns nothing.

        **A stdio child does not inherit scoped-mcp's environment**, however many
        credentials the broker process itself holds. Anything the child needs must
        be named here explicitly.

        What it gets instead is a minimal safe base, and the mechanism matters more
        than any snapshot of it: the MCP SDK forwards a fixed ALLOWLIST of names
        (`mcp.client.stdio.DEFAULT_INHERITED_ENV_VARS` — currently HOME, LOGNAME,
        PATH, SHELL, TERM, USER on POSIX), and forwards each one **only if it is set
        in the parent**. So the base is a subset of that list, not the list itself:
        measured on this host, a child saw HOME, LOGNAME, PATH, SHELL with TERM and
        USER unset in the parent, and all six with them set. Python adds LC_CTYPE on
        top, which is not part of the SDK allowlist at all.

        Do not treat any of those names as guaranteed present. The allowlist is
        SDK-version and platform dependent, and membership of it is necessary but
        not sufficient — read the constant if you need the current answer.

        `env` EXTENDS that safe base rather than replacing it: a module declaring
        one variable still gets PATH. It does not widen to the rest of the broker
        environment — only the keys named here are added. That is the intended
        exposure model (vikunja#436 explicitly rejected blanket passthrough), and
        it is asserted against a real spawned child in
        tests/test_modules/test_mcp_proxy.py rather than against the transport
        spec, since neither property is observable from the spec alone.

        Note what this means for diagnosis: a child silently missing a credential
        looks identical to the upstream feature being disabled. If a proxied
        stdio server reports a capability as "not configured", check for an `env`
        block in the manifest before concluding the upstream is at fault — that
        misreading is what vikunja#436 recorded.

    headers (dict[str, str]): Optional HTTP headers to send with every request
        to the upstream MCP server. Only applies to HTTP (url) transport — has
        no effect on stdio transport. Sensitive header values (e.g. Authorization)
        are automatically redacted by the structlog sanitize processor.

    ${VAR_NAME} substitution applies to `headers` values and to `env` values, and
        in fact to every field of the manifest: manifest.py expands the whole file
        as text before it is parsed as YAML (`_expand_env_vars`, called from
        `load_manifest`), reading from the environment of the scoped-mcp process.
        It is not a per-field feature of this module and there is no field it
        skips. Two consequences worth knowing:
          - Only the braced form is expanded. A bare $VAR is left alone.
          - An undefined variable is a hard startup failure for the whole agent,
            not a silent empty string — the manifest names it and load fails.
        Expanded values are never logged. `env` values are never logged either:
        the one place `env` is mentioned in a log record is the ignored-on-HTTP
        warning below, which emits sorted key names only — the same
        keys-not-values discipline _validate_arguments uses for arguments.

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
import contextlib
import functools
import inspect
import keyword
import operator
import re
from datetime import UTC, datetime
from typing import Any, ClassVar

import anyio
import jsonschema
import structlog
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from ._base import ToolModule

_log = structlog.get_logger("audit")

# Errors that indicate the persistent stdio upstream's transport is dead (subprocess
# exited, pipe closed, connection reset) — as opposed to a legitimate tool-level error
# from a healthy upstream. A single transparent reconnect+retry is attempted for these;
# anything else propagates untouched so real upstream outages are not masked (plan item 4).
_RECONNECTABLE_ERRORS: tuple[type[BaseException], ...] = (
    anyio.BrokenResourceError,
    anyio.ClosedResourceError,
    anyio.EndOfStream,
    ConnectionError,  # includes ConnectionResetError / BrokenPipeError
    ProcessLookupError,
    EOFError,
)


def _is_reconnectable(exc: BaseException) -> bool:
    """True if exc (or, unwrapping an ExceptionGroup, any leaf) is a dead-transport error."""
    if isinstance(exc, _RECONNECTABLE_ERRORS):
        return True
    if isinstance(exc, BaseExceptionGroup):
        return any(_is_reconnectable(e) for e in exc.exceptions)
    return False


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
    # scoping=None: mcp_proxy forwards to upstream servers that carry their own
    # access model. Room/resource scoping for upstream services (e.g. which Matrix
    # rooms an agent may read/write) must be enforced at the upstream token level —
    # issue a per-agent token with the required scope, not a shared operator token.
    # Attempting to enforce scope here would require parsing every upstream tool's
    # semantics, which is not feasible generically (M-01).
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
        self._env: dict[str, str] = config.get("env", {}) or {}
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
        if self._env and self._url:
            # Mirror of the headers warning above. Without it, an `env` block on an
            # HTTP module is accepted in silence and looks configured — the same
            # shape of misreading vikunja#436 recorded, where a missing credential
            # was indistinguishable from a disabled upstream feature.
            # Key names only, never values: env is a common secret carrier.
            _log.warning(
                "mcp_proxy_env_ignored",
                reason="env config has no effect on http transport (nothing is spawned)",
                env_keys=sorted(self._env),
            )

        allowlist = config.get("tool_allowlist", [])
        denylist = config.get("tool_denylist", [])
        self._tool_allowlist: set[str] = set(allowlist) if allowlist else set()
        self._tool_denylist: set[str] = set(denylist)
        self._discovery_timeout: float = float(config.get("discovery_timeout_seconds", 10.0))
        self._client_handle: Any | None = None  # outer Client for stdio — retained for __aexit__
        self._persistent_client: Any | None = None  # return value of __aenter__; used for calls
        # Serializes dead-transport reconnects so N concurrent callers that hit the same broken
        # pipe don't each tear down and replace the handle (F-02). Created here (outside the
        # event loop) — asyncio.Lock binds to the running loop lazily on first use.
        self._reconnect_lock = asyncio.Lock()

        # {upstream_tool_name: inputSchema_dict | None} — populated at discovery, refreshed
        # on stdio reconnect via _refresh_schemas(). Used by proxy_call to validate arguments
        # against the upstream-declared JSON Schema before forwarding the call.
        self._schemas: dict[str, dict[str, Any] | None] = {}

        # The normalized names actually registered as proxy methods, in discovery order.
        # Kept separately from _schemas (which is keyed by the RAW upstream name) because
        # this is what tool_inventory() reports, and the raw name is upstream-controlled:
        # an upstream could advertise a tool whose name carries markup, newlines or
        # control characters, and the inventory flows into an agent's context and from
        # there into whatever that agent renders it with. The normalized form is
        # ``[a-zA-Z0-9_]+`` by construction, and is also the truthful answer to what this
        # proxy registered.
        self._registered_names: list[str] = []

        # Discover tools synchronously at init time (before event loop starts).
        self._proxy_methods: list[Any] = asyncio.run(
            asyncio.wait_for(self._discover_tools(), timeout=self._discovery_timeout)
        )

        # When this instance's tool set was determined. Discovery happens exactly once,
        # here, and is never widened afterwards (see _refresh_schemas_from_client) — so
        # this timestamp bounds how stale the exposed surface can be. It is NOT always
        # the process start time: a module that failed init and was later recovered by
        # the self-healer re-discovers, and this moves while the process does not.
        self._discovered_at: str = datetime.now(UTC).isoformat()

    def tool_inventory(self, include_names: bool = False) -> dict[str, Any]:
        """Return what this proxy actually registered from its upstream.

        The registry surfaces this through ``scoped_mcp_status``, ``GET /health``
        and the health file so an external drift check can compare like-for-like:
        two agents proxying the same upstream with the same filtering must report
        the same ``tool_count``, and a mismatch is unambiguous drift — one of them
        is running against a tool set the upstream no longer has (vikunja#517).

        ``allowlisted``/``denylisted`` are what make that comparison sound: a
        count difference between an allowlisted and an unfiltered agent is
        expected, not drift.

        SECURITY: counts, booleans and a timestamp only. ``include_names`` adds
        the registered tool names and nothing else — never a schema, a URL, a
        header, or a credential. ``/health`` is unauthenticated, so the registry
        calls this with ``include_names=False`` there and on the health file;
        only the authenticated ``scoped_mcp_status`` tool passes True.

        The names reported are the **normalized** ones this proxy registered, not
        the raw upstream strings. The raw name is upstream-controlled and this
        payload lands in an agent's context, from where the agent may render it
        into Matrix or a tracker ticket — escaping belongs to those destinations
        and cannot be assumed here, so the value is constrained to
        ``[a-zA-Z0-9_]+`` at the source instead (IV-01/OE-01).
        """
        inventory: dict[str, Any] = {
            "tool_count": len(self._schemas),
            "transport": "http" if self._url else "stdio",
            "allowlisted": bool(self._tool_allowlist),
            "denylisted": bool(self._tool_denylist),
            "discovered_at": self._discovered_at,
        }
        if include_names:
            inventory["tools"] = sorted(self._registered_names)
        return inventory

    def _transport(self) -> str | dict | StreamableHttpTransport:
        """Return a fastmcp.Client-compatible transport spec."""
        if self._url:
            if self._headers:
                return StreamableHttpTransport(url=self._url, headers=self._headers)
            return self._url
        spec: dict = {"command": self._command, "args": self._args}
        if self._env:
            spec["env"] = self._env
        return {"mcpServers": {"upstream": spec}}

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
            self._registered_names.append(safe)

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

    async def _reconnect_persistent(self, failed_client: Any) -> None:
        """Tear down and re-open the persistent stdio upstream client (single attempt).

        Called by proxy_call when a call fails with a dead-transport error, passing the
        client handle that failed. Serialized by ``self._reconnect_lock`` and guarded by a
        re-check (F-02): if a concurrent caller already replaced the dead handle, this returns
        without reconnecting so the peer's fresh client is not torn down mid-call — the caller
        then simply retries against the current handle.

        Best-effort cleanup of the old (already-broken) handle — its __aexit__ may itself
        raise, which we swallow — then a fresh Client is opened exactly as in startup(), and
        schemas are refreshed against the new connection. Any failure here propagates to the
        caller, which surfaces it as a normal tool error (no second reconnect).
        """
        async with self._reconnect_lock:
            if self._persistent_client is not failed_client:
                return  # a concurrent caller already healed the transport
            old = self._client_handle
            self._client_handle = None
            self._persistent_client = None
            if old is not None:
                # old transport already broken — cleanup errors are expected, ignore them
                with contextlib.suppress(Exception):
                    await old.__aexit__(None, None, None)
            self._client_handle = Client(self._transport())
            self._persistent_client = await self._client_handle.__aenter__()
            await self._refresh_schemas_from_client(self._persistent_client)

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
        keywords at call time.

        This signature is NOT private to the proxy: FastMCP derives the inputSchema it
        advertises to clients from these annotations, so whatever is lost here is lost
        from the published schema too. A narrowing is therefore not recoverable by
        _validate_arguments() — that runs against the full upstream schema and would
        accept the value, but the client rejects it first against the narrower schema
        it was given, so the call never arrives. This docstring previously argued a
        lossy mapping was safe *because* of _validate_arguments; that reasoning holds
        for the call path and is wrong for the advertise path, and it is what let
        vikunja#755 through. Widen rather than narrow when a type cannot be expressed.

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
            """Map one JSON Schema property to a Python annotation.

            Both union spellings are handled, and both are handled the same way:

              ``type: [X, null]``            — the JSON Schema list form
              ``anyOf: [{type: X}, {...}]``  — emitted by pydantic/FastMCP for
                                               ``Optional[T]`` and for genuine unions

            A *single* non-null branch is ``Optional[T]`` and annotates as ``T``.
            **Two or more non-null branches are a real union and must annotate as a
            real union** (``int | str``), because FastMCP derives the advertised
            inputSchema from this annotation — so collapsing to the first branch does
            not merely lose precision internally, it publishes a narrower schema than
            the upstream declared and clients then reject values the upstream accepts
            (SMCP-42 / vikunja#755). The collapse was also branch-order dependent:
            ``anyOf:[integer,string]`` narrowed to ``int`` and ``anyOf:[string,integer]``
            to ``str``, so which values an agent could pass depended on the order the
            upstream happened to emit.

            Any branch this mapping cannot express falls back to ``Any`` for the whole
            property. That direction is deliberate: ``Any`` publishes no constraint, so
            it is never narrower than upstream, and ``_validate_arguments`` still checks
            every call against the full upstream schema. Narrowing is the failure mode
            that silently removes capability; widening is caught on the call path.
            """
            t = prop.get("type")
            if isinstance(t, list):
                branches: list[Any] = [x for x in t if x != "null"]
            elif t is None:
                any_of = prop.get("anyOf", [])
                # A branch is "null" only if it says so. Anything else is a real branch,
                # including one carrying no "type" at all (a $ref, or an enum-only
                # branch) — those are kept here precisely so they can force the Any
                # fallback below rather than being filtered out and letting a lone
                # typed sibling narrow the property.
                branches = []
                for x in any_of:
                    if not isinstance(x, dict):
                        branches.append(None)  # unmappable — forces Any
                        continue
                    branch_type = x.get("type")
                    if branch_type == "null":
                        continue
                    if isinstance(branch_type, list):
                        # The two union spellings nested: an anyOf branch that is itself
                        # a `type: [...]` list. Valid JSON Schema, just an unusual way to
                        # write it. Flatten rather than widen — the flattened union is
                        # exactly what the upstream declared, where Any would drop a
                        # constraint we can in fact express. (SMCP-42 audit, LOW-1)
                        branches.extend(b for b in branch_type if b != "null")
                    else:
                        branches.append(branch_type)
            elif isinstance(t, str):
                return json_py.get(t, Any)
            else:
                # `type` present but neither a string nor a list — malformed upstream.
                return Any

            if not branches:
                # No non-null branch at all (e.g. type: ["null"]) — nothing to express.
                return Any
            # The isinstance guard matters as much as the mapping. An unhashable branch
            # value (a list, from the nested spelling above) raises TypeError out of
            # json_py.get, and _discover_tools has no per-tool try/except — so one odd
            # schema aborted discovery for the whole module and denied every tool from
            # that upstream. Unmappable must widen, never raise. (SMCP-42 audit, LOW-1)
            mapped = [json_py.get(b) if isinstance(b, str) else None for b in branches]
            if any(m is None for m in mapped):
                return Any
            # dict.fromkeys dedupes while preserving upstream branch order, so the
            # published anyOf reads in the same order the upstream declared it.
            unique = list(dict.fromkeys(mapped))
            if len(unique) == 1:
                return unique[0]
            return functools.reduce(operator.or_, unique)

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
                # stdio: reuse the persistent subprocess opened in startup().
                # The single subprocess is shared across all concurrent calls — MCP
                # JSON-RPC multiplexes requests by id, but the subprocess stdin/stdout
                # are a single pipe. This is a reliability concern under high concurrency
                # (I-01), not a security issue. HTTP upstreams (below) are unaffected —
                # each call opens a fresh connection.
                #
                # Under a long-lived scoped-mcp process (SMCP-15) this subprocess lives for
                # hours/days, so an upstream that dies or restarts leaves a dead pipe. On a
                # dead-transport error, reconnect once and retry transparently so the agent
                # never sees a spurious failure it would have to retry itself (plan item 4).
                failed_client = module._persistent_client
                try:
                    result = await failed_client.call_tool(upstream_tool_name, arguments=kwargs)
                except Exception as exc:
                    if not _is_reconnectable(exc):
                        raise
                    _log.warning(
                        "mcp_proxy_reconnect",
                        module=module.name,
                        tool=upstream_tool_name,
                        error=type(exc).__name__,
                    )
                    # Reconnect only if this handle is still the live one (else a concurrent
                    # caller already healed it), then retry against the current handle.
                    await module._reconnect_persistent(failed_client)
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
