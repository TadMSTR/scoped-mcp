"""Module registry — discovers, filters, instantiates, and registers tool modules.

The registry is the bridge between manifests and FastMCP. It:
  1. Scans scoped_mcp/modules/ for ToolModule subclasses.
  2. Filters to the set declared in the manifest.
  3. Instantiates each module with agent context, credentials, and config.
  4. Creates a child FastMCP instance per module, registers mode-filtered tools
     (each wrapped by @audited), and mounts to the parent server with namespace=module.name.

Modules NOT listed in the manifest are never loaded, even if they exist in
the modules directory.

Namespace collisions (two modules with the same name) raise ManifestError at startup.

Fault isolation: a single module failing to import, instantiate, or start up does not
terminate the entire process. Failed modules are excluded from tool registration. The
always-present scoped_mcp_status tool reports their status so the operator can diagnose
and fix the problem.
"""

from __future__ import annotations

import asyncio
import fnmatch
import importlib
import inspect
import json
import os
import pkgutil
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastmcp import FastMCP

from . import modules as modules_pkg
from .audit import audited, get_ops_logger
from .credentials import filter_vault_credentials, resolve_credentials
from .exceptions import ManifestError
from .identity import AgentContext
from .manifest import Manifest, ModuleConfig
from .middleware import MiddlewareChain, ToolCallMiddleware
from .modules._base import ToolModule

logger = structlog.get_logger("ops")


def _discover_module_classes() -> tuple[dict[str, type[ToolModule]], dict[str, str]]:
    """Scan the scoped_mcp.modules package and return (discovered_ok, failed_imports).

    failed_imports maps module file stems (== class names by convention) to error
    strings for modules that raised on import. A per-module import failure does not
    abort discovery — all remaining modules are still scanned.

    Namespace collisions (two successfully-imported modules sharing the same .name)
    still raise ManifestError immediately, as that indicates a code bug.
    """
    discovered: dict[str, type[ToolModule]] = {}
    failed_imports: dict[str, str] = {}

    for mod_info in pkgutil.iter_modules(modules_pkg.__path__):
        if mod_info.name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"scoped_mcp.modules.{mod_info.name}")
        except Exception as exc:
            logger.error("module_import_failed", module=mod_info.name, error=str(exc))
            failed_imports[mod_info.name] = f"{type(exc).__name__}: {exc}"
            continue

        for _attr_name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, ToolModule) and obj is not ToolModule and hasattr(obj, "name"):
                name = obj.name
                if name in discovered:
                    raise ManifestError(
                        f"Duplicate module name '{name}' found in "
                        f"'{mod_info.name}' and a previously loaded module"
                    )
                discovered[name] = obj

    return discovered, failed_imports


def _resolve_module_credentials(
    module_cls: type[ToolModule],
    manifest: Manifest,
    vault_bundle: dict[str, str] | None = None,
) -> dict[str, str]:
    """Resolve credentials for a single module.

    When the manifest credential source is 'vault', vault_bundle must be the
    pre-fetched bundle from VaultCredentialSource.fetch(). The bundle is
    filtered to only the keys this module needs.
    """
    if not module_cls.required_credentials and not module_cls.optional_credentials:
        return {}

    cred_cfg = manifest.credentials
    if cred_cfg.source == "vault":
        return filter_vault_credentials(
            vault_bundle=vault_bundle or {},
            required_keys=module_cls.required_credentials,
            optional_keys=module_cls.optional_credentials,
        )
    return resolve_credentials(
        source=cred_cfg.source,
        required_keys=module_cls.required_credentials,
        file_path=cred_cfg.path,
        strict_permissions=cred_cfg.strict_permissions,
        optional_keys=module_cls.optional_credentials,
    )


def _write_health_file(module_health: dict, ops: object) -> None:
    """Write module health JSON to SCOPED_MCP_HEALTH_FILE if the env var is set.

    The file is written (or overwritten) at the end of each startup, giving
    session-start hooks a stable location to check for degraded modules.
    """
    path = os.environ.get("SCOPED_MCP_HEALTH_FILE")
    if not path:
        return
    failed = {k: v for k, v in module_health.items() if v.get("status") != "running"}
    data = {
        "modules": module_health,
        "failed_count": len(failed),
        "total_count": len(module_health),
        "healthy": len(failed) == 0,
    }
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        ops.info("health_file_written", path=path, failed=len(failed), total=len(module_health))
    except OSError as exc:
        ops.warning("health_file_write_failed", path=path, error=str(exc))


def _make_module_lifespan(
    module_instances: list[tuple[str, ToolModule]],
    vault_source: object = None,
    module_health: dict | None = None,
) -> object:
    """Build a FastMCP-compatible lifespan that calls startup/shutdown on all modules.

    Module startup failures are isolated: a single failing module does not prevent other
    modules from starting. Failures are recorded in module_health and the server yields
    normally so the working subset of tools remains available.

    module_instances: list of (manifest_name, instance) pairs
    vault_source: optional VaultCredentialSource; its token renewal task is started
        before modules come up and cancelled on shutdown.
    module_health: mutable dict keyed by manifest_name. Caller pre-populates entries for
        discovery/init failures; this function updates entries for startup results.
    """
    if module_health is None:
        module_health = {}

    @asynccontextmanager
    async def lifespan(server):  # server arg required by FastMCP lifespan protocol
        ops = get_ops_logger()
        started: list[tuple[str, ToolModule]] = []
        try:
            if vault_source is not None:
                await vault_source.start_renewal()

            async def _start(manifest_name: str, mod: ToolModule) -> None:
                ops.info("module_startup", module=manifest_name)
                started.append((manifest_name, mod))  # before await — always captured for cleanup
                await mod.startup()

            results = await asyncio.gather(
                *(_start(name, m) for name, m in module_instances),
                return_exceptions=True,
            )

            startup_failed: list[str] = []
            for (manifest_name, _mod), result in zip(module_instances, results, strict=False):
                if isinstance(result, BaseException):
                    err = f"{type(result).__name__}: {result}"
                    ops.error("module_startup_failed", module=manifest_name, error=err)
                    module_health[manifest_name] = {"status": "failed_startup", "error": err}
                    startup_failed.append(manifest_name)
                else:
                    module_health.setdefault(manifest_name, {})["status"] = "running"

            all_failed = [k for k, v in module_health.items() if v.get("status") != "running"]
            if all_failed:
                ops.warning(
                    "modules_degraded",
                    failed_modules=all_failed,
                    loaded_count=len(module_health) - len(all_failed),
                    total_count=len(module_health),
                )

            _write_health_file(module_health, ops)
            yield {}
        finally:
            for manifest_name, mod in reversed(started):
                ops.info("module_shutdown", module=manifest_name)
                try:
                    await mod.shutdown()
                except Exception as exc:
                    ops.error("module_shutdown_error", module=manifest_name, error=str(exc))
            if vault_source is not None:
                await vault_source.close()

    return lifespan


def _resolve_class_name(module_name: str, module_cfg: ModuleConfig) -> str:
    """Return the module class name to look up — type: if set, else the manifest key."""
    return module_cfg.type if module_cfg.type is not None else module_name


def _register_signing_hook_if_available(vault_bundle: dict[str, str], ops: object) -> None:
    """Register the agent-bus ed25519 signing hook if signing keys are in the Vault bundle.

    Auto-enabled when the bundle contains signing_private_key + signing_public_key.
    Silently no-ops if the cryptography package is not installed.
    """
    private_key = vault_bundle.get("signing_private_key", "")
    public_key = vault_bundle.get("signing_public_key", "")
    if not private_key or not public_key:
        return
    try:
        from .contrib.signing_hook import create_signing_hook
        from .hooks import register_before

        hook = create_signing_hook(private_key_b64=private_key, public_key_b64=public_key)
        register_before("agent-bus", "log_event", hook)
        ops.info("signing_hook_registered", server="agent-bus", tool="log_event")
    except ImportError:
        pass  # cryptography package not installed — signing unavailable


def _register_status_tool(server: FastMCP, module_health: dict) -> None:
    """Register scoped_mcp_status as a built-in tool on the parent server.

    This tool is always present regardless of manifest content. Operators can call it
    at session start to identify degraded modules and act before running further tasks.

    module_health is captured by closure and updated live by the lifespan, so the tool
    reflects startup failures that occur after build_server() returns.
    """

    async def scoped_mcp_status() -> dict:
        """Return the health status of all manifest-declared modules.

        Status values:
          running        — module loaded and started successfully
          failed_import  — module Python file could not be imported (missing dep, syntax error)
          failed_init    — module class could not be instantiated (bad config, missing credential)
          failed_startup — module startup() raised (service unreachable, bad state, etc.)

        Call this at session start to check for degraded modules before running tasks.
        """
        failed = {k: v for k, v in module_health.items() if v.get("status") != "running"}
        return {
            "modules": module_health,
            "failed_count": len(failed),
            "total_count": len(module_health),
            "healthy": len(failed) == 0,
        }

    server.tool(name="scoped_mcp_status")(scoped_mcp_status)


def _warn_unmatched_patterns(manifest: Manifest, tool_names: list[str], ops: object) -> None:
    """Warn for any gating patterns that match no registered tool (H-02).

    Tool names use the format ``{manifest_key}_{method}`` (underscores). Dotted
    patterns such as ``mcp_proxy.*`` will never match — operators must use
    ``mcp_proxy_*``. A pattern that matches nothing silently fails open
    (approval_required / shadow / per_tool rules never fire).
    """
    naming_hint = (
        "Tool names use {manifest_key}_{method} format — use underscores, not dots"
        " (e.g. mcp_proxy_* not mcp_proxy.*)"
    )

    if manifest.hitl is not None:
        for pattern in manifest.hitl.approval_required:
            if not any(fnmatch.fnmatch(t, pattern) for t in tool_names):
                ops.warning(
                    "hitl_pattern_matches_no_tools",
                    list="approval_required",
                    pattern=pattern,
                    hint=naming_hint,
                )
        for pattern in manifest.hitl.shadow:
            if not any(fnmatch.fnmatch(t, pattern) for t in tool_names):
                ops.warning(
                    "hitl_pattern_matches_no_tools",
                    list="shadow",
                    pattern=pattern,
                    hint=naming_hint,
                )

    if manifest.rate_limits is not None:
        for pattern in manifest.rate_limits.per_tool:
            if not any(fnmatch.fnmatch(t, pattern) for t in tool_names):
                ops.warning(
                    "rate_limit_pattern_matches_no_tools",
                    list="per_tool",
                    pattern=pattern,
                    hint=naming_hint,
                )


def build_server(
    agent_ctx: AgentContext,
    manifest: Manifest,
    middleware: list[ToolCallMiddleware] | None = None,
    auth: Any = None,
) -> FastMCP:
    """Discover modules, filter to manifest, register tools, return a ready FastMCP server.

    Module failures are isolated at every phase:
      - Import failure: module file cannot be imported → excluded from available set
      - Init failure:   module.__init__() raises       → excluded from tool registration
      - Startup failure: module.startup() raises       → lifespan records failure,
        server still starts

    The scoped_mcp_status tool (always registered) lets the operator inspect which modules
    are healthy and which failed, with error details.

    Truly unknown modules (not in available AND not in failed_imports) still raise
    ManifestError — that indicates a manifest typo, not a runtime failure.

    Each module gets its own child FastMCP instance mounted on the parent with
    namespace=module.name. Tool names become e.g. "filesystem_read_file".

    middleware: optional list of ToolCallMiddleware applied to every tool call.
        Middleware wraps the @audited function — spans include the full call duration.
        Empty list (default) adds no overhead.
    """
    ops = get_ops_logger()
    ops.info("registry_start", agent_id=agent_ctx.agent_id, agent_type=agent_ctx.agent_type)

    available, failed_imports = _discover_module_classes()
    ops.info("modules_discovered", count=len(available), names=list(available.keys()))
    if failed_imports:
        ops.warning("modules_import_failed", modules=list(failed_imports.keys()))

    # module_health is built up here; the lifespan updates it with startup results.
    module_health: dict[str, dict] = {}

    # Validate manifest modules: must resolve to a known class, a known import failure,
    # or raise ManifestError (typo / missing module file).
    unknown = []
    for module_name, module_cfg in manifest.modules.items():
        class_name = _resolve_class_name(module_name, module_cfg)
        if class_name in failed_imports:
            err = failed_imports[class_name]
            ops.error("module_load_failed", module=module_name, class_name=class_name, error=err)
            module_health[module_name] = {"status": "failed_import", "error": err}
        elif class_name not in available:
            unknown.append(f"{module_name!r} (type={class_name!r})")
    if unknown:
        raise ManifestError(
            f"Manifest references unknown module(s): {', '.join(unknown)}. "
            f"Available: {', '.join(sorted(available.keys()))}"
        )

    # Pre-fetch Vault credentials once before the module loop.
    # VaultCredentialSource.fetch() is synchronous and must run before the event loop.
    vault_source = None
    vault_bundle: dict[str, str] | None = None
    if manifest.credentials.source == "vault":
        from .credentials_vault import VaultCredentialSource  # optional [vault] extra

        vc = manifest.credentials.vault  # non-None guaranteed by manifest validator
        vault_source = VaultCredentialSource(
            addr=vc.addr,
            role_id_env=vc.role_id_env,
            secret_id_env=vc.secret_id_env,
            path=vc.path,
            agent_type=agent_ctx.agent_type,
            kv_version=vc.kv_version,
        )
        vault_bundle = vault_source.fetch()
        _register_signing_hook_if_available(vault_bundle, ops)

    # Instantiate modules, skipping any that failed discovery.
    all_instances: list[tuple[str, ModuleConfig, ToolModule]] = []
    for module_name, module_cfg in manifest.modules.items():
        if module_name in module_health:
            continue  # already failed at import — skip
        class_name = _resolve_class_name(module_name, module_cfg)
        module_cls = available[class_name]
        ops.info("loading_module", module=module_name, class_name=class_name, mode=module_cfg.mode)
        try:
            credentials = _resolve_module_credentials(
                module_cls, manifest, vault_bundle=vault_bundle
            )
            instance = module_cls(
                agent_ctx=agent_ctx,
                credentials=credentials,
                config=module_cfg.config,
            )
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            ops.error("module_init_failed", module=module_name, error=err)
            module_health[module_name] = {"status": "failed_init", "error": err}
            continue
        # Expose the manifest key to mcp_proxy for pre-call hook lookups.
        if hasattr(instance, "_manifest_key"):
            instance._manifest_key = module_name
        module_health[module_name] = {"status": "instantiated"}
        all_instances.append((module_name, module_cfg, instance))

    # Create the parent server with the module lifespan.
    # auth (a FastMCP TokenVerifier / AuthProvider) is set only for the HTTP transport —
    # it enforces bearer authentication on every request before tool dispatch. None (stdio)
    # leaves the server unauthenticated, matching stdio's private-pipe isolation.
    server = FastMCP(
        f"scoped-mcp/{agent_ctx.agent_id}",
        lifespan=_make_module_lifespan(
            [(name, inst) for name, _, inst in all_instances],
            vault_source=vault_source,
            module_health=module_health,
        ),
        auth=auth,
    )

    chain = MiddlewareChain(middleware or [])

    # Register tools with child servers and mount (only successfully instantiated modules).
    registered_tool_names: list[str] = []
    for module_name, module_cfg, instance in all_instances:
        child = FastMCP(module_name)
        tool_methods = instance.get_tool_methods(module_cfg.mode)
        if not tool_methods:
            ops.warning("no_tools_registered", module=module_name, mode=module_cfg.mode)
        for method in tool_methods:
            # audit_tool_name is the full namespaced name used in logs and @audited.
            # child.tool() receives only the bare method name — server.mount(prefix=)
            # applies the module_name prefix, so using the full name here would double it.
            audit_tool_name = f"{module_name}_{method.__name__}"
            registered_tool_names.append(audit_tool_name)
            # Wrap with @audited — this is the only place @audited is applied.
            # Module authors must not apply it themselves.
            wrapped = audited(audit_tool_name)(method)
            if middleware:
                wrapped = chain.wrap(audit_tool_name, wrapped, agent_ctx)
            child.tool(name=method.__name__)(wrapped)
            ops.info("tool_registered", tool=audit_tool_name, mode=module_cfg.mode)
        server.mount(child, prefix=module_name)

    # Always-present status tool — no module namespace prefix.
    _register_status_tool(server, module_health)
    registered_tool_names.append("scoped_mcp_status")

    # Validate policy patterns against registered tool names (H-02).
    # Tool names follow the format {manifest_key}_{method} (underscores, not dots).
    # A pattern that matches no registered tool silently never fires — warn loudly
    # so operators catch misconfigured approval_required/shadow/per_tool rules at
    # startup rather than discovering them after a security incident.
    _warn_unmatched_patterns(manifest, registered_tool_names, ops)

    ops.info("registry_complete", agent_id=agent_ctx.agent_id)
    return server
