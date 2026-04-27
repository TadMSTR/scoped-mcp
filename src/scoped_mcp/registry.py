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
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from contextlib import asynccontextmanager

import structlog
from fastmcp import FastMCP

from . import modules as modules_pkg
from .audit import audited, get_ops_logger
from .credentials import resolve_credentials
from .exceptions import ManifestError
from .identity import AgentContext
from .manifest import Manifest, ModuleConfig
from .modules._base import ToolModule

logger = structlog.get_logger("ops")


def _discover_module_classes() -> dict[str, type[ToolModule]]:
    """Scan the scoped_mcp.modules package and return a dict of name → class."""
    discovered: dict[str, type[ToolModule]] = {}

    for mod_info in pkgutil.iter_modules(modules_pkg.__path__):
        if mod_info.name.startswith("_"):
            continue
        module = importlib.import_module(f"scoped_mcp.modules.{mod_info.name}")
        for _attr_name, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, ToolModule) and obj is not ToolModule and hasattr(obj, "name"):
                name = obj.name
                if name in discovered:
                    raise ManifestError(
                        f"Duplicate module name '{name}' found in "
                        f"'{mod_info.name}' and a previously loaded module"
                    )
                discovered[name] = obj

    return discovered


def _resolve_module_credentials(
    module_cls: type[ToolModule],
    manifest: Manifest,
) -> dict[str, str]:
    """Resolve credentials for a single module."""
    if not module_cls.required_credentials and not module_cls.optional_credentials:
        return {}

    cred_cfg = manifest.credentials
    return resolve_credentials(
        source=cred_cfg.source,
        required_keys=module_cls.required_credentials,
        file_path=cred_cfg.path,
        strict_permissions=cred_cfg.strict_permissions,
        optional_keys=module_cls.optional_credentials,
    )


def _make_module_lifespan(module_instances: list) -> object:
    """Build a FastMCP-compatible lifespan that calls startup/shutdown on all modules."""

    @asynccontextmanager
    async def lifespan(server):  # server arg required by FastMCP lifespan protocol
        ops = get_ops_logger()
        for mod in module_instances:
            ops.info("module_startup", module=mod.name)
            await mod.startup()
        try:
            yield {}
        finally:
            for mod in reversed(module_instances):
                ops.info("module_shutdown", module=mod.name)
                await mod.shutdown()

    return lifespan


def _resolve_class_name(module_name: str, module_cfg: ModuleConfig) -> str:
    """Return the module class name to look up — type: if set, else the manifest key."""
    return module_cfg.type if module_cfg.type is not None else module_name


def build_server(agent_ctx: AgentContext, manifest: Manifest) -> FastMCP:
    """Discover modules, filter to manifest, register tools, return a ready FastMCP server.

    Each module gets its own child FastMCP instance mounted on the parent with
    namespace=module.name. Tool names become e.g. "filesystem_read_file".
    """
    ops = get_ops_logger()
    ops.info("registry_start", agent_id=agent_ctx.agent_id, agent_type=agent_ctx.agent_type)

    available = _discover_module_classes()
    ops.info("modules_discovered", count=len(available), names=list(available.keys()))

    # Validate: all manifest modules must resolve to a known class
    unknown = []
    for module_name, module_cfg in manifest.modules.items():
        class_name = _resolve_class_name(module_name, module_cfg)
        if class_name not in available:
            unknown.append(f"{module_name!r} (type={class_name!r})")
    if unknown:
        raise ManifestError(
            f"Manifest references unknown module(s): {', '.join(unknown)}. "
            f"Available: {', '.join(sorted(available.keys()))}"
        )

    # Instantiate all modules first so they can be captured in the lifespan closure.
    all_instances = []
    for module_name, module_cfg in manifest.modules.items():
        class_name = _resolve_class_name(module_name, module_cfg)
        module_cls = available[class_name]
        ops.info("loading_module", module=module_name, class_name=class_name, mode=module_cfg.mode)
        credentials = _resolve_module_credentials(module_cls, manifest)
        instance = module_cls(
            agent_ctx=agent_ctx,
            credentials=credentials,
            config=module_cfg.config,
        )
        all_instances.append((module_name, module_cfg, instance))

    # Create the parent server with the module lifespan.
    server = FastMCP(
        f"scoped-mcp/{agent_ctx.agent_id}",
        lifespan=_make_module_lifespan([inst for _, _, inst in all_instances]),
    )

    # Register tools with child servers and mount.
    for module_name, module_cfg, instance in all_instances:
        child = FastMCP(module_name)
        tool_methods = instance.get_tool_methods(module_cfg.mode)
        if not tool_methods:
            ops.warning("no_tools_registered", module=module_name, mode=module_cfg.mode)
        for method in tool_methods:
            tool_name = f"{module_name}_{method.__name__}"
            # Wrap with @audited — this is the only place @audited is applied.
            # Module authors must not apply it themselves.
            wrapped = audited(tool_name)(method)
            child.tool(name=tool_name)(wrapped)
            ops.info("tool_registered", tool=tool_name, mode=module_cfg.mode)
        server.mount(child, prefix=module_name)

    ops.info("registry_complete", agent_id=agent_ctx.agent_id)
    return server
