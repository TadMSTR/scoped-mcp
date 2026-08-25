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
import contextlib
import fnmatch
import importlib
import inspect
import json
import os
import pkgutil
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
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
from .module_selfheal import (
    DependencyGateBudget,
    ModuleSelfHealer,
    await_dependency_ready,
    is_loopback_url,
    redact_url,
)
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


def _split_failed_by_optional(module_health: dict, optional_modules: set[str]) -> tuple[dict, dict]:
    """Split non-running module_health entries into (required_failed, optional_failed).

    Modules flagged ``optional: true`` in the manifest (SMCP-31) — e.g.
    claudebox-ops when claudebox is intentionally powered off — must not count
    toward failed_count/healthy, but stay visible separately so an *unplanned*
    outage of an optional dependency is still discoverable.
    """
    required_failed: dict = {}
    optional_failed: dict = {}
    for name, health in module_health.items():
        if health.get("status") == "running":
            continue
        if name in optional_modules:
            optional_failed[name] = health
        else:
            required_failed[name] = health
    return required_failed, optional_failed


def _read_previous_offline_optional(path: str | None) -> set[str]:
    """Return the ``offline_optional_modules`` set from a prior health-file write.

    Used to detect healthy<->offline transitions across a process restart
    (SMCP-31) without a separate state store — the health file already persists
    across restarts for the external prober, so it doubles as the "last known
    state" this comparison needs. Returns an empty set if the file is absent,
    unreadable, the env var isn't configured, or the file's content is
    syntactically-valid but not the expected dict shape (e.g. a stale/foreign
    file at the configured path) — the caller then treats every currently-offline
    optional module as newly-offline (a safe, alert-heavy default, never a
    silent one). Must never raise: this runs on every lifespan startup, and an
    uncaught exception here would crash the whole process's module startup —
    exactly the fault-isolation failure SMCP-31 exists to prevent.
    """
    if not path:
        return set()
    try:
        with open(path) as f:
            data = json.load(f)
        return set(data.get("offline_optional_modules", []))
    except (OSError, ValueError, AttributeError, TypeError):
        return set()


async def _alert_optional_module_transitions(
    previous_offline: set[str],
    current_offline: set[str],
    agent_id: str,
    agent_type: str,
) -> None:
    """Fire one low-severity ops alert per healthy<->offline transition (SMCP-31).

    Reuses the existing SMCP-26 Matrix->ntfy alert path. No alert fires while an
    optional module's offline/healthy state is unchanged from the previous
    process run — only on a genuine transition, so an already-offline claudebox
    does not re-alert on every PM2 restart while it stays down. Recovery
    (offline -> healthy) fires too, so the return to normal is visible.
    """
    from .ops_alert import send_ops_alert

    for name in sorted(current_offline - previous_offline):
        await send_ops_alert(
            "optional_module_offline",
            {"agent_id": agent_id, "agent_type": agent_type, "module": name},
        )
    for name in sorted(previous_offline - current_offline):
        await send_ops_alert(
            "optional_module_recovered",
            {"agent_id": agent_id, "agent_type": agent_type, "module": name},
        )


def _redact_module_errors(module_health: dict) -> dict:
    """Return a copy of ``module_health`` with each ``error`` reduced to its type.

    ``module_health[name]["error"]`` is ``f"{type(exc).__name__}: {exc}"``. The
    message half can embed whatever the raising library chose to include —
    notably a dependency URL with inline userinfo. Anything written to a file or
    pushed to an alert gets the type half only; the full string stays in the ops
    log and the authenticated status tool.

    Entries without an ``error`` pass through unchanged, so a ``running`` module
    is untouched.
    """
    redacted: dict = {}
    for name, health in module_health.items():
        if not isinstance(health, dict) or "error" not in health:
            redacted[name] = health
            continue
        entry = {k: v for k, v in health.items() if k != "error"}
        error_type = str(health["error"]).split(":", 1)[0].strip()
        if error_type:
            entry["error_type"] = error_type
        redacted[name] = entry
    return redacted


def _build_tool_inventory(
    instances: dict[str, ToolModule],
    module_health: dict,
    include_names: bool = False,
) -> dict[str, dict]:
    """Return ``{module_name: inventory}`` for every running proxy module.

    Answers "what is this process actually serving from each upstream", which is
    what turns a *suspected* stale proxy into a confirmed one (vikunja#517). An
    ``mcp_proxy`` enumerates its upstream exactly once, at ``__init__``, and never
    widens that set afterwards — so a proxy can sit indefinitely on a tool list the
    upstream has since grown, and nothing in the process notices. Comparing counts
    across two agents proxying the same upstream detects that with no upstream
    credentials, which is the whole point: the drift check must not be handed a
    fleet-wide credential set.

    Duck-typed on ``tool_inventory()`` rather than ``isinstance(McpProxyModule)`` so
    a module type is free to opt in later, and so a module whose import failed can
    never break status reporting. A module that does not implement it (or raises
    from it) is simply absent — this feeds three health reporters and must not be
    able to fail any of them.

    Only ``running`` modules are included. A module that instantiated but failed
    ``startup()`` has discovered tools it cannot actually serve; reporting its count
    would tell a drift consumer the agent is serving a surface it is not. Its
    failure is already visible in ``failed_count``/``module_health``.

    SECURITY: ``include_names`` is False for the unauthenticated ``/health`` route
    and the on-disk health file, True only for the authenticated
    ``scoped_mcp_status`` tool. See ``McpProxyModule.tool_inventory``.
    """
    inventory: dict[str, dict] = {}
    for name, instance in instances.items():
        if module_health.get(name, {}).get("status") != "running":
            continue
        fn = getattr(instance, "tool_inventory", None)
        if not callable(fn):
            continue
        try:
            inventory[name] = fn(include_names=include_names)
        except Exception:  # a health reporter must never fail on one bad module
            continue
    return inventory


def _write_health_file(
    module_health: dict,
    ops: object,
    credential_health: dict | None = None,
    optional_modules: set[str] | None = None,
    instances: dict[str, ToolModule] | None = None,
) -> None:
    """Write health JSON to SCOPED_MCP_HEALTH_FILE if the env var is set.

    Written at the end of startup and again on every credential-health state
    transition, giving an external watcher a stable, refreshable file to poll.
    ``written_at`` lets that watcher detect a wedged process whose file has gone
    stale. When a Vault credential source is present its ``credential_health()``
    snapshot is folded in, and the top-level ``healthy`` reflects both module and
    token health.

    ``optional_modules`` (SMCP-31): module names whose failure must not count
    toward ``failed_count``/``healthy`` — tracked separately under
    ``offline_optional_modules`` instead.

    ``instances`` (vikunja#517): live module instances, keyed by manifest name. When
    given, a ``tool_inventory`` block reports each running proxy's registered tool
    count, transport and filtering state, so a watcher can confirm a stale proxy
    rather than infer one. Passed by reference and read at write time, so a module
    recovered by the self-healer is reflected on the next write.

    SECURITY: per-module entries are written with the exception **type** only
    (``error_type``), never the raw exception message. A module constructor can
    raise with a message echoing back a dependency URL carrying inline
    credentials, and this file is a plain on-disk artifact polled by external
    watchers. Same contract the ops alerts and the ``/health`` route already
    hold. The full message stays available to the operator through the ops log
    (``module_init_failed``) and the authenticated ``scoped_mcp_status`` tool.
    Tool inventory is written **without** names for the same reason.
    """
    path = os.environ.get("SCOPED_MCP_HEALTH_FILE")
    if not path:
        return
    required_failed, optional_failed = _split_failed_by_optional(
        module_health, optional_modules or set()
    )
    token_healthy = credential_health is None or credential_health.get("token_healthy", True)
    data = {
        "modules": _redact_module_errors(module_health),
        "failed_count": len(required_failed),
        "total_count": len(module_health),
        "healthy": len(required_failed) == 0 and token_healthy,
        "written_at": datetime.now(UTC).isoformat(),
    }
    if optional_failed:
        data["offline_optional_modules"] = sorted(optional_failed)
    tool_inventory = _build_tool_inventory(instances or {}, module_health)
    if tool_inventory:
        data["tool_inventory"] = tool_inventory
    if credential_health is not None:
        data["credentials"] = credential_health
    try:
        # Atomic write: an external prober now polls this file on its own schedule, so a
        # torn in-place write could hand it half-serialized JSON. Write a sibling temp
        # file and os.replace() it into place (atomic on the same filesystem).
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
        ops.info(
            "health_file_written",
            path=path,
            failed=len(required_failed),
            offline_optional=len(optional_failed),
            total=len(module_health),
            token_healthy=token_healthy,
        )
    except OSError as exc:
        ops.warning("health_file_write_failed", path=path, error=str(exc))


def _make_module_lifespan(
    module_instances: list[tuple[str, ToolModule]],
    vault_source: object = None,
    module_health: dict | None = None,
    agent_ctx: AgentContext | None = None,
    optional_modules: set[str] | None = None,
    selfheal_retry: Callable[[str], Awaitable[ToolModule | None]] | None = None,
    instances: dict[str, ToolModule] | None = None,
) -> object:
    """Build a FastMCP-compatible lifespan that calls startup/shutdown on all modules.

    Module startup failures are isolated: a single failing module does not prevent other
    modules from starting. Failures are recorded in module_health and the server yields
    normally so the working subset of tools remains available.

    module_instances: list of (manifest_name, instance) pairs
    vault_source: optional VaultCredentialSource; its token renewal task is started
        before modules come up and cancelled on shutdown. When present, a credential-
        health transition callback is registered that rewrites the health file and
        fires a Vault-independent ops alert on each healthy⇄degraded edge.
    module_health: mutable dict keyed by manifest_name. Caller pre-populates entries for
        discovery/init failures; this function updates entries for startup results.
    agent_ctx: optional identity, included in ops-alert payloads.
    optional_modules: manifest module names flagged ``optional: true`` (SMCP-31) — their
        failure is excluded from failed_count/healthy everywhere this lifespan touches the
        health file, and drives the healthy<->offline transition alert below.
    selfheal_retry: optional coroutine taking a module name and re-running the full
        instantiate → startup → register-tools sequence for it, returning the recovered
        instance (or raising on failure). When given, any module left in ``failed_init``/
        ``failed_startup`` after startup is retried by a background task with exponential
        backoff, so a dependency that comes up late recovers with no restart. Recovered
        instances are appended to the shutdown list so they are torn down normally.
    instances: live module instances keyed by manifest name, shared by reference with
        build_server and updated in place when the self-healer replaces one. Folded
        into every health-file write as ``tool_inventory`` (vikunja#517).
    """
    if module_health is None:
        module_health = {}
    optional_modules = optional_modules or set()
    instances = {} if instances is None else instances

    agent_id = agent_ctx.agent_id if agent_ctx is not None else "unknown"
    agent_type = agent_ctx.agent_type if agent_ctx is not None else "unknown"

    async def _on_credential_health_change(health: dict) -> None:
        """Fire once per token-health transition — rewrite health file + ops alert.

        Runs inside the renewal loop's task; must be best-effort. _write_health_file
        only touches the local filesystem and send_ops_alert never raises, so a
        transition can rewrite the file and notify #alerts even while Vault is down.
        """
        ops = get_ops_logger()
        _write_health_file(
            module_health,
            ops,
            credential_health=health,
            optional_modules=optional_modules,
            instances=instances,
        )
        from .ops_alert import send_ops_alert

        token_healthy = health.get("token_healthy", True)
        event = "vault_credentials_recovered" if token_healthy else "vault_credentials_degraded"
        await send_ops_alert(
            event,
            {
                "agent_id": agent_id,
                "agent_type": agent_type,
                "token_healthy": token_healthy,
                "consecutive_failures": health.get("consecutive_failures"),
                "reauth_enabled": health.get("reauth_enabled"),
            },
        )

    @asynccontextmanager
    async def lifespan(server):  # server arg required by FastMCP lifespan protocol
        ops = get_ops_logger()
        started: list[tuple[str, ToolModule]] = []
        healer: ModuleSelfHealer | None = None
        try:
            if vault_source is not None:
                vault_source.set_health_change_callback(_on_credential_health_change)
                from .ops_alert import alerting_configured

                if not alerting_configured():
                    ops.warning(
                        "ops_alert_unconfigured",
                        hint="set SCOPED_MCP_ALERT_MATRIX_{HOMESERVER,TOKEN,ROOM} to "
                        "route credential-degradation alerts to #alerts",
                    )
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

            startup_cred_health = (
                vault_source.credential_health() if vault_source is not None else None
            )

            # SMCP-31: detect optional-module healthy<->offline transitions before
            # overwriting the health file, so the comparison is against the previous
            # process's last-known state (persisted in the health file itself — no
            # separate state store needed). This is the single point where both
            # init-time (failed_import/failed_init) and startup-time (failed_startup)
            # failures are both known, so it covers an optional module failing at
            # either phase.
            if optional_modules:
                health_file_path = os.environ.get("SCOPED_MCP_HEALTH_FILE")
                previous_offline = _read_previous_offline_optional(health_file_path)
                _, optional_failed = _split_failed_by_optional(module_health, optional_modules)
                current_offline = set(optional_failed)
                try:
                    await _alert_optional_module_transitions(
                        previous_offline, current_offline, agent_id, agent_type
                    )
                except Exception as exc:  # best-effort — must never block startup
                    ops.warning("optional_module_alert_failed", error=type(exc).__name__)

            _write_health_file(
                module_health,
                ops,
                credential_health=startup_cred_health,
                optional_modules=optional_modules,
                instances=instances,
            )

            # Background re-init loop. Started only when something actually
            # failed, so a healthy process pays nothing for it. Recovery flips
            # module_health to "running", which /health reads live on every
            # request — the next probe returns 200 with no restart.
            if selfheal_retry is not None:

                async def _retry_and_track(name: str) -> None:
                    instance = await selfheal_retry(name)
                    if instance is not None:
                        # Recovered mid-life: still needs shutdown at process exit.
                        started.append((name, instance))

                def _rewrite_health_file() -> None:
                    _write_health_file(
                        module_health,
                        ops,
                        credential_health=(
                            vault_source.credential_health() if vault_source is not None else None
                        ),
                        optional_modules=optional_modules,
                        instances=instances,
                    )

                healer = ModuleSelfHealer(
                    _retry_and_track,
                    module_health,
                    agent_id=agent_id,
                    agent_type=agent_type,
                    optional_modules=optional_modules,
                    on_health_change=_rewrite_health_file,
                )
                await healer.start()

            yield {}
        finally:
            if healer is not None:
                await healer.close()
            for manifest_name, mod in reversed(started):
                ops.info("module_shutdown", module=manifest_name)
                try:
                    await mod.shutdown()
                except Exception as exc:
                    ops.error("module_shutdown_error", module=manifest_name, error=str(exc))
            if vault_source is not None:
                await vault_source.close()

    return lifespan


def _gate_local_dependency(
    module_name: str,
    module_cfg: ModuleConfig,
    ops: object,
    budget: DependencyGateBudget,
) -> None:
    """Wait for a module's loopback HTTP dependency to bind, within a bounded budget.

    No-op unless the module's config declares a ``url`` that is loopback — a
    remote dependency must never gate startup (it may be ``optional: true`` and
    deliberately powered off, SMCP-31), and a module with no URL has nothing to
    wait for.

    ``budget`` is shared across every module in this build, so a manifest with a
    dozen loopback dependencies cannot multiply its per-module budget into a
    startup measured in minutes. When it is drained, the gate is skipped
    entirely.

    Logs a single ``dependency_wait`` line when a wait actually occurred, so the
    race shows up in the logs next time instead of being invisible. Nothing is
    logged on the happy path where the port is already bound.

    On timeout this returns normally and the caller proceeds to instantiate. The
    module will fail as it does today and be recorded ``failed_init``; the
    background re-init loop covers it from there. Startup never hangs.
    """
    url = module_cfg.config.get("url")
    if not isinstance(url, str) or not is_loopback_url(url):
        return
    requested = module_cfg.dependency_wait_timeout_seconds
    if requested <= 0:
        return  # gate explicitly disabled for this module
    allowance = budget.allowance(requested)
    if allowance <= 0:
        ops.info("dependency_wait_budget_exhausted", module=module_name, url=redact_url(url))
        return
    ready, elapsed = await_dependency_ready(
        url,
        timeout=allowance,
        interval=module_cfg.dependency_wait_interval_seconds,
    )
    budget.consume(elapsed)
    if elapsed >= module_cfg.dependency_wait_interval_seconds or not ready:
        ops.info(
            "dependency_wait",
            module=module_name,
            url=redact_url(url),
            elapsed_seconds=round(elapsed, 2),
            ready=ready,
            budget_remaining_seconds=round(budget.remaining, 2),
        )


def _register_module_tools(
    child: FastMCP,
    module_name: str,
    module_cfg: ModuleConfig,
    instance: ToolModule,
    chain: MiddlewareChain,
    middleware: list[ToolCallMiddleware] | None,
    agent_ctx: AgentContext,
    ops: object,
) -> list[str]:
    """Register a module's mode-filtered tools onto its child server.

    Returns the full namespaced audit tool names, for policy-pattern validation.

    Called twice for a recovered module's lifetime: once at startup for modules
    that instantiated cleanly, and once from the background re-init loop for one
    that did not. FastMCP's ``mount()`` is a live link — a tool added to an
    already-mounted child is immediately visible and dispatchable on the parent —
    so the second call needs no remount and no restart.
    """
    registered: list[str] = []
    tool_methods = instance.get_tool_methods(module_cfg.mode)
    if not tool_methods:
        ops.warning("no_tools_registered", module=module_name, mode=module_cfg.mode)
    for method in tool_methods:
        # audit_tool_name is the full namespaced name used in logs and @audited.
        # child.tool() receives only the bare method name — server.mount(namespace=)
        # applies the module_name prefix, so using the full name here would double it.
        audit_tool_name = f"{module_name}_{method.__name__}"
        registered.append(audit_tool_name)
        # Wrap with @audited — this is the only place @audited is applied.
        # Module authors must not apply it themselves.
        wrapped = audited(audit_tool_name)(method)
        if middleware:
            wrapped = chain.wrap(audit_tool_name, wrapped, agent_ctx)
        child.tool(name=method.__name__)(wrapped)
        ops.info("tool_registered", tool=audit_tool_name, mode=module_cfg.mode)
    return registered


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


def _manifest_status_fields(manifest_snapshot: dict[str, Any]) -> dict[str, Any]:
    """Compute manifest-staleness fields for scoped_mcp_status (SMCP-24).

    manifest_snapshot holds manifest_path/manifest_loaded_at/manifest_mtime_at_load,
    captured once in build_server() when the manifest was loaded. This re-stats the
    file at call time and compares against that captured mtime — under SMCP-15's
    long-lived HTTP transport, a module is only re-discovered at process start, so a
    manifest edit made after that has no effect until a PM2 restart. Without this
    signal, nothing distinguishes "warm and current" from "warm and stale".

    Returns {} if no manifest_path was captured (e.g. build_server() called without
    one, as in most tests). If the file can no longer be stat()'d at call time, the
    static path/loaded_at fields are still returned but manifest_stale is omitted —
    this is a soft diagnostic signal and must never raise from scoped_mcp_status.
    """
    path = manifest_snapshot.get("manifest_path")
    mtime_at_load = manifest_snapshot.get("manifest_mtime_at_load")
    if path is None or mtime_at_load is None:
        return {}

    fields: dict[str, Any] = {
        "manifest_path": path,
        "manifest_loaded_at": manifest_snapshot.get("manifest_loaded_at"),
    }
    try:
        current_mtime = os.path.getmtime(path)
    except OSError:
        return fields

    if current_mtime > mtime_at_load:
        fields["manifest_stale"] = True
        fields["manifest_stale_hint"] = (
            "manifest file has changed since this process started — restart the "
            "scoped-mcp-<agent> PM2 process to pick up the change"
        )
    return fields


def _register_status_tool(
    server: FastMCP,
    module_health: dict,
    manifest_snapshot: dict[str, Any] | None = None,
    vault_source: object = None,
    optional_modules: set[str] | None = None,
    instances: dict[str, ToolModule] | None = None,
) -> None:
    """Register scoped_mcp_status as a built-in tool on the parent server.

    This tool is always present regardless of manifest content. Operators can call it
    at session start to identify degraded modules and act before running further tasks.

    module_health is captured by closure and updated live by the lifespan, so the tool
    reflects startup failures that occur after build_server() returns. manifest_snapshot
    is likewise captured by closure so each call re-stats the manifest file fresh.

    vault_source, when present, contributes a ``credentials`` block from its
    ``credential_health()`` snapshot and drags top-level ``healthy`` to false when the
    Vault token is unhealthy — so a process stuck in a permanent renewal-failure loop
    can no longer report ``healthy: true``. stdio / env-credential agents pass None and
    the block is omitted entirely.

    optional_modules (SMCP-31): module names flagged ``optional: true`` — their failure
    is excluded from failed_count/healthy and surfaced instead as offline_optional_modules.

    instances (vikunja#517): live module instances keyed by manifest name, shared by
    reference with build_server so the self-healer's replacements are picked up. This
    is the **authenticated** reporter, so it is the only one that gets tool *names* —
    /health and the health file get counts only.
    """
    manifest_snapshot = manifest_snapshot or {}
    optional_modules = optional_modules or set()
    instances = {} if instances is None else instances

    async def scoped_mcp_status() -> dict:
        """Return the health status of all manifest-declared modules.

        Status values:
          running        — module loaded and started successfully
          failed_import  — module Python file could not be imported (missing dep, syntax error)
          failed_init    — module class could not be instantiated (bad config, missing credential)
          failed_startup — module startup() raised (service unreachable, bad state, etc.)

        A module flagged ``optional: true`` in the manifest does not count toward
        failed_count/healthy when failed — see offline_optional_modules instead.

        manifest_stale (bool, present only if true) signals the manifest file has
        changed since this process started — under the HTTP transport, that requires
        a PM2 restart to take effect (see manifest_stale_hint for the exact command).

        tool_inventory reports, per running mcp_proxy module, the tool names and count
        actually registered from that upstream, its transport, whether an allowlist or
        denylist filtered it, and when discovery ran. A proxy enumerates its upstream
        once at startup and never re-discovers, so a count that disagrees with another
        agent proxying the same upstream under the same filtering means this process is
        serving a stale tool set and needs a restart.

        Call this at session start to check for degraded modules before running tasks.
        """
        required_failed, optional_failed = _split_failed_by_optional(
            module_health, optional_modules
        )
        healthy = len(required_failed) == 0
        result = {
            "modules": module_health,
            "failed_count": len(required_failed),
            "total_count": len(module_health),
            "healthy": healthy,
        }
        if optional_failed:
            result["offline_optional_modules"] = sorted(optional_failed)
        tool_inventory = _build_tool_inventory(instances, module_health, include_names=True)
        if tool_inventory:
            result["tool_inventory"] = tool_inventory
        # Credential health (Vault agents only). Never raises — a missing/None
        # vault_source omits the block so stdio/env-cred agents are unaffected.
        if vault_source is not None:
            try:
                cred_health = vault_source.credential_health()
                result["credentials"] = cred_health
                result["healthy"] = healthy and cred_health.get("token_healthy", True)
            except Exception as exc:  # diagnostic tool must never fail
                result["credentials"] = {"error": type(exc).__name__}
        result.update(_manifest_status_fields(manifest_snapshot))
        return result

    server.tool(name="scoped_mcp_status")(scoped_mcp_status)


def _register_hitl_confirm_tool(
    server: FastMCP,
    state: Any,
    agent_ctx: AgentContext,
) -> None:
    """Register ``scoped_mcp_hitl_confirm`` — the interactive-mode approval tool.

    Registered ONLY when the manifest sets ``hitl.mode: interactive`` (see
    build_server). For an ``enforce``-mode agent the tool is never created, so it
    cannot be reached for anything gating a headless run — the operator must use
    the out-of-band Matrix/CLI path instead.

    The tool trusts the requesting agent's own report that the operator approved
    or denied in the current conversation. That is the deliberate, operator-accepted
    trust downgrade of interactive mode — the same trust level every other tool call
    in an interactive session already runs under. It resolves via the shared
    :mod:`hitl_endpoint` approve/deny logic (no duplicated approval logic), tagged
    ``resolved_via="interactive_self_service"`` so the audit trail stays honest.
    """
    from . import hitl_endpoint

    agent_id = agent_ctx.agent_id

    async def scoped_mcp_hitl_confirm(approval_id: str, decision: str) -> dict:
        """Resolve a pending HITL approval for THIS agent, in-session.

        Only call this AFTER the operator has given an explicit, unambiguous
        approve/deny **in the current conversation turn**. Never call it
        speculatively, never on an old approval, never chained automatically —
        treat it exactly like any other "wait for explicit confirmation"
        instruction governing a risky action.

        Args:
            approval_id: the ``{agent}.{uuid}`` id from the HITL rejection message.
            decision: ``"approve"`` or ``"deny"``.

        Returns a result dict with a ``status`` key:
        approved | denied | not_found | already_decided | invalid_decision |
        backend_unavailable. On ``approved``, retry the original gated tool call —
        it will find the one-time pre-approval token and proceed.
        """
        if not approval_id or not isinstance(approval_id, str):
            return {"status": "invalid_decision", "detail": "approval_id is required"}
        decision_norm = (decision or "").strip().lower()
        if decision_norm not in ("approve", "deny"):
            return {
                "status": "invalid_decision",
                "detail": "decision must be 'approve' or 'deny'",
            }
        try:
            if decision_norm == "approve":
                return await hitl_endpoint.approve(
                    state, agent_id, approval_id, resolved_via="interactive_self_service"
                )
            return await hitl_endpoint.deny(
                state, agent_id, approval_id, resolved_via="interactive_self_service"
            )
        except Exception as exc:
            # Fail-closed: a state-backend error must never resolve to an approval.
            _log = get_ops_logger()
            _log.error(
                "hitl_confirm_backend_error",
                approval_id=approval_id,
                agent_id=agent_id,
                error=type(exc).__name__,
            )
            return {"status": "backend_unavailable", "error": type(exc).__name__}

    server.tool(name="scoped_mcp_hitl_confirm")(scoped_mcp_hitl_confirm)


def _register_health_route(
    server: FastMCP,
    module_health: dict,
    vault_source: object,
    optional_modules: set[str] | None = None,
    instances: dict[str, ToolModule] | None = None,
) -> None:
    """Register an unauthenticated GET /health route (http transport only).

    FastMCP custom routes are unauthenticated by design and share the existing HTTP
    port — no new port, no bearer — so an external prober (or a dumb load balancer)
    can act on the status code alone: 200 when healthy, 503 when degraded.

    SECURITY: the body exposes only booleans, counts, and derived timestamps — never
    the client token, a lease id, or any secret. credential_health() is constructed to
    the same contract; module details are reduced to failed/total counts here.

    optional_modules (SMCP-31): module names flagged ``optional: true`` — their failure
    is excluded from failed_count/healthy (200, not 503) and surfaced instead as
    offline_optional_modules.

    instances (vikunja#517): live module instances keyed by manifest name, used to add a
    ``tool_inventory`` block. This route is unauthenticated, so the inventory is built
    with ``include_names=False`` — per-module tool **counts**, transport and filtering
    booleans only, never the tool names, and never a URL or header. Module names are
    already implied by the manifest and were never the sensitive part; the count is what
    a drift check needs. Every scoped-mcp binds 127.0.0.1, so this is loopback-only.
    """
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    optional_modules = optional_modules or set()
    instances = {} if instances is None else instances

    @server.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> JSONResponse:
        required_failed, optional_failed = _split_failed_by_optional(
            module_health, optional_modules
        )
        healthy = len(required_failed) == 0
        payload: dict[str, Any] = {
            "status": "healthy",
            "modules": {"failed_count": len(required_failed), "total_count": len(module_health)},
            "written_at": datetime.now(UTC).isoformat(),
        }
        if optional_failed:
            payload["offline_optional_modules"] = sorted(optional_failed)
        tool_inventory = _build_tool_inventory(instances, module_health)
        if tool_inventory:
            payload["tool_inventory"] = tool_inventory
        if vault_source is not None:
            try:
                cred_health = vault_source.credential_health()
                payload["credentials"] = cred_health
                healthy = healthy and cred_health.get("token_healthy", True)
            except Exception as exc:  # a health probe must never 500
                payload["credentials"] = {"error": type(exc).__name__}
                healthy = False
        payload["status"] = "healthy" if healthy else "degraded"
        return JSONResponse(payload, status_code=200 if healthy else 503)


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
    manifest_path: str | None = None,
    transport: str = "stdio",
    state: Any = None,
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

    manifest_path: optional path the manifest was loaded from (SMCP-24). When given,
        its mtime is captured here and re-checked on every scoped_mcp_status call, so
        a manifest edit made after this process started is visible as manifest_stale
        instead of silently having no effect until the next PM2 restart.

    transport: "stdio" (default) or "http". Under "http" the unauthenticated /health
        route is registered so an external prober can poll credential/module health on
        the existing HTTP port; under stdio there is no HTTP server so it is skipped.
    """
    ops = get_ops_logger()
    ops.info("registry_start", agent_id=agent_ctx.agent_id, agent_type=agent_ctx.agent_type)

    # SMCP-31: modules flagged optional: true — their failure never counts toward
    # failed_count/healthy, see _split_failed_by_optional.
    optional_modules = {name for name, cfg in manifest.modules.items() if cfg.optional}

    manifest_snapshot: dict[str, Any] = {}
    if manifest_path is not None:
        try:
            manifest_snapshot = {
                "manifest_path": manifest_path,
                "manifest_loaded_at": datetime.now(UTC).isoformat(),
                "manifest_mtime_at_load": os.path.getmtime(manifest_path),
            }
        except OSError as exc:
            ops.warning("manifest_stat_failed_at_load", path=manifest_path, error=str(exc))

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

    # Instantiate modules, skipping any that failed discovery. One shared gate
    # budget for the whole build keeps total startup bounded no matter how many
    # loopback dependencies the manifest declares.
    gate_budget = DependencyGateBudget()
    all_instances: list[tuple[str, ModuleConfig, ToolModule]] = []
    for module_name, module_cfg in manifest.modules.items():
        if module_name in module_health:
            continue  # already failed at import — skip
        class_name = _resolve_class_name(module_name, module_cfg)
        module_cls = available[class_name]
        ops.info("loading_module", module=module_name, class_name=class_name, mode=module_cfg.mode)
        _gate_local_dependency(module_name, module_cfg, ops, gate_budget)
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

    # Live instance registry, shared by reference with the lifespan, the status tool and
    # the /health route so all three report the *current* instance for each module. It has
    # to be a shared mutable mapping rather than a snapshot: the self-healer replaces a
    # recovered module's instance wholesale, and a snapshot taken here would keep reporting
    # the tool inventory of an instance that no longer serves anything (vikunja#517).
    instance_registry: dict[str, ToolModule] = {name: inst for name, _, inst in all_instances}

    chain = MiddlewareChain(middleware or [])

    # One child FastMCP per declared module, populated below. Held here so the
    # re-init loop can register a recovered module's tools onto the child that
    # was already mounted at startup — the documented live-linking path, rather
    # than mounting onto a parent that is already serving.
    module_children: dict[str, FastMCP] = {}

    async def _retry_module(module_name: str) -> ToolModule | None:
        """Re-run instantiate → startup → register-tools for one failed module.

        Handed to the lifespan, which drives it from a backoff loop. Raises on
        failure (the loop reschedules); on success the module's tools are live on
        the parent server and module_health says ``running`` with no error, which
        is what flips /health back to 200.
        """
        module_cfg = manifest.modules[module_name]
        class_name = _resolve_class_name(module_name, module_cfg)
        module_cls = available[class_name]

        def _instantiate() -> ToolModule:
            credentials = _resolve_module_credentials(
                module_cls, manifest, vault_bundle=vault_bundle
            )
            return module_cls(
                agent_ctx=agent_ctx,
                credentials=credentials,
                config=module_cfg.config,
            )

        # Off the event loop on purpose: mcp_proxy.__init__ discovers upstream
        # tools with asyncio.run(), which raises inside a running loop. A worker
        # thread gives it the same bare-thread environment it had at startup.
        try:
            instance = await asyncio.to_thread(_instantiate)
        except Exception as exc:
            module_health[module_name] = {
                "status": "failed_init",
                "error": f"{type(exc).__name__}: {exc}",
            }
            raise

        if hasattr(instance, "_manifest_key"):
            instance._manifest_key = module_name

        try:
            await instance.startup()
            # Every retryable module has a child mounted below — only
            # failed_import is excluded from that loop, and failed_import is
            # never retried. A KeyError here would mean the two have diverged,
            # which should surface loudly rather than register tools nowhere.
            #
            # Registration is inside this try so a failure here still tears the
            # instance down. Otherwise a module that started (holding a
            # subprocess or socket) but failed to register would be orphaned:
            # never reachable, never shut down, and replaced by a fresh instance
            # on the next attempt.
            _register_module_tools(
                module_children[module_name],
                module_name,
                module_cfg,
                instance,
                chain,
                middleware,
                agent_ctx,
                ops,
            )
        except Exception as exc:
            module_health[module_name] = {
                "status": "failed_startup",
                "error": f"{type(exc).__name__}: {exc}",
            }
            # A half-started module may hold a subprocess or socket; drop it
            # before the next attempt builds a fresh instance.
            with contextlib.suppress(Exception):
                await instance.shutdown()
            raise
        # Publish the recovered instance BEFORE flipping to running. The inventory
        # builder keys off status == "running", so this order means a reporter can
        # never see running with the previous (or no) instance still registered and
        # report the tool set of an object that is no longer serving.
        instance_registry[module_name] = instance
        # Replaces the dict wholesale, so the recorded error is cleared too.
        module_health[module_name] = {"status": "running"}
        return instance

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
            agent_ctx=agent_ctx,
            optional_modules=optional_modules,
            selfheal_retry=_retry_module,
            instances=instance_registry,
        ),
        auth=auth,
    )

    # Mount a child for EVERY module that could still come up, including ones
    # that failed to instantiate. A module recovering later then only has to add
    # tools to its existing child — mount() is a live link, so those tools become
    # dispatchable on the parent immediately, with no remount and no restart.
    # failed_import is excluded: its Python class does not exist in this process,
    # so no amount of retrying will produce an instance.
    for module_name in manifest.modules:
        if module_health.get(module_name, {}).get("status") == "failed_import":
            continue
        child = FastMCP(module_name)
        module_children[module_name] = child
        server.mount(child, namespace=module_name)

    # Register tools for the modules that instantiated cleanly.
    registered_tool_names: list[str] = []
    for module_name, module_cfg, instance in all_instances:
        registered_tool_names.extend(
            _register_module_tools(
                module_children[module_name],
                module_name,
                module_cfg,
                instance,
                chain,
                middleware,
                agent_ctx,
                ops,
            )
        )

    # Always-present status tool — no module namespace prefix.
    _register_status_tool(
        server,
        module_health,
        manifest_snapshot,
        vault_source=vault_source,
        optional_modules=optional_modules,
        instances=instance_registry,
    )
    registered_tool_names.append("scoped_mcp_status")

    # Interactive-mode HITL confirm tool (SMCP — hitl interactive mode). Registered
    # ONLY when the manifest opts into hitl.mode: interactive AND actually gates
    # tools AND a shared state backend exists to resolve against. For an
    # enforce-mode agent the tool is never registered — an unattended run cannot
    # reach it, so gating still requires the out-of-band Matrix/CLI path. Not gated
    # on transport: it dispatches over the same channel as every other tool.
    if (
        manifest.hitl is not None
        and manifest.hitl.mode == "interactive"
        and manifest.hitl.approval_required
        and state is not None
    ):
        _register_hitl_confirm_tool(server, state, agent_ctx)
        registered_tool_names.append("scoped_mcp_hitl_confirm")
        ops.info("hitl_confirm_tool_registered", agent_id=agent_ctx.agent_id)

    # Unauthenticated /health route — only under http, where an external prober can
    # reach it. Under stdio there is no HTTP server, so registration would be dead.
    if transport == "http":
        _register_health_route(
            server,
            module_health,
            vault_source,
            optional_modules=optional_modules,
            instances=instance_registry,
        )

        # HITL approve endpoint (SMCP-14) — only meaningful when this agent gates
        # tools AND we have a shared state backend to hold the pending record/OTP.
        # The routes self-authenticate with SCOPED_MCP_HITL_TOKEN (custom routes
        # bypass the MCP bearer verifier).
        if manifest.hitl is not None and manifest.hitl.approval_required and state is not None:
            from .hitl_http import register_hitl_routes

            register_hitl_routes(server, state, agent_ctx)

    # L4: OTel credential-health metrics for SigNoz (opt-in). No-op unless a Vault
    # source is present and an OTLP endpoint is configured; the otel extra being
    # absent (ImportError) degrades to nothing, matching the tracing path.
    if vault_source is not None and os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        try:
            from .contrib.otel import init_credential_metrics

            if init_credential_metrics(
                vault_source.credential_health, agent_ctx.agent_id, agent_ctx.agent_type
            ):
                ops.info("credential_metrics_enabled")
        except ImportError:
            ops.warning("credential_metrics_unavailable", reason="otel_extra_missing")

    # Validate policy patterns against registered tool names (H-02).
    # Tool names follow the format {manifest_key}_{method} (underscores, not dots).
    # A pattern that matches no registered tool silently never fires — warn loudly
    # so operators catch misconfigured approval_required/shadow/per_tool rules at
    # startup rather than discovering them after a security incident.
    _warn_unmatched_patterns(manifest, registered_tool_names, ops)

    ops.info("registry_complete", agent_id=agent_ctx.agent_id)
    return server
