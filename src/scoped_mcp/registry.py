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
    unreadable, or the env var isn't configured — the caller then treats every
    currently-offline optional module as newly-offline (a safe, alert-heavy
    default, never a silent one).
    """
    if not path:
        return set()
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return set()
    return set(data.get("offline_optional_modules", []))


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


def _write_health_file(
    module_health: dict,
    ops: object,
    credential_health: dict | None = None,
    optional_modules: set[str] | None = None,
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
    """
    path = os.environ.get("SCOPED_MCP_HEALTH_FILE")
    if not path:
        return
    required_failed, optional_failed = _split_failed_by_optional(
        module_health, optional_modules or set()
    )
    token_healthy = credential_health is None or credential_health.get("token_healthy", True)
    data = {
        "modules": module_health,
        "failed_count": len(required_failed),
        "total_count": len(module_health),
        "healthy": len(required_failed) == 0 and token_healthy,
        "written_at": datetime.now(UTC).isoformat(),
    }
    if optional_failed:
        data["offline_optional_modules"] = sorted(optional_failed)
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
    """
    if module_health is None:
        module_health = {}
    optional_modules = optional_modules or set()

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
            module_health, ops, credential_health=health, optional_modules=optional_modules
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
            )
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
    """
    manifest_snapshot = manifest_snapshot or {}
    optional_modules = optional_modules or set()

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


def _register_health_route(
    server: FastMCP,
    module_health: dict,
    vault_source: object,
    optional_modules: set[str] | None = None,
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
    """
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    optional_modules = optional_modules or set()

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
            agent_ctx=agent_ctx,
            optional_modules=optional_modules,
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
    _register_status_tool(
        server,
        module_health,
        manifest_snapshot,
        vault_source=vault_source,
        optional_modules=optional_modules,
    )
    registered_tool_names.append("scoped_mcp_status")

    # Unauthenticated /health route — only under http, where an external prober can
    # reach it. Under stdio there is no HTTP server, so registration would be dead.
    if transport == "http":
        _register_health_route(
            server, module_health, vault_source, optional_modules=optional_modules
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
