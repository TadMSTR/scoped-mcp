"""Startup dependency gating and background re-initialisation for tool modules.

Two cooperating mechanisms, both aimed at the same failure: a module whose
dependency is not yet listening when the process starts.

**Phase 1 — dependency-ready gate** (:func:`await_dependency_ready`). Before a
module backed by a *loopback* HTTP URL is instantiated, poll that URL's TCP port
until it accepts a connection, within a bounded budget. This kills the common
race at source: PM2 brings the five ``scoped-mcp-*`` proxies up alongside the
local ``system-ops`` they all proxy, and whichever proxy wins the start ordering
would otherwise fail instantiation against an unbound port.

Only loopback dependencies gate startup. A remote dependency (e.g. an ops proxy
on another host) is legitimately ``optional: true`` (SMCP-31) and may be powered
off on purpose — blocking startup on it would convert a supported state into an
outage.

**Phase 2 — background re-init loop** (:class:`ModuleSelfHealer`). The gate has a
bounded budget and a dependency can also die *mid-life*, so the gate alone is not
sufficient. After startup, one asyncio task retries just the modules left in
``failed_init``/``failed_startup``, with exponential backoff to a cap. On success
it registers the module's tools onto its already-mounted child server, flips
``module_health`` to ``running``, and rewrites the health file — at which point
``/health`` returns 200 on the very next probe and the external prober emits its
own RECOVERED. No restart, no operator involvement.

This mirrors :mod:`scoped_mcp.credentials_vault`, which solves the identical
shape of problem for Vault tokens: background task, self-heal, health-file
rewrite on transition, and one degraded/recovered ops alert per transition —
never per retry attempt.

Why instantiation is retried in a worker thread
-----------------------------------------------
``mcp_proxy.__init__`` discovers upstream tools via ``asyncio.run()``, which is
only legal when no event loop is running on the calling thread. That holds for
the initial pass in ``build_server`` (synchronous, pre-loop) but *not* for this
retry loop, which by definition runs inside the server's loop. Instantiation
therefore goes through ``asyncio.to_thread`` so the module sees a bare thread
with no running loop, exactly as it did at startup.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import socket
import time
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit

import structlog

_log = structlog.get_logger("ops")

# Module health statuses the self-healer will retry. ``failed_import`` is
# deliberately excluded: the module's Python class could not be imported, which
# no amount of waiting fixes within this process.
RETRYABLE_STATUSES = frozenset({"failed_init", "failed_startup"})

# Defaults for the dependency-ready gate. Overridable per module in the manifest.
DEFAULT_DEPENDENCY_TIMEOUT_SECONDS = 30.0
DEFAULT_DEPENDENCY_INTERVAL_SECONDS = 1.0

# Ceiling on the TOTAL time one process may spend in dependency gates, across
# every module. A real manifest declares 9-16 loopback dependencies; without a
# shared ceiling, a full outage would cost 16 x 30s = eight minutes of startup
# before /health even exists to report the problem. The per-module budget bounds
# one wait; this bounds their sum.
DEFAULT_TOTAL_GATE_BUDGET_SECONDS = 60.0
_TOTAL_GATE_BUDGET_ENV = "SCOPED_MCP_DEPENDENCY_WAIT_BUDGET_SECONDS"

# Backoff bounds for the re-init loop: cheap enough to recover a transient
# outage quickly, capped so a permanently broken module costs almost nothing.
DEFAULT_BASE_DELAY_SECONDS = 5.0
DEFAULT_MAX_DELAY_SECONDS = 300.0

# Per-connect timeout for a single gate poll. Short — a loopback port either
# accepts immediately or is not bound; a long timeout would just eat the budget.
_CONNECT_TIMEOUT_SECONDS = 2.0

# Exception types that will not resolve by waiting: a bad manifest config, a
# missing credential, a broken import. These start at the backoff cap rather
# than hot-looping through the ramp. They are still retried — misclassifying a
# transient fault as permanent and giving up would recreate the very bug this
# module exists to fix — just at minimum cost.
_PERMANENT_EXC_TYPES: tuple[type[BaseException], ...] = (
    ImportError,
    TypeError,
    ValueError,
)


def redact_url(url: str) -> str:
    """Return ``url`` with any userinfo and query string stripped.

    Dependency URLs are logged and fed into ops alerts. A URL of the form
    ``http://user:token@host:port/path?key=secret`` would otherwise publish a
    credential to the log stream and to ``#alerts``. Host, port, scheme and path
    are all that is diagnostically useful here.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    netloc = parts.hostname or ""
    if parts.port is not None:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def is_loopback_url(url: str) -> bool:
    """True when ``url`` is an http(s) URL whose host is loopback.

    ``localhost`` is treated as loopback by name — it is the spelling used in
    the manifests and resolving it here would make the check depend on DNS at
    startup. Any host that neither parses as a loopback IP nor is a
    ``localhost`` label returns False, so a remote dependency never gates
    startup.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    if parts.scheme not in ("http", "https"):
        return False
    host = parts.hostname
    if not host:
        return False
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def await_dependency_ready(
    url: str,
    timeout: float = DEFAULT_DEPENDENCY_TIMEOUT_SECONDS,
    interval: float = DEFAULT_DEPENDENCY_INTERVAL_SECONDS,
) -> tuple[bool, float]:
    """Poll ``url``'s TCP port until it accepts a connection or the budget expires.

    Returns ``(ready, elapsed_seconds)``. A successful TCP connect is the whole
    test: it proves something is bound and listening. No HTTP request is made and
    no status code is required — an MCP endpoint answers an unauthenticated probe
    with 401/404/405/406 depending on the server, all of which mean "port is up",
    so requiring a particular response would only add false negatives.

    Synchronous by design. This runs from ``build_server``, before the event loop
    exists, on the same thread that will shortly call ``asyncio.run`` inside a
    module's ``__init__``.

    Never raises, and never waits longer than ``timeout``: on expiry the caller
    falls through to its normal init path, records ``failed_init``, and the
    background re-init loop takes over from there. Startup stays bounded.
    """
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    started = time.monotonic()
    if not host:
        return False, 0.0

    deadline = started + max(timeout, 0.0)
    while True:
        try:
            with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT_SECONDS):
                return True, time.monotonic() - started
        except OSError:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False, time.monotonic() - started
        time.sleep(min(interval, remaining))


class DependencyGateBudget:
    """A shared, draining ceiling on total dependency-gate wait time.

    One instance per ``build_server`` call, consulted by every module's gate. Once
    drained, remaining gates become no-ops and their modules fall through to
    ``failed_init`` — where the background re-init loop picks them up anyway. The
    gate is an optimisation that removes the common race; the retry loop is the
    actual guarantee, so cutting gates short costs recovery latency, never
    recoverability.

    Overridable with ``SCOPED_MCP_DEPENDENCY_WAIT_BUDGET_SECONDS``. A malformed or
    negative value falls back to the default rather than failing startup.
    """

    def __init__(self, total: float | None = None) -> None:
        if total is None:
            raw = os.environ.get(_TOTAL_GATE_BUDGET_ENV)
            total = DEFAULT_TOTAL_GATE_BUDGET_SECONDS
            if raw is not None:
                try:
                    parsed = float(raw)
                except ValueError:
                    _log.warning(
                        "dependency_wait_budget_invalid",
                        value=raw,
                        default=DEFAULT_TOTAL_GATE_BUDGET_SECONDS,
                    )
                else:
                    if parsed >= 0:
                        total = parsed
                    else:
                        _log.warning("dependency_wait_budget_invalid", value=raw)
        self._remaining = max(float(total), 0.0)

    @property
    def remaining(self) -> float:
        return self._remaining

    def allowance(self, requested: float) -> float:
        """Largest wait this gate may take without breaching the shared ceiling."""
        return min(max(requested, 0.0), self._remaining)

    def consume(self, elapsed: float) -> None:
        self._remaining = max(self._remaining - max(elapsed, 0.0), 0.0)


def classify_failure(exc: BaseException) -> str:
    """Return ``"permanent"`` or ``"transient"`` for a module init/startup failure.

    Only used to choose a starting backoff delay — never to stop retrying. A
    connection error is transient and worth a fast ramp; a config or import error
    almost certainly is not, so it goes straight to the cap.
    """
    if isinstance(exc, _PERMANENT_EXC_TYPES):
        return "permanent"
    return "transient"


class ModuleSelfHealer:
    """Background task that retries modules left in a retryable failed state.

    Constructed with a ``retry_module`` coroutine supplied by the registry, which
    owns the actual re-instantiate → startup → register-tools sequence. This class
    owns only the scheduling, the backoff, the state bookkeeping, and the
    one-alert-per-transition discipline.

    Alert routing follows the existing SMCP-31 split. A required module's failure
    is a real degradation and gets ``module_init_degraded`` / ``module_recovered``.
    An ``optional: true`` module has already produced ``optional_module_offline``
    from the lifespan's own transition check, so it only gets the matching
    ``optional_module_recovered`` here — no duplicate degraded alert.

    Alert payloads deliberately carry the exception *type* and never the message.
    ``module_health[name]["error"]`` stores ``f"{type(exc).__name__}: {exc}"``, and
    an exception raised from a URL with inline credentials would otherwise publish
    that credential to ``#alerts``. This matches ``/health``, which exposes only
    counts and booleans.
    """

    def __init__(
        self,
        retry_module: Callable[[str], Awaitable[None]],
        module_health: dict,
        *,
        agent_id: str = "unknown",
        agent_type: str = "unknown",
        optional_modules: set[str] | None = None,
        on_health_change: Callable[[], None] | None = None,
        base_delay: float = DEFAULT_BASE_DELAY_SECONDS,
        max_delay: float = DEFAULT_MAX_DELAY_SECONDS,
    ) -> None:
        self._retry_module = retry_module
        self._module_health = module_health
        self._agent_id = agent_id
        self._agent_type = agent_type
        self._optional_modules = optional_modules or set()
        self._on_health_change = on_health_change
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._task: asyncio.Task | None = None
        # module -> next delay in seconds; also the set of modules being retried.
        self._delays: dict[str, float] = {}
        # Modules a degraded alert has already been sent for, so a retry storm
        # cannot become an alert storm.
        self._alerted: set[str] = set()

    def pending_modules(self) -> list[str]:
        """Module names currently in a retryable failed state, in manifest order."""
        return [
            name
            for name, health in self._module_health.items()
            if health.get("status") in RETRYABLE_STATUSES
        ]

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        """Start the retry task if — and only if — something needs retrying.

        A fully healthy process starts no task and pays nothing. Emits one
        ``module_init_degraded`` per initially-failed required module before the
        loop begins, so the degradation is announced once at the transition into
        the failed state rather than once per retry.
        """
        pending = self.pending_modules()
        if not pending:
            return
        for name in pending:
            self._delays[name] = self._initial_delay(name)
            await self._alert_degraded(name)
        self._task = asyncio.create_task(self._loop(), name="scoped-mcp-module-selfheal")
        _log.info(
            "module_selfheal_started",
            modules=pending,
            base_delay=self._base_delay,
            max_delay=self._max_delay,
        )

    async def close(self) -> None:
        """Cancel the retry task cleanly on shutdown.

        Bounded like ``VaultCredentialSource.close()``: a module instantiation in
        flight inside ``asyncio.to_thread`` runs on a worker thread that cannot be
        cancelled, so waiting on it unboundedly could stall process termination.
        """
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(self._task), timeout=5.0)
        self._task = None

    # ── internal ──────────────────────────────────────────────────────────────

    def _initial_delay(self, name: str) -> float:
        error = self._module_health.get(name, {}).get("error", "")
        exc_type = error.split(":", 1)[0].strip()
        if exc_type in {t.__name__ for t in _PERMANENT_EXC_TYPES}:
            return self._max_delay
        return self._base_delay

    def _is_optional(self, name: str) -> bool:
        return name in self._optional_modules

    async def _alert_degraded(self, name: str) -> None:
        """One ``module_init_degraded`` per module entering the failed state."""
        if name in self._alerted:
            return
        self._alerted.add(name)
        if self._is_optional(name):
            # SMCP-31's lifespan check already alerted optional_module_offline.
            return
        await self._send_alert("module_init_degraded", name)

    async def _alert_recovered(self, name: str) -> None:
        self._alerted.discard(name)
        event = "optional_module_recovered" if self._is_optional(name) else "module_recovered"
        await self._send_alert(event, name)

    async def _send_alert(self, event: str, name: str) -> None:
        """Best-effort ops alert — must never break the retry loop."""
        from .ops_alert import send_ops_alert

        error = self._module_health.get(name, {}).get("error", "")
        # Type only, never the message — see the class docstring.
        error_type = error.split(":", 1)[0].strip() or None
        payload = {
            "agent_id": self._agent_id,
            "agent_type": self._agent_type,
            "module": name,
            "status": self._module_health.get(name, {}).get("status"),
        }
        if event == "module_init_degraded" and error_type:
            payload["error_type"] = error_type
        try:
            await send_ops_alert(event, payload)
        except Exception as exc:  # pragma: no cover - send_ops_alert swallows its own
            _log.warning("module_selfheal_alert_failed", module=name, error=type(exc).__name__)

    async def _loop(self) -> None:
        """Retry each pending module on its own backoff schedule until it recovers."""
        while self._delays:
            sleep_for = min(self._delays.values())
            await asyncio.sleep(sleep_for)
            # Everything whose delay has come due this tick.
            due = [name for name, delay in self._delays.items() if delay <= sleep_for]
            for name, delay in list(self._delays.items()):
                if name not in due:
                    self._delays[name] = delay - sleep_for
            for name in due:
                await self._attempt(name)

    async def _attempt(self, name: str) -> None:
        """One retry of one module. Never raises — a failure just reschedules."""
        try:
            await self._retry_module(name)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            delay = min(self._delays.get(name, self._base_delay) * 2, self._max_delay)
            if classify_failure(exc) == "permanent":
                delay = self._max_delay
            self._delays[name] = delay
            _log.warning(
                "module_selfheal_retry_failed",
                module=name,
                error=type(exc).__name__,
                next_retry_seconds=delay,
            )
            return

        self._delays.pop(name, None)
        _log.info("module_selfheal_recovered", module=name)
        if self._on_health_change is not None:
            with contextlib.suppress(Exception):
                self._on_health_change()
        await self._alert_recovered(name)
