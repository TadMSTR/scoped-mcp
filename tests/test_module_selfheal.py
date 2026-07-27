"""Tests for the dependency-ready gate and the background module re-init loop.

The headline test is ``test_race_regression_module_recovers_without_restart``: it
reproduces the original incident — a module whose loopback dependency is not
listening at startup — and asserts the process heals itself once the dependency
comes up. That test is red on the pre-fix code, where ``failed_init`` was
recorded and then ``continue``d past with no retry for the life of the process.
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
from typing import Any, ClassVar
from unittest.mock import patch

import pytest

from scoped_mcp import module_selfheal, registry
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import Manifest
from scoped_mcp.module_selfheal import (
    DependencyGateBudget,
    ModuleSelfHealer,
    await_dependency_ready,
    classify_failure,
    is_loopback_url,
    redact_url,
)
from scoped_mcp.modules._base import ToolModule, tool
from scoped_mcp.registry import _gate_local_dependency, build_server

# Retry cadence used across the integration tests. Real defaults are 5s → 5min;
# these keep the suite fast without changing the code under test.
_FAST_BASE_DELAY = 0.05
_FAST_MAX_DELAY = 0.2

# Upper bound on how long a test will wait for the self-healer to notice a
# dependency that has come up. Generous relative to _FAST_MAX_DELAY so a loaded
# CI runner does not produce a flake.
_RECOVERY_TIMEOUT = 15.0


def _free_port() -> int:
    """Return a port that is currently unbound.

    Inherently a small race (nothing stops another process claiming it in the
    gap), but this is the standard approach and the window is sub-millisecond.
    """
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _DependentModule(ToolModule):
    """Stand-in for mcp_proxy: connects to its configured URL during __init__.

    This is the exact failure shape the build targets — mcp_proxy discovers
    upstream tools in ``__init__``, so an unbound dependency port turns into an
    exception before the module ever exists.
    """

    name = "dependent"
    scoping = None
    required_credentials: ClassVar[list[str]] = []
    optional_credentials: ClassVar[list[str]] = []

    def __init__(self, agent_ctx: Any, credentials: dict, config: dict) -> None:
        super().__init__(agent_ctx, credentials, config)
        from urllib.parse import urlsplit

        parts = urlsplit(config["url"])
        with socket.create_connection((parts.hostname, parts.port), timeout=1):
            pass

    @tool(mode="read")
    async def ping(self) -> str:
        return "pong"


class _AlwaysBrokenModule(ToolModule):
    """A module whose config is wrong in a way no amount of waiting will fix."""

    name = "always-broken"
    scoping = None
    required_credentials: ClassVar[list[str]] = []
    optional_credentials: ClassVar[list[str]] = []

    def __init__(self, agent_ctx: Any, credentials: dict, config: dict) -> None:
        super().__init__(agent_ctx, credentials, config)
        raise ValueError("missing required config field")

    @tool(mode="read")
    async def noop(self) -> str:  # pragma: no cover - never instantiated
        return "noop"


def _manifest(module_name: str, class_name: str, port: int, **cfg: Any) -> Manifest:
    module: dict[str, Any] = {
        "type": class_name,
        "mode": "read",
        "config": {"url": f"http://127.0.0.1:{port}/mcp"},
    }
    module.update(cfg)
    return Manifest.model_validate({"agent_type": "test", "modules": {module_name: module}})


def _capture_alerts(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict]]:
    """Record every ops alert instead of sending it. Thread-safe enough: the
    healer only ever alerts from its own single task."""
    sent: list[tuple[str, dict]] = []

    async def _fake_send(event: str, detail: dict) -> bool:
        sent.append((event, detail))
        return True

    from scoped_mcp import ops_alert

    monkeypatch.setattr(ops_alert, "send_ops_alert", _fake_send)
    return sent


def _use_fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the lifespan build a healer with a test-speed backoff.

    The lifespan constructs ModuleSelfHealer with the production defaults and no
    delay arguments, so injecting them here needs no production-side test hook.
    """
    real_cls = module_selfheal.ModuleSelfHealer

    def _fast(*args: Any, **kwargs: Any) -> ModuleSelfHealer:
        kwargs.setdefault("base_delay", _FAST_BASE_DELAY)
        kwargs.setdefault("max_delay", _FAST_MAX_DELAY)
        return real_cls(*args, **kwargs)

    monkeypatch.setattr(registry, "ModuleSelfHealer", _fast)


def _tool_names(server: Any) -> list[str]:
    return [t.name for t in asyncio.run(server.list_tools())]


# ── Phase 1: dependency-ready gate ────────────────────────────────────────────


def test_is_loopback_url_accepts_loopback_forms() -> None:
    assert is_loopback_url("http://localhost:8282/mcp")
    assert is_loopback_url("http://127.0.0.1:8282/mcp")
    assert is_loopback_url("http://127.0.0.2:8282/mcp")
    assert is_loopback_url("https://[::1]:8282/mcp")


def test_is_loopback_url_rejects_remote_and_non_http() -> None:
    """A remote dependency must never gate startup — claudebox-ops is optional:true
    (SMCP-31) and is powered off on purpose sometimes."""
    assert not is_loopback_url("http://192.168.1.11:8282/mcp")
    assert not is_loopback_url("http://claudebox.internal:8282/mcp")
    assert not is_loopback_url("ws://localhost:8282/mcp")
    assert not is_loopback_url("not a url at all")
    assert not is_loopback_url("")
    assert not is_loopback_url("http:///mcp")  # http scheme, no host


def test_is_loopback_url_userinfo_cannot_spoof_the_host() -> None:
    """Audit INFO: pin the userinfo cases explicitly. urlsplit().hostname strips
    userinfo before the loopback check, so the decision always tracks the host the
    connection would actually go to — never the decorative part before the '@'."""
    # Looks loopback, connects to evil.com → must be rejected.
    assert not is_loopback_url("http://localhost@evil.com/mcp")
    assert not is_loopback_url("http://127.0.0.1:8282@evil.com/mcp")
    # Looks remote, connects to localhost → correctly accepted.
    assert is_loopback_url("http://evil.com@localhost:8282/mcp")


@pytest.mark.parametrize(
    "url",
    [
        "http://0177.0.0.1:8282/mcp",  # octal IPv4
        "http://2130706433:8282/mcp",  # integer IPv4
        "http://127.0.0.1.evil.com:8282/mcp",  # loopback-prefixed hostname
        "http://[fe80::1%eth0]:8282/mcp",  # IPv6 zone id
    ],
)
def test_is_loopback_url_obfuscated_forms_fail_closed(url: str) -> None:
    """Audit INFO: alternate/obfuscated address encodings must fail CLOSED — i.e.
    return False, which skips the gate entirely and never connects. A false negative
    only costs the module a retry cycle; a false positive would let a non-loopback
    host gate startup."""
    assert is_loopback_url(url) is False


def test_is_loopback_url_accepts_dot_localhost_suffix() -> None:
    """Audit INFO: `.localhost` is reserved for loopback by RFC 6761 §6.3, so
    accepting it is intended, not a bypass. Pinned so the behaviour is deliberate
    rather than incidental."""
    assert is_loopback_url("http://anything.localhost:8282/mcp")
    # ...but only as a real label boundary — a lookalike registrable domain is not.
    assert not is_loopback_url("http://evil-localhost:8282/mcp")
    assert not is_loopback_url("http://localhost.evil.com:8282/mcp")


def test_redact_url_strips_userinfo_and_query() -> None:
    """Dependency URLs reach the log stream and ops alerts; inline credentials
    must not travel with them."""
    out = redact_url("http://user:s3cret@localhost:8282/mcp?token=abc")
    assert out == "http://localhost:8282/mcp"
    assert "s3cret" not in out
    assert "abc" not in out


def test_redact_url_strips_the_fragment_too() -> None:
    """Audit INFO: urlunsplit's 5th element is the fragment — pin that it is blanked,
    so a token hidden after '#' cannot ride along into logs or #alerts."""
    out = redact_url("http://localhost:8282/mcp?q=1#token=s3cret")
    assert out == "http://localhost:8282/mcp"
    assert "s3cret" not in out


def test_await_dependency_ready_returns_immediately_when_bound() -> None:
    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
        ready, elapsed = await_dependency_ready(
            f"http://127.0.0.1:{port}/mcp", timeout=5.0, interval=0.05
        )
    assert ready is True
    assert elapsed < 1.0


def test_await_dependency_ready_is_bounded_when_never_bound() -> None:
    """Startup must never hang: the gate returns within its budget and hands off
    to the failed_init path."""
    port = _free_port()
    started = time.monotonic()
    ready, elapsed = await_dependency_ready(
        f"http://127.0.0.1:{port}/mcp", timeout=0.5, interval=0.05
    )
    duration = time.monotonic() - started
    assert ready is False
    assert duration < 5.0
    assert elapsed >= 0.4


def test_await_dependency_ready_waits_for_a_late_bind() -> None:
    port = _free_port()
    listeners: list[socket.socket] = []

    def _bind_later() -> None:
        time.sleep(0.3)
        listeners.append(socket.create_server(("127.0.0.1", port)))

    binder = threading.Thread(target=_bind_later)
    binder.start()
    try:
        ready, elapsed = await_dependency_ready(
            f"http://127.0.0.1:{port}/mcp", timeout=10.0, interval=0.05
        )
    finally:
        binder.join()
        for listener in listeners:
            listener.close()

    assert ready is True
    assert elapsed >= 0.2


def _gate_manifest(url: str, **cfg: Any) -> Any:
    module: dict[str, Any] = {"type": "mcp_proxy", "config": {"url": url}}
    module.update(cfg)
    manifest = Manifest.model_validate({"agent_type": "test", "modules": {"m": module}})
    return manifest.modules["m"]


def test_gate_skips_remote_dependency_without_waiting() -> None:
    """A remote URL is not polled at all — no delay, no startup gating."""
    import structlog

    cfg = _gate_manifest("http://192.168.1.11:8282/mcp", dependency_wait_timeout_seconds=30)
    budget = DependencyGateBudget(total=30.0)
    started = time.monotonic()
    _gate_local_dependency("remote", cfg, structlog.get_logger("ops"), budget)
    assert time.monotonic() - started < 1.0
    assert budget.remaining == 30.0  # nothing consumed


def test_gate_disabled_by_zero_timeout_consumes_no_budget() -> None:
    import structlog

    cfg = _gate_manifest(f"http://127.0.0.1:{_free_port()}/mcp", dependency_wait_timeout_seconds=0)
    budget = DependencyGateBudget(total=30.0)
    started = time.monotonic()
    _gate_local_dependency("m", cfg, structlog.get_logger("ops"), budget)
    assert time.monotonic() - started < 1.0
    assert budget.remaining == 30.0


def test_shared_budget_bounds_total_startup_across_many_modules() -> None:
    """The real manifests declare 9-16 loopback dependencies. Per-module budgets
    alone would multiply into minutes of startup during a full outage; the shared
    ceiling is what keeps the sum bounded."""
    import structlog

    ops = structlog.get_logger("ops")
    budget = DependencyGateBudget(total=0.6)
    cfg = _gate_manifest(
        f"http://127.0.0.1:{_free_port()}/mcp",
        dependency_wait_timeout_seconds=30,
        dependency_wait_interval_seconds=0.05,
    )

    started = time.monotonic()
    for i in range(16):
        _gate_local_dependency(f"mod-{i}", cfg, ops, budget)
    duration = time.monotonic() - started

    # 16 modules x 30s per-module budget would be eight minutes without the cap.
    assert duration < 10.0
    assert budget.remaining == 0.0


def test_budget_reads_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCOPED_MCP_DEPENDENCY_WAIT_BUDGET_SECONDS", "7.5")
    assert DependencyGateBudget().remaining == 7.5


@pytest.mark.parametrize("value", ["not-a-number", "-5"])
def test_budget_falls_back_on_bad_env_value(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    """A malformed override must not take startup down — it falls back to the default."""
    monkeypatch.setenv("SCOPED_MCP_DEPENDENCY_WAIT_BUDGET_SECONDS", value)
    assert DependencyGateBudget().remaining == module_selfheal.DEFAULT_TOTAL_GATE_BUDGET_SECONDS


def test_budget_allowance_never_exceeds_remaining() -> None:
    budget = DependencyGateBudget(total=10.0)
    assert budget.allowance(30.0) == 10.0
    budget.consume(4.0)
    assert budget.allowance(30.0) == 6.0
    budget.consume(100.0)  # over-consumption clamps at zero, never goes negative
    assert budget.remaining == 0.0
    assert budget.allowance(30.0) == 0.0


def test_gate_lets_module_start_when_dependency_binds_late(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Phase 1: with the gate in place, a dependency that binds within budget means
    the module comes up running on the first attempt — no failed_init at all."""
    _capture_alerts(monkeypatch)
    port = _free_port()
    listeners: list[socket.socket] = []

    def _bind_later() -> None:
        time.sleep(0.4)
        listeners.append(socket.create_server(("127.0.0.1", port)))

    binder = threading.Thread(target=_bind_later)
    binder.start()

    manifest = _manifest(
        "dep",
        "dependent",
        port,
        dependency_wait_timeout_seconds=10,
        dependency_wait_interval_seconds=0.05,
    )
    try:
        with patch(
            "scoped_mcp.registry._discover_module_classes",
            return_value=({"dependent": _DependentModule}, {}),
        ):
            server = build_server(agent_ctx, manifest)
    finally:
        binder.join()
        for listener in listeners:
            listener.close()

    assert "dep_ping" in _tool_names(server)


def test_gate_timeout_falls_through_to_failed_init(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Budget expiry is not an error path of its own — it hands off to the
    existing failed_init behaviour, and startup still completes."""
    _capture_alerts(monkeypatch)
    port = _free_port()
    manifest = _manifest(
        "dep",
        "dependent",
        port,
        dependency_wait_timeout_seconds=0.3,
        dependency_wait_interval_seconds=0.05,
    )
    started = time.monotonic()
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"dependent": _DependentModule}, {}),
    ):
        server = build_server(agent_ctx, manifest)
    assert time.monotonic() - started < 10.0
    assert "dep_ping" not in _tool_names(server)


# ── Phase 2: background re-init loop ──────────────────────────────────────────


def test_race_regression_module_recovers_without_restart(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The incident, end to end.

    Dependency port closed at startup → module failed_init → /health 503. Bind the
    port; the module must reach running and /health must flip to 200 **with no
    restart**, having emitted exactly one degraded and one recovery alert.

    Red before the fix: without a retry loop the module stays failed_init forever
    and /health never leaves 503.
    """
    from starlette.testclient import TestClient

    alerts = _capture_alerts(monkeypatch)
    _use_fast_backoff(monkeypatch)

    port = _free_port()
    manifest = _manifest("dep", "dependent", port, dependency_wait_timeout_seconds=0)

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"dependent": _DependentModule}, {}),
    ):
        server = build_server(agent_ctx, manifest, transport="http")

    # Nothing registered yet — the module never instantiated.
    assert "dep_ping" not in _tool_names(server)

    with TestClient(server.http_app()) as client:
        assert client.get("/health").status_code == 503

        listener = socket.create_server(("127.0.0.1", port))
        try:
            deadline = time.monotonic() + _RECOVERY_TIMEOUT
            status = 503
            while time.monotonic() < deadline:
                status = client.get("/health").status_code
                if status == 200:
                    break
                time.sleep(0.05)
            assert status == 200, "module never recovered — /health stayed 503"
            body = client.get("/health").json()
            assert body["status"] == "healthy"
            assert body["modules"]["failed_count"] == 0
        finally:
            listener.close()

    # Tools registered onto the already-mounted child are live on the parent.
    assert "dep_ping" in _tool_names(server)

    events = [e for e, _ in alerts]
    assert events.count("module_init_degraded") == 1
    assert events.count("module_recovered") == 1


def test_degraded_alert_carries_error_type_not_message(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exception message can embed a credentialed URL. The alert must carry the
    exception type only, matching what /health exposes."""
    from starlette.testclient import TestClient

    alerts = _capture_alerts(monkeypatch)
    _use_fast_backoff(monkeypatch)

    secret = "http://user:hunter2@localhost:9/mcp"

    class _LeakyModule(_AlwaysBrokenModule):
        name = "leaky"

        def __init__(self, agent_ctx: Any, credentials: dict, config: dict) -> None:
            ToolModule.__init__(self, agent_ctx, credentials, config)
            raise ConnectionError(f"failed to connect to {secret}")

    manifest = _manifest("leaky", "leaky", _free_port(), dependency_wait_timeout_seconds=0)
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"leaky": _LeakyModule}, {}),
    ):
        server = build_server(agent_ctx, manifest, transport="http")

    with TestClient(server.http_app()):
        time.sleep(0.2)

    degraded = [d for e, d in alerts if e == "module_init_degraded"]
    assert len(degraded) == 1
    assert degraded[0]["error_type"] == "ConnectionError"
    payload = repr(degraded[0])
    assert "hunter2" not in payload
    assert secret not in payload


def test_permanent_failure_backs_off_to_cap_with_one_alert(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A module that can never come up must not hot-loop and must not alert-storm."""
    from starlette.testclient import TestClient

    alerts = _capture_alerts(monkeypatch)
    _use_fast_backoff(monkeypatch)

    manifest = _manifest("broken", "always-broken", _free_port(), dependency_wait_timeout_seconds=0)
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"always-broken": _AlwaysBrokenModule}, {}),
    ):
        server = build_server(agent_ctx, manifest, transport="http")

    with TestClient(server.http_app()) as client:
        time.sleep(_FAST_MAX_DELAY * 5)
        assert client.get("/health").status_code == 503

    events = [e for e, _ in alerts]
    assert events.count("module_init_degraded") == 1
    assert events.count("module_recovered") == 0


def test_optional_module_failure_still_healthy_and_not_double_alerted(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SMCP-31 unregressed: an optional module that fails leaves /health at 200 and
    lands in offline_optional_modules. It is still retried, but the degraded alert
    stays with the lifespan's optional_module_offline — no duplicate."""
    from starlette.testclient import TestClient

    alerts = _capture_alerts(monkeypatch)
    _use_fast_backoff(monkeypatch)

    manifest = _manifest(
        "claudebox-ops",
        "always-broken",
        _free_port(),
        optional=True,
        dependency_wait_timeout_seconds=0,
    )
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"always-broken": _AlwaysBrokenModule}, {}),
    ):
        server = build_server(agent_ctx, manifest, transport="http")

    with TestClient(server.http_app()) as client:
        time.sleep(_FAST_MAX_DELAY * 3)
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["offline_optional_modules"] == ["claudebox-ops"]

    events = [e for e, _ in alerts]
    assert "module_init_degraded" not in events


def test_optional_module_recovery_emits_optional_recovered(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An optional module that comes back reports through the SMCP-31 event name."""
    from starlette.testclient import TestClient

    alerts = _capture_alerts(monkeypatch)
    _use_fast_backoff(monkeypatch)

    port = _free_port()
    manifest = _manifest(
        "claudebox-ops", "dependent", port, optional=True, dependency_wait_timeout_seconds=0
    )
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"dependent": _DependentModule}, {}),
    ):
        server = build_server(agent_ctx, manifest, transport="http")

    with TestClient(server.http_app()):
        listener = socket.create_server(("127.0.0.1", port))
        try:
            deadline = time.monotonic() + _RECOVERY_TIMEOUT
            while time.monotonic() < deadline:
                if any(e == "optional_module_recovered" for e, _ in alerts):
                    break
                time.sleep(0.05)
        finally:
            listener.close()

    events = [e for e, _ in alerts]
    assert events.count("optional_module_recovered") == 1
    assert "module_recovered" not in events


def test_healthy_process_starts_no_retry_task(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No failures, no background task, no alerts — the healthy path pays nothing."""
    from starlette.testclient import TestClient

    alerts = _capture_alerts(monkeypatch)
    _use_fast_backoff(monkeypatch)

    with socket.create_server(("127.0.0.1", 0)) as listener:
        port = listener.getsockname()[1]
        manifest = _manifest("dep", "dependent", port)
        with patch(
            "scoped_mcp.registry._discover_module_classes",
            return_value=({"dependent": _DependentModule}, {}),
        ):
            server = build_server(agent_ctx, manifest, transport="http")

        with TestClient(server.http_app()) as client:
            assert client.get("/health").status_code == 200

    assert alerts == []
    assert "dep_ping" in _tool_names(server)


def test_retry_task_cancelled_cleanly_on_shutdown(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Leaving the lifespan must cancel the retry task — no pending-task warnings,
    no task surviving into the next test."""
    from starlette.testclient import TestClient

    _capture_alerts(monkeypatch)
    _use_fast_backoff(monkeypatch)

    manifest = _manifest("broken", "always-broken", _free_port(), dependency_wait_timeout_seconds=0)
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"always-broken": _AlwaysBrokenModule}, {}),
    ):
        server = build_server(agent_ctx, manifest, transport="http")

    with TestClient(server.http_app()):
        time.sleep(_FAST_MAX_DELAY)

    # The healer's task lived on the TestClient's loop, which is now closed. If
    # close() had not cancelled it, that loop would have been torn down with a
    # pending task and asyncio would have logged "Task was destroyed but it is
    # pending!". Assert the observable consequence: a fresh lifespan still works.
    with TestClient(server.http_app()) as client:
        assert client.get("/health").status_code == 503


# ── ModuleSelfHealer unit behaviour ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_healer_start_is_noop_when_nothing_failed() -> None:
    async def _never_called(name: str) -> None:  # pragma: no cover - asserted unreachable
        raise AssertionError(f"retry should not be attempted for {name}")

    healer = ModuleSelfHealer(_never_called, {"good": {"status": "running"}})
    await healer.start()
    assert healer.running is False
    assert healer.pending_modules() == []
    await healer.close()


@pytest.mark.asyncio
async def test_healer_retries_until_success_then_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    _capture_alerts(monkeypatch)
    health = {"mod": {"status": "failed_init", "error": "ConnectionError: refused"}}
    attempts = 0

    async def _retry(name: str) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ConnectionError("still down")
        health[name] = {"status": "running"}

    healer = ModuleSelfHealer(_retry, health, base_delay=0.01, max_delay=0.05)
    await healer.start()
    deadline = time.monotonic() + 5.0
    while healer.running and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    await healer.close()

    assert attempts == 3
    assert health["mod"] == {"status": "running"}
    assert healer.pending_modules() == []


@pytest.mark.asyncio
async def test_healer_recovery_triggers_health_file_rewrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """/health reads module_health live, but the on-disk health file the external
    prober polls needs an explicit rewrite on the transition."""
    _capture_alerts(monkeypatch)
    health = {"mod": {"status": "failed_init", "error": "ConnectionError: refused"}}
    rewrites = 0

    def _on_change() -> None:
        nonlocal rewrites
        rewrites += 1

    async def _retry(name: str) -> None:
        health[name] = {"status": "running"}

    healer = ModuleSelfHealer(
        _retry, health, base_delay=0.01, max_delay=0.05, on_health_change=_on_change
    )
    await healer.start()
    deadline = time.monotonic() + 5.0
    while healer.running and time.monotonic() < deadline:
        await asyncio.sleep(0.01)
    await healer.close()

    assert rewrites == 1


@pytest.mark.asyncio
async def test_healer_close_is_safe_when_never_started() -> None:
    async def _retry(name: str) -> None:  # pragma: no cover - never reached
        return None

    healer = ModuleSelfHealer(_retry, {})
    await healer.close()  # must not raise


@pytest.mark.asyncio
async def test_healer_never_retries_failed_import() -> None:
    """failed_import means the Python class is not in this process — retrying is
    pointless, so it is excluded from the pending set."""

    async def _retry(name: str) -> None:  # pragma: no cover - never reached
        raise AssertionError("failed_import must not be retried")

    healer = ModuleSelfHealer(_retry, {"mod": {"status": "failed_import", "error": "ImportError"}})
    assert healer.pending_modules() == []
    await healer.start()
    assert healer.running is False


@pytest.mark.asyncio
async def test_healer_degraded_alert_fires_once_per_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """start() is the only degraded-alert edge; calling it again must not re-alert."""
    alerts = _capture_alerts(monkeypatch)
    health = {"mod": {"status": "failed_init", "error": "ConnectionError: refused"}}

    async def _retry(name: str) -> None:
        raise ConnectionError("still down")

    healer = ModuleSelfHealer(_retry, health, base_delay=10.0, max_delay=10.0)
    await healer.start()
    await healer.close()
    await healer.start()
    await healer.close()

    assert [e for e, _ in alerts].count("module_init_degraded") == 1


@pytest.mark.asyncio
async def test_healer_starts_permanent_looking_failure_at_the_cap() -> None:
    """A config/import error will not fix itself by waiting, so it skips the ramp and
    costs one attempt per cap interval. A connection error ramps from base."""

    async def _retry(name: str) -> None:  # pragma: no cover - never started
        return None

    healer = ModuleSelfHealer(
        _retry,
        {
            "transient": {"status": "failed_init", "error": "ConnectionError: refused"},
            "permanent": {"status": "failed_init", "error": "ValueError: bad config"},
            "unknown": {"status": "failed_init"},
        },
        base_delay=5.0,
        max_delay=300.0,
    )
    assert healer._initial_delay("transient") == 5.0
    assert healer._initial_delay("permanent") == 300.0
    # No recorded error at all is treated as transient — retry cheaply rather than
    # assume the worst.
    assert healer._initial_delay("unknown") == 5.0


@pytest.mark.asyncio
async def test_healer_retries_every_pending_module(monkeypatch: pytest.MonkeyPatch) -> None:
    """Modules sitting at different points on the backoff curve must all keep being
    retried — a module on a short delay must not starve one on a long delay."""
    _capture_alerts(monkeypatch)
    health = {
        "transient": {"status": "failed_init", "error": "ConnectionError: refused"},
        "permanent": {"status": "failed_init", "error": "ValueError: bad config"},
    }
    attempts: dict[str, int] = {"transient": 0, "permanent": 0}

    async def _retry(name: str) -> None:
        attempts[name] += 1
        raise ConnectionError("still down")

    healer = ModuleSelfHealer(_retry, health, base_delay=0.01, max_delay=0.05)
    await healer.start()
    await asyncio.sleep(1.0)
    await healer.close()

    assert attempts["transient"] >= 1
    assert attempts["permanent"] >= 1


@pytest.mark.asyncio
async def test_healer_cancellation_propagates_out_of_an_in_flight_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry in progress at shutdown must not be swallowed and rescheduled."""
    _capture_alerts(monkeypatch)
    health = {"mod": {"status": "failed_init", "error": "ConnectionError: refused"}}
    entered = asyncio.Event()

    async def _retry(name: str) -> None:
        entered.set()
        await asyncio.sleep(30)

    healer = ModuleSelfHealer(_retry, health, base_delay=0.01, max_delay=0.02)
    await healer.start()
    await asyncio.wait_for(entered.wait(), timeout=5.0)
    await healer.close()

    assert healer.running is False


def test_redact_url_handles_an_unparseable_url() -> None:
    assert redact_url("http://[unclosed") == "<unparseable-url>"


def test_is_loopback_url_handles_an_unparseable_url() -> None:
    assert is_loopback_url("http://[unclosed") is False


def test_await_dependency_ready_rejects_a_hostless_url() -> None:
    ready, elapsed = await_dependency_ready("http:///mcp", timeout=5.0, interval=0.05)
    assert ready is False
    assert elapsed == 0.0


def test_retry_recovers_a_module_that_failed_startup_not_init(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """failed_startup is retryable too: the module instantiates but its startup()
    raises until the dependency is there. The half-started instance is discarded
    and a fresh one built on the next attempt."""
    from starlette.testclient import TestClient

    alerts = _capture_alerts(monkeypatch)
    _use_fast_backoff(monkeypatch)

    # Fail the lifespan's startup AND the first retry's startup, so the retry
    # path's own failure handling is exercised rather than succeeding first try.
    _FAILURES = 2
    state = {"attempts": 0, "shutdowns": 0}

    class _LateStarter(ToolModule):
        name = "late-starter"
        scoping = None
        required_credentials: ClassVar[list[str]] = []
        optional_credentials: ClassVar[list[str]] = []
        # Present so the registry stamps the manifest key on it, as it does for
        # mcp_proxy — exercises that path on the retry route too.
        _manifest_key = ""

        async def startup(self) -> None:
            state["attempts"] += 1
            if state["attempts"] <= _FAILURES:
                raise ConnectionError("upstream not ready")

        async def shutdown(self) -> None:
            state["shutdowns"] += 1

        @tool(mode="read")
        async def ping(self) -> str:
            return "pong"

    manifest = _manifest("late", "late-starter", _free_port(), dependency_wait_timeout_seconds=0)
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"late-starter": _LateStarter}, {}),
    ):
        server = build_server(agent_ctx, manifest, transport="http")

    with TestClient(server.http_app()) as client:
        assert client.get("/health").status_code == 503
        deadline = time.monotonic() + _RECOVERY_TIMEOUT
        status = 503
        while time.monotonic() < deadline:
            status = client.get("/health").status_code
            if status == 200:
                break
            time.sleep(0.05)
        assert status == 200, "failed_startup module never recovered"

    assert state["attempts"] == _FAILURES + 1
    # The retry that failed at startup discarded its half-started instance
    # instead of leaking it, on top of the lifespan's own shutdown pass.
    assert state["shutdowns"] >= 2
    assert "late_ping" in _tool_names(server)
    events = [e for e, _ in alerts]
    assert events.count("module_init_degraded") == 1
    assert events.count("module_recovered") == 1


def test_failed_import_module_is_not_mounted_and_not_retried(
    agent_ctx: AgentContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A module whose class could not be imported gets no child server and no retry —
    waiting cannot conjure a class into this process."""
    from starlette.testclient import TestClient

    alerts = _capture_alerts(monkeypatch)
    _use_fast_backoff(monkeypatch)

    manifest = Manifest.model_validate(
        {"agent_type": "test", "modules": {"bad": {"type": "bad", "config": {}}}}
    )
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({}, {"bad": "ImportError: missing dep"}),
    ):
        server = build_server(agent_ctx, manifest, transport="http")

    with TestClient(server.http_app()) as client:
        time.sleep(_FAST_MAX_DELAY * 3)
        assert client.get("/health").status_code == 503

    # Never entered the retry set, so it never produced a degraded alert either.
    assert [e for e, _ in alerts] == []
    assert not any(n.startswith("bad_") for n in _tool_names(server))


def test_classify_failure_splits_transient_from_permanent() -> None:
    assert classify_failure(ConnectionRefusedError("refused")) == "transient"
    assert classify_failure(OSError("all connection attempts failed")) == "transient"
    assert classify_failure(TimeoutError("timed out")) == "transient"
    assert classify_failure(ValueError("missing required config field")) == "permanent"
    assert classify_failure(ImportError("no module named x")) == "permanent"
