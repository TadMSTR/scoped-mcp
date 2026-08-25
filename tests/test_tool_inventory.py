"""Per-module tool inventory in the three health reporters (vikunja#517).

An ``mcp_proxy`` enumerates its upstream exactly once, at ``__init__``, and never
widens that set afterwards. So a proxy can sit indefinitely on a tool list the
upstream has since grown, and nothing in the process notices — which is what
happened to sysadmin's vikunja-mcp for two days across two releases.

The detector for that is a *count comparison across agents proxying the same
upstream*, deliberately not a query against the upstream (which would need that
upstream's credentials). These tests pin the three properties that comparison
depends on: the count is present, it is the post-filter count with the filtering
state alongside it, and it reflects the instance that is actually serving.

They also pin the redaction contract: ``/health`` is unauthenticated, so it gets
counts and never names.
"""

from __future__ import annotations

import json
import socket
import time
from typing import ClassVar
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest
from fastmcp import FastMCP

from scoped_mcp import module_selfheal, ops_alert, registry
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import Manifest
from scoped_mcp.modules._base import ToolModule, tool
from scoped_mcp.registry import (
    _build_tool_inventory,
    _register_health_route,
    _register_status_tool,
    _write_health_file,
    build_server,
)


class _FakeProxy:
    """Stand-in for McpProxyModule with a controllable inventory."""

    def __init__(self, tools: list[str], transport: str = "http", allowlisted: bool = False):
        self._tools = tools
        self._transport = transport
        self._allowlisted = allowlisted

    def tool_inventory(self, include_names: bool = False) -> dict:
        inv = {
            "tool_count": len(self._tools),
            "transport": self._transport,
            "allowlisted": self._allowlisted,
            "denylisted": False,
            "discovered_at": "2026-08-25T12:00:00+00:00",
        }
        if include_names:
            inv["tools"] = sorted(self._tools)
        return inv


class _PlainModule:
    """A non-proxy module — has no upstream, so no inventory to report."""


class _BrokenProxy:
    def tool_inventory(self, include_names: bool = False) -> dict:
        raise RuntimeError("upstream state is unreadable")


class _FakeVaultSource:
    def __init__(self, health: dict) -> None:
        self._health = health

    def credential_health(self) -> dict:
        return self._health


class _FakeOps:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def info(self, event: str, **kw) -> None:
        self.events.append((event, kw))

    def warning(self, event: str, **kw) -> None:
        self.events.append((event, kw))


# ── _build_tool_inventory ─────────────────────────────────────────────────────


def test_inventory_reports_each_running_proxy() -> None:
    instances = {
        "vikunja-mcp": _FakeProxy(["a", "b", "c"]),
        "githost-mcp": _FakeProxy(["x"]),
    }
    health = {"vikunja-mcp": {"status": "running"}, "githost-mcp": {"status": "running"}}
    inv = _build_tool_inventory(instances, health)
    assert inv["vikunja-mcp"]["tool_count"] == 3
    assert inv["githost-mcp"]["tool_count"] == 1


def test_inventory_excludes_module_that_failed_startup() -> None:
    """A module that instantiated but failed startup discovered tools it cannot serve.

    Reporting its count would tell a drift consumer this agent is serving a surface
    it is not — the failure is already visible in failed_count/module_health.
    """
    instances = {"vikunja-mcp": _FakeProxy(["a", "b"])}
    inv = _build_tool_inventory(instances, {"vikunja-mcp": {"status": "failed_startup"}})
    assert inv == {}


def test_inventory_skips_modules_without_an_inventory() -> None:
    """Non-proxy modules have no upstream to drift from and are simply absent."""
    instances = {"filesystem": _PlainModule(), "vikunja-mcp": _FakeProxy(["a"])}
    health = {"filesystem": {"status": "running"}, "vikunja-mcp": {"status": "running"}}
    assert set(_build_tool_inventory(instances, health)) == {"vikunja-mcp"}


def test_inventory_survives_a_module_that_raises() -> None:
    """This feeds three health reporters — one bad module must not fail any of them."""
    instances = {"broken": _BrokenProxy(), "vikunja-mcp": _FakeProxy(["a"])}
    health = {"broken": {"status": "running"}, "vikunja-mcp": {"status": "running"}}
    inv = _build_tool_inventory(instances, health)
    assert set(inv) == {"vikunja-mcp"}


def test_inventory_include_names_is_opt_in() -> None:
    instances = {"vikunja-mcp": _FakeProxy(["b", "a"])}
    health = {"vikunja-mcp": {"status": "running"}}
    assert "tools" not in _build_tool_inventory(instances, health)["vikunja-mcp"]
    named = _build_tool_inventory(instances, health, include_names=True)
    assert named["vikunja-mcp"]["tools"] == ["a", "b"]


# ── GET /health (unauthenticated) ─────────────────────────────────────────────


def _health_client(module_health: dict, vault_source: object, instances: dict | None = None):
    from starlette.testclient import TestClient

    server = FastMCP("scoped-mcp/test")
    _register_health_route(server, module_health, vault_source, instances=instances)
    return TestClient(server.http_app())


def test_health_route_reports_per_module_tool_counts() -> None:
    instances = {"vikunja-mcp": _FakeProxy(["a", "b", "c"], allowlisted=True)}
    with _health_client({"vikunja-mcp": {"status": "running"}}, None, instances) as client:
        body = client.get("/health").json()
    entry = body["tool_inventory"]["vikunja-mcp"]
    assert entry["tool_count"] == 3
    assert entry["transport"] == "http"
    assert entry["allowlisted"] is True
    assert entry["discovered_at"] == "2026-08-25T12:00:00+00:00"


def test_health_route_omits_tool_names() -> None:
    """The whole security question this feature raised: /health is unauthenticated.

    Counts and booleans widen disclosure by nothing an operator's manifest does not
    already state. Tool *names* would be new, so they stay on the authenticated tool.
    """
    instances = {"vikunja-mcp": _FakeProxy(["backlog_summary", "task_link_commit"])}
    with _health_client({"vikunja-mcp": {"status": "running"}}, None, instances) as client:
        resp = client.get("/health")
    body = resp.text
    assert "backlog_summary" not in body
    assert "task_link_commit" not in body
    assert "tools" not in resp.json()["tool_inventory"]["vikunja-mcp"]


def test_health_route_omits_inventory_when_no_proxies() -> None:
    """No proxy modules → no empty block. Keeps the body unchanged for stdio agents."""
    with _health_client({"filesystem": {"status": "running"}}, None, {}) as client:
        assert "tool_inventory" not in client.get("/health").json()


def test_health_route_inventory_does_not_affect_status_code() -> None:
    """The inventory is diagnostic. A stale-but-running proxy is still a 200 —
    deciding it is drift needs a second agent to compare against, which is the
    caller's job, not this route's."""
    instances = {"vikunja-mcp": _FakeProxy(["a"])}
    with _health_client({"vikunja-mcp": {"status": "running"}}, None, instances) as client:
        assert client.get("/health").status_code == 200


def test_health_route_unchanged_without_instances() -> None:
    """Callers that pass no instances (stdio transport, existing tests) see the old body."""
    vs = _FakeVaultSource({"source": "vault", "token_healthy": True})
    with _health_client({"mod": {"status": "running"}}, vs) as client:
        body = client.get("/health").json()
    assert "tool_inventory" not in body
    assert body["modules"] == {"failed_count": 0, "total_count": 1}


# ── scoped_mcp_status (authenticated) ─────────────────────────────────────────


async def _call_status(module_health: dict, instances: dict | None = None) -> dict:
    """Dispatch scoped_mcp_status the way a client would, not by calling the closure.

    That also pins the payload as JSON-serializable, which the closure alone would not.
    """
    server = FastMCP("scoped-mcp/test")
    _register_status_tool(server, module_health, {}, instances=instances)
    return (await server.call_tool("scoped_mcp_status", {})).structured_content


@pytest.mark.asyncio
async def test_status_tool_reports_tool_names() -> None:
    """The authenticated reporter names the tools — that is what makes a flagged pair
    diagnosable ("which tool is this agent missing") rather than merely countable."""
    instances = {"vikunja-mcp": _FakeProxy(["task_link_commit", "backlog_summary"])}
    result = await _call_status({"vikunja-mcp": {"status": "running"}}, instances)
    entry = result["tool_inventory"]["vikunja-mcp"]
    assert entry["tools"] == ["backlog_summary", "task_link_commit"]
    assert entry["tool_count"] == 2


@pytest.mark.asyncio
async def test_status_tool_omits_inventory_when_no_proxies() -> None:
    result = await _call_status({"filesystem": {"status": "running"}}, {})
    assert "tool_inventory" not in result


@pytest.mark.asyncio
async def test_status_tool_still_reports_health_without_instances() -> None:
    result = await _call_status({"mod": {"status": "running"}})
    assert result["healthy"] is True
    assert "tool_inventory" not in result


# ── health file (on-disk, external watcher) ───────────────────────────────────


def test_health_file_carries_counts_without_names(tmp_path, monkeypatch) -> None:
    """The file is a plain on-disk artifact polled by an external prober — same
    name-free contract as /health, and the same reason."""
    path = tmp_path / "health.json"
    monkeypatch.setenv("SCOPED_MCP_HEALTH_FILE", str(path))
    instances = {"vikunja-mcp": _FakeProxy(["backlog_summary", "task_link_commit"])}
    _write_health_file({"vikunja-mcp": {"status": "running"}}, _FakeOps(), instances=instances)
    raw = path.read_text()
    assert "backlog_summary" not in raw
    entry = json.loads(raw)["tool_inventory"]["vikunja-mcp"]
    assert entry["tool_count"] == 2
    assert "tools" not in entry


def test_health_file_omits_inventory_without_instances(tmp_path, monkeypatch) -> None:
    path = tmp_path / "health.json"
    monkeypatch.setenv("SCOPED_MCP_HEALTH_FILE", str(path))
    _write_health_file({"mod": {"status": "running"}}, _FakeOps())
    assert "tool_inventory" not in json.loads(path.read_text())


# ── end to end: a self-healed module reports the instance that is serving ─────


class _RecoverableProxy(ToolModule):
    """Stand-in for mcp_proxy: reaches its upstream during ``__init__``.

    Same failure shape as the real thing — discovery runs in ``__init__``, so an
    unbound port turns into an exception before the module exists at all, and the
    instance that eventually serves is one the self-healer built, not one
    build_server did.
    """

    name = "recoverable"
    scoping = None
    required_credentials: ClassVar[list[str]] = []
    optional_credentials: ClassVar[list[str]] = []

    def __init__(self, agent_ctx, credentials: dict, config: dict) -> None:
        super().__init__(agent_ctx, credentials, config)
        parts = urlsplit(config["url"])
        with socket.create_connection((parts.hostname, parts.port), timeout=1):
            pass
        self._discovered = ["alpha", "beta", "gamma"]

    def tool_inventory(self, include_names: bool = False) -> dict:
        inv = {
            "tool_count": len(self._discovered),
            "transport": "http",
            "allowlisted": False,
            "denylisted": False,
            "discovered_at": "2026-08-25T12:00:00+00:00",
        }
        if include_names:
            inv["tools"] = sorted(self._discovered)
        return inv

    @tool(mode="read")
    async def ping(self) -> str:
        return "pong"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _use_fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    real_cls = module_selfheal.ModuleSelfHealer

    def _fast(*args, **kwargs):
        kwargs.setdefault("base_delay", 0.05)
        kwargs.setdefault("max_delay", 0.2)
        return real_cls(*args, **kwargs)

    monkeypatch.setattr(registry, "ModuleSelfHealer", _fast)


def test_self_healed_module_appears_in_the_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module recovered mid-life must report the instance that is actually serving.

    build_server never saw this instance — the module failed ``__init__`` with its
    port closed, so it was absent from ``all_instances`` entirely, and the object
    now answering calls was built by the self-healer. If the reporters held a
    snapshot taken at build time, or if the retry path did not publish its new
    instance, /health would show a recovered module with no inventory at all —
    silently telling a drift check "nothing to compare" for the one module whose
    tool surface was most recently re-read.

    Red before this build in the obvious way (no inventory anywhere); red against
    a snapshot-based implementation for the reason above.
    """
    from starlette.testclient import TestClient

    async def _no_alerts(event: str, detail: dict) -> bool:
        return True

    monkeypatch.setattr(ops_alert, "send_ops_alert", _no_alerts)
    _use_fast_backoff(monkeypatch)

    port = _free_port()
    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {
                "upstream-mcp": {
                    "type": "recoverable",
                    "mode": "read",
                    # Skip the startup dependency gate — this test is about what the
                    # reporters do after recovery, not how long build_server waits.
                    "dependency_wait_timeout_seconds": 0,
                    "config": {"url": f"http://127.0.0.1:{port}/mcp"},
                }
            },
        }
    )
    ctx = AgentContext(agent_id="test-agent", agent_type="test")

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"recoverable": _RecoverableProxy}, {}),
    ):
        server = build_server(ctx, manifest, transport="http")

    with TestClient(server.http_app()) as client:
        # Failed init: degraded, and nothing to report an inventory for.
        first = client.get("/health")
        assert first.status_code == 503
        assert "upstream-mcp" not in first.json().get("tool_inventory", {})

        listener = socket.create_server(("127.0.0.1", port))
        try:
            deadline = time.monotonic() + 15.0
            body: dict = {}
            while time.monotonic() < deadline:
                resp = client.get("/health")
                if resp.status_code == 200:
                    body = resp.json()
                    break
                time.sleep(0.05)
            assert body, "module never recovered — /health stayed 503"
        finally:
            listener.close()

    assert body["tool_inventory"]["upstream-mcp"]["tool_count"] == 3
    assert "tools" not in body["tool_inventory"]["upstream-mcp"]
