"""Module-level ``deviation`` marker and the ``mcp_proxy_unfiltered`` warning (1.21.0).

githost-scoped-2026-11 p3, #947 (id 1030) and #520 (id 603). A manifest's grant for a
server can differ from host-forge/scripts' grant ruleset only through a typed, reviewed
marker. scoped-mcp validates the marker's shape at load and shows it in
``scoped_mcp_status``, and enforces nothing from it. Separately, every mcp_proxy module
with no ``tool_allowlist`` says so at startup, because a denylist or no list at all
exposes every tool an upstream adds later.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
import typing
from datetime import date
from unittest.mock import MagicMock, patch

import pytest
import structlog
from fastmcp import FastMCP
from pydantic import ValidationError

from scoped_mcp import manifest as manifest_mod
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import GRANT_LINT_RULES, Manifest, ModuleConfig, ModuleDeviation
from scoped_mcp.registry import _warn_if_unfiltered_proxy, build_server

VALID = {
    "rules": ["allowlist_required"],
    "reason": "read-only upstream; every tool is a read",
    "decided_by": "Ted",
    "decided": "2026-11-08",
    "ticket": "#520 (id 603)",
}


def _manifest(modules: dict) -> Manifest:
    return Manifest.model_validate({"agent_type": "test", "modules": modules})


# ── the model ─────────────────────────────────────────────────────────────────


def test_a_valid_deviation_loads():
    cfg = ModuleConfig.model_validate({"type": "mcp_proxy", "deviation": VALID})
    assert cfg.deviation == ModuleDeviation(
        rules=["allowlist_required"],
        reason=VALID["reason"],
        decided_by="Ted",
        decided=date(2026, 11, 8),
        ticket="#520 (id 603)",
    )


def test_a_yaml_date_loads():
    """`decided: 2026-11-08` unquoted in YAML parses to a date, not a string."""
    import yaml

    doc = yaml.safe_load(
        "rules: [hitl_required, consistent_mode]\n"
        "reason: r\ndecided_by: Ted\ndecided: 2026-11-08\nticket: '#1 (id 2)'\n"
    )
    assert isinstance(doc["decided"], date)
    assert ModuleDeviation.model_validate(doc).decided == date(2026, 11, 8)


def test_no_deviation_is_the_default():
    assert ModuleConfig.model_validate({"type": "mcp_proxy"}).deviation is None


def test_the_rule_names_match_the_literal():
    """GRANT_LINT_RULES is what docs and grant-lint.py name; the Literal is what loads."""
    (rules_type,) = typing.get_args(ModuleDeviation.model_fields["rules"].annotation)
    assert typing.get_args(rules_type) == GRANT_LINT_RULES


@pytest.mark.parametrize("field", sorted(VALID))
def test_every_field_is_required(field):
    bad = {k: v for k, v in VALID.items() if k != field}
    with pytest.raises(ValidationError) as exc:
        ModuleDeviation.model_validate(bad)
    assert field in str(exc.value)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("ticket", "#520", "ticket"),
        ("ticket", "vikunja#520", "ticket"),
        ("ticket", "#520 (id 603)\n", "ticket"),
        ("ticket", "#520 (id 603) ", "ticket"),
        ("ticket", "520 (id 603)", "ticket"),
        ("rules", [], "rules"),
        ("rules", ["allowlist_requred"], "rules"),
        ("rules", ["allowlist_required", "allowlist_required"], "more than once"),
        ("rules", "allowlist_required", "rules"),
        ("reason", "", "reason"),
        ("reason", "   ", "blank"),
        ("reason", "x" * 501, "reason"),
        ("reason", "line one\nline two", "line-break"),
        ("reason", "bell\x07", "control"),
        ("reason", "sep\u2028arator", "line-break"),
        ("decided_by", "", "decided_by"),
        ("decided_by", "T" * 65, "decided_by"),
        ("decided_by", "Ted\r", "control"),
        ("decided", "yesterday", "decided"),
        ("decided", "2026-13-01", "decided"),
    ],
)
def test_each_invalid_shape_is_refused_by_name(field, value, message):
    with pytest.raises(ValidationError) as exc:
        ModuleDeviation.model_validate({**VALID, field: value})
    text = str(exc.value)
    assert field in text
    assert message in text


def test_an_extra_key_is_refused():
    with pytest.raises(ValidationError) as exc:
        ModuleDeviation.model_validate({**VALID, "expires": "2027-01-01"})
    assert "expires" in str(exc.value)


def test_a_bad_deviation_fails_the_whole_manifest():
    """Refused at load, so a broker never starts on a manifest with a malformed marker."""
    with pytest.raises(ValidationError) as exc:
        _manifest({"githost-mcp": {"type": "mcp_proxy", "deviation": {**VALID, "ticket": "x"}}})
    assert "deviation" in str(exc.value)
    assert "ticket" in str(exc.value)


def test_deviation_is_module_level_not_a_proxy_config_key():
    """Inside `config:` it would be an unknown mcp_proxy key, warned about and ignored."""
    from scoped_mcp.modules import mcp_proxy_config

    assert "deviation" not in mcp_proxy_config.KNOWN_CONFIG_KEYS
    assert "deviation" in ModuleConfig.model_fields


def test_for_status_caps_every_text_field():
    """The load limits already hold; the output caps hold even if a value bypassed them."""
    dev = ModuleDeviation.model_construct(
        rules=["consistent_mode"],
        reason="r" * 5000,
        decided_by="d" * 500,
        decided=date(2026, 11, 8),
        ticket="#1 (id 2)" + "z" * 500,
    )
    shown = dev.for_status()
    assert len(shown["reason"]) == manifest_mod.DEVIATION_REASON_MAX
    assert len(shown["decided_by"]) == manifest_mod.DEVIATION_DECIDED_BY_MAX
    assert len(shown["ticket"]) == 32
    assert shown["decided"] == "2026-11-08"
    assert shown["rules"] == ["consistent_mode"]


# ── scoped_mcp_status ─────────────────────────────────────────────────────────


def _mock_module_cls():
    mock_cls = MagicMock()
    mock_cls.required_credentials = []
    mock_cls.optional_credentials = []
    mock_cls.return_value.get_tool_methods.return_value = []
    return mock_cls


def _status(server: FastMCP) -> dict:
    return asyncio.run(server.call_tool("scoped_mcp_status", {})).structured_content


def test_status_shows_the_deviation_under_its_module(agent_ctx: AgentContext, tmp_path):
    manifest = _manifest(
        {
            "with-dev": {"type": "mock", "deviation": VALID},
            "without": {"type": "mock"},
        }
    )
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"mock": _mock_module_cls()}, {}),
    ):
        server = build_server(agent_ctx, manifest)
    result = _status(server)
    assert result["modules"]["with-dev"]["deviation"] == {
        "rules": ["allowlist_required"],
        "reason": VALID["reason"],
        "decided_by": "Ted",
        "decided": "2026-11-08",
        "ticket": "#520 (id 603)",
    }
    assert "deviation" not in result["modules"]["without"]
    # Information only: the module's health is reported exactly as without a marker.
    assert result["modules"]["with-dev"]["status"] == result["modules"]["without"]["status"]
    json.dumps(result)


def test_status_does_not_write_the_deviation_into_shared_health(agent_ctx: AgentContext):
    """module_health also feeds the unauthenticated /health route and the health file."""
    from scoped_mcp import registry

    seen: list[dict] = []
    real = registry._register_status_tool

    def spy(server, module_health, *a, **kw):
        seen.append(module_health)
        return real(server, module_health, *a, **kw)

    manifest = _manifest({"with-dev": {"type": "mock", "deviation": VALID}})
    with (
        patch(
            "scoped_mcp.registry._discover_module_classes",
            return_value=({"mock": _mock_module_cls()}, {}),
        ),
        patch("scoped_mcp.registry._register_status_tool", side_effect=spy),
    ):
        server = build_server(agent_ctx, manifest)
    assert _status(server)["modules"]["with-dev"]["deviation"]
    (health,) = seen
    assert "deviation" not in health["with-dev"]


# ── mcp_proxy_unfiltered ──────────────────────────────────────────────────────


class _Ops:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def warning(self, event: str, **kw) -> None:
        self.events.append((event, kw))


class _Proxy:
    name = "mcp_proxy"

    def __init__(self, allowlisted: bool, denylisted: bool, count: int = 5) -> None:
        self._inv = {"tool_count": count, "allowlisted": allowlisted, "denylisted": denylisted}

    def tool_inventory(self, include_names: bool = False) -> dict:
        return dict(self._inv)


@pytest.mark.parametrize(
    ("allowlisted", "denylisted", "warns"),
    [(False, False, True), (False, True, True), (True, False, False), (True, True, False)],
)
def test_the_warning_fires_without_an_allowlist(allowlisted, denylisted, warns):
    ops = _Ops()
    cfg = ModuleConfig.model_validate({"type": "mcp_proxy"})
    _warn_if_unfiltered_proxy("srv", cfg, _Proxy(allowlisted, denylisted), ops)
    if warns:
        assert ops.events == [
            (
                "mcp_proxy_unfiltered",
                {
                    "module": "srv",
                    "tool_count": 5,
                    "denylisted": denylisted,
                    "has_deviation": False,
                },
            )
        ]
    else:
        assert ops.events == []


def test_the_warning_reports_a_deviation():
    ops = _Ops()
    cfg = ModuleConfig.model_validate({"type": "mcp_proxy", "deviation": VALID})
    _warn_if_unfiltered_proxy("srv", cfg, _Proxy(False, False), ops)
    assert ops.events[0][1]["has_deviation"] is True


def test_a_non_proxy_module_never_warns():
    ops = _Ops()
    plain = MagicMock()
    plain.name = "filesystem"
    _warn_if_unfiltered_proxy("fs", ModuleConfig(), plain, ops)
    assert ops.events == []


def test_a_broken_inventory_does_not_break_startup():
    class Broken(_Proxy):
        def tool_inventory(self, include_names: bool = False) -> dict:
            raise RuntimeError("unreadable")

    ops = _Ops()
    _warn_if_unfiltered_proxy("srv", ModuleConfig(), Broken(False, False), ops)
    assert ops.events == []


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def three_tool_upstream():
    """A real streamable-HTTP FastMCP upstream on loopback serving three tools."""
    import uvicorn

    app = FastMCP("upstream")

    @app.tool
    def read_a() -> str:
        return "a"

    @app.tool
    def read_b() -> str:
        return "b"

    @app.tool
    def delete_c() -> str:
        return "c"

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app.http_app(), host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(timeout=10)


def test_real_brokers_warn_for_denylist_and_no_list_only(agent_ctx, three_tool_upstream):
    """End to end through build_server and the real McpProxyModule."""
    manifest = _manifest(
        {
            "allow": {
                "type": "mcp_proxy",
                "config": {"url": three_tool_upstream, "tool_allowlist": ["read_a"]},
            },
            "deny": {
                "type": "mcp_proxy",
                "config": {"url": three_tool_upstream, "tool_denylist": ["delete_c"]},
            },
            "open": {
                "type": "mcp_proxy",
                "config": {"url": three_tool_upstream},
                "deviation": {**VALID, "rules": ["allowlist_required"]},
            },
        }
    )
    with structlog.testing.capture_logs() as logs:
        build_server(agent_ctx, manifest)
    warnings = sorted(
        (e for e in logs if e["event"] == "mcp_proxy_unfiltered"), key=lambda e: e["module"]
    )
    assert [
        (w["module"], w["tool_count"], w["denylisted"], w["has_deviation"]) for w in warnings
    ] == [("deny", 2, True, False), ("open", 3, False, True)]
    assert "read_a" not in json.dumps(warnings), "counts only, no tool names"
