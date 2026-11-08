"""forward_identity, result_attributes and unknown-key warnings on mcp_proxy (1.20.0).

githost-scoped-2026-11 p2. scoped-mcp already read X-Forge-Run-Id / X-Forge-Task-Id on
every call but used them only for HITL attribution, and mcp_proxy sent an upstream only
the manifest's static headers. These tests drive a real loopback FastMCP upstream that
echoes the headers it received, so they check what goes over the wire.
"""

from __future__ import annotations

import ast
import asyncio
import json
import pathlib
import socket
import threading
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import structlog
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from mcp.types import TextContent

from scoped_mcp.audit import SESSION_ID, audited
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import Manifest
from scoped_mcp.modules import mcp_proxy_config as cfg
from scoped_mcp.modules.mcp_proxy import McpProxyModule

RUN = "11111111-2222-4333-8444-555555555555"
TASK = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


@pytest.fixture
def agent_ctx() -> AgentContext:
    return AgentContext(agent_id="test-agent", agent_type="test")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def echo_upstream():
    """A real streamable-HTTP FastMCP server on loopback, in its own thread and loop.

    Its one tool returns the X-Forge-* and test headers it received, plus a qmd-shaped
    structured result so result_attributes has something real to read.
    """
    app = FastMCP("echo")

    @app.tool
    def query() -> dict:
        h = get_http_headers()
        return {
            "headers": {k: v for k, v in h.items() if k.startswith(("x-forge-", "x-static"))},
            "results": [
                {"file": "docs/host-forge/services.md", "snippet": "SECRET SNIPPET"},
                {"file": "docs/other.md", "snippet": "x"},
                {"file": "agent-memory/agents/x.md", "snippet": "y"},
            ],
        }

    import uvicorn

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


def _module(agent_ctx, url: str, **config: Any) -> McpProxyModule:
    mod = McpProxyModule(agent_ctx=agent_ctx, credentials={}, config={"url": url, **config})
    mod._manifest_key = "qmd"
    return mod


def _received(mod: McpProxyModule) -> tuple[dict, Any]:
    (method,) = mod.get_tool_methods(mode=None)
    result = asyncio.run(method())
    return result["headers"], result


# ---------------------------------------------------------------------------
# forward_identity, over the wire
# ---------------------------------------------------------------------------


def test_forward_identity_sends_run_task_and_session(agent_ctx, echo_upstream, monkeypatch):
    monkeypatch.setenv("FORGE_RUN_ID", RUN)
    monkeypatch.setenv("FORGE_TASK_ID", TASK)
    mod = _module(agent_ctx, echo_upstream, forward_identity=True, headers={"X-Static": "kept"})
    headers, _ = _received(mod)
    assert headers["x-forge-run-id"] == RUN
    assert headers["x-forge-task-id"] == TASK
    assert headers["x-forge-session-id"] == SESSION_ID
    assert headers["x-static"] == "kept", "static manifest headers must still be sent"


def test_forward_identity_is_off_by_default(agent_ctx, echo_upstream, monkeypatch):
    monkeypatch.setenv("FORGE_RUN_ID", RUN)
    monkeypatch.setenv("FORGE_TASK_ID", TASK)
    headers, _ = _received(_module(agent_ctx, echo_upstream))
    assert not any(k.startswith("x-forge-") for k in headers)


def test_a_missing_or_invalid_id_is_omitted_never_sent_empty(agent_ctx, echo_upstream, monkeypatch):
    monkeypatch.setenv("FORGE_RUN_ID", "${FORGE_RUN_ID}")  # what an interactive session sends
    monkeypatch.delenv("FORGE_TASK_ID", raising=False)
    headers, _ = _received(_module(agent_ctx, echo_upstream, forward_identity=True))
    assert "x-forge-run-id" not in headers
    assert "x-forge-task-id" not in headers
    assert headers["x-forge-session-id"] == SESSION_ID


def test_each_call_gets_its_own_ids(agent_ctx, echo_upstream, monkeypatch):
    """The transport is built per call: a later call must not reuse an earlier call's id."""
    mod = _module(agent_ctx, echo_upstream, forward_identity=True)
    monkeypatch.setenv("FORGE_RUN_ID", RUN)
    first, _ = _received(mod)
    monkeypatch.setenv("FORGE_RUN_ID", TASK)
    second, _ = _received(mod)
    assert (first["x-forge-run-id"], second["x-forge-run-id"]) == (RUN, TASK)


def test_static_headers_naming_a_forwarded_header_are_refused(agent_ctx):
    with pytest.raises(ValueError, match="X-Forge-Run-Id"):
        McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={
                "url": "http://127.0.0.1:1/mcp",
                "forward_identity": True,
                "headers": {"x-forge-run-id": "static"},
            },
        )


def test_static_forwarded_header_is_allowed_while_forward_identity_is_off():
    assert cfg.validate_proxy_config({"headers": {"X-Forge-Run-Id": "x"}}) == []


def test_forward_identity_must_be_a_bool():
    assert cfg.validate_proxy_config({"forward_identity": "yes"}) == [
        "forward_identity must be true or false"
    ]


def test_forward_identity_on_stdio_warns_once(agent_ctx):
    with (
        patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient,
        structlog.testing.capture_logs() as logs,
    ):
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[])
        MockClient.return_value = mock_cm
        McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"command": "/bin/true", "forward_identity": True},
        )
    assert [e["event"] for e in logs].count("mcp_proxy_forward_identity_ignored") == 1


def test_manifest_validation_refuses_the_header_clash():
    with pytest.raises(ValueError, match="X-Forge-Task-Id"):
        Manifest.model_validate(
            {
                "agent_type": "test",
                "modules": {
                    "githost-mcp": {
                        "type": "mcp_proxy",
                        "config": {
                            "url": "http://127.0.0.1:1/mcp",
                            "forward_identity": True,
                            "headers": {"X-Forge-Task-Id": "x"},
                        },
                    }
                },
            }
        )


# ---------------------------------------------------------------------------
# Unknown config keys
# ---------------------------------------------------------------------------


def test_an_unknown_key_is_warned_by_name_only(agent_ctx, echo_upstream):
    with structlog.testing.capture_logs() as logs:
        _module(agent_ctx, echo_upstream, forward_identiy="SECRET-VALUE")  # typo, on purpose
    warnings = [e for e in logs if e["event"] == "mcp_proxy_unknown_config_key"]
    assert [w["key"] for w in warnings] == ["forward_identiy"]
    assert "SECRET-VALUE" not in json.dumps(logs, default=str)


def test_known_keys_do_not_warn(agent_ctx, echo_upstream):
    with structlog.testing.capture_logs() as logs:
        _module(agent_ctx, echo_upstream, forward_identity=True, tool_denylist=[])
    assert not [e for e in logs if e["event"] == "mcp_proxy_unknown_config_key"]


def test_every_key_mcp_proxy_reads_is_a_known_key():
    """Closed world: a new config.get("…") in mcp_proxy.py must be added to
    KNOWN_CONFIG_KEYS, or it would be warned about as unknown in every manifest that
    uses it. And every known key must still be read somewhere."""
    source = pathlib.Path(cfg.__file__).with_name("mcp_proxy.py").read_text()
    read: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "config"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            read.add(node.args[0].value)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and node.value.id == "config"
            and isinstance(node.slice, ast.Constant)
        ):
            read.add(node.slice.value)
    assert read, "found no config reads — the AST walk is broken"
    assert read - cfg.KNOWN_CONFIG_KEYS == set(), "add these to KNOWN_CONFIG_KEYS"
    assert cfg.KNOWN_CONFIG_KEYS - read == set(), "KNOWN_CONFIG_KEYS lists keys nothing reads"


def test_unknown_keys_with_unprintable_names_are_not_echoed():
    assert cfg.unknown_keys({"bad\nkey": 1, "url": "x"}) == ["<unprintable>"]


# ---------------------------------------------------------------------------
# result_attributes
# ---------------------------------------------------------------------------

_QMD_EXTRACTOR = {
    "tool": "qmd_query",
    "path": "results[].file",
    "transform": "first_path_segment",
    "name": "collections",
}


def _audited_call(mod: McpProxyModule) -> tuple[Any, list[dict]]:
    (method,) = mod.get_tool_methods(mode=None)
    wrapped = audited("qmd_query")(method)
    with structlog.testing.capture_logs() as logs:
        result = asyncio.run(wrapped())
    return result, [e for e in logs if e["event"] == "tool_call"]


def test_result_attributes_count_collections_onto_the_audit_record(agent_ctx, echo_upstream):
    mod = _module(agent_ctx, echo_upstream, result_attributes=[_QMD_EXTRACTOR])
    _result, (record,) = _audited_call(mod)
    assert record["result_attrs"] == {"collections": {"docs": 2, "agent-memory": 1}}
    flat = json.dumps(record, default=str)
    assert "SECRET SNIPPET" not in flat and "services.md" not in flat


def test_the_result_returned_to_the_agent_is_unchanged(agent_ctx, echo_upstream):
    plain = _module(agent_ctx, echo_upstream)
    extracting = _module(agent_ctx, echo_upstream, result_attributes=[_QMD_EXTRACTOR])
    (m1,) = plain.get_tool_methods(mode=None)
    (m2,) = extracting.get_tool_methods(mode=None)
    without = asyncio.run(m1())
    with_attrs = asyncio.run(m2())
    assert json.dumps(with_attrs, sort_keys=True) == json.dumps(without, sort_keys=True)


def test_upstream_tool_name_matches_too(agent_ctx, echo_upstream):
    ext = {**_QMD_EXTRACTOR, "tool": "query"}
    _result, (record,) = _audited_call(_module(agent_ctx, echo_upstream, result_attributes=[ext]))
    assert record["result_attrs"]["collections"]["docs"] == 2


def test_a_missing_path_is_recorded_and_never_fails_the_call(agent_ctx, echo_upstream):
    ext = {**_QMD_EXTRACTOR, "path": "nope[].file"}
    result, (record,) = _audited_call(_module(agent_ctx, echo_upstream, result_attributes=[ext]))
    assert "results" in result
    assert record["result_attrs_error"] == {"collections": "PathMissing"}
    assert "result_attrs" not in record


def test_other_tools_are_not_extracted(agent_ctx, echo_upstream):
    ext = {**_QMD_EXTRACTOR, "tool": "qmd_get"}
    _result, (record,) = _audited_call(_module(agent_ctx, echo_upstream, result_attributes=[ext]))
    assert "result_attrs" not in record and "result_attrs_error" not in record


def test_result_attrs_land_on_the_current_span(agent_ctx, echo_upstream):
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("t")
    mod = _module(agent_ctx, echo_upstream, result_attributes=[_QMD_EXTRACTOR])
    (method,) = mod.get_tool_methods(mode=None)
    wrapped = audited("qmd_query")(method)

    async def run() -> None:
        with tracer.start_as_current_span("tools/call qmd_query"):
            await wrapped()

    asyncio.run(run())
    (span,) = exporter.get_finished_spans()
    assert json.loads(span.attributes["scoped_mcp.result.collections"]) == {
        "agent-memory": 1,
        "docs": 2,
    }


def test_text_block_json_is_read_when_there_is_no_structured_content():
    payload = cfg.result_payload(
        None, [TextContent(type="text", text='{"results": [{"file": "a/b"}]}')]
    )
    assert cfg.count_values(payload, "results[].file", "first_path_segment") == {"a": 1}


def test_non_json_text_is_a_recorded_error():
    with pytest.raises(cfg.ResultNotJson):
        cfg.result_payload(None, [TextContent(type="text", text="Found 3 results")])


def test_values_that_are_not_plain_are_counted_as_other():
    payload = {"results": [{"file": "has space/x"}, {"file": "a" * 65 + "/x"}, {"file": 7}]}
    assert cfg.count_values(payload, "results[].file", "first_path_segment") == {"other": 3}


def test_distinct_values_are_capped_with_overflow_as_other():
    payload = {"results": [{"file": f"c{i}/x"} for i in range(50)]}
    counts = cfg.count_values(payload, "results[].file", "first_path_segment")
    assert len(counts) == cfg.MAX_RESULT_KEYS
    assert sum(counts.values()) == 50
    assert counts["other"] == 50 - (cfg.MAX_RESULT_KEYS - 1)


@pytest.mark.parametrize(
    ("extractors", "message"),
    [
        ([{**_QMD_EXTRACTOR, "transform": "upper"}], "transform must be one of"),
        # Unhashable values: a dict membership test on them raises TypeError, which
        # would crash `scoped-mcp validate` instead of reporting the problem.
        ([{**_QMD_EXTRACTOR, "transform": ["first_path_segment"]}], "transform must be one of"),
        ([{**_QMD_EXTRACTOR, "transform": {"a": 1}}], "transform must be one of"),
        ([{**_QMD_EXTRACTOR, "path": "results[*].file"}], "path must be a dotted path"),
        ([{**_QMD_EXTRACTOR, "path": "a..b"}], "path must be a dotted path"),
        ([{**_QMD_EXTRACTOR, "extra": 1}], "exactly the keys"),
        ([{**_QMD_EXTRACTOR, "name": "Bad-Name"}], "name must match"),
        ([_QMD_EXTRACTOR, _QMD_EXTRACTOR], "used twice"),
        (
            [{**_QMD_EXTRACTOR, "name": f"n{i}"} for i in range(cfg.MAX_RESULT_EXTRACTORS + 1)],
            "at most 8",
        ),
        ("results[].file", "must be a list"),
    ],
)
def test_result_attribute_shapes_are_validated(extractors, message):
    problems = cfg.validate_proxy_config({"result_attributes": extractors})
    assert any(message in p for p in problems), problems


def test_a_valid_extractor_passes_validation():
    assert cfg.validate_proxy_config({"result_attributes": [_QMD_EXTRACTOR]}) == []


# ---------------------------------------------------------------------------
# run_id / task_id on scoped-mcp's own audit records
# ---------------------------------------------------------------------------


def _audited_fn(fn, monkeypatch, run: str | None, task: str | None):
    for name, value in (("FORGE_RUN_ID", run), ("FORGE_TASK_ID", task)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    with structlog.testing.capture_logs() as logs:
        try:
            asyncio.run(audited("x_tool")(fn)())
        except RuntimeError:
            pass
    return [e for e in logs if e["event"] in ("tool_call", "tool_error")]


def test_tool_call_records_carry_run_and_task(monkeypatch):
    async def ok() -> str:
        return "fine"

    (record,) = _audited_fn(ok, monkeypatch, RUN, TASK)
    assert (record["run_id"], record["task_id"]) == (RUN, TASK)


def test_tool_error_records_carry_them_too(monkeypatch):
    async def boom() -> str:
        raise RuntimeError("x")

    (record,) = _audited_fn(boom, monkeypatch, RUN, None)
    assert record["event"] == "tool_error"
    assert (record["run_id"], record["task_id"]) == (RUN, None)


def test_absent_ids_are_null(monkeypatch):
    async def ok() -> str:
        return "fine"

    (record,) = _audited_fn(ok, monkeypatch, None, None)
    assert record["run_id"] is None and record["task_id"] is None


def test_otel_middleware_sets_forge_ids(monkeypatch):
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from scoped_mcp.contrib.otel import OtelMiddleware

    monkeypatch.setenv("FORGE_RUN_ID", RUN)
    monkeypatch.setenv("FORGE_TASK_ID", TASK)
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    mw = OtelMiddleware(tracer_provider=provider)
    ctx = AgentContext(agent_id="a", agent_type="t")
    asyncio.run(mw(ctx, "x_tool", {}, AsyncMock(return_value="ok")))
    (span,) = exporter.get_finished_spans()
    assert span.attributes["forge.run_id"] == RUN
    assert span.attributes["forge.task_id"] == TASK


def test_otel_middleware_omits_absent_ids(monkeypatch):
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from scoped_mcp.contrib.otel import OtelMiddleware

    monkeypatch.delenv("FORGE_RUN_ID", raising=False)
    monkeypatch.delenv("FORGE_TASK_ID", raising=False)
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    mw = OtelMiddleware(tracer_provider=provider)
    asyncio.run(mw(AgentContext(agent_id="a", agent_type="t"), "x", {}, AsyncMock()))
    (span,) = exporter.get_finished_spans()
    assert "forge.run_id" not in span.attributes and "forge.task_id" not in span.attributes
