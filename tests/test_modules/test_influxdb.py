"""Tests for modules/influxdb.py — bucket scoping, structured filter query
construction, line-protocol escaping, measurement / identifier validation.

Covers 2026-04-16 audit findings H1 (Flux injection), M2 (line-protocol escaping),
M3 (measurement validation).
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.influxdb import (
    InfluxDBModule,
    _escape_tag,
    _parse_flux_csv,
    _render_field_value,
    _validate_measurement,
    _validate_time,
)


@pytest.fixture
def influx_module(agent_ctx: AgentContext) -> InfluxDBModule:
    return InfluxDBModule(
        agent_ctx=agent_ctx,
        credentials={
            "INFLUXDB_URL": "http://influxdb.test",
            "INFLUXDB_TOKEN": "EXAMPLE_TOKEN",
        },
        config={"org": "testorg", "buckets": ["metrics", "alerts"]},
    )


# ── Bucket allowlist ──────────────────────────────────────────────────────────


def test_validate_bucket_allowed(influx_module: InfluxDBModule) -> None:
    influx_module._validate_bucket("metrics")  # should not raise


def test_validate_bucket_not_allowed(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ScopeViolation):
        influx_module._validate_bucket("other-agent-bucket")


def test_validate_bucket_traversal_attempt(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ScopeViolation):
        influx_module._validate_bucket("metrics/../other")


# ── Structured filter query builder (H1) ─────────────────────────────────────


def test_build_query_single_filter(influx_module: InfluxDBModule) -> None:
    flux = influx_module._build_query(
        "metrics",
        [{"field": "_measurement", "op": "==", "value": "cpu"}],
        "-1h",
        "now()",
    )
    assert 'from(bucket: "metrics")' in flux
    assert "range(start: -1h, stop: now())" in flux
    assert 'r._measurement == "cpu"' in flux
    assert flux.count("range(") == 1


def test_build_query_multiple_filters_anded(influx_module: InfluxDBModule) -> None:
    flux = influx_module._build_query(
        "metrics",
        [
            {"field": "_measurement", "op": "==", "value": "cpu"},
            {"field": "host", "op": "!=", "value": "other"},
        ],
        "-1h",
        "now()",
    )
    assert 'r._measurement == "cpu" and r.host != "other"' in flux


def test_build_query_or_logical_op(influx_module: InfluxDBModule) -> None:
    flux = influx_module._build_query(
        "metrics",
        [
            {"field": "host", "op": "==", "value": "a"},
            {"field": "host", "op": "==", "value": "b"},
        ],
        "-1h",
        "now()",
        logical_op="or",
    )
    assert 'r.host == "a" or r.host == "b"' in flux


def test_build_query_string_value_is_json_escaped(influx_module: InfluxDBModule) -> None:
    """Strings with quotes / backslashes cannot break out of the Flux literal."""
    flux = influx_module._build_query(
        "metrics",
        [{"field": "host", "op": "==", "value": 'evil") |> drop(columns:["'}],
        "-1h",
        "now()",
    )
    # json.dumps escapes the embedded quote, so the Flux literal stays closed.
    assert '"evil\\") |> drop(columns:[\\""' in flux


def test_build_query_rejects_bad_field_name(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="filter field"):
        influx_module._build_query(
            "metrics",
            [{"field": "host) |> drop(", "op": "==", "value": "x"}],
            "-1h",
            "now()",
        )


def test_build_query_rejects_bad_op(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="not allowed"):
        influx_module._build_query(
            "metrics",
            [{"field": "host", "op": "; drop(", "value": "x"}],
            "-1h",
            "now()",
        )


def test_build_query_rejects_bad_logical_op(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="logical_op"):
        influx_module._build_query(
            "metrics",
            [{"field": "host", "op": "==", "value": "x"}],
            "-1h",
            "now()",
            logical_op="xor",
        )


def test_build_query_rejects_empty_filters(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        influx_module._build_query("metrics", [], "-1h", "now()")


def test_build_query_rejects_bad_time(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="Invalid time"):
        influx_module._build_query(
            "metrics",
            [{"field": "host", "op": "==", "value": "x"}],
            ") |> drop(columns:[",
            "now()",
        )


def test_build_query_accepts_rfc3339(influx_module: InfluxDBModule) -> None:
    flux = influx_module._build_query(
        "metrics",
        [{"field": "host", "op": "==", "value": "a"}],
        "2024-01-01T00:00:00Z",
        "2024-01-02T00:00:00Z",
    )
    assert "start: 2024-01-01T00:00:00Z, stop: 2024-01-02T00:00:00Z" in flux


def test_build_query_rejects_unsupported_value_type(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="Unsupported filter value"):
        influx_module._build_query(
            "metrics",
            [{"field": "host", "op": "==", "value": [1, 2, 3]}],
            "-1h",
            "now()",
        )


def test_build_query_filter_missing_key(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="missing required keys"):
        influx_module._build_query(
            "metrics",
            [{"field": "host", "op": "=="}],
            "-1h",
            "now()",
        )


# ── Time validator ───────────────────────────────────────────────────────────


def test_validate_time_accepts_now() -> None:
    assert _validate_time("now()") == "now()"


def test_validate_time_accepts_duration() -> None:
    assert _validate_time("-30m") == "-30m"
    assert _validate_time("1h") == "1h"


def test_validate_time_accepts_rfc3339() -> None:
    assert _validate_time("2024-01-01T00:00:00Z") == "2024-01-01T00:00:00Z"


def test_validate_time_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        _validate_time("DROP TABLE")


# ── Measurement validator (M3) ───────────────────────────────────────────────


def test_measurement_valid() -> None:
    assert _validate_measurement("cpu_usage") == "cpu_usage"
    assert _validate_measurement("http-requests") == "http-requests"


def test_measurement_rejects_spaces() -> None:
    with pytest.raises(ValueError, match="Invalid measurement"):
        _validate_measurement("cpu usage")


def test_measurement_rejects_quote() -> None:
    with pytest.raises(ValueError, match="Invalid measurement"):
        _validate_measurement('cpu"; DROP')


def test_measurement_rejects_empty() -> None:
    with pytest.raises(ValueError, match="Invalid measurement"):
        _validate_measurement("")


# ── Line-protocol escaping (M2) ──────────────────────────────────────────────


def test_escape_tag_escapes_comma() -> None:
    assert _escape_tag("a,b", kind="tag value") == "a\\,b"


def test_escape_tag_escapes_space() -> None:
    assert _escape_tag("a b", kind="tag value") == "a\\ b"


def test_escape_tag_escapes_equals() -> None:
    assert _escape_tag("a=b", kind="tag value") == "a\\=b"


def test_escape_tag_escapes_backslash() -> None:
    assert _escape_tag("a\\b", kind="tag value") == "a\\\\b"


def test_escape_tag_rejects_newline() -> None:
    with pytest.raises(ValueError, match="newline"):
        _escape_tag("line1\nline2", kind="tag value")


def test_escape_tag_rejects_carriage_return() -> None:
    with pytest.raises(ValueError, match="newline"):
        _escape_tag("a\rb", kind="tag value")


def test_render_field_value_string_escapes_quotes() -> None:
    assert _render_field_value('he said "hi"') == '"he said \\"hi\\""'


def test_render_field_value_string_rejects_newline() -> None:
    with pytest.raises(ValueError, match="newline"):
        _render_field_value("inject\nmeasurement,t=x f=1")


def test_render_field_value_int_gets_i_suffix() -> None:
    assert _render_field_value(5) == "5i"


def test_render_field_value_float_has_no_suffix() -> None:
    assert _render_field_value(0.5) == "0.5"


def test_render_field_value_bool() -> None:
    assert _render_field_value(True) == "true"
    assert _render_field_value(False) == "false"


# ── Write points ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_write_points_success(influx_module: InfluxDBModule) -> None:
    route = respx.post("http://influxdb.test/api/v2/write").mock(return_value=Response(204))
    result = await influx_module.write_points(
        bucket="metrics",
        measurement="cpu",
        points=[{"tags": {"host": "server1"}, "fields": {"usage": 0.75}}],
    )
    assert result is True
    body = route.calls[0].request.content.decode()
    assert "cpu,host=server1 usage=0.75" in body


@pytest.mark.asyncio
@respx.mock
async def test_write_points_escapes_tag_value(influx_module: InfluxDBModule) -> None:
    route = respx.post("http://influxdb.test/api/v2/write").mock(return_value=Response(204))
    await influx_module.write_points(
        bucket="metrics",
        measurement="cpu",
        points=[{"tags": {"host": "a,b c"}, "fields": {"usage": 1.0}}],
    )
    body = route.calls[0].request.content.decode()
    assert "cpu,host=a\\,b\\ c usage=1.0" in body


@pytest.mark.asyncio
async def test_write_points_rejects_newline_in_tag_value(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="newline"):
        await influx_module.write_points(
            bucket="metrics",
            measurement="cpu",
            points=[{"tags": {"host": "evil\nmalicious,t=x f=1"}, "fields": {"u": 1.0}}],
        )


@pytest.mark.asyncio
async def test_write_points_rejects_newline_in_field_string(
    influx_module: InfluxDBModule,
) -> None:
    with pytest.raises(ValueError, match="newline"):
        await influx_module.write_points(
            bucket="metrics",
            measurement="cpu",
            points=[{"tags": {"host": "a"}, "fields": {"msg": "x\nmeasurement,t=y f=1"}}],
        )


@pytest.mark.asyncio
async def test_write_points_rejects_bad_tag_key(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="tag key"):
        await influx_module.write_points(
            bucket="metrics",
            measurement="cpu",
            points=[{"tags": {"bad key": "x"}, "fields": {"u": 1.0}}],
        )


@pytest.mark.asyncio
async def test_write_points_rejects_bad_field_key(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="field key"):
        await influx_module.write_points(
            bucket="metrics",
            measurement="cpu",
            points=[{"tags": {"host": "a"}, "fields": {"bad key": 1.0}}],
        )


@pytest.mark.asyncio
async def test_write_points_rejects_empty_fields(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        await influx_module.write_points(
            bucket="metrics",
            measurement="cpu",
            points=[{"tags": {"host": "a"}, "fields": {}}],
        )


@pytest.mark.asyncio
async def test_write_points_rejects_bad_measurement(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="Invalid measurement"):
        await influx_module.write_points(
            bucket="metrics",
            measurement="cpu,host=evil usage=99",
            points=[{"fields": {"u": 1.0}}],
        )


@pytest.mark.asyncio
async def test_write_points_blocked_bucket(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ScopeViolation):
        await influx_module.write_points(
            bucket="other-agent-metrics",
            measurement="cpu",
            points=[{"fields": {"usage": 0.5}}],
        )


# ── Delete points ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_delete_points_success(influx_module: InfluxDBModule) -> None:
    respx.post("http://influxdb.test/api/v2/delete").mock(return_value=Response(204))
    result = await influx_module.delete_points(
        bucket="metrics",
        measurement="cpu",
        start="2024-01-01T00:00:00Z",
        stop="2024-01-02T00:00:00Z",
    )
    assert result is True


@pytest.mark.asyncio
async def test_delete_points_blocked_bucket(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ScopeViolation):
        await influx_module.delete_points(
            bucket="foreign-bucket",
            measurement="cpu",
            start="2024-01-01T00:00:00Z",
            stop="2024-01-02T00:00:00Z",
        )


@pytest.mark.asyncio
async def test_delete_points_rejects_bad_measurement(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="Invalid measurement"):
        await influx_module.delete_points(
            bucket="metrics",
            measurement='cpu" OR "1"="1',
            start="2024-01-01T00:00:00Z",
            stop="2024-01-02T00:00:00Z",
        )


@pytest.mark.asyncio
async def test_delete_points_rejects_bad_time(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="Invalid time"):
        await influx_module.delete_points(
            bucket="metrics",
            measurement="cpu",
            start="'; DROP users;--",
            stop="now()",
        )


# ── get_schema (M3) ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_schema_rejects_bad_measurement(influx_module: InfluxDBModule) -> None:
    with pytest.raises(ValueError, match="Invalid measurement"):
        await influx_module.get_schema(bucket="metrics", measurement='cpu") |> drop(columns:["')


# ── Config validation ─────────────────────────────────────────────────────────


def test_missing_org_raises(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="org"):
        InfluxDBModule(
            agent_ctx=agent_ctx,
            credentials={"INFLUXDB_URL": "http://test", "INFLUXDB_TOKEN": "t"},
            config={"buckets": ["metrics"]},
        )


def test_empty_buckets_raises(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="buckets"):
        InfluxDBModule(
            agent_ctx=agent_ctx,
            credentials={"INFLUXDB_URL": "http://test", "INFLUXDB_TOKEN": "t"},
            config={"org": "testorg", "buckets": []},
        )


# ── CSV parser ────────────────────────────────────────────────────────────────


def test_parse_flux_csv_basic() -> None:
    csv = "#group,false,false\n_measurement,_value\ncpu,0.75\n"
    rows = _parse_flux_csv(csv)
    assert len(rows) == 1
    assert rows[0]["_value"] == "0.75"


def test_parse_flux_csv_empty() -> None:
    assert _parse_flux_csv("") == []
