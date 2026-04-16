"""Tests for modules/influxdb.py — bucket scoping, query template, write/delete."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.influxdb import InfluxDBModule, _parse_flux_csv


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


# ── Query template ────────────────────────────────────────────────────────────

def test_build_query_template(influx_module: InfluxDBModule) -> None:
    flux = influx_module._build_query("metrics", 'r._measurement == "cpu"', "-1h", "now()")
    assert 'from(bucket: "metrics")' in flux
    assert 'range(start: -1h, stop: now())' in flux
    assert 'r._measurement == "cpu"' in flux
    # Verify no user-injected range() could override the template
    assert flux.count("range(") == 1


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
