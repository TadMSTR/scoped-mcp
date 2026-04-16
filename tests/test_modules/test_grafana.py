"""Tests for modules/grafana.py — folder scoping, dashboard CRUD."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.grafana import GrafanaModule


@pytest.fixture
def grafana_module(agent_ctx: AgentContext) -> GrafanaModule:
    return GrafanaModule(
        agent_ctx=agent_ctx,
        credentials={
            "GRAFANA_URL": "http://grafana.test",
            "GRAFANA_SERVICE_ACCOUNT_TOKEN": "EXAMPLE_TOKEN",
        },
        config={},
    )


def _mock_folder_list(folder_uid: str = "folder-abc", title: str = "agent-test-agent-1"):
    """Mock GET /api/folders returning the agent's folder."""
    respx.get("http://grafana.test/api/folders").mock(
        return_value=Response(200, json=[{"uid": folder_uid, "title": title}])
    )
    return folder_uid


# ── Folder creation ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_ensure_folder_finds_existing(grafana_module: GrafanaModule) -> None:
    folder_uid = _mock_folder_list()
    respx.get("http://grafana.test/api/search").mock(return_value=Response(200, json=[]))
    await grafana_module.list_dashboards()
    assert grafana_module._folder_uid == folder_uid


@pytest.mark.asyncio
@respx.mock
async def test_ensure_folder_creates_if_missing(grafana_module: GrafanaModule) -> None:
    respx.get("http://grafana.test/api/folders").mock(return_value=Response(200, json=[]))
    respx.post("http://grafana.test/api/folders").mock(
        return_value=Response(200, json={"uid": "new-folder-uid", "title": "agent-test-agent-1"})
    )
    respx.get("http://grafana.test/api/search").mock(return_value=Response(200, json=[]))
    await grafana_module.list_dashboards()
    assert grafana_module._folder_uid == "new-folder-uid"


# ── Dashboard CRUD ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_list_dashboards(grafana_module: GrafanaModule) -> None:
    _mock_folder_list()
    respx.get("http://grafana.test/api/search").mock(
        return_value=Response(200, json=[{"uid": "dash-1", "title": "My Dashboard"}])
    )
    result = await grafana_module.list_dashboards()
    assert len(result) == 1
    assert result[0]["uid"] == "dash-1"


@pytest.mark.asyncio
@respx.mock
async def test_get_dashboard_wrong_folder_blocked(grafana_module: GrafanaModule) -> None:
    _mock_folder_list(folder_uid="agent-folder")
    # Dashboard belongs to a different folder
    respx.get("http://grafana.test/api/dashboards/uid/dash-x").mock(
        return_value=Response(
            200,
            json={
                "dashboard": {"uid": "dash-x"},
                "meta": {"folderUid": "other-folder"},
            },
        )
    )
    with pytest.raises(ScopeViolation):
        await grafana_module.get_dashboard("dash-x")


@pytest.mark.asyncio
@respx.mock
async def test_create_dashboard_injects_folder(grafana_module: GrafanaModule) -> None:
    import json as _json

    folder_uid = _mock_folder_list()
    route = respx.post("http://grafana.test/api/dashboards/db").mock(
        return_value=Response(200, json={"uid": "new-dash", "status": "success"})
    )
    await grafana_module.create_dashboard(title="Test", panels=[])
    sent = _json.loads(route.calls[0].request.content)
    assert sent["folderUid"] == folder_uid


@pytest.mark.asyncio
@respx.mock
async def test_delete_dashboard_wrong_folder_blocked(grafana_module: GrafanaModule) -> None:
    _mock_folder_list(folder_uid="agent-folder")
    respx.get("http://grafana.test/api/dashboards/uid/dash-other").mock(
        return_value=Response(
            200,
            json={
                "dashboard": {"uid": "dash-other"},
                "meta": {"folderUid": "someone-elses-folder"},
            },
        )
    )
    with pytest.raises(ScopeViolation):
        await grafana_module.delete_dashboard("dash-other")


# ── M1: allowed_datasources allowlist ────────────────────────────────────────


def _ds_module(agent_ctx: AgentContext, allowed: list[str] | None) -> GrafanaModule:
    config: dict = {}
    if allowed is not None:
        config["allowed_datasources"] = allowed
    return GrafanaModule(
        agent_ctx=agent_ctx,
        credentials={
            "GRAFANA_URL": "http://grafana.test",
            "GRAFANA_SERVICE_ACCOUNT_TOKEN": "EXAMPLE_TOKEN",
        },
        config=config,
    )


@pytest.mark.asyncio
async def test_query_datasource_disabled_without_allowlist(agent_ctx: AgentContext) -> None:
    """With no allowed_datasources configured, query_datasource must refuse."""
    mod = _ds_module(agent_ctx, allowed=None)
    with pytest.raises(ScopeViolation, match="allowed_datasources"):
        await mod.query_datasource(datasource="prom", query="up")


@pytest.mark.asyncio
async def test_query_datasource_rejects_non_allowlisted(agent_ctx: AgentContext) -> None:
    mod = _ds_module(agent_ctx, allowed=["prom-agent"])
    with pytest.raises(ScopeViolation, match="not in the agent's allowed_datasources"):
        await mod.query_datasource(datasource="loki-prod", query="{}")


@pytest.mark.asyncio
@respx.mock
async def test_query_datasource_allows_listed(agent_ctx: AgentContext) -> None:
    mod = _ds_module(agent_ctx, allowed=["prom-agent"])
    respx.get("http://grafana.test/api/datasources/name/prom-agent").mock(
        return_value=Response(200, json={"uid": "ds-abc"})
    )
    route = respx.post("http://grafana.test/api/ds/query").mock(
        return_value=Response(200, json={"results": {}})
    )
    result = await mod.query_datasource(datasource="prom-agent", query="up")
    assert route.called
    assert result == {"results": {}}


@pytest.mark.asyncio
@respx.mock
async def test_list_datasources_filtered_by_allowlist(agent_ctx: AgentContext) -> None:
    mod = _ds_module(agent_ctx, allowed=["prom-agent"])
    respx.get("http://grafana.test/api/datasources").mock(
        return_value=Response(
            200,
            json=[
                {"name": "prom-agent", "uid": "a"},
                {"name": "loki-prod", "uid": "b"},
                {"name": "postgres-prod", "uid": "c"},
            ],
        )
    )
    result = await mod.list_datasources()
    names = [d["name"] for d in result]
    assert names == ["prom-agent"]


@pytest.mark.asyncio
@respx.mock
async def test_list_datasources_unfiltered_when_no_allowlist(agent_ctx: AgentContext) -> None:
    mod = _ds_module(agent_ctx, allowed=None)
    respx.get("http://grafana.test/api/datasources").mock(
        return_value=Response(200, json=[{"name": "a", "uid": "1"}, {"name": "b", "uid": "2"}])
    )
    result = await mod.list_datasources()
    assert len(result) == 2


def test_grafana_rejects_invalid_allowlist_entry(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="allowed_datasources"):
        _ds_module(agent_ctx, allowed=["bad/name"])


def test_grafana_rejects_non_list_allowlist(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="allowed_datasources"):
        GrafanaModule(
            agent_ctx=agent_ctx,
            credentials={
                "GRAFANA_URL": "http://grafana.test",
                "GRAFANA_SERVICE_ACCOUNT_TOKEN": "EXAMPLE_TOKEN",
            },
            config={"allowed_datasources": "prom-agent"},  # type: ignore[dict-item]
        )
