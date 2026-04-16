"""Tests for modules/http_proxy.py — service allowlist, SSRF prevention, credential injection."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.http_proxy import HttpProxyModule, _is_ssrf_target


@pytest.fixture
def proxy_module(agent_ctx: AgentContext) -> HttpProxyModule:
    return HttpProxyModule(
        agent_ctx=agent_ctx,
        credentials={"MY_API_TOKEN": "EXAMPLE_TOKEN"},
        config={
            "allowed_services": [
                {
                    "name": "my_api",
                    "base_url": "https://api.example.com",
                    "credential_key": "MY_API_TOKEN",
                },
                {
                    "name": "public_api",
                    "base_url": "https://public.example.com",
                },
            ]
        },
    )


# ── SSRF detection ────────────────────────────────────────────────────────────

def test_ssrf_localhost() -> None:
    assert _is_ssrf_target("http://localhost/api") is True


def test_ssrf_127_0_0_1() -> None:
    assert _is_ssrf_target("http://127.0.0.1/api") is True


def test_ssrf_10_x_x_x() -> None:
    assert _is_ssrf_target("http://10.0.0.1/api") is True


def test_ssrf_192_168_x_x() -> None:
    assert _is_ssrf_target("http://192.168.1.1/api") is True


def test_ssrf_169_254_metadata() -> None:
    assert _is_ssrf_target("http://169.254.169.254/latest/meta-data/") is True


def test_public_url_not_ssrf() -> None:
    assert _is_ssrf_target("https://api.example.com/v1") is False


def test_ssrf_blocked_at_init(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="blocked base_url"):
        HttpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={
                "allowed_services": [
                    {"name": "internal", "base_url": "http://192.168.1.1"}
                ]
            },
        )


# ── Service allowlist ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_unlisted_service_blocked(proxy_module: HttpProxyModule) -> None:
    with pytest.raises(ScopeViolation):
        await proxy_module.get(service="evil_api", path="/data")


def test_no_services_raises(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="allowed_services"):
        HttpProxyModule(agent_ctx=agent_ctx, credentials={}, config={"allowed_services": []})


# ── Credential injection ──────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_credential_injected_as_bearer(proxy_module: HttpProxyModule) -> None:
    route = respx.get("https://api.example.com/data").mock(return_value=Response(200, json={"ok": True}))
    await proxy_module.get(service="my_api", path="/data")
    auth = route.calls[0].request.headers.get("Authorization")
    assert auth == "Bearer EXAMPLE_TOKEN"


@pytest.mark.asyncio
@respx.mock
async def test_no_credential_when_not_configured(proxy_module: HttpProxyModule) -> None:
    route = respx.get("https://public.example.com/data").mock(return_value=Response(200, json={}))
    await proxy_module.get(service="public_api", path="/data")
    auth = route.calls[0].request.headers.get("Authorization")
    assert auth is None


# ── HTTP methods ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
@respx.mock
async def test_get_returns_json(proxy_module: HttpProxyModule) -> None:
    respx.get("https://api.example.com/items").mock(
        return_value=Response(200, json={"items": [1, 2, 3]})
    )
    result = await proxy_module.get(service="my_api", path="/items")
    assert result == {"items": [1, 2, 3]}


@pytest.mark.asyncio
@respx.mock
async def test_post_sends_body(proxy_module: HttpProxyModule) -> None:
    import json as _json
    route = respx.post("https://api.example.com/create").mock(
        return_value=Response(201, json={"id": "123"})
    )
    result = await proxy_module.post(service="my_api", path="/create", body={"name": "test"})
    sent = _json.loads(route.calls[0].request.content)
    assert sent == {"name": "test"}
    assert result["id"] == "123"


@pytest.mark.asyncio
@respx.mock
async def test_delete_empty_response(proxy_module: HttpProxyModule) -> None:
    respx.delete("https://api.example.com/item/1").mock(return_value=Response(204))
    result = await proxy_module.delete(service="my_api", path="/item/1")
    assert result == {"status": "deleted"}
