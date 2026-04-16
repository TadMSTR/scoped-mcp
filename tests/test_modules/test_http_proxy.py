"""Tests for modules/http_proxy.py — service allowlist, SSRF prevention, credential injection.

SSRF tests cover the 2026-04-16 audit finding H2: IPv4-mapped IPv6,
IPv6 link-local, unspecified (``::``), NAT64, CGNAT, and ``0.0.0.0/8``
must all be blocked, and hostnames must be re-resolved at request time to
defeat DNS rebinding.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest
import respx
from httpx import Response

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.http_proxy import (
    HttpProxyModule,
    _is_ssrf_target,
    _resolve_and_check,
)


@pytest.fixture
def _mock_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route every getaddrinfo to a public IP so H2's DNS check passes in tests
    that use respx to mock httpx. Only applies to tests that request this
    fixture explicitly — rebinding-defense tests override it per-test.
    """

    def fake_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


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


# ── H2: extended IP blocklist ────────────────────────────────────────────────


def test_ssrf_ipv4_mapped_ipv6() -> None:
    assert _is_ssrf_target("http://[::ffff:127.0.0.1]/x") is True


def test_ssrf_ipv6_link_local() -> None:
    assert _is_ssrf_target("http://[fe80::1]/x") is True


def test_ssrf_ipv6_unspecified() -> None:
    assert _is_ssrf_target("http://[::]/x") is True


def test_ssrf_nat64() -> None:
    assert _is_ssrf_target("http://[64:ff9b::1]/x") is True


def test_ssrf_cgnat() -> None:
    assert _is_ssrf_target("http://100.64.0.1/x") is True


def test_ssrf_zero_block() -> None:
    assert _is_ssrf_target("http://0.0.0.0/x") is True


# ── H2: DNS-rebinding defense via async resolve_and_check ────────────────────


@pytest.mark.asyncio
async def test_resolve_and_check_literal_public_ip_passes() -> None:
    await _resolve_and_check("93.184.216.34")  # example.com — public


@pytest.mark.asyncio
async def test_resolve_and_check_literal_private_ip_blocked() -> None:
    with pytest.raises(ScopeViolation, match="blocked"):
        await _resolve_and_check("10.0.0.1")


@pytest.mark.asyncio
async def test_resolve_and_check_resolves_to_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """A hostname whose DNS points at an internal IP at request time is blocked."""

    def fake_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.1.2.3", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ScopeViolation, match="resolves to a blocked address"):
        await _resolve_and_check("evil.example.com")


@pytest.mark.asyncio
async def test_resolve_and_check_public_hostname_passes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    await _resolve_and_check("api.example.com")


@pytest.mark.asyncio
async def test_get_blocks_rebound_host(
    monkeypatch: pytest.MonkeyPatch, proxy_module: HttpProxyModule
) -> None:
    """A request to a whitelisted service is rejected if DNS returns an internal IP."""

    def fake_getaddrinfo(host: str, port: Any, *args: Any, **kwargs: Any):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.168.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ScopeViolation, match="resolves to a blocked address"):
        await proxy_module.get(service="my_api", path="/x")


def test_ssrf_blocked_at_init(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="blocked base_url"):
        HttpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"allowed_services": [{"name": "internal", "base_url": "http://192.168.1.1"}]},
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
async def test_credential_injected_as_bearer(
    proxy_module: HttpProxyModule, _mock_public_dns: None
) -> None:
    route = respx.get("https://api.example.com/data").mock(
        return_value=Response(200, json={"ok": True})
    )
    await proxy_module.get(service="my_api", path="/data")
    auth = route.calls[0].request.headers.get("Authorization")
    assert auth == "Bearer EXAMPLE_TOKEN"


@pytest.mark.asyncio
@respx.mock
async def test_no_credential_when_not_configured(
    proxy_module: HttpProxyModule, _mock_public_dns: None
) -> None:
    route = respx.get("https://public.example.com/data").mock(return_value=Response(200, json={}))
    await proxy_module.get(service="public_api", path="/data")
    auth = route.calls[0].request.headers.get("Authorization")
    assert auth is None


# ── HTTP methods ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_get_returns_json(proxy_module: HttpProxyModule, _mock_public_dns: None) -> None:
    respx.get("https://api.example.com/items").mock(
        return_value=Response(200, json={"items": [1, 2, 3]})
    )
    result = await proxy_module.get(service="my_api", path="/items")
    assert result == {"items": [1, 2, 3]}


@pytest.mark.asyncio
@respx.mock
async def test_post_sends_body(proxy_module: HttpProxyModule, _mock_public_dns: None) -> None:
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
async def test_delete_empty_response(proxy_module: HttpProxyModule, _mock_public_dns: None) -> None:
    respx.delete("https://api.example.com/item/1").mock(return_value=Response(204))
    result = await proxy_module.delete(service="my_api", path="/item/1")
    assert result == {"status": "deleted"}
