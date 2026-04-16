"""Generic HTTP API proxy with service allowlist and credential injection.

Scope: requests are restricted to declared services only. Unlisted services
and internal-looking URLs (SSRF prevention) are rejected before any I/O.

Security model (2026-04-16 audit, finding H2):
- ``_BLOCKED_IP_NETWORKS`` covers the standard RFC1918 / loopback / link-local
  ranges plus IPv4-mapped IPv6 (``::ffff:0:0/96``), IPv6 link-local
  (``fe80::/10``), unspecified (``::/128``), NAT64 (``64:ff9b::/96``),
  ``0.0.0.0/8``, and CGNAT (``100.64.0.0/10``).
- For hostnames (not literal IPs), the module does an async ``getaddrinfo``
  resolution before every request and rejects the request if any resolved
  address lands in the blocklist. This also defends against DNS rebinding.

Config:
    allowed_services (list[dict]): each entry has:
        name (str): service identifier used in tool calls.
        base_url (str): base URL for this service.
        credential_key (str, optional): credential key to inject as a Bearer token.

Required credentials: per service — keys named in allowed_services[*].credential_key.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, ClassVar
from urllib.parse import urlparse

import httpx

from ..exceptions import ScopeViolation
from ._base import ToolModule, tool

# Internal/link-local/reserved address ranges that must not be reachable via
# http_proxy. Covers H2 findings: IPv4-mapped IPv6, IPv6 link-local, unspecified,
# NAT64, 0.0.0.0/8, and CGNAT.
_BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("64:ff9b::/96"),
]

_BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal", "169.254.169.254"}


def _ip_is_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(addr in net for net in _BLOCKED_IP_NETWORKS)


def _is_ssrf_target(url: str) -> bool:
    """Return True if the URL's host is a literal IP in the blocklist or a
    known internal hostname. Hostnames that require DNS resolution are left
    for ``_resolve_and_check`` to handle at request time.
    """
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if host in _BLOCKED_HOSTNAMES:
        return True

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return _ip_is_blocked(addr)


async def _resolve_and_check(host: str) -> None:
    """Resolve ``host`` and raise ``ScopeViolation`` if any address is blocked.

    Runs on every request (not once at startup) so a hostname whose DNS record
    is flipped to an internal IP — the DNS-rebinding case — is caught before
    the HTTP call is issued.
    """
    # Literal IPs are already handled by _is_ssrf_target; skip DNS lookup.
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if _ip_is_blocked(addr):
            raise ScopeViolation(f"Host '{host}' is a blocked address: {addr}")
        return

    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None)
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if _ip_is_blocked(addr):
            raise ScopeViolation(f"Host '{host}' resolves to a blocked address: {ip}")


class HttpProxyModule(ToolModule):
    name: ClassVar[str] = "http_proxy"
    scoping = None
    required_credentials: ClassVar[list[str]] = []  # dynamic per allowed_services

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        raw_services = config.get("allowed_services", [])
        if not raw_services:
            raise ValueError("http_proxy module requires at least one 'allowed_services' entry")

        self._services: dict[str, dict[str, Any]] = {}
        for svc in raw_services:
            name = svc["name"]
            base_url = svc["base_url"].rstrip("/")
            if _is_ssrf_target(base_url):
                raise ValueError(f"Service '{name}' has a blocked base_url: {base_url}")
            self._services[name] = {
                "base_url": base_url,
                "credential_key": svc.get("credential_key"),
            }

    def _get_service(self, service: str) -> dict[str, Any]:
        if service not in self._services:
            raise ScopeViolation(
                f"Service '{service}' is not in the allowed_services list. "
                f"Allowed: {list(self._services.keys())}"
            )
        return self._services[service]

    def _make_headers(self, service_cfg: dict[str, Any]) -> dict[str, str]:
        headers: dict[str, str] = {}
        cred_key = service_cfg.get("credential_key")
        if cred_key and cred_key in self.credentials:
            headers["Authorization"] = f"Bearer {self.credentials[cred_key]}"
        return headers

    def _build_url(self, service_cfg: dict[str, Any], path: str) -> str:
        base = service_cfg["base_url"]
        clean_path = path.lstrip("/")
        url = f"{base}/{clean_path}"
        if _is_ssrf_target(url):
            raise ScopeViolation(f"Constructed URL resolves to a blocked address: {url}")
        return url

    @staticmethod
    async def _check_host(url: str) -> None:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            raise ScopeViolation(f"URL '{url}' has no host")
        await _resolve_and_check(host)

    @tool(mode="read")
    async def get(
        self, service: str, path: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Make a GET request to an allowlisted service.

        Args:
            service: Service name from the allowed_services config.
            path: URL path (relative to the service base_url).
            params: Optional query parameters.

        Returns:
            Response body as a dict (JSON) or {"text": "..."} for non-JSON responses.
        """
        svc = self._get_service(service)
        url = self._build_url(svc, path)
        await self._check_host(url)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, params=params or {}, headers=self._make_headers(svc))
            response.raise_for_status()
        try:
            return response.json()
        except Exception:
            return {"text": response.text}

    @tool(mode="write")
    async def post(
        self, service: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Make a POST request to an allowlisted service.

        Args:
            service: Service name from the allowed_services config.
            path: URL path.
            body: Request body (sent as JSON).

        Returns:
            Response body as a dict.
        """
        svc = self._get_service(service)
        url = self._build_url(svc, path)
        await self._check_host(url)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=body or {}, headers=self._make_headers(svc))
            response.raise_for_status()
        try:
            return response.json()
        except Exception:
            return {"text": response.text}

    @tool(mode="write")
    async def put(
        self, service: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Make a PUT request to an allowlisted service.

        Args:
            service: Service name from the allowed_services config.
            path: URL path.
            body: Request body (sent as JSON).

        Returns:
            Response body as a dict.
        """
        svc = self._get_service(service)
        url = self._build_url(svc, path)
        await self._check_host(url)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.put(url, json=body or {}, headers=self._make_headers(svc))
            response.raise_for_status()
        try:
            return response.json()
        except Exception:
            return {"text": response.text}

    @tool(mode="write")
    async def delete(self, service: str, path: str) -> dict[str, Any]:
        """Make a DELETE request to an allowlisted service.

        Args:
            service: Service name from the allowed_services config.
            path: URL path.

        Returns:
            Response body as a dict, or {"status": "deleted"} for empty responses.
        """
        svc = self._get_service(service)
        url = self._build_url(svc, path)
        await self._check_host(url)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.delete(url, headers=self._make_headers(svc))
            response.raise_for_status()
        if response.content:
            try:
                return response.json()
            except Exception:
                return {"text": response.text}
        return {"status": "deleted"}
