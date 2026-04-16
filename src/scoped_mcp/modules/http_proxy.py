"""Generic HTTP API proxy with service allowlist and credential injection.

Scope: requests are restricted to declared services only. Unlisted services
and internal-looking URLs (SSRF prevention) are rejected before any I/O.

Config:
    allowed_services (list[dict]): each entry has:
        name (str): service identifier used in tool calls.
        base_url (str): base URL for this service.
        credential_key (str, optional): credential key to inject as a Bearer token.

Required credentials: per service — keys named in allowed_services[*].credential_key.
"""

from __future__ import annotations

import ipaddress
from typing import Any, ClassVar
from urllib.parse import urlparse

import httpx

from ..exceptions import ScopeViolation
from ._base import ToolModule, tool

# Internal/link-local address ranges that must not be reachable via http_proxy.
_BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal", "169.254.169.254"}


def _is_ssrf_target(url: str) -> bool:
    """Return True if the URL resolves to an address that should be blocked."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if host in _BLOCKED_HOSTNAMES:
        return True

    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in _BLOCKED_IP_NETWORKS)
    except ValueError:
        # Not an IP address — hostname. Block obvious internal patterns.
        # We can't do DNS resolution here without an async context; operators
        # should run scoped-mcp in a network-restricted environment for defense
        # in depth.
        return False


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

    @tool(mode="read")
    async def get(self, service: str, path: str, params: dict[str, Any] = {}) -> dict[str, Any]:
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
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, params=params, headers=self._make_headers(svc))
            response.raise_for_status()
        try:
            return response.json()
        except Exception:
            return {"text": response.text}

    @tool(mode="write")
    async def post(self, service: str, path: str, body: dict[str, Any] = {}) -> dict[str, Any]:
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
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=body, headers=self._make_headers(svc))
            response.raise_for_status()
        try:
            return response.json()
        except Exception:
            return {"text": response.text}

    @tool(mode="write")
    async def put(self, service: str, path: str, body: dict[str, Any] = {}) -> dict[str, Any]:
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
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.put(url, json=body, headers=self._make_headers(svc))
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
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.delete(url, headers=self._make_headers(svc))
            response.raise_for_status()
        if response.content:
            try:
                return response.json()
            except Exception:
                return {"text": response.text}
        return {"status": "deleted"}
