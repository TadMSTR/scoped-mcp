"""Grafana module — dashboard and alert management, scoped to agent folder.

Scope: proxy-layer folder scoping. Grafana SA tokens are org-scoped (cannot be
folder-scoped at token level), so enforcement is at the proxy layer:

  1. At startup, the proxy creates or verifies the agent's folder (agent-{agent_id}).
  2. On reads: dashboard list filtered to the agent's folderUid.
  3. On writes: agent's folderUid is injected; requests specifying a different
     folderUid are rejected.
  4. On uid lookups: meta.folderUid is verified before proceeding.

Targets Grafana v12+ API. Falls back to v11 endpoints where noted.

Config:
    grafana_url (str): optional override — defaults to GRAFANA_URL credential.

Required credentials:
    GRAFANA_URL: base URL of the Grafana instance (e.g. https://grafana.example.com)
    GRAFANA_SERVICE_ACCOUNT_TOKEN: SA token with folders:read/write, dashboards:read/write
"""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from ..exceptions import ScopeViolation
from ._base import ToolModule, tool


class GrafanaModule(ToolModule):
    name: ClassVar[str] = "grafana"
    scoping = None
    required_credentials: ClassVar[list[str]] = [
        "GRAFANA_URL",
        "GRAFANA_SERVICE_ACCOUNT_TOKEN",
    ]

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        self._base_url = (
            config.get("grafana_url") or credentials["GRAFANA_URL"]
        ).rstrip("/")
        self._token = credentials["GRAFANA_SERVICE_ACCOUNT_TOKEN"]
        self._folder_title = f"agent-{agent_ctx.agent_id}"
        self._folder_uid: str | None = None  # resolved at first use

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _ensure_folder(self, client: httpx.AsyncClient) -> str:
        """Return the agent folder UID, creating the folder if it doesn't exist."""
        if self._folder_uid:
            return self._folder_uid

        # Try to find existing folder
        resp = await client.get(f"{self._base_url}/api/folders", headers=self._headers())
        resp.raise_for_status()
        for folder in resp.json():
            if folder.get("title") == self._folder_title:
                self._folder_uid = folder["uid"]
                return self._folder_uid

        # Create it
        resp = await client.post(
            f"{self._base_url}/api/folders",
            json={"title": self._folder_title},
            headers=self._headers(),
        )
        resp.raise_for_status()
        self._folder_uid = resp.json()["uid"]
        return self._folder_uid

    async def _verify_dashboard_folder(self, client: httpx.AsyncClient, uid: str) -> None:
        """Raise ScopeViolation if the dashboard is not in the agent's folder."""
        folder_uid = await self._ensure_folder(client)
        resp = await client.get(
            f"{self._base_url}/api/dashboards/uid/{uid}",
            headers=self._headers(),
        )
        resp.raise_for_status()
        data = resp.json()
        dashboard_folder = data.get("meta", {}).get("folderUid", "")
        if dashboard_folder != folder_uid:
            raise ScopeViolation(
                f"Dashboard '{uid}' is not in the agent folder '{self._folder_title}'"
            )

    @tool(mode="read")
    async def list_dashboards(self) -> list[dict[str, Any]]:
        """List dashboards in the agent's folder.

        Returns:
            List of dashboard metadata dicts.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            folder_uid = await self._ensure_folder(client)
            resp = await client.get(
                f"{self._base_url}/api/search",
                params={"type": "dash-db", "folderUIDs": folder_uid},
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    @tool(mode="read")
    async def get_dashboard(self, uid: str) -> dict[str, Any]:
        """Get a dashboard by UID (must be in the agent's folder).

        Args:
            uid: Dashboard UID.

        Returns:
            Dashboard model dict.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            await self._verify_dashboard_folder(client, uid)
            resp = await client.get(
                f"{self._base_url}/api/dashboards/uid/{uid}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    @tool(mode="read")
    async def list_datasources(self) -> list[dict[str, Any]]:
        """List available datasources (read-only metadata, org-scoped).

        Returns:
            List of datasource metadata dicts.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{self._base_url}/api/datasources",
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    @tool(mode="read")
    async def query_datasource(self, datasource: str, query: str) -> dict[str, Any]:
        """Execute a query against a named datasource.

        Args:
            datasource: Datasource name.
            query: Query expression (format depends on datasource type).

        Returns:
            Query result dict.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Get datasource UID by name
            resp = await client.get(
                f"{self._base_url}/api/datasources/name/{datasource}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            ds = resp.json()

            resp = await client.post(
                f"{self._base_url}/api/ds/query",
                json={
                    "queries": [{"datasource": {"uid": ds["uid"]}, "expr": query}],
                },
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    @tool(mode="write")
    async def create_dashboard(self, title: str, panels: list[dict[str, Any]]) -> dict[str, Any]:
        """Create a new dashboard in the agent's folder.

        Args:
            title: Dashboard title.
            panels: List of Grafana panel definitions.

        Returns:
            Created dashboard metadata.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            folder_uid = await self._ensure_folder(client)
            payload = {
                "dashboard": {
                    "id": None,
                    "uid": None,
                    "title": title,
                    "panels": panels,
                    "schemaVersion": 38,
                },
                "folderUid": folder_uid,
                "overwrite": False,
            }
            resp = await client.post(
                f"{self._base_url}/api/dashboards/db",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    @tool(mode="write")
    async def update_dashboard(self, uid: str, panels: list[dict[str, Any]]) -> dict[str, Any]:
        """Update the panels of an existing dashboard (must be in the agent's folder).

        Args:
            uid: Dashboard UID.
            panels: New panel definitions.

        Returns:
            Updated dashboard metadata.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            await self._verify_dashboard_folder(client, uid)
            folder_uid = self._folder_uid

            # Fetch current dashboard to preserve version and other fields
            resp = await client.get(
                f"{self._base_url}/api/dashboards/uid/{uid}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            existing = resp.json()
            dashboard = existing["dashboard"]
            dashboard["panels"] = panels

            payload = {
                "dashboard": dashboard,
                "folderUid": folder_uid,
                "overwrite": True,
            }
            resp = await client.post(
                f"{self._base_url}/api/dashboards/db",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()

    @tool(mode="write")
    async def delete_dashboard(self, uid: str) -> bool:
        """Delete a dashboard (must be in the agent's folder).

        Args:
            uid: Dashboard UID.

        Returns:
            True on success.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            await self._verify_dashboard_folder(client, uid)
            resp = await client.delete(
                f"{self._base_url}/api/dashboards/uid/{uid}",
                headers=self._headers(),
            )
            resp.raise_for_status()
        return True

    @tool(mode="write")
    async def create_alert_rule(self, name: str, condition: dict[str, Any]) -> dict[str, Any]:
        """Create an alert rule in the agent's folder.

        Args:
            name: Alert rule name.
            condition: Grafana alert condition dict (grafanaConditions format).

        Returns:
            Created alert rule metadata.
        """
        async with httpx.AsyncClient(timeout=15.0) as client:
            folder_uid = await self._ensure_folder(client)
            payload = {
                "title": name,
                "condition": "C",
                "data": condition.get("data", []),
                "folderUID": folder_uid,
                "ruleGroup": f"agent-{self.agent_ctx.agent_id}",
                "noDataState": "NoData",
                "execErrState": "Error",
                "for": condition.get("for", "5m"),
            }
            resp = await client.post(
                f"{self._base_url}/api/v1/provisioning/alert-rules",
                json=payload,
                headers=self._headers(),
            )
            resp.raise_for_status()
            return resp.json()
