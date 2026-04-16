"""InfluxDB module — bucket-scoped time-series operations via httpx.

Scope: NamespaceScope on bucket names. Every tool takes `bucket` as an explicit
parameter; the module validates it against the agent's allowlist before building
any Flux query. No free-form Flux is accepted — queries are built from a proxy
template using a restricted predicate parameter.

Defense in depth: proxy-layer bucket allowlist + operator-provisioned bucket-scoped
Read/Write tokens (InfluxDB 2.x supports this natively).

Config:
    org (str): required — InfluxDB organization name.
    buckets (list[str]): required — allowlisted bucket names for this agent.

Required credentials:
    INFLUXDB_URL: base URL (e.g. https://influxdb.example.com)
    INFLUXDB_TOKEN: Read/Write token scoped to the allowlisted buckets
    INFLUXDB_ORG: organization name (overrides config.org if set)
"""

from __future__ import annotations

from typing import Any, ClassVar

import httpx

from ..exceptions import ScopeViolation
from ..scoping import NamespaceScope
from ._base import ToolModule, tool


class InfluxDBModule(ToolModule):
    name: ClassVar[str] = "influxdb"
    scoping: ClassVar[NamespaceScope] = NamespaceScope()
    required_credentials: ClassVar[list[str]] = [
        "INFLUXDB_URL",
        "INFLUXDB_TOKEN",
    ]

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        self._base_url = credentials["INFLUXDB_URL"].rstrip("/")
        self._token = credentials["INFLUXDB_TOKEN"]
        self._org = (
            credentials.get("INFLUXDB_ORG") or config.get("org")
        )
        if not self._org:
            raise ValueError("influxdb module requires 'org' in config or INFLUXDB_ORG credential")

        raw_buckets = config.get("buckets", [])
        if not raw_buckets:
            raise ValueError("influxdb module requires at least one 'buckets' entry in config")

        # Bucket allowlist — namespaced with agent_id prefix
        self._allowed_buckets: set[str] = set(raw_buckets)
        # Track runtime-created buckets (prefixed at creation time)
        self._runtime_buckets: set[str] = set()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Token {self._token}",
            "Content-Type": "application/json",
        }

    def _validate_bucket(self, bucket: str) -> None:
        """Raise ScopeViolation if bucket is not in the allowlist."""
        if bucket not in self._allowed_buckets and bucket not in self._runtime_buckets:
            raise ScopeViolation(
                f"Bucket '{bucket}' is not in the allowlisted buckets for this agent. "
                f"Allowed: {sorted(self._allowed_buckets)}"
            )

    def _build_query(self, bucket: str, predicate: str, range_start: str, range_stop: str) -> str:
        """Build a Flux query from a template. No free-form Flux accepted."""
        # predicate is a filter expression only, e.g. 'r._measurement == "cpu"'
        # It is inserted into a fixed template — agents cannot inject range() or other clauses.
        return (
            f'from(bucket: "{bucket}")\n'
            f'  |> range(start: {range_start}, stop: {range_stop})\n'
            f'  |> filter(fn: (r) => {predicate})'
        )

    @tool(mode="read")
    async def query(
        self,
        bucket: str,
        predicate: str,
        range_start: str = "-1h",
        range_stop: str = "now()",
    ) -> list[dict[str, Any]]:
        """Query time-series data from an allowlisted bucket.

        Args:
            bucket: Bucket name (must be in config.buckets).
            predicate: Flux filter predicate (e.g. 'r._measurement == "cpu"').
                       Only filter expressions are accepted — not full Flux queries.
            range_start: Start of the time range (default: -1h).
            range_stop: End of the time range (default: now()).

        Returns:
            List of data point dicts.
        """
        self._validate_bucket(bucket)
        flux = self._build_query(bucket, predicate, range_start, range_stop)

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/v2/query",
                params={"org": self._org},
                content=flux,
                headers={**self._headers(), "Content-Type": "application/vnd.flux"},
            )
            resp.raise_for_status()
            # Parse annotated CSV response
            return _parse_flux_csv(resp.text)

    @tool(mode="read")
    async def list_measurements(self, bucket: str) -> list[str]:
        """List measurement names in an allowlisted bucket.

        Args:
            bucket: Bucket name.

        Returns:
            List of measurement names.
        """
        self._validate_bucket(bucket)
        flux = (
            f'import "influxdata/influxdb/schema"\n'
            f'schema.measurements(bucket: "{bucket}")'
        )
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/v2/query",
                params={"org": self._org},
                content=flux,
                headers={**self._headers(), "Content-Type": "application/vnd.flux"},
            )
            resp.raise_for_status()
            rows = _parse_flux_csv(resp.text)
            return [r.get("_value", "") for r in rows if r.get("_value")]

    @tool(mode="read")
    async def get_schema(self, bucket: str, measurement: str) -> dict[str, Any]:
        """Get field keys and tag keys for a measurement.

        Args:
            bucket: Bucket name.
            measurement: Measurement name.

        Returns:
            Dict with "fields" and "tags" lists.
        """
        self._validate_bucket(bucket)
        flux_fields = (
            f'import "influxdata/influxdb/schema"\n'
            f'schema.fieldKeys(bucket: "{bucket}", predicate: (r) => r._measurement == "{measurement}")'
        )
        flux_tags = (
            f'import "influxdata/influxdb/schema"\n'
            f'schema.tagKeys(bucket: "{bucket}", predicate: (r) => r._measurement == "{measurement}")'
        )
        async with httpx.AsyncClient(timeout=15.0) as client:
            r_fields = await client.post(
                f"{self._base_url}/api/v2/query",
                params={"org": self._org},
                content=flux_fields,
                headers={**self._headers(), "Content-Type": "application/vnd.flux"},
            )
            r_tags = await client.post(
                f"{self._base_url}/api/v2/query",
                params={"org": self._org},
                content=flux_tags,
                headers={**self._headers(), "Content-Type": "application/vnd.flux"},
            )
        r_fields.raise_for_status()
        r_tags.raise_for_status()
        fields = [r.get("_value") for r in _parse_flux_csv(r_fields.text) if r.get("_value")]
        tags = [r.get("_value") for r in _parse_flux_csv(r_tags.text) if r.get("_value")]
        return {"fields": fields, "tags": tags}

    @tool(mode="write")
    async def write_points(
        self,
        bucket: str,
        measurement: str,
        points: list[dict[str, Any]],
    ) -> bool:
        """Write data points to an allowlisted bucket using Line Protocol.

        Args:
            bucket: Bucket name.
            measurement: Measurement name.
            points: List of dicts with "tags" (dict), "fields" (dict), and optional "time" (int ns).

        Returns:
            True on success.
        """
        self._validate_bucket(bucket)
        lines = []
        for point in points:
            tags = ",".join(f"{k}={v}" for k, v in point.get("tags", {}).items())
            fields = ",".join(f'{k}={v}' for k, v in point.get("fields", {}).items())
            tag_str = f",{tags}" if tags else ""
            ts = f" {point['time']}" if "time" in point else ""
            lines.append(f"{measurement}{tag_str} {fields}{ts}")

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/v2/write",
                params={"org": self._org, "bucket": bucket, "precision": "ns"},
                content="\n".join(lines),
                headers={**self._headers(), "Content-Type": "text/plain; charset=utf-8"},
            )
            resp.raise_for_status()
        return True

    @tool(mode="write")
    async def create_bucket(self, name: str, retention_days: int = 30) -> bool:
        """Create a new bucket with the agent's namespace prefix.

        The bucket name is automatically prefixed with '{agent_id}-'.

        Args:
            name: Bucket name suffix (prefix is added automatically).
            retention_days: Retention period in days.

        Returns:
            True on success.
        """
        prefixed_name = f"{self.agent_ctx.agent_id}-{name}"
        retention_seconds = retention_days * 86400

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/v2/buckets",
                json={
                    "name": prefixed_name,
                    "orgID": await self._get_org_id(client),
                    "retentionRules": [{"type": "expire", "everySeconds": retention_seconds}],
                },
                headers=self._headers(),
            )
            resp.raise_for_status()

        self._runtime_buckets.add(prefixed_name)
        return True

    @tool(mode="write")
    async def delete_points(
        self,
        bucket: str,
        measurement: str,
        start: str,
        stop: str,
    ) -> bool:
        """Delete data points from an allowlisted bucket.

        Args:
            bucket: Bucket name.
            measurement: Measurement name to delete from.
            start: Start time in RFC3339 format.
            stop: Stop time in RFC3339 format.

        Returns:
            True on success.
        """
        self._validate_bucket(bucket)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/v2/delete",
                params={"org": self._org, "bucket": bucket},
                json={
                    "start": start,
                    "stop": stop,
                    "predicate": f'_measurement="{measurement}"',
                },
                headers=self._headers(),
            )
            resp.raise_for_status()
        return True

    async def _get_org_id(self, client: httpx.AsyncClient) -> str:
        """Resolve org name to org ID."""
        resp = await client.get(
            f"{self._base_url}/api/v2/orgs",
            params={"org": self._org},
            headers=self._headers(),
        )
        resp.raise_for_status()
        orgs = resp.json().get("orgs", [])
        if not orgs:
            raise ValueError(f"Organization '{self._org}' not found in InfluxDB")
        return orgs[0]["id"]


def _parse_flux_csv(csv_text: str) -> list[dict[str, Any]]:
    """Parse annotated CSV returned by the InfluxDB v2 query API."""
    rows: list[dict[str, Any]] = []
    headers: list[str] = []

    for line in csv_text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if not headers:
            headers = parts
            continue
        if len(parts) >= len(headers):
            rows.append(dict(zip(headers, parts)))

    return rows
