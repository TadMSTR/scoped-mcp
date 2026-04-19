"""InfluxDB module — bucket-scoped time-series operations via httpx.

Scope: NamespaceScope on bucket names. Every tool takes ``bucket`` as an explicit
parameter; the module validates it against the agent's allowlist before any HTTP
call. No free-form Flux is ever accepted — queries are built from structured
filter input and validated tokens.

Security model (2026-04-16 audit, findings H1 / M2 / M3):
- ``query()`` takes a list of structured filter dicts, not a raw Flux predicate.
  Each filter's field name is matched against a Flux identifier regex, its op
  against a closed set, and its value is rendered by type (strings go through
  ``json.dumps`` for quote-safe escaping).
- Time range inputs (``range_start`` / ``range_stop``) are matched against a
  validator that accepts RFC3339 literals, Flux duration literals, and ``now()``.
- Measurement names go through ``_MEASUREMENT_PATTERN`` wherever they're used.
- ``write_points`` escapes tag keys, tag values, and field keys per the InfluxDB
  line-protocol spec and rejects any value containing newline / carriage return.

Config:
    org (str): required — InfluxDB organization name.
    buckets (list[str]): required — allowlisted bucket names for this agent.

Required credentials:
    INFLUXDB_URL: base URL (e.g. https://influxdb.example.com)
    INFLUXDB_TOKEN: Read/Write token scoped to the allowlisted buckets
    INFLUXDB_ORG: organization name (overrides config.org if set)
"""

from __future__ import annotations

import json
from typing import Any, ClassVar, Literal

import httpx

from ..exceptions import ScopeViolation
from ..scoping import NamespaceScope
from ._base import ToolModule, tool
from ._influxdb_validators import (
    _LOGICAL_OPS,
    _escape_tag,
    _parse_flux_csv,
    _render_field_value,
    _render_filter,
    _validate_identifier,
    _validate_measurement,
    _validate_time,
)


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
        self._org = credentials.get("INFLUXDB_ORG") or config.get("org")
        if not self._org:
            raise ValueError("influxdb module requires 'org' in config or INFLUXDB_ORG credential")

        raw_buckets = config.get("buckets", [])
        if not raw_buckets:
            raise ValueError("influxdb module requires at least one 'buckets' entry in config")

        self._allowed_buckets: set[str] = set(raw_buckets)
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

    def _build_query(
        self,
        bucket: str,
        filters: list[dict[str, Any]],
        range_start: str,
        range_stop: str,
        logical_op: str = "and",
    ) -> str:
        """Build a Flux query from structured filter input. No agent-controlled
        string is interpolated into the Flux source — every segment is either a
        validated token or a value rendered through ``_render_filter_value``.
        """
        if not isinstance(filters, list) or not filters:
            raise ValueError("filters must be a non-empty list of {field, op, value} dicts")
        if logical_op not in _LOGICAL_OPS:
            raise ValueError(
                f"logical_op {logical_op!r} not allowed. Allowed: {sorted(_LOGICAL_OPS)}"
            )

        rendered = [_render_filter(f) for f in filters]
        filter_expr = f" {logical_op} ".join(rendered)
        start = _validate_time(range_start)
        stop = _validate_time(range_stop)
        return (
            f"from(bucket: {json.dumps(bucket)})\n"
            f"  |> range(start: {start}, stop: {stop})\n"
            f"  |> filter(fn: (r) => {filter_expr})"
        )

    @tool(mode="read")
    async def query(
        self,
        bucket: str,
        filters: list[dict[str, Any]],
        range_start: str = "-1h",
        range_stop: str = "now()",
        logical_op: Literal["and", "or"] = "and",
    ) -> list[dict[str, Any]]:
        """Query time-series data from an allowlisted bucket.

        Args:
            bucket: Bucket name (must be in config.buckets).
            filters: Non-empty list of filter dicts. Each dict has:
                - ``field``: Flux identifier (e.g. "_measurement", "host").
                - ``op``: one of ``==``, ``!=``, ``<``, ``<=``, ``>``, ``>=``,
                  ``=~``, ``!~``.
                - ``value``: string / int / float / bool. Strings are
                  JSON-escaped automatically.
            range_start: RFC3339, Flux duration (e.g. ``-1h``), or ``now()``.
                Defaults to ``-1h``.
            range_stop: same accepted forms. Defaults to ``now()``.
            logical_op: how to combine filters: ``and`` or ``or``. Defaults
                to ``and``.

        Returns:
            List of data point dicts.
        """
        self._validate_bucket(bucket)
        flux = self._build_query(bucket, filters, range_start, range_stop, logical_op)

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/v2/query",
                params={"org": self._org},
                content=flux,
                headers={**self._headers(), "Content-Type": "application/vnd.flux"},
            )
            resp.raise_for_status()
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
            'import "influxdata/influxdb/schema"\n'
            f"schema.measurements(bucket: {json.dumps(bucket)})"
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
            measurement: Measurement name (strictly validated).

        Returns:
            Dict with "fields" and "tags" lists.
        """
        self._validate_bucket(bucket)
        _validate_measurement(measurement)
        predicate = f"(r) => r._measurement == {json.dumps(measurement)}"
        flux_fields = (
            'import "influxdata/influxdb/schema"\n'
            f"schema.fieldKeys(bucket: {json.dumps(bucket)}, predicate: {predicate})"
        )
        flux_tags = (
            'import "influxdata/influxdb/schema"\n'
            f"schema.tagKeys(bucket: {json.dumps(bucket)}, predicate: {predicate})"
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
            measurement: Measurement name (strictly validated).
            points: List of dicts with "tags" (dict), "fields" (dict; non-empty),
                and optional "time" (int ns).

        Returns:
            True on success.
        """
        self._validate_bucket(bucket)
        _validate_measurement(measurement)

        if not isinstance(points, list) or not points:
            raise ValueError("points must be a non-empty list")

        lines: list[str] = []
        escaped_measurement = _escape_tag(measurement, kind="measurement")
        for i, point in enumerate(points):
            if not isinstance(point, dict):
                raise ValueError(f"points[{i}] must be a dict")

            fields_in = point.get("fields", {})
            if not isinstance(fields_in, dict) or not fields_in:
                raise ValueError(f"points[{i}].fields must be a non-empty dict")

            tags_in = point.get("tags", {})
            if not isinstance(tags_in, dict):
                raise ValueError(f"points[{i}].tags must be a dict")

            tag_parts: list[str] = []
            for k, v in tags_in.items():
                _validate_identifier(k, kind="tag key")
                tag_parts.append(f"{k}={_escape_tag(str(v), kind='tag value')}")

            field_parts: list[str] = []
            for k, v in fields_in.items():
                _validate_identifier(k, kind="field key")
                field_parts.append(f"{k}={_render_field_value(v)}")

            tag_str = f",{','.join(tag_parts)}" if tag_parts else ""
            ts = ""
            if "time" in point:
                t = point["time"]
                if not isinstance(t, int):
                    raise ValueError(f"points[{i}].time must be an int (ns)")
                ts = f" {t}"
            lines.append(f"{escaped_measurement}{tag_str} {','.join(field_parts)}{ts}")

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
            measurement: Measurement name (strictly validated).
            start: Start time (RFC3339, duration, or ``now()``).
            stop: Stop time (same accepted forms).

        Returns:
            True on success.
        """
        self._validate_bucket(bucket)
        _validate_measurement(measurement)
        _validate_time(start)
        _validate_time(stop)

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
