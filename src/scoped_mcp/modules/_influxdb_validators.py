"""Validators, constants, and helpers for the InfluxDB module.

Extracted from influxdb.py to keep that file under 300 LOC. These are
private (_-prefixed) — do not re-export from __init__.py.
"""

from __future__ import annotations

import json
import re
from typing import Any

_FLUX_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MEASUREMENT_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
_DURATION = re.compile(r"^-?\d+(ns|us|µs|ms|s|m|h|d|w|mo|y)$")

_ALLOWED_OPS: frozenset[str] = frozenset({"==", "!=", "<", "<=", ">", ">=", "=~", "!~"})
_LOGICAL_OPS: frozenset[str] = frozenset({"and", "or"})


def _validate_measurement(value: str) -> str:
    if not isinstance(value, str) or not _MEASUREMENT_PATTERN.match(value):
        raise ValueError(
            f"Invalid measurement name: {value!r}. Must match {_MEASUREMENT_PATTERN.pattern}"
        )
    return value


def _validate_identifier(value: str, kind: str = "identifier") -> str:
    if not isinstance(value, str) or not _FLUX_IDENT.match(value):
        raise ValueError(f"Invalid {kind}: {value!r}. Must match {_FLUX_IDENT.pattern}")
    return value


def _validate_time(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Invalid time value: {value!r}")
    v = value.strip()
    if v == "now()":
        return v
    if _RFC3339.match(v) or _DURATION.match(v):
        return v
    raise ValueError(
        f"Invalid time value: {value!r}. Expected RFC3339, a duration like -1h, or now()."
    )


def _render_filter_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    raise ValueError(f"Unsupported filter value type: {type(value).__name__}")


def _render_filter(f: dict[str, Any]) -> str:
    if not isinstance(f, dict):
        raise ValueError(f"Each filter must be a dict, got {type(f).__name__}")
    field = f.get("field")
    op = f.get("op")
    value = f.get("value")
    if field is None or op is None or "value" not in f:
        raise ValueError(f"Filter missing required keys (field, op, value): {f!r}")
    _validate_identifier(field, kind="filter field")
    if op not in _ALLOWED_OPS:
        raise ValueError(f"Filter op {op!r} not allowed. Allowed: {sorted(_ALLOWED_OPS)}")
    return f"r.{field} {op} {_render_filter_value(value)}"


# Line-protocol escaping per
# https://docs.influxdata.com/influxdb/v2/reference/syntax/line-protocol/
def _escape_tag(value: str, kind: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Line-protocol {kind} must be a string, got {type(value).__name__}")
    if "\n" in value or "\r" in value:
        raise ValueError(f"Line-protocol {kind} must not contain newline/carriage return")
    return value.replace("\\", "\\\\").replace(",", "\\,").replace("=", "\\=").replace(" ", "\\ ")


def _render_field_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return f"{value}i"
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        if "\n" in value or "\r" in value:
            raise ValueError("Field string value must not contain newline/carriage return")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise ValueError(f"Unsupported field value type: {type(value).__name__}")


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
            rows.append(dict(zip(headers, parts, strict=False)))

    return rows
