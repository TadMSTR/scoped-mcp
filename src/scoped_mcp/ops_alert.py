"""Vault-independent operational alerting for scoped-mcp.

Posts critical operational events — Vault credential degradation, 401 bursts — to a
notification channel configured entirely from plain environment variables, never from
the Vault credential bundle and never through the agent's per-manifest notification
*tool* modules. That independence is the whole point: the alert must still fire when
Vault (the dependency that broke) is the broken thing, and when a 401'd client can't
reach any tool at all.

Primary sink — Matrix (the ``#alerts`` room):

    SCOPED_MCP_ALERT_MATRIX_HOMESERVER   base URL, e.g. https://matrix.example.com
    SCOPED_MCP_ALERT_MATRIX_TOKEN        access token for the alerting account
    SCOPED_MCP_ALERT_MATRIX_ROOM         room id, e.g. !abc123:example.com

Fallback sink — ntfy (SMCP-27), fires only when Matrix is down or unconfigured:

    SCOPED_MCP_ALERT_NTFY_URL            full topic URL, e.g. https://ntfy.example.com/forge
    SCOPED_MCP_ALERT_NTFY_TOKEN          optional bearer/access token for the topic

Design:
  * Best-effort — every failure is swallowed and logged. Alerting must never crash the
    renewal loop, the auth path, or the process.
  * Vault-independent — config is read fresh from os.environ on every send, and no sink
    touches the Vault credential bundle. That is the whole point: the alert must fire even
    when Vault (the broken dependency) is unreachable.
  * Matrix primary, ntfy fallback — send_ops_alert tries Matrix first; ntfy fires *only*
    when the Matrix send fails or Matrix is unconfigured. This is a fallback, not fan-out:
    on the happy path (Matrix accepted) ntfy is never contacted. Deploying ntfy on a host
    external to forge keeps the fallback path alive even when forge itself is degraded.
  * Fire-once-per-transition — the healthy<->degraded dedup lives in the caller
    (registry.py), keyed on the transition, not the sink, so one transition yields one
    alert overall regardless of which sink delivered it.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import structlog

_log = structlog.get_logger("ops")

_MATRIX_HOMESERVER_ENV = "SCOPED_MCP_ALERT_MATRIX_HOMESERVER"
_MATRIX_TOKEN_ENV = "SCOPED_MCP_ALERT_MATRIX_TOKEN"
_MATRIX_ROOM_ENV = "SCOPED_MCP_ALERT_MATRIX_ROOM"

_NTFY_URL_ENV = "SCOPED_MCP_ALERT_NTFY_URL"
_NTFY_TOKEN_ENV = "SCOPED_MCP_ALERT_NTFY_TOKEN"

# Short, fixed timeout — alerting is best-effort and must never stall a caller.
_ALERT_TIMEOUT_SECONDS = 8.0


def alerting_configured() -> bool:
    """True when at least one alert sink is fully configured from the environment."""
    return _matrix_config() is not None or _ntfy_config() is not None


def _matrix_config() -> tuple[str, str, str] | None:
    homeserver = os.environ.get(_MATRIX_HOMESERVER_ENV, "").strip()
    token = os.environ.get(_MATRIX_TOKEN_ENV, "").strip()
    room = os.environ.get(_MATRIX_ROOM_ENV, "").strip()
    if homeserver and token and room:
        return homeserver, token, room
    return None


def _ntfy_config() -> tuple[str, str] | None:
    """Return (topic_url, token) for the ntfy fallback sink, or None if unconfigured.

    Only the topic URL is required; the token is optional (unauthenticated topics send
    without an Authorization header). Vault-independent — read fresh from os.environ.
    """
    url = os.environ.get(_NTFY_URL_ENV, "").strip()
    token = os.environ.get(_NTFY_TOKEN_ENV, "").strip()
    if url:
        return url, token
    return None


def _format_body(event: str, detail: dict[str, Any]) -> str:
    """Render a compact, human-readable alert body.

    Detail values are expected to be booleans/counts/ids — never secrets. Callers
    are responsible for not passing token or lease strings.
    """
    lines = [f"[scoped-mcp] {event}"]
    for key, value in detail.items():
        lines.append(f"  {key}: {value}")
    return "\n".join(lines)


async def send_ops_alert(event: str, detail: dict[str, Any]) -> bool:
    """Post an operational alert. Matrix primary, ntfy fallback. Best-effort, never raises.

    Delivery order: try Matrix first; only if the Matrix send fails or Matrix is
    unconfigured, fall back to ntfy. This is a fallback, not fan-out — when Matrix
    accepts the message, ntfy is never contacted.

    Returns True if a sink accepted the message, False otherwise (including when no sink
    is configured — the caller/startup path warns about that separately).
    """
    body = _format_body(event, detail)
    delivered = False

    matrix = _matrix_config()
    if matrix is not None:
        homeserver, token, room = matrix
        delivered = await _send_matrix(homeserver, token, room, body)

    # Fallback: Matrix down or unconfigured. ntfy is deliberately independent of forge/Vault
    # so it still fires when those are the broken dependency.
    if not delivered:
        ntfy = _ntfy_config()
        if ntfy is not None:
            url, token = ntfy
            delivered = await _send_ntfy(url, token, event, body)

    if not delivered:
        _log.warning("ops_alert_not_delivered", alert_event=event)
    return delivered


async def _send_matrix(homeserver: str, token: str, room: str, body: str) -> bool:
    """Send a plain-text message to a Matrix room via the client-server API.

    Uses a direct httpx call (no matrix-nio / libolm) — unencrypted rooms only, which
    matches the existing matrix tool module. Swallows and logs every failure.
    """
    try:
        import httpx  # optional [http] extra
    except ImportError:
        _log.warning("ops_alert_matrix_unavailable", reason="httpx_not_installed")
        return False

    import urllib.parse

    homeserver = homeserver.rstrip("/")
    room_encoded = urllib.parse.quote(room, safe="")
    txn_id = uuid.uuid4().hex
    url = f"{homeserver}/_matrix/client/v3/rooms/{room_encoded}/send/m.room.message/{txn_id}"
    payload = {"msgtype": "m.text", "body": body}

    try:
        async with httpx.AsyncClient(timeout=_ALERT_TIMEOUT_SECONDS) as client:
            response = await client.put(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
        return True
    except Exception as exc:
        # Never let an alert-send failure propagate into the renewal/auth path.
        _log.warning("ops_alert_matrix_failed", error=type(exc).__name__)
        return False


async def _send_ntfy(url: str, token: str, event: str, body: str) -> bool:
    """POST an alert to an ntfy topic URL. Swallows and logs every failure.

    ``url`` is the full topic URL (e.g. https://ntfy.example.com/forge). The event goes
    in the ntfy ``Title`` header and the formatted body is the message payload. When
    ``token`` is set it is sent as a bearer token for authenticated topics.
    """
    try:
        import httpx  # optional [http] extra
    except ImportError:
        _log.warning("ops_alert_ntfy_unavailable", reason="httpx_not_installed")
        return False

    # Strip control chars from the header value — defense-in-depth; httpx/h11 reject CRLF.
    safe_title = f"scoped-mcp: {event}".replace("\r", "").replace("\n", " ")[:250]
    headers = {"Title": safe_title, "Priority": "high", "Tags": "rotating_light"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with httpx.AsyncClient(timeout=_ALERT_TIMEOUT_SECONDS) as client:
            response = await client.post(url, content=body.encode("utf-8"), headers=headers)
            response.raise_for_status()
        return True
    except Exception as exc:
        # Never let an alert-send failure propagate into the renewal/auth path.
        _log.warning("ops_alert_ntfy_failed", error=type(exc).__name__)
        return False
