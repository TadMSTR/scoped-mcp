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

Design:
  * Best-effort — every failure is swallowed and logged. Alerting must never crash the
    renewal loop, the auth path, or the process.
  * Vault-independent — config is read fresh from os.environ on every send.
  * Pluggable sink — send_ops_alert dispatches to every configured sink. Today only
    Matrix is wired; an ntfy fallback (SMCP-27, deferred) drops in behind this same
    interface without touching any caller.
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

# Short, fixed timeout — alerting is best-effort and must never stall a caller.
_ALERT_TIMEOUT_SECONDS = 8.0


def alerting_configured() -> bool:
    """True when at least one alert sink is fully configured from the environment."""
    return _matrix_config() is not None


def _matrix_config() -> tuple[str, str, str] | None:
    homeserver = os.environ.get(_MATRIX_HOMESERVER_ENV, "").strip()
    token = os.environ.get(_MATRIX_TOKEN_ENV, "").strip()
    room = os.environ.get(_MATRIX_ROOM_ENV, "").strip()
    if homeserver and token and room:
        return homeserver, token, room
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
    """Post an operational alert to every configured sink. Best-effort, never raises.

    Returns True if at least one sink accepted the message, False otherwise (including
    when no sink is configured — the caller/startup path warns about that separately).
    """
    body = _format_body(event, detail)
    delivered = False

    matrix = _matrix_config()
    if matrix is not None:
        homeserver, token, room = matrix
        delivered = await _send_matrix(homeserver, token, room, body) or delivered

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
