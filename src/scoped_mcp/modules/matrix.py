"""Matrix module — send messages to Matrix rooms via the client-server API.

Write-only. Room IDs are validated against an allowlist declared in config.
Uses direct httpx calls to the Matrix client-server API; does NOT depend on
matrix-nio or libolm. Only unencrypted rooms are supported in v0.1.

Matrix client-server API used:
  PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}

Config:
    allowed_rooms (list[str]): required — list of permitted room IDs.

Required credentials:
    MATRIX_HOMESERVER: base URL of the homeserver (e.g. https://matrix.example.com)
    MATRIX_ACCESS_TOKEN: access token for the sending account
"""

from __future__ import annotations

import uuid
from typing import ClassVar

import httpx

from ..exceptions import ScopeViolation
from ._base import ToolModule, tool


class MatrixModule(ToolModule):
    name: ClassVar[str] = "matrix"
    scoping = None
    required_credentials: ClassVar[list[str]] = [
        "MATRIX_HOMESERVER",
        "MATRIX_ACCESS_TOKEN",
    ]

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        self._allowed_rooms = set(config.get("allowed_rooms", []))
        if not self._allowed_rooms:
            raise ValueError("matrix module requires at least one 'allowed_rooms' entry")

    @tool(mode="write")
    async def send(self, room: str, message: str) -> bool:
        """Send a plain-text message to an allowlisted Matrix room.

        Only unencrypted rooms are supported (v0.1 limitation — no libolm dependency).

        Args:
            room: Matrix room ID (e.g. !abc123:matrix.example.com).
            message: Plain-text message body.

        Returns:
            True on success.
        """
        if room not in self._allowed_rooms:
            raise ScopeViolation(f"Room '{room}' is not in the allowed_rooms list")

        homeserver = self.credentials["MATRIX_HOMESERVER"].rstrip("/")
        token = self.credentials["MATRIX_ACCESS_TOKEN"]
        txn_id = str(uuid.uuid4()).replace("-", "")

        # URL-encode the room ID (! and : are valid but some servers are strict)
        import urllib.parse

        room_encoded = urllib.parse.quote(room, safe="")

        url = f"{homeserver}/_matrix/client/v3/rooms/{room_encoded}/send/m.room.message/{txn_id}"
        payload = {"msgtype": "m.text", "body": message}

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.put(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()

        return True
