"""ntfy module — push notifications to an ntfy topic.

Write-only. No resource scoping needed — credential isolation is the protection:
the agent never sees the ntfy URL or token; it only calls send().

Config:
    topic (str): required — topic name. Supports {agent_id} template.
    max_priority (str): optional — cap on priority level. Default: "urgent".
                        Values: "min", "low", "default", "high", "urgent".

Required credentials:
    NTFY_URL: base URL of the ntfy server (e.g. https://ntfy.example.com)
    NTFY_TOKEN: optional bearer token for authenticated topics (set to empty string if not needed)
"""

from __future__ import annotations

from typing import ClassVar

import httpx

from ._base import ToolModule, tool

_PRIORITY_LEVELS = ["min", "low", "default", "high", "urgent"]


class NtfyModule(ToolModule):
    name: ClassVar[str] = "ntfy"
    scoping = None
    required_credentials: ClassVar[list[str]] = ["NTFY_URL"]

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        topic_template = config.get("topic", "agents-{agent_id}")
        self._topic = topic_template.format(agent_id=agent_ctx.agent_id)
        self._max_priority = config.get("max_priority", "urgent")
        if self._max_priority not in _PRIORITY_LEVELS:
            raise ValueError(f"Invalid max_priority: {self._max_priority!r}")

    def _cap_priority(self, priority: str) -> str:
        """Clamp the requested priority to max_priority."""
        try:
            requested_idx = _PRIORITY_LEVELS.index(priority)
            max_idx = _PRIORITY_LEVELS.index(self._max_priority)
            return _PRIORITY_LEVELS[min(requested_idx, max_idx)]
        except ValueError:
            return "default"

    @tool(mode="write")
    async def send(
        self, title: str, message: str, priority: str = "default", tags: str = ""
    ) -> bool:
        """Send a push notification to the configured ntfy topic.

        Args:
            title: Notification title.
            message: Notification body.
            priority: One of min, low, default, high, urgent. Capped by config.
            tags: Comma-separated ntfy tags (e.g. "warning,robot").

        Returns:
            True on success.
        """
        url = self.credentials["NTFY_URL"].rstrip("/")
        token = self.credentials.get("NTFY_TOKEN", "")
        capped = self._cap_priority(priority)

        # Strip control chars defense-in-depth — httpx/h11 also reject CRLF in headers.
        safe_title = title.replace("\r", "").replace("\n", " ")[:250]
        safe_tags = tags.replace("\r", "").replace("\n", " ")[:250] if tags else ""

        headers = {
            "Title": safe_title,
            "Priority": capped,
        }
        if safe_tags:
            headers["Tags"] = safe_tags
        if token:
            headers["Authorization"] = f"Bearer {token}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(f"{url}/{self._topic}", content=message, headers=headers)
            response.raise_for_status()

        return True
