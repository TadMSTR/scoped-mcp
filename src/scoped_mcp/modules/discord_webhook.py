"""Discord webhook module — send messages via a Discord webhook URL.

Write-only. Same pattern as slack_webhook — one URL = one channel.
Credential isolation: the agent never sees the webhook URL.

Required credentials:
    DISCORD_WEBHOOK_URL: full Discord webhook URL
"""

from __future__ import annotations

from typing import ClassVar

import httpx

from ._base import ToolModule, tool


class DiscordWebhookModule(ToolModule):
    name: ClassVar[str] = "discord_webhook"
    scoping = None
    required_credentials: ClassVar[list[str]] = ["DISCORD_WEBHOOK_URL"]

    @tool(mode="write")
    async def send(self, content: str) -> bool:
        """Send a message to the configured Discord channel via webhook.

        Args:
            content: Message content (up to 2000 characters per Discord limits).

        Returns:
            True on success.
        """
        if len(content) > 2000:
            content = content[:1997] + "..."

        webhook_url = self.credentials["DISCORD_WEBHOOK_URL"]

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook_url, json={"content": content})
            response.raise_for_status()

        return True
