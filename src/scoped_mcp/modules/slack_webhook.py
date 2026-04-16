"""Slack webhook module — send messages via an incoming webhook URL.

Write-only. No room/recipient scoping needed — one webhook URL = one channel.
Credential isolation: the agent never sees the webhook URL.

Required credentials:
    SLACK_WEBHOOK_URL: full Slack incoming webhook URL
"""

from __future__ import annotations

from typing import ClassVar

import httpx

from ._base import ToolModule, tool


class SlackWebhookModule(ToolModule):
    name: ClassVar[str] = "slack_webhook"
    scoping = None
    required_credentials: ClassVar[list[str]] = ["SLACK_WEBHOOK_URL"]

    @tool(mode="write")
    async def send(self, text: str) -> bool:
        """Send a message to the configured Slack channel via webhook.

        Args:
            text: Message text (Slack mrkdwn formatting supported).

        Returns:
            True on success.
        """
        webhook_url = self.credentials["SLACK_WEBHOOK_URL"]

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook_url, json={"text": text})
            response.raise_for_status()

        return True
