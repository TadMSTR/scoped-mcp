"""SMTP module — send email via SMTP with credential isolation.

Write-only. The 'to' address is validated against an allowlist declared in config.
The agent never receives SMTP credentials; it only specifies recipient and body.

Config:
    from_address (str): required — sender address.
    allowed_recipients (list[str]): required — list of permitted 'to' addresses.

Required credentials:
    SMTP_HOST: hostname of the SMTP server
    SMTP_PORT: port number (string, e.g. "587")
    SMTP_USER: SMTP username
    SMTP_PASSWORD: SMTP password
"""

from __future__ import annotations

from email.message import EmailMessage
from typing import ClassVar

import aiosmtplib

from ..exceptions import ScopeViolation
from ._base import ToolModule, tool


class SmtpModule(ToolModule):
    name: ClassVar[str] = "smtp"
    scoping = None
    required_credentials: ClassVar[list[str]] = [
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USER",
        "SMTP_PASSWORD",
    ]

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        self._from = config.get("from_address")
        if not self._from:
            raise ValueError("smtp module requires 'from_address' in config")
        self._allowed = set(config.get("allowed_recipients", []))
        if not self._allowed:
            raise ValueError("smtp module requires at least one 'allowed_recipients' entry")

    @tool(mode="write")
    async def send(self, to: str, subject: str, body: str) -> bool:
        """Send an email to an allowlisted recipient.

        Args:
            to: Recipient email address (must be in allowed_recipients).
            subject: Email subject line.
            body: Plain-text email body.

        Returns:
            True on success.
        """
        if to not in self._allowed:
            raise ScopeViolation(
                f"Recipient '{to}' is not in the allowed_recipients list"
            )

        msg = EmailMessage()
        msg["From"] = self._from
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)

        await aiosmtplib.send(
            msg,
            hostname=self.credentials["SMTP_HOST"],
            port=int(self.credentials["SMTP_PORT"]),
            username=self.credentials["SMTP_USER"],
            password=self.credentials["SMTP_PASSWORD"],
            start_tls=True,
        )

        return True
