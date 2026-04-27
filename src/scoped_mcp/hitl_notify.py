"""Notification channels for HITL approval requests.

Notifiers send a short message to an operator-facing channel (ntfy, matrix,
webhook, log) when a tool call is suspended awaiting approval.

The message body MUST go through the audit.py redaction pipeline before it
reaches the notifier — by the time a string lands here it is already
sanitised. Notifiers must not log raw argument values to any extra channel.
"""

from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable

import structlog

_log = structlog.get_logger("audit")


@runtime_checkable
class Notifier(Protocol):
    """Send a HITL notification. Implementations must not raise on transport
    failures — log and return so the approval loop continues."""

    async def notify(
        self,
        approval_id: str,
        tool_name: str,
        agent_id: str,
        agent_type: str,
        arguments_summary: dict[str, Any],
        timeout_seconds: int,
    ) -> None: ...


def _format_message(
    approval_id: str,
    tool_name: str,
    agent_id: str,
    agent_type: str,
    arguments_summary: dict[str, Any],
    timeout_seconds: int,
) -> str:
    """Build the operator-facing notification body. Inputs are pre-sanitised."""
    args_lines = "\n".join(f"  {k}: {v}" for k, v in arguments_summary.items())
    return (
        f"[scoped-mcp] Approval required\n"
        f"Agent: {agent_id} ({agent_type})\n"
        f"Tool: {tool_name}\n"
        f"Args:\n{args_lines or '  (none)'}\n"
        f"Approval ID: {approval_id}\n"
        f"Timeout: {timeout_seconds}s\n\n"
        f"Approve: scoped-mcp hitl approve {approval_id}\n"
        f"Reject:  scoped-mcp hitl reject {approval_id}"
    )


class LogNotifier:
    """Default notifier — emits a structured warning log only.

    Useful for testing, dev, and homelab setups where the operator is already
    watching the audit stream. Production deployments should prefer an
    operator-facing channel (ntfy / matrix / webhook).
    """

    async def notify(
        self,
        approval_id: str,
        tool_name: str,
        agent_id: str,
        agent_type: str,
        arguments_summary: dict[str, Any],
        timeout_seconds: int,
    ) -> None:
        _log.warning(
            "hitl_approval_required",
            approval_id=approval_id,
            tool=tool_name,
            agent_id=agent_id,
            agent_type=agent_type,
            arguments_summary=arguments_summary,
            timeout_seconds=timeout_seconds,
        )


class NtfyNotifier:
    """Send the approval message to an ntfy topic via HTTP POST.

    Requires httpx (provided by the [http] optional extra). Failures are
    logged at warning and swallowed — a notification outage cannot wedge the
    approval loop.
    """

    def __init__(self, url: str | None, topic: str) -> None:
        if not topic:
            raise ValueError("NtfyNotifier requires a non-empty topic")
        self._url = (url or "https://ntfy.sh").rstrip("/")
        self._topic = topic

    async def notify(
        self,
        approval_id: str,
        tool_name: str,
        agent_id: str,
        agent_type: str,
        arguments_summary: dict[str, Any],
        timeout_seconds: int,
    ) -> None:
        try:
            import httpx  # local import — optional [http] extra
        except ImportError:
            _log.warning(
                "hitl_notify_skipped_missing_dep",
                channel="ntfy",
                detail="httpx not installed; install scoped-mcp[http]",
            )
            return

        body = _format_message(
            approval_id, tool_name, agent_id, agent_type, arguments_summary, timeout_seconds
        )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    f"{self._url}/{self._topic}",
                    content=body.encode("utf-8"),
                    headers={
                        "Title": f"Approval required: {tool_name}",
                        "Tags": "warning,scoped-mcp",
                    },
                )
        except Exception as e:
            _log.warning(
                "hitl_notify_failed",
                channel="ntfy",
                error=type(e).__name__,
            )


class WebhookNotifier:
    """POST a JSON body to a webhook URL.

    Body schema:
        {"approval_id": str, "tool": str, "agent_id": str, "agent_type": str,
         "arguments_summary": {...}, "timeout_seconds": int, "message": str}
    """

    def __init__(self, url: str) -> None:
        if not url:
            raise ValueError("WebhookNotifier requires a non-empty url")
        self._url = url

    async def notify(
        self,
        approval_id: str,
        tool_name: str,
        agent_id: str,
        agent_type: str,
        arguments_summary: dict[str, Any],
        timeout_seconds: int,
    ) -> None:
        try:
            import httpx
        except ImportError:
            _log.warning(
                "hitl_notify_skipped_missing_dep",
                channel="webhook",
                detail="httpx not installed; install scoped-mcp[http]",
            )
            return

        payload = {
            "approval_id": approval_id,
            "tool": tool_name,
            "agent_id": agent_id,
            "agent_type": agent_type,
            "arguments_summary": arguments_summary,
            "timeout_seconds": timeout_seconds,
            "message": _format_message(
                approval_id,
                tool_name,
                agent_id,
                agent_type,
                arguments_summary,
                timeout_seconds,
            ),
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(self._url, json=payload)
        except Exception as e:
            _log.warning(
                "hitl_notify_failed",
                channel="webhook",
                error=type(e).__name__,
            )


class MatrixNotifier:
    """Send the approval message to a Matrix room.

    Requires MATRIX_HOMESERVER and MATRIX_ACCESS_TOKEN to be present in the
    process environment (same pattern as the matrix tool module — credentials
    stay outside the manifest).
    """

    def __init__(self, room: str) -> None:
        if not room:
            raise ValueError("MatrixNotifier requires a non-empty room")
        self._room = room

    async def notify(
        self,
        approval_id: str,
        tool_name: str,
        agent_id: str,
        agent_type: str,
        arguments_summary: dict[str, Any],
        timeout_seconds: int,
    ) -> None:
        import os

        homeserver = os.environ.get("MATRIX_HOMESERVER", "").rstrip("/")
        token = os.environ.get("MATRIX_ACCESS_TOKEN", "")
        if not homeserver or not token:
            _log.warning(
                "hitl_notify_skipped_missing_credentials",
                channel="matrix",
                detail="MATRIX_HOMESERVER or MATRIX_ACCESS_TOKEN unset",
            )
            return

        try:
            import httpx
        except ImportError:
            _log.warning(
                "hitl_notify_skipped_missing_dep",
                channel="matrix",
                detail="httpx not installed; install scoped-mcp[http]",
            )
            return

        body = _format_message(
            approval_id, tool_name, agent_id, agent_type, arguments_summary, timeout_seconds
        )
        url = f"{homeserver}/_matrix/client/v3/rooms/{self._room}/send/m.room.message"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    content=json.dumps({"msgtype": "m.text", "body": body}),
                )
        except Exception as e:
            _log.warning(
                "hitl_notify_failed",
                channel="matrix",
                error=type(e).__name__,
            )


def build_notifier(notify_cfg: Any) -> Notifier:
    """Construct the appropriate Notifier for the manifest's notify config.

    notify_cfg is the validated NotifyConfig pydantic model — fields are
    already required-checked before this is called.
    """
    nt = notify_cfg.type
    if nt == "log":
        return LogNotifier()
    if nt == "ntfy":
        return NtfyNotifier(url=notify_cfg.url, topic=notify_cfg.topic)
    if nt == "webhook":
        return WebhookNotifier(url=notify_cfg.url)
    if nt == "matrix":
        return MatrixNotifier(room=notify_cfg.room)
    from .exceptions import ConfigError

    raise ConfigError(f"Unknown hitl.notify.type: {nt!r}")
