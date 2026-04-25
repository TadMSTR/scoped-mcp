"""Tests for notification modules — credential isolation, recipient/room validation.

All HTTP calls use respx (httpx mock backend). No real SMTP/ntfy/Slack/Discord
connections are made during tests. Matrix tests live in test_matrix.py.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.discord_webhook import DiscordWebhookModule
from scoped_mcp.modules.ntfy import NtfyModule
from scoped_mcp.modules.slack_webhook import SlackWebhookModule

# ── NtfyModule ────────────────────────────────────────────────────────────────


@pytest.fixture
def ntfy_module(agent_ctx: AgentContext) -> NtfyModule:
    return NtfyModule(
        agent_ctx=agent_ctx,
        credentials={"NTFY_URL": "http://ntfy.test"},
        config={"topic": "test-topic", "max_priority": "high"},
    )


@pytest.mark.asyncio
@respx.mock
async def test_ntfy_send_success(ntfy_module: NtfyModule) -> None:
    respx.post("http://ntfy.test/test-topic").mock(return_value=Response(200))
    result = await ntfy_module.send(title="Hello", message="World")
    assert result is True


@pytest.mark.asyncio
@respx.mock
async def test_ntfy_priority_capped(ntfy_module: NtfyModule) -> None:
    """Priority 'urgent' should be capped to 'high' per config."""
    route = respx.post("http://ntfy.test/test-topic").mock(return_value=Response(200))
    await ntfy_module.send(title="Alert", message="msg", priority="urgent")
    assert route.called
    sent_priority = route.calls[0].request.headers.get("Priority")
    assert sent_priority == "high"


@pytest.mark.asyncio
@respx.mock
async def test_ntfy_topic_uses_agent_id(agent_ctx: AgentContext) -> None:
    """Topic template {agent_id} should be rendered."""
    mod = NtfyModule(
        agent_ctx=agent_ctx,
        credentials={"NTFY_URL": "http://ntfy.test"},
        config={"topic": "agents-{agent_id}"},
    )
    route = respx.post("http://ntfy.test/agents-test-agent-1").mock(return_value=Response(200))
    await mod.send(title="t", message="m")
    assert route.called


def test_ntfy_invalid_max_priority(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="max_priority"):
        NtfyModule(
            agent_ctx=agent_ctx,
            credentials={"NTFY_URL": "http://ntfy.test"},
            config={"max_priority": "critical"},  # not a valid level
        )


def test_ntfy_credential_not_exposed_in_config(ntfy_module: NtfyModule) -> None:
    """Credentials must not appear in the module's config dict."""
    assert "NTFY_URL" not in ntfy_module.config
    assert "NTFY_TOKEN" not in ntfy_module.config


def test_ntfy_declares_ntfy_token_as_optional() -> None:
    assert "NTFY_TOKEN" in NtfyModule.optional_credentials


@pytest.mark.asyncio
@respx.mock
async def test_ntfy_attaches_bearer_when_token_present(agent_ctx: AgentContext) -> None:
    """L2: when NTFY_TOKEN is supplied, send() must attach Authorization header."""
    mod = NtfyModule(
        agent_ctx=agent_ctx,
        credentials={"NTFY_URL": "http://ntfy.test", "NTFY_TOKEN": "tk-ntfy-example"},
        config={"topic": "t"},
    )
    route = respx.post("http://ntfy.test/t").mock(return_value=Response(200))
    await mod.send(title="x", message="y")
    auth = route.calls[0].request.headers.get("Authorization")
    assert auth == "Bearer tk-ntfy-example"


@pytest.mark.asyncio
@respx.mock
async def test_ntfy_no_auth_header_when_token_absent(ntfy_module: NtfyModule) -> None:
    """Without NTFY_TOKEN in credentials, no Authorization header is sent."""
    route = respx.post("http://ntfy.test/test-topic").mock(return_value=Response(200))
    await ntfy_module.send(title="x", message="y")
    assert route.calls[0].request.headers.get("Authorization") is None


# ── SlackWebhookModule ────────────────────────────────────────────────────────


@pytest.fixture
def slack_module(agent_ctx: AgentContext) -> SlackWebhookModule:
    return SlackWebhookModule(
        agent_ctx=agent_ctx,
        credentials={"SLACK_WEBHOOK_URL": "http://hooks.test/slack"},
        config={},
    )


@pytest.mark.asyncio
@respx.mock
async def test_slack_send_success(slack_module: SlackWebhookModule) -> None:
    respx.post("http://hooks.test/slack").mock(return_value=Response(200))
    result = await slack_module.send(text="hello from agent")
    assert result is True


def test_slack_credential_not_in_config(slack_module: SlackWebhookModule) -> None:
    assert "SLACK_WEBHOOK_URL" not in slack_module.config


# ── DiscordWebhookModule ──────────────────────────────────────────────────────


@pytest.fixture
def discord_module(agent_ctx: AgentContext) -> DiscordWebhookModule:
    return DiscordWebhookModule(
        agent_ctx=agent_ctx,
        credentials={"DISCORD_WEBHOOK_URL": "http://hooks.test/discord"},
        config={},
    )


@pytest.mark.asyncio
@respx.mock
async def test_discord_send_success(discord_module: DiscordWebhookModule) -> None:
    respx.post("http://hooks.test/discord").mock(return_value=Response(200))
    result = await discord_module.send(content="hello")
    assert result is True


@pytest.mark.asyncio
@respx.mock
async def test_discord_truncates_long_content(discord_module: DiscordWebhookModule) -> None:
    respx.post("http://hooks.test/discord").mock(return_value=Response(200))
    long_msg = "x" * 2500
    await discord_module.send(content=long_msg)
    # Verify the request body was truncated
    import json

    sent_body = json.loads(respx.calls[0].request.content)
    assert len(sent_body["content"]) == 2000


def test_discord_credential_not_in_config(discord_module: DiscordWebhookModule) -> None:
    assert "DISCORD_WEBHOOK_URL" not in discord_module.config
