"""Tests for modules/matrix.py — allowlist enforcement, successful send."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.matrix import MatrixModule


@pytest.fixture
def matrix_module(agent_ctx: AgentContext) -> MatrixModule:
    return MatrixModule(
        agent_ctx=agent_ctx,
        credentials={
            "MATRIX_HOMESERVER": "http://matrix.test",
            "MATRIX_ACCESS_TOKEN": "EXAMPLE_TOKEN",
        },
        config={"allowed_rooms": ["!room1:matrix.test"]},
    )


@pytest.mark.asyncio
@respx.mock
async def test_send_success(matrix_module: MatrixModule) -> None:
    respx.put(url__regex=r"http://matrix\.test/_matrix/client/v3/rooms/.+/send/.+").mock(
        return_value=Response(200, json={"event_id": "$abc"})
    )
    result = await matrix_module.send(room="!room1:matrix.test", message="hello")
    assert result is True


@pytest.mark.asyncio
async def test_blocked_room_raises_scope_violation(matrix_module: MatrixModule) -> None:
    with pytest.raises(ScopeViolation):
        await matrix_module.send(room="!evil:attacker.com", message="inject")


def test_no_allowed_rooms_raises(agent_ctx: AgentContext) -> None:
    with pytest.raises(ValueError, match="allowed_rooms"):
        MatrixModule(
            agent_ctx=agent_ctx,
            credentials={
                "MATRIX_HOMESERVER": "http://matrix.test",
                "MATRIX_ACCESS_TOKEN": "EXAMPLE_TOKEN",
            },
            config={},
        )
