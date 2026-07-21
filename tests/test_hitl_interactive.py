"""Tests for interactive-mode HITL (hitl.mode: interactive).

Covers the two halves of the feature:

* Registration gating — ``scoped_mcp_hitl_confirm`` is registered ONLY when the
  manifest opts into ``hitl.mode: interactive`` AND actually gates tools. An
  enforce-mode agent must not expose it at all (not merely permission-denied —
  never registered), so it cannot resolve a gated call in an unattended run.
* Behavior — the tool resolves via the shared ``hitl_endpoint`` logic (same
  peek/claim/token-write as the bot path), tagging the audit ``resolved_via``
  channel ``interactive_self_service``.

Uses InProcessBackend so no Dragonfly/Postgres is required. The manifest is
declared with ``state_backend: dragonfly`` (required by the manifest validator
whenever tools are gated) but ``build_server`` is handed an InProcessBackend
directly, so no real connection is made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from fastmcp import Client

from scoped_mcp import hitl_endpoint
from scoped_mcp.hitl import _otp_key, _preapproval_key
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import Manifest
from scoped_mcp.registry import build_server
from scoped_mcp.state import InProcessBackend

AGENT = "test-agent-1"  # matches the agent_ctx fixture's agent_id
APPROVAL_ID = f"{AGENT}.abc123def456"
TOOL = "gitea_pr_merge"
ARGS_HASH = "deadbeefcafe0001"


def _mock_module_cls():
    """A mock module class whose instances report no tools."""
    mock_cls = MagicMock()
    mock_cls.required_credentials = []
    mock_cls.optional_credentials = []
    mock_cls.return_value.get_tool_methods.return_value = []
    return mock_cls


def _manifest(*, mode: str | None, approval_required: list[str] | None) -> Manifest:
    """Build a validated manifest with an optional hitl block."""
    data: dict = {
        "agent_type": "developer",
        "modules": {"my-mod": {"type": "mock", "config": {}}},
        "state_backend": {"type": "dragonfly", "url": "redis://localhost:6379/0"},
    }
    if mode is not None or approval_required is not None:
        hitl: dict = {}
        if mode is not None:
            hitl["mode"] = mode
        if approval_required is not None:
            hitl["approval_required"] = approval_required
        data["hitl"] = hitl
    return Manifest.model_validate(data)


def _build(agent_ctx: AgentContext, manifest: Manifest, state: InProcessBackend):
    from unittest.mock import patch

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"mock": _mock_module_cls()}, {}),
    ):
        return build_server(agent_ctx, manifest, state=state)


async def _seed(state: InProcessBackend, *, ttl: int = 300) -> None:
    """Write the pending record + OTP the middleware creates on reject."""
    payload = json.dumps(
        {"tool": TOOL, "agent_id": AGENT, "args_hash": ARGS_HASH, "approval_id": APPROVAL_ID}
    )
    await state.set_with_ttl(f"hitl:{APPROVAL_ID}", payload, ttl)
    await state.set_with_ttl(_otp_key(APPROVAL_ID), "seed-otp", ttl)


# ── registration gating ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_confirm_tool_registered_for_interactive_mode(agent_ctx: AgentContext) -> None:
    manifest = _manifest(mode="interactive", approval_required=[TOOL])
    server = _build(agent_ctx, manifest, InProcessBackend())

    names = [t.name for t in await server.list_tools()]
    assert "scoped_mcp_hitl_confirm" in names


@pytest.mark.asyncio
async def test_confirm_tool_absent_for_enforce_mode(agent_ctx: AgentContext) -> None:
    """Default enforce mode must NOT register the tool — not registered at all,
    so an unattended run can never reach it."""
    manifest = _manifest(mode="enforce", approval_required=[TOOL])
    server = _build(agent_ctx, manifest, InProcessBackend())

    names = [t.name for t in await server.list_tools()]
    assert "scoped_mcp_hitl_confirm" not in names
    # sanity: the agent DID configure gating, it just resolves out-of-band
    assert "scoped_mcp_status" in names


@pytest.mark.asyncio
async def test_confirm_tool_absent_when_default_mode(agent_ctx: AgentContext) -> None:
    """An hitl block with no explicit mode defaults to enforce → tool absent."""
    manifest = _manifest(mode=None, approval_required=[TOOL])
    server = _build(agent_ctx, manifest, InProcessBackend())

    names = [t.name for t in await server.list_tools()]
    assert "scoped_mcp_hitl_confirm" not in names


@pytest.mark.asyncio
async def test_confirm_tool_absent_when_interactive_but_nothing_gated(
    agent_ctx: AgentContext,
) -> None:
    """interactive mode with no approval_required has nothing to confirm → absent."""
    manifest = _manifest(mode="interactive", approval_required=[])
    server = _build(agent_ctx, manifest, InProcessBackend())

    names = [t.name for t in await server.list_tools()]
    assert "scoped_mcp_hitl_confirm" not in names


# ── behavior ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_confirm_approve_writes_preapproval_token(agent_ctx: AgentContext) -> None:
    state = InProcessBackend()
    await _seed(state)
    server = _build(agent_ctx, _manifest(mode="interactive", approval_required=[TOOL]), state)

    async with Client(server) as client:
        result = await client.call_tool(
            "scoped_mcp_hitl_confirm", {"approval_id": APPROVAL_ID, "decision": "approve"}
        )

    assert result.data["status"] == "approved"
    # The one-time token the middleware consumes on retry is present...
    token = json.loads(await state.get(_preapproval_key(TOOL, ARGS_HASH)))
    assert token == {"status": "approved", "approval_id": APPROVAL_ID}
    # ...and the pending record is consumed.
    assert await state.get(f"hitl:{APPROVAL_ID}") is None


@pytest.mark.asyncio
async def test_confirm_deny_clears_without_token(agent_ctx: AgentContext) -> None:
    state = InProcessBackend()
    await _seed(state)
    server = _build(agent_ctx, _manifest(mode="interactive", approval_required=[TOOL]), state)

    async with Client(server) as client:
        result = await client.call_tool(
            "scoped_mcp_hitl_confirm", {"approval_id": APPROVAL_ID, "decision": "deny"}
        )

    assert result.data["status"] == "denied"
    assert await state.get(f"hitl:{APPROVAL_ID}") is None
    # deny must never write an approval token
    assert await state.get(_preapproval_key(TOOL, ARGS_HASH)) is None


@pytest.mark.asyncio
async def test_confirm_invalid_decision_rejected(agent_ctx: AgentContext) -> None:
    state = InProcessBackend()
    await _seed(state)
    server = _build(agent_ctx, _manifest(mode="interactive", approval_required=[TOOL]), state)

    async with Client(server) as client:
        result = await client.call_tool(
            "scoped_mcp_hitl_confirm", {"approval_id": APPROVAL_ID, "decision": "maybe"}
        )

    assert result.data["status"] == "invalid_decision"
    # pending untouched — a bad decision must not consume the request
    assert await state.get(f"hitl:{APPROVAL_ID}") is not None


@pytest.mark.asyncio
async def test_confirm_cross_agent_id_not_found(agent_ctx: AgentContext) -> None:
    """An approval_id belonging to a different agent must not be actionable."""
    state = InProcessBackend()
    other_id = "someone-else.deadbeef1234"
    await state.set_with_ttl(
        f"hitl:{other_id}",
        json.dumps({"tool": TOOL, "agent_id": "someone-else", "args_hash": ARGS_HASH}),
        300,
    )
    server = _build(agent_ctx, _manifest(mode="interactive", approval_required=[TOOL]), state)

    async with Client(server) as client:
        result = await client.call_tool(
            "scoped_mcp_hitl_confirm", {"approval_id": other_id, "decision": "approve"}
        )

    assert result.data["status"] == "not_found"
    # the other agent's pending record is untouched
    assert await state.get(f"hitl:{other_id}") is not None


# ── resolved_via audit tag ────────────────────────────────────────────────────


class _RecordingRegistry:
    def __init__(self) -> None:
        self.resolves: list[dict] = []

    async def insert_hitl_approval(self, **kw: object) -> None:
        pass

    async def resolve_hitl_approval(
        self, approval_id, state, expected_state=None, resolved_via=None
    ) -> None:
        self.resolves.append({"state": state, "resolved_via": resolved_via})


@pytest.mark.asyncio
async def test_confirm_tags_interactive_self_service(agent_ctx: AgentContext, monkeypatch) -> None:
    """A resolution through the interactive tool is tagged interactive_self_service."""
    recording = _RecordingRegistry()

    async def _fake_get_registry():
        return recording

    monkeypatch.setattr("scoped_mcp.registry_db.get_registry", _fake_get_registry)

    state = InProcessBackend()
    await _seed(state)
    server = _build(agent_ctx, _manifest(mode="interactive", approval_required=[TOOL]), state)

    async with Client(server) as client:
        await client.call_tool(
            "scoped_mcp_hitl_confirm", {"approval_id": APPROVAL_ID, "decision": "approve"}
        )

    assert any(
        r["state"] == "approved" and r["resolved_via"] == "interactive_self_service"
        for r in recording.resolves
    )


@pytest.mark.asyncio
async def test_confirm_fails_closed_on_backend_error(agent_ctx: AgentContext, monkeypatch) -> None:
    """A state-backend error inside approve must NEVER resolve to an approval —
    the tool returns backend_unavailable and writes no pre-approval token."""
    state = InProcessBackend()
    await _seed(state)
    server = _build(agent_ctx, _manifest(mode="interactive", approval_required=[TOOL]), state)

    async def _boom(*a, **k):
        raise RuntimeError("dragonfly down")

    # Force the shared endpoint logic to raise mid-resolution.
    monkeypatch.setattr(hitl_endpoint, "approve", _boom)

    async with Client(server) as client:
        result = await client.call_tool(
            "scoped_mcp_hitl_confirm", {"approval_id": APPROVAL_ID, "decision": "approve"}
        )

    assert result.data["status"] == "backend_unavailable"
    # fail-closed: no pre-approval token written, pending record untouched
    assert await state.get(_preapproval_key(TOOL, ARGS_HASH)) is None
    assert await state.get(f"hitl:{APPROVAL_ID}") is not None


@pytest.mark.asyncio
async def test_endpoint_approve_defaults_to_operator_endpoint(monkeypatch) -> None:
    """The direct endpoint approve (unchanged callers) tags operator_endpoint."""
    recording = _RecordingRegistry()

    async def _fake_get_registry():
        return recording

    monkeypatch.setattr("scoped_mcp.registry_db.get_registry", _fake_get_registry)

    state = InProcessBackend()
    payload = json.dumps(
        {"tool": TOOL, "agent_id": AGENT, "args_hash": ARGS_HASH, "approval_id": APPROVAL_ID}
    )
    await state.set_with_ttl(f"hitl:{APPROVAL_ID}", payload, 300)
    await state.set_with_ttl(_otp_key(APPROVAL_ID), "seed-otp", 300)

    result = await hitl_endpoint.approve(state, AGENT, APPROVAL_ID)  # default resolved_via

    assert result["status"] == "approved"
    assert any(
        r["state"] == "approved" and r["resolved_via"] == "operator_endpoint"
        for r in recording.resolves
    )
