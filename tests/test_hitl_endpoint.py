"""Tests for the transport-agnostic HITL approval endpoint logic.

Uses InProcessBackend so no Dragonfly/Postgres is required. The registry audit
writes are no-ops here (AGENT_REGISTRY_DSN unset => disabled DAL).
"""

from __future__ import annotations

import json

import pytest

from scoped_mcp import hitl_endpoint
from scoped_mcp.hitl import _otp_key, _preapproval_key
from scoped_mcp.state import InProcessBackend

AGENT = "developer"
APPROVAL_ID = f"{AGENT}.abc123def456"
TOOL = "gitea_pr_merge"
ARGS_HASH = "deadbeefcafe0001"


async def _seed(state: InProcessBackend, *, otp: str = "seed-otp-value", ttl: int = 300) -> None:
    """Write the pending record + OTP the middleware would create on reject."""
    payload = json.dumps(
        {
            "tool": TOOL,
            "agent_id": AGENT,
            "args_hash": ARGS_HASH,
            "approval_id": APPROVAL_ID,
        }
    )
    await state.set_with_ttl(f"hitl:{APPROVAL_ID}", payload, ttl)
    await state.set_with_ttl(_otp_key(APPROVAL_ID), otp, ttl)


async def test_approve_bot_form_writes_preapproval_and_clears_state():
    state = InProcessBackend()
    await _seed(state)

    result = await hitl_endpoint.approve(state, AGENT, APPROVAL_ID)  # no OTP => bot form

    assert result["status"] == "approved"
    assert result["tool"] == TOOL
    # pre-approval token the middleware consumes on retry is present...
    assert await state.get(_preapproval_key(TOOL, ARGS_HASH)) == "approved"
    # ...and the pending record + OTP are gone (one-time).
    assert await state.get(f"hitl:{APPROVAL_ID}") is None
    assert await state.get(_otp_key(APPROVAL_ID)) is None


async def test_approve_is_one_time():
    state = InProcessBackend()
    await _seed(state)
    first = await hitl_endpoint.approve(state, AGENT, APPROVAL_ID)
    second = await hitl_endpoint.approve(state, AGENT, APPROVAL_ID)
    assert first["status"] == "approved"
    assert second["status"] == "not_found"  # pending already consumed


async def test_approve_unknown_id_not_found():
    state = InProcessBackend()
    result = await hitl_endpoint.approve(state, AGENT, f"{AGENT}.doesnotexist")
    assert result["status"] == "not_found"


async def test_approve_rejects_cross_agent_id():
    state = InProcessBackend()
    await _seed(state)
    # An approval_id whose prefix is a different agent must never be actioned here.
    result = await hitl_endpoint.approve(state, "sysadmin", APPROVAL_ID)
    assert result["status"] == "not_found"
    # pending untouched
    assert await state.get(f"hitl:{APPROVAL_ID}") is not None


async def test_courier_correct_otp_approves():
    state = InProcessBackend()
    await _seed(state, otp="the-real-otp")
    result = await hitl_endpoint.approve(state, AGENT, APPROVAL_ID, otp="the-real-otp")
    assert result["status"] == "approved"
    assert await state.get(_preapproval_key(TOOL, ARGS_HASH)) == "approved"


async def test_courier_wrong_otp_denied_and_pending_preserved():
    state = InProcessBackend()
    await _seed(state, otp="the-real-otp")
    result = await hitl_endpoint.approve(state, AGENT, APPROVAL_ID, otp="WRONG")
    assert result["status"] == "invalid_otp"
    # No pre-approval token written.
    assert await state.get(_preapproval_key(TOOL, ARGS_HASH)) is None
    # Pending record is NOT destroyed by a bad guess (OTP is consumed though).
    assert await state.get(f"hitl:{APPROVAL_ID}") is not None


async def test_deny_clears_pending_and_otp():
    state = InProcessBackend()
    await _seed(state)
    result = await hitl_endpoint.deny(state, AGENT, APPROVAL_ID)
    assert result["status"] == "denied"
    assert await state.get(f"hitl:{APPROVAL_ID}") is None
    assert await state.get(_otp_key(APPROVAL_ID)) is None
    # deny must never write an approval token
    assert await state.get(_preapproval_key(TOOL, ARGS_HASH)) is None


async def test_deny_unknown_id_not_found():
    state = InProcessBackend()
    result = await hitl_endpoint.deny(state, AGENT, f"{AGENT}.nope")
    assert result["status"] == "not_found"


async def test_list_pending_excludes_token_keys():
    state = InProcessBackend()
    await _seed(state)
    # Add a preapproval token that shares the hitl: namespace — must be excluded.
    await state.set_with_ttl(_preapproval_key(TOOL, ARGS_HASH), "approved", 300)

    pending = await hitl_endpoint.list_pending(state, AGENT)
    assert len(pending) == 1
    assert pending[0]["approval_id"] == APPROVAL_ID
    assert pending[0]["tool"] == TOOL
    assert pending[0]["agent_id"] == AGENT


async def test_missing_args_hash_binding_refuses():
    state = InProcessBackend()
    # Pending record without args_hash — cannot bind a pre-approval token.
    payload = json.dumps({"tool": TOOL, "agent_id": AGENT, "approval_id": APPROVAL_ID})
    await state.set_with_ttl(f"hitl:{APPROVAL_ID}", payload, 300)
    result = await hitl_endpoint.approve(state, AGENT, APPROVAL_ID)
    assert result["status"] == "not_found"
    assert await state.get(_preapproval_key(TOOL, "")) is None


# --- bearer check --------------------------------------------------------


class _FakeRequest:
    def __init__(self, headers: dict[str, str]):
        self.headers = headers


def test_bearer_missing_secret_is_503(monkeypatch):
    from scoped_mcp.hitl_http import _check_bearer

    monkeypatch.delenv("SCOPED_MCP_HITL_TOKEN", raising=False)
    ok, code = _check_bearer(_FakeRequest({"authorization": "Bearer whatever"}))
    assert ok is False and code == 503


def test_bearer_wrong_token_is_401(monkeypatch):
    from scoped_mcp.hitl_http import _check_bearer

    monkeypatch.setenv("SCOPED_MCP_HITL_TOKEN", "correct-horse")
    ok, code = _check_bearer(_FakeRequest({"authorization": "Bearer wrong"}))
    assert ok is False and code == 401


def test_bearer_missing_header_is_401(monkeypatch):
    from scoped_mcp.hitl_http import _check_bearer

    monkeypatch.setenv("SCOPED_MCP_HITL_TOKEN", "correct-horse")
    ok, code = _check_bearer(_FakeRequest({}))
    assert ok is False and code == 401


def test_bearer_correct_token_ok(monkeypatch):
    from scoped_mcp.hitl_http import _check_bearer

    monkeypatch.setenv("SCOPED_MCP_HITL_TOKEN", "correct-horse")
    ok, _ = _check_bearer(_FakeRequest({"authorization": "Bearer correct-horse"}))
    assert ok is True


# --- middleware -> endpoint integration ----------------------------------


async def test_middleware_reject_then_endpoint_approve_then_pass_through():
    """Full loop: gated call rejected (pending + OTP written) -> endpoint approve
    -> agent retry passes through. Confirms the agent never touches the endpoint."""
    from scoped_mcp.exceptions import HitlRejectedError
    from scoped_mcp.hitl import HitlMiddleware, _otp_key
    from scoped_mcp.hitl_notify import LogNotifier

    state = InProcessBackend()
    mw = HitlMiddleware(
        state=state,
        agent_id=AGENT,
        agent_type="build",
        approval_required=["gitea_pr_merge"],
        shadow=[],
        timeout_seconds=300,
        notifier=LogNotifier(),
    )

    called = {"n": 0}

    async def call_next():
        called["n"] += 1
        return {"merged": True}

    # 1. First call is rejected and registers a pending approval + OTP.
    with pytest.raises(HitlRejectedError) as exc:
        await mw(None, "gitea_pr_merge", {"repo": "x", "pr": 1}, call_next)
    assert called["n"] == 0
    approval_id = str(exc.value).split("approval ID: ")[1].split(")")[0].strip()
    assert approval_id.startswith(f"{AGENT}.")
    assert await state.get(_otp_key(approval_id)) is not None  # OTP minted, server-side only

    # 2. Operator approves through the endpoint (bot form — no OTP presented).
    result = await hitl_endpoint.approve(state, AGENT, approval_id)
    assert result["status"] == "approved"

    # 3. Agent retries the identical call — now it passes through to the tool.
    out = await mw(None, "gitea_pr_merge", {"repo": "x", "pr": 1}, call_next)
    assert out == {"merged": True}
    assert called["n"] == 1

    # 4. One-time: a second retry is gated again (token already consumed).
    with pytest.raises(HitlRejectedError):
        await mw(None, "gitea_pr_merge", {"repo": "x", "pr": 1}, call_next)
    assert called["n"] == 1
