"""HTTP-surface tests for the /hitl/* routes (SMCP-14 Phase B).

Drives the actual Starlette routes through a TestClient to prove: the routes are
wired onto the FastMCP http app, they self-authenticate (custom routes bypass
the MCP bearer verifier), and status codes map correctly. Uses InProcessBackend
so no Dragonfly is required.
"""

from __future__ import annotations

import json

from fastmcp import FastMCP
from starlette.testclient import TestClient

from scoped_mcp.hitl import _otp_key, _preapproval_key
from scoped_mcp.hitl_http import register_hitl_routes
from scoped_mcp.identity import AgentContext
from scoped_mcp.state import InProcessBackend

AGENT = "developer"
APPROVAL_ID = f"{AGENT}.abc123def456"
TOOL = "gitea_pr_merge"
ARGS_HASH = "deadbeefcafe0001"
TOKEN = "endpoint-bearer-secret"


def _app_with_seed(monkeypatch):
    monkeypatch.setenv("SCOPED_MCP_HITL_TOKEN", TOKEN)
    state = InProcessBackend()
    payload = json.dumps(
        {"tool": TOOL, "agent_id": AGENT, "args_hash": ARGS_HASH, "approval_id": APPROVAL_ID}
    )

    # InProcessBackend methods are async; seed synchronously via its private store
    # to keep the test simple (no event loop needed before TestClient starts one).
    import time

    state._store[f"hitl:{APPROVAL_ID}"] = (payload, time.monotonic() + 300)
    state._store[_otp_key(APPROVAL_ID)] = ("seed-otp", time.monotonic() + 300)

    server = FastMCP("scoped-mcp/test")
    register_hitl_routes(server, state, AgentContext(agent_id=AGENT, agent_type="build"))
    return server.http_app(), state


def test_approve_requires_bearer(monkeypatch):
    app, _ = _app_with_seed(monkeypatch)
    with TestClient(app) as client:
        r = client.post("/hitl/approve", json={"approval_id": APPROVAL_ID})
        assert r.status_code == 401
        r = client.post(
            "/hitl/approve",
            json={"approval_id": APPROVAL_ID},
            headers={"Authorization": "Bearer wrong"},
        )
        assert r.status_code == 401


def test_approve_missing_secret_is_503(monkeypatch):
    monkeypatch.delenv("SCOPED_MCP_HITL_TOKEN", raising=False)
    state = InProcessBackend()
    server = FastMCP("scoped-mcp/test")
    register_hitl_routes(server, state, AgentContext(agent_id=AGENT, agent_type="build"))
    with TestClient(server.http_app()) as client:
        r = client.post(
            "/hitl/approve",
            json={"approval_id": APPROVAL_ID},
            headers={"Authorization": "Bearer anything"},
        )
        assert r.status_code == 503


def test_approve_happy_path_and_pending_listing(monkeypatch):
    app, state = _app_with_seed(monkeypatch)
    auth = {"Authorization": f"Bearer {TOKEN}"}
    with TestClient(app) as client:
        # pending lists the seeded approval
        r = client.get("/hitl/pending", headers=auth)
        assert r.status_code == 200
        assert [p["approval_id"] for p in r.json()["pending"]] == [APPROVAL_ID]

        # approve (bot form — no OTP)
        r = client.post("/hitl/approve", json={"approval_id": APPROVAL_ID}, headers=auth)
        assert r.status_code == 200
        assert r.json()["status"] == "approved"

        # pre-approval token is now present for the middleware to consume
        import anyio

        assert anyio.run(state.get, _preapproval_key(TOOL, ARGS_HASH)) == "approved"

        # second approve is one-time → 404
        r = client.post("/hitl/approve", json={"approval_id": APPROVAL_ID}, headers=auth)
        assert r.status_code == 404


def test_approve_bad_request(monkeypatch):
    app, _ = _app_with_seed(monkeypatch)
    auth = {"Authorization": f"Bearer {TOKEN}"}
    with TestClient(app) as client:
        r = client.post("/hitl/approve", json={}, headers=auth)
        assert r.status_code == 400


def test_deny_via_http(monkeypatch):
    app, state = _app_with_seed(monkeypatch)
    auth = {"Authorization": f"Bearer {TOKEN}"}
    with TestClient(app) as client:
        r = client.post("/hitl/deny", json={"approval_id": APPROVAL_ID}, headers=auth)
        assert r.status_code == 200
        assert r.json()["status"] == "denied"
        # no approval token written on deny
        import anyio

        assert anyio.run(state.get, _preapproval_key(TOOL, ARGS_HASH)) is None
