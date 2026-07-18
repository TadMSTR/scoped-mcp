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

        # pre-approval token is now present for the middleware to consume, and
        # carries the approval_id (SMCP-39) so the middleware can resolve the
        # audit row to "consumed" once the token is actually used.
        import anyio

        token = json.loads(anyio.run(state.get, _preapproval_key(TOOL, ARGS_HASH)))
        assert token == {"status": "approved", "approval_id": APPROVAL_ID}

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


def _app_with_suffixed_agent(monkeypatch, deployed_agent_id: str):
    """Like _app_with_seed, but the deployed AGENT_ID carries a clone-pool suffix."""
    monkeypatch.setenv("SCOPED_MCP_HITL_TOKEN", TOKEN)
    state = InProcessBackend()
    approval_id = f"{deployed_agent_id}.abc123def456"
    payload = json.dumps(
        {
            "tool": TOOL,
            "agent_id": deployed_agent_id,
            "args_hash": ARGS_HASH,
            "approval_id": approval_id,
        }
    )
    import time

    state._store[f"hitl:{approval_id}"] = (payload, time.monotonic() + 300)

    server = FastMCP("scoped-mcp/test")
    register_hitl_routes(
        server, state, AgentContext(agent_id=deployed_agent_id, agent_type="build")
    )
    return server.http_app()


def test_pending_agent_id_query_exact_match_unchanged(monkeypatch):
    """SMCP-37 regression: the exact-match path (live deployed configs) keeps working."""
    app = _app_with_suffixed_agent(monkeypatch, "sysadmin-01")
    auth = {"Authorization": f"Bearer {TOKEN}"}
    with TestClient(app) as client:
        r = client.get("/hitl/pending", params={"agent_id": "sysadmin-01"}, headers=auth)
        assert r.status_code == 200
        assert len(r.json()["pending"]) == 1


def test_pending_agent_id_query_normalizes_clone_suffix(monkeypatch):
    """SMCP-37: a bare alias in the query param matches a suffixed deployed AGENT_ID."""
    app = _app_with_suffixed_agent(monkeypatch, "sysadmin-01")
    auth = {"Authorization": f"Bearer {TOKEN}"}
    with TestClient(app) as client:
        r = client.get("/hitl/pending", params={"agent_id": "sysadmin"}, headers=auth)
        assert r.status_code == 200
        assert r.json()["agent_id"] == "sysadmin-01"
        assert len(r.json()["pending"]) == 1


def test_pending_agent_id_query_rejects_different_agent(monkeypatch):
    """SMCP-37: normalization must not let a genuinely different agent match."""
    app = _app_with_suffixed_agent(monkeypatch, "sysadmin-01")
    auth = {"Authorization": f"Bearer {TOKEN}"}
    with TestClient(app) as client:
        r = client.get("/hitl/pending", params={"agent_id": "developer"}, headers=auth)
        assert r.status_code == 200
        assert r.json()["pending"] == []
