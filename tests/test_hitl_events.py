"""HITL lifecycle events (operator-panel-2026-09 part 3, scoped-mcp 1.18.0).

The test that matters most is the leak test: a gated call whose arguments carry a sentinel
value is driven through request → approve → consume, request → deny → reconcile,
request → expire → reconcile and a refused token, under each signing mode. The sentinel's
bytes must appear in no outbox file. ``record["arguments"]`` only exists when signing is
on, which is why all three modes run.

The other property that matters: a failed emit never changes the gate's decision.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scoped_mcp import hitl_approver, hitl_endpoint, hitl_events, registry_db
from scoped_mcp.exceptions import HitlRejectedError
from scoped_mcp.hitl import HitlMiddleware, _preapproval_key
from scoped_mcp.manifest import AuditConfig

from .test_hitl_signing import FakeRedis, PrefixedState, _approval_id_from

AGENT = "developer"
TOOL = "githost-mcp_gitea_pr_merge"
SENTINEL = "SENTINEL-ARG-9d41c7e2"
SENTINEL_SECRET = "SENTINEL-TOKEN-55aa01"

# agent-bus's own outbox validator, imported for the contract test only. Optional
# locally (a contributor without agent-bus can run the rest of the suite), REQUIRED in
# CI, where SCOPED_MCP_REQUIRE_AGENT_BUS=1 turns a missing module into a failure rather
# than a skip that passes by not running.
try:
    import outbox as bus_outbox
except ImportError:  # pragma: no cover - depends on the environment
    bus_outbox = None


class FakeRegistry:
    """hitl_approvals over a dict. Implements only what the HITL paths call."""

    enabled = True

    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}

    async def insert_hitl_approval(self, approval_id, agent_id, tool_name, state, **kw):
        self.rows[approval_id] = {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "state": state,
            "overdue": False,
        }

    async def resolve_hitl_approval(self, approval_id, state, expected_state=None, **kw):
        row = self.rows.get(approval_id)
        if row is None or (expected_state is not None and row["state"] != expected_state):
            return False
        row["state"] = state
        return True

    async def list_pending_hitl(self, agent_id, grace_seconds, limit=200):
        return [
            {"approval_id": aid, "tool_name": r["tool_name"], "overdue": r["overdue"]}
            for aid, r in self.rows.items()
            if r["agent_id"] == agent_id and r["state"] == "pending"
        ]

    async def upsert_session(self, *a, **kw):
        return None


class _Notifier:
    async def notify(self, **kw: Any) -> None:
        pass


async def _executed() -> str:
    return "EXECUTED"


@pytest.fixture
def outbox(tmp_path, monkeypatch):
    hitl_events.configure_hitl_events(enabled=True, comms_dir=str(tmp_path))
    yield tmp_path / "outbox" / "scoped-mcp"
    hitl_events.configure_hitl_events(enabled=False, comms_dir=None)


@pytest.fixture
def registry(monkeypatch):
    reg = FakeRegistry()

    async def _get():
        return reg

    monkeypatch.setattr(registry_db, "get_registry", _get)
    return reg


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


_STARTED: list[HitlMiddleware] = []


@pytest.fixture(autouse=True)
async def _stop_reconcilers():
    yield
    while _STARTED:
        rec = _STARTED.pop()._reconciler
        if rec is not None:
            await rec.close()


def _mw(state, mode, key, registry) -> HitlMiddleware:
    async def _get():
        return registry

    mw = HitlMiddleware(
        state=state,
        agent_id=AGENT,
        agent_type="build",
        approval_required=["*"],
        shadow=[],
        timeout_seconds=300,
        notifier=_Notifier(),
        signing_mode=mode,
        public_key=key.public_key() if mode != "off" else None,
        reconciler=hitl_events.HitlReconciler(
            state=state, agent_id=AGENT, interval=3600, registry_getter=_get
        ),
    )
    _STARTED.append(mw)
    return mw


def _args(n: int) -> dict[str, Any]:
    return {"repo": "org/repo", "pr_number": n, "body": f"{SENTINEL} {n}", "token": SENTINEL_SECRET}


def _files(outbox: Path) -> list[Path]:
    return (
        sorted(p for p in outbox.iterdir() if not p.name.startswith(".")) if outbox.is_dir() else []
    )


def _events(outbox: Path) -> list[dict]:
    return [json.loads(p.read_text()) for p in _files(outbox)]


async def _request(mw, args) -> str:
    with pytest.raises(HitlRejectedError) as ei:
        await mw(None, TOOL, dict(args), _executed)
    return _approval_id_from(ei.value)


async def _approve(mode, redis, state, key, aid) -> None:
    if mode == "off":
        # The unsigned route: what the endpoint writes. Refused under enforce.
        result = await hitl_endpoint.approve(state, AGENT, aid)
        assert result["status"] == "approved"
    else:
        rc = await hitl_approver.run(
            aid, deny=False, client=redis, private_key=key, confirm=lambda _p: True
        )
        assert rc == hitl_approver.EXIT_OK


# ── the leak test ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("mode", ["off", "observe", "enforce"])
async def test_no_argument_value_reaches_any_event(mode, outbox, registry, key):
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, mode, key, registry)

    # request → approve → consume
    aid1 = await _request(mw, _args(1))
    await _approve(mode, redis, state, key, aid1)
    assert await mw(None, TOOL, _args(1), _executed) == "EXECUTED"

    # request → deny (approver) → reconcile
    aid2 = await _request(mw, _args(2))
    assert (
        await hitl_approver.run(aid2, deny=True, client=redis, private_key=None, confirm=None) == 0
    )
    # request → expire → reconcile
    aid3 = await _request(mw, _args(3))
    registry.rows[aid3]["overdue"] = True
    assert await mw._reconciler.reconcile_once() == 2

    # a refused token (signing on only: under off every token is accepted)
    if mode != "off":
        await state.set_with_ttl(
            _preapproval_key(TOOL, mw_hash(_args(4))),
            json.dumps({"status": "approved", "approval_id": f"{AGENT}.aaaaaaaaaaaa"}),
            60,
        )
        if mode == "enforce":
            await _request(mw, _args(4))
        else:
            assert await mw(None, TOOL, _args(4), _executed) == "EXECUTED"

    files = _files(outbox)
    assert files, "no events were written at all — the test proves nothing"
    for p in files:
        raw = p.read_bytes()
        assert SENTINEL.encode() not in raw, p.name
        assert SENTINEL_SECRET.encode() not in raw, p.name

    names = [e["event"] for e in _events(outbox)]
    assert names.count("hitl.requested") == (4 if mode == "enforce" else 3)
    assert names.count("hitl.approved") == (2 if mode == "observe" else 1)
    closed = [e["metadata"] for e in _events(outbox) if e["event"] == "hitl.closed"]
    assert sorted(m["outcome"] for m in closed) == ["denied", "expired"]
    assert {m["approval_id"] for m in closed} == {aid2, aid3}
    refused = [e["metadata"] for e in _events(outbox) if e["event"] == "hitl.refused"]
    if mode == "off":
        assert refused == []
    else:
        [r] = refused
        assert r["accepted"] is (mode == "observe")
        assert "approval_id" not in r


def mw_hash(args: dict) -> str:
    from scoped_mcp.hitl import _canonical_args_hash

    return _canonical_args_hash(args)


@pytest.mark.skipif(
    bus_outbox is None and os.environ.get("SCOPED_MCP_REQUIRE_AGENT_BUS") != "1",
    reason="agent-bus not installed (required in CI)",
)
@pytest.mark.parametrize("mode", ["off", "enforce"])
async def test_every_event_file_passes_agent_bus_validator(mode, outbox, registry, key):
    assert bus_outbox is not None, "SCOPED_MCP_REQUIRE_AGENT_BUS=1 but agent-bus is missing"
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, mode, key, registry)
    aid = await _request(mw, _args(1))
    await _approve(mode, redis, state, key, aid)
    await mw(None, TOOL, _args(1), _executed)
    aid2 = await _request(mw, _args(2))
    await hitl_endpoint.deny(state, AGENT, aid2)
    files = _files(outbox)
    assert len(files) == 4
    for p in files:
        bus_outbox.read_and_validate(p, {hitl_events.SOURCE})


# ── the gate's decision does not depend on the emit ─────────────────────────


@pytest.mark.parametrize("mode", ["off", "enforce"])
async def test_an_emit_failure_changes_nothing(mode, outbox, registry, key, monkeypatch):
    def boom(*a, **kw):
        raise OSError("disk full")

    monkeypatch.setattr(hitl_events, "_write", boom)
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, mode, key, registry)

    aid = await _request(mw, _args(1))  # still rejected
    await _approve(mode, redis, state, key, aid)
    assert await mw(None, TOOL, _args(1), _executed) == "EXECUTED"  # still runs
    # and a second identical call is gated again: the approval was one-time
    await _request(mw, _args(1))
    assert _files(outbox) == []


async def test_disabled_writes_nothing(tmp_path, registry, key):
    hitl_events.configure_hitl_events(enabled=False, comms_dir=str(tmp_path))
    assert not hitl_events.is_enabled()
    redis = FakeRedis()
    mw = _mw(PrefixedState(redis, AGENT), "enforce", key, registry)
    await _request(mw, _args(1))
    assert not (tmp_path / "outbox").exists()


# ── each event's fields ─────────────────────────────────────────────────────


async def test_requested_carries_exactly_the_listed_fields(outbox, registry, key):
    redis = FakeRedis()
    mw = _mw(PrefixedState(redis, AGENT), "enforce", key, registry)
    aid = await _request(mw, _args(1))
    [e] = _events(outbox)
    assert e["event"] == "hitl.requested"
    assert e["source"] == "scoped-mcp" and e["target"] is None
    md = e["metadata"]
    assert set(md) == {
        "approval_id",
        "agent_id",
        "agent_type",
        "tool",
        "args_sha256_prefix",
        "expires_at",
        "signing_mode",
    }
    assert md["approval_id"] == aid
    assert len(md["args_sha256_prefix"]) == 12
    assert md["signing_mode"] == "enforce"


async def test_endpoint_deny_emits_closed_and_reconcile_does_not_repeat_it(outbox, registry, key):
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, "off", key, registry)
    aid = await _request(mw, _args(1))
    # the endpoint resolves the row in-process
    registry.rows[aid]["state"] = "denied"
    await hitl_endpoint.deny(state, AGENT, aid)
    assert await mw._reconciler.reconcile_once() == 0
    closed = [e for e in _events(outbox) if e["event"] == "hitl.closed"]
    assert len(closed) == 1 and closed[0]["metadata"]["outcome"] == "denied"


async def test_reconcile_closes_a_row_once_across_two_processes(outbox, registry, key):
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, "enforce", key, registry)
    aid = await _request(mw, _args(1))
    registry.rows[aid]["overdue"] = True
    other = hitl_events.HitlReconciler(
        state=state, agent_id=AGENT, registry_getter=lambda: _aw(registry)
    )
    assert await mw._reconciler.reconcile_once() + await other.reconcile_once() == 1
    assert [e["event"] for e in _events(outbox)].count("hitl.closed") == 1


async def _aw(v):
    return v


async def test_reconcile_leaves_a_live_request_alone(outbox, registry, key):
    redis = FakeRedis()
    mw = _mw(PrefixedState(redis, AGENT), "enforce", key, registry)
    aid = await _request(mw, _args(1))
    assert await mw._reconciler.reconcile_once() == 0
    assert registry.rows[aid]["state"] == "pending"


async def test_reconcile_is_a_noop_without_a_registry(outbox):
    class _Off:
        enabled = False

    rec = hitl_events.HitlReconciler(
        state=None, agent_id=AGENT, registry_getter=lambda: _aw(_Off())
    )
    assert await rec.reconcile_once() == 0


async def test_reconcile_loop_starts_once_and_stops(outbox, registry, key):
    redis = FakeRedis()
    mw = _mw(PrefixedState(redis, AGENT), "enforce", key, registry)
    await _request(mw, _args(1))
    task = mw._reconciler._task
    assert task is not None and not task.done()
    await _request(mw, _args(2))
    assert mw._reconciler._task is task
    await mw._reconciler.close()
    assert mw._reconciler._task is None


async def test_a_malformed_approval_id_is_dropped_from_approved(outbox):
    await hitl_events.approved(
        approval_id=f"x {SENTINEL}", agent_id=AGENT, tool=TOOL, signing_mode="off"
    )
    [e] = _events(outbox)
    assert "approval_id" not in e["metadata"]
    assert SENTINEL not in json.dumps(e)


async def test_long_fields_are_capped(outbox):
    await hitl_events.closed(
        approval_id="a" * 500, agent_id=AGENT, tool="t" * 500, outcome="expired"
    )
    [e] = _events(outbox)
    assert len(e["metadata"]["tool"]) == hitl_events.FIELD_CHARS
    assert len(e["summary"]) <= hitl_events.SUMMARY_CHARS


async def test_files_are_0600_in_a_0700_dir(outbox):
    await hitl_events.closed(
        approval_id=f"{AGENT}.aaaaaaaaaaaa", agent_id=AGENT, tool=TOOL, outcome="expired"
    )
    [p] = _files(outbox)
    assert oct(p.stat().st_mode & 0o777) == "0o600"
    assert oct(outbox.stat().st_mode & 0o777) == "0o700"


def test_stamps_are_strictly_increasing(monkeypatch):
    monkeypatch.setattr(hitl_events, "_last_stamp", None)
    stamps = [hitl_events._next_stamp() for _ in range(50)]
    assert stamps == sorted(stamps) and len(set(stamps)) == 50


# ── config ──────────────────────────────────────────────────────────────────


def test_the_toggle_defaults_off():
    assert AuditConfig().agent_bus_hitl_emit is False


def test_the_toggle_requires_the_comms_dir():
    with pytest.raises(ValueError, match="agent_bus_hitl_emit"):
        AuditConfig(agent_bus_hitl_emit=True)
    assert AuditConfig(agent_bus_hitl_emit=True, agent_bus_comms_dir="/x").agent_bus_hitl_emit


# ── registry_db additions ───────────────────────────────────────────────────


class _Conn:
    def __init__(self, status="UPDATE 1", rows=None):
        self.status = status
        self.rows = rows or []
        self.calls: list = []

    async def execute(self, q, *p):
        self.calls.append((q, *p))
        return self.status

    async def fetch(self, q, *p):
        self.calls.append((q, *p))
        return self.rows


class _Ctx:
    def __init__(self, c):
        self.c = c

    async def __aenter__(self):
        return self.c

    async def __aexit__(self, *a):
        return False


class _Pool:
    def __init__(self, c):
        self.c = c

    def acquire(self):
        return _Ctx(self.c)


@pytest.mark.parametrize("status,expected", [("UPDATE 1", True), ("UPDATE 0", False)])
async def test_resolve_reports_whether_it_changed_a_row(status, expected):
    reg = registry_db.RegistryDB(pool=_Pool(_Conn(status)))
    assert await reg.resolve_hitl_approval("a.b", "expired", expected_state="pending") is expected


async def test_resolve_is_false_when_disabled_or_broken():
    assert await registry_db.RegistryDB(pool=None).resolve_hitl_approval("a", "x") is False

    class _Broken:
        def acquire(self):
            raise RuntimeError("down")

    assert await registry_db.RegistryDB(pool=_Broken()).resolve_hitl_approval("a", "x") is False


async def test_list_pending_hitl_is_scoped_to_one_agent_and_fail_open():
    conn = _Conn(rows=[{"approval_id": "developer.a", "tool_name": "t", "overdue": True}])
    reg = registry_db.RegistryDB(pool=_Pool(conn))
    rows = await reg.list_pending_hitl("developer", 120)
    assert rows == [{"approval_id": "developer.a", "tool_name": "t", "overdue": True}]
    q, *params = conn.calls[0]
    assert "agent_id = $1" in q and "state = 'pending'" in q
    assert params == ["developer", 120, 200]
    assert await registry_db.RegistryDB(pool=None).list_pending_hitl("developer", 120) == []

    class _Broken:
        def acquire(self):
            raise RuntimeError("down")

    assert await registry_db.RegistryDB(pool=_Broken()).list_pending_hitl("d", 1) == []
