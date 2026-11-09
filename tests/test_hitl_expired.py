"""An expired approval says ``expired``, not ``not_found`` (vikunja#628 option E).

Before 1.22.0 an approve of a lapsed id answered ``not_found``, which reads as "you passed a
wrong id": the agent had no way to tell that the fix was to re-issue the call. The four
cases now each get their own status, and another agent's id never answers ``expired``.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import pytest

from scoped_mcp import hitl_endpoint
from scoped_mcp.exceptions import HitlRejectedError
from scoped_mcp.hitl import (
    ISSUED_MARKER_GRACE_SECONDS,
    HitlMiddleware,
    _issued_key,
)
from scoped_mcp.hitl_events import deny_tombstone_key
from scoped_mcp.state import InProcessBackend

AGENT = "developer"
TOOL = "githost-mcp_gitea_pr_merge"
TIMEOUT = 300


class _Notifier:
    async def notify(self, **kwargs: Any) -> None:
        pass


async def _passthrough() -> str:
    return "ok"


def _mw(state: InProcessBackend, agent_id: str = AGENT) -> HitlMiddleware:
    return HitlMiddleware(
        state=state,
        agent_id=agent_id,
        agent_type=agent_id,
        approval_required=["*"],
        shadow=[],
        timeout_seconds=TIMEOUT,
        notifier=_Notifier(),
    )


async def _request(state: InProcessBackend, agent_id: str = AGENT) -> str:
    """Make a gated call through the real middleware; return the approval id it issued."""
    with pytest.raises(HitlRejectedError) as exc:
        await _mw(state, agent_id)(
            agent_ctx=None, tool_name=TOOL, kwargs={"pr_number": 7}, call_next=_passthrough
        )
    m = re.search(r"approval ID: ([\w.-]+)\)", str(exc.value))
    assert m, str(exc.value)
    return m.group(1)


async def _lapse(state: InProcessBackend, approval_id: str) -> None:
    """What the pending key's TTL does at the timeout: the record and its OTP go."""
    await state.delete(f"hitl:{approval_id}")
    await state.delete(f"hitl:otp:{approval_id}")


def _after_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    later = time.time() + TIMEOUT + 1
    monkeypatch.setattr(hitl_endpoint.time, "time", lambda: later)


# ── the marker ────────────────────────────────────────────────────────────────


async def test_a_request_writes_an_issued_marker_with_its_expiry() -> None:
    state = InProcessBackend()
    before = time.time()
    aid = await _request(state)
    marker = json.loads(await state.get(_issued_key(aid)))
    assert set(marker) == {"expires_at"}
    assert before + TIMEOUT <= marker["expires_at"] <= time.time() + TIMEOUT


async def test_a_failed_marker_write_does_not_change_the_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The marker is best-effort: the gate still rejects with an id, and the request stands."""
    state = InProcessBackend()
    real = state.set_with_ttl

    async def flaky(key: str, value: str, ttl: int) -> None:
        if ":issued:" in key:
            raise ConnectionError("marker write failed")
        await real(key, value, ttl)

    monkeypatch.setattr(state, "set_with_ttl", flaky)
    aid = await _request(state)
    assert await state.get(f"hitl:{aid}") is not None
    assert await state.get(_issued_key(aid)) is None


# ── the four statuses ─────────────────────────────────────────────────────────


async def test_expired_id_answers_expired_with_the_way_out(monkeypatch: pytest.MonkeyPatch) -> None:
    state = InProcessBackend()
    aid = await _request(state)
    await _lapse(state, aid)
    _after_timeout(monkeypatch)
    result = await hitl_endpoint.approve(state, AGENT, aid)
    assert result == {"status": "expired", "detail": hitl_endpoint.EXPIRED_DETAIL}
    assert "re-issue the original tool call" in result["detail"]


async def test_unknown_id_answers_not_found() -> None:
    state = InProcessBackend()
    await _request(state)  # a real request exists, but not this one
    result = await hitl_endpoint.approve(state, AGENT, f"{AGENT}.000000000000")
    assert result == {"status": "not_found"}


async def test_another_agents_id_never_answers_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even with that agent's expired marker readable in the same backend, the ownership
    check comes first, so the response cannot show that the id exists."""
    state = InProcessBackend()
    other = await _request(state, agent_id="sysadmin")
    await _lapse(state, other)
    _after_timeout(monkeypatch)
    # Control: to its own agent, the same id does answer expired.
    assert (await hitl_endpoint.approve(state, "sysadmin", other))["status"] == "expired"
    assert await hitl_endpoint.approve(state, AGENT, other) == {"status": "not_found"}
    assert await hitl_endpoint.deny(state, AGENT, other) == {"status": "not_found"}


async def test_decided_id_answers_already_decided_before_and_after_its_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = InProcessBackend()
    aid = await _request(state)
    assert (await hitl_endpoint.approve(state, AGENT, aid))["status"] == "approved"
    assert (await hitl_endpoint.approve(state, AGENT, aid))["status"] == "already_decided"
    _after_timeout(monkeypatch)
    # The decided marker outlives the timeout: a decided id never turns into "expired".
    assert (await hitl_endpoint.approve(state, AGENT, aid))["status"] == "already_decided"


async def test_denied_id_answers_already_decided_after_its_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = InProcessBackend()
    aid = await _request(state)
    assert (await hitl_endpoint.deny(state, AGENT, aid))["status"] == "denied"
    _after_timeout(monkeypatch)
    assert (await hitl_endpoint.approve(state, AGENT, aid))["status"] == "already_decided"


async def test_a_deny_tombstone_alone_answers_already_decided(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """scoped-mcp-approve --deny from another uid leaves its tombstone; a lost marker
    update must not turn that deny into "expired"."""
    state = InProcessBackend()
    aid = await _request(state)
    await _lapse(state, aid)
    await state.set_with_ttl(deny_tombstone_key(aid), "1", 3600)
    _after_timeout(monkeypatch)
    assert (await hitl_endpoint.approve(state, AGENT, aid))["status"] == "already_decided"


async def test_a_record_gone_before_its_time_answers_already_decided() -> None:
    """Only a decision removes a pending record early, whoever made it."""
    state = InProcessBackend()
    aid = await _request(state)
    await _lapse(state, aid)
    assert (await hitl_endpoint.approve(state, AGENT, aid))["status"] == "already_decided"


async def test_deny_of_an_expired_id_answers_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    state = InProcessBackend()
    aid = await _request(state)
    await _lapse(state, aid)
    _after_timeout(monkeypatch)
    assert (await hitl_endpoint.deny(state, AGENT, aid))["status"] == "expired"


async def test_lapse_between_peek_and_claim_answers_expired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The record was there at the peek and gone at the claim, past its timeout."""
    state = InProcessBackend()
    aid = await _request(state)
    real_get_delete = state.get_delete

    async def lapsing_get_delete(key: str) -> Any:
        if key == f"hitl:{aid}":
            await state.delete(key)
            _after_timeout(monkeypatch)
        return await real_get_delete(key)

    monkeypatch.setattr(state, "get_delete", lapsing_get_delete)
    assert (await hitl_endpoint.approve(state, AGENT, aid))["status"] == "expired"


@pytest.mark.parametrize(
    "marker",
    [None, "not json", json.dumps([1, 2]), json.dumps({"expires_at": "soon"}), "true"],
)
async def test_a_missing_or_malformed_marker_answers_not_found(
    marker: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No marker (past its grace, or a request from before 1.22.0) keeps the old answer."""
    state = InProcessBackend()
    aid = await _request(state)
    await _lapse(state, aid)
    await state.delete(_issued_key(aid))
    if marker is not None:
        await state.set_with_ttl(_issued_key(aid), marker, 60)
    _after_timeout(monkeypatch)
    assert (await hitl_endpoint.approve(state, AGENT, aid))["status"] == "not_found"


def test_the_marker_outlives_the_request_by_an_hour() -> None:
    assert ISSUED_MARKER_GRACE_SECONDS == 3600


# ── side keys in the pending scan ─────────────────────────────────────────────


async def test_list_pending_skips_tombstones_and_markers() -> None:
    """Before 1.22.0 a deny tombstone (value "1", JSON for an int) made list_pending raise
    AttributeError, so /hitl/pending answered 503 for an hour after any deny."""
    state = InProcessBackend()
    live = await _request(state)
    denied = await _request(state)
    await _lapse(state, denied)
    await state.set_with_ttl(deny_tombstone_key(denied), "1", 3600)
    pending = await hitl_endpoint.list_pending(state, AGENT)
    assert [p["approval_id"] for p in pending] == [live]


async def test_list_pending_skips_a_pending_shaped_key_with_a_non_object_value() -> None:
    state = InProcessBackend()
    await state.set_with_ttl(f"hitl:{AGENT}.aaaaaaaaaaaa", json.dumps([1]), 60)
    assert await hitl_endpoint.list_pending(state, AGENT) == []


async def test_list_pending_skips_a_side_key_even_when_its_value_looks_like_a_record() -> None:
    """The namespace filter, independently of the value check: a side key is never listed,
    whatever it holds."""
    state = InProcessBackend()
    aid = f"{AGENT}.bbbbbbbbbbbb"
    record = json.dumps({"approval_id": aid, "agent_id": AGENT, "tool": TOOL})
    for key in (_issued_key(aid), deny_tombstone_key(aid), f"hitl:otp:{aid}"):
        await state.set_with_ttl(key, record, 60)
    assert await hitl_endpoint.list_pending(state, AGENT) == []
