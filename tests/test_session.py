"""Tests for session attribution (session.py).

The load-bearing case is ``test_literal_placeholder_is_rejected``. When
``FORGE_RUN_ID`` is unset, the Claude CLI interpolates the ``.mcp.json`` header
to the *literal string* ``${FORGE_RUN_ID}`` rather than omitting the header or
sending an empty value — measured against a real CLI, not assumed. Accepting
that value would register one shared ``sessions`` row named ``${FORGE_RUN_ID}``
that every interactive approval across every agent would then join to, turning
an audit column from "unknown" into "known and wrong". The UUID check is the
control that prevents it, so it is tested as a security property.
"""

from __future__ import annotations

import pytest

from scoped_mcp import session
from scoped_mcp.identity import AgentContext

RUN_ID = "11111111-2222-3333-4444-555555555555"
TASK_ID = "deadbeef-0000-1111-2222-333333333333"


@pytest.fixture(autouse=True)
def _clean_memo(monkeypatch):
    """Each test starts with empty memos and no ambient FORGE_* in the env."""
    session._reset_for_tests()
    monkeypatch.delenv("FORGE_RUN_ID", raising=False)
    monkeypatch.delenv("FORGE_TASK_ID", raising=False)
    yield
    session._reset_for_tests()


class _Registry:
    """Records what the DAL was asked to write."""

    def __init__(self, enabled=True, upsert_ok=True, link_ok=True):
        self.enabled = enabled
        self._upsert_ok = upsert_ok
        self._link_ok = link_ok
        self.upserts: list[dict] = []
        self.links: list[dict] = []

    async def upsert_session(self, **kw):
        self.upserts.append(kw)
        return self._upsert_ok

    async def insert_session_task(self, **kw):
        self.links.append(kw)
        return self._link_ok


def _use(monkeypatch, registry):
    async def _get_registry():
        return registry

    monkeypatch.setattr("scoped_mcp.registry_db.get_registry", _get_registry)
    return registry


def _headers(monkeypatch, **values):
    """Install a fake in-flight request exposing the given headers."""
    monkeypatch.setattr(session, "_header", lambda name: values.get(name))


# -- validation ---------------------------------------------------------------


def test_literal_placeholder_is_rejected():
    """The exact value an interactive session sends must never be accepted.

    If this ever passes a value through, every non-dispatcher session shares one
    bogus session row. See the module docstring.
    """
    assert session._valid_uuid("${FORGE_RUN_ID}") is None
    assert session._valid_uuid("$FORGE_RUN_ID") is None
    assert session._valid_uuid("${FORGE_TASK_ID}") is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        "   ",
        "not-a-uuid",
        "1111",
        RUN_ID[:-1],
        RUN_ID + "e",
        "zzzzzzzz-2222-3333-4444-555555555555",
    ],
)
def test_non_uuid_values_are_rejected(value):
    assert session._valid_uuid(value) is None


def test_canonical_uuid_is_accepted():
    assert session._valid_uuid(RUN_ID) == RUN_ID
    assert session._valid_uuid(f"  {RUN_ID}  ") == RUN_ID
    assert session._valid_uuid(RUN_ID.upper()) == RUN_ID.upper()


# -- reading the identity -----------------------------------------------------


def test_reads_run_identity_from_headers(monkeypatch):
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID, session.TASK_ID_HEADER: TASK_ID})
    assert session.read_run_identity() == (RUN_ID, TASK_ID)


def test_falls_back_to_env_for_stdio(monkeypatch):
    """No HTTP request in context (stdio) — the env still carries the id."""
    _headers(monkeypatch)
    monkeypatch.setenv("FORGE_RUN_ID", RUN_ID)
    monkeypatch.setenv("FORGE_TASK_ID", TASK_ID)
    assert session.read_run_identity() == (RUN_ID, TASK_ID)


def test_placeholder_header_does_not_mask_a_real_env_value(monkeypatch):
    """A junk header must fall through to the env, not shadow it.

    Under stdio the header is absent; under a misconfigured HTTP client it can be
    the uninterpolated literal. Neither may suppress a genuine id.
    """
    _headers(monkeypatch, **{session.RUN_ID_HEADER: "${FORGE_RUN_ID}"})
    monkeypatch.setenv("FORGE_RUN_ID", RUN_ID)
    assert session.read_run_identity()[0] == RUN_ID


def test_no_identity_anywhere(monkeypatch):
    _headers(monkeypatch)
    assert session.read_run_identity() == (None, None)


# -- registration -------------------------------------------------------------


async def test_interactive_session_registers_nothing(monkeypatch):
    """No launcher-minted id ⇒ no row, and the registry is never consulted."""
    _headers(monkeypatch)
    reg = _use(monkeypatch, _Registry())
    assert await session.attribute_current_call("developer") is None
    assert reg.upserts == []
    assert reg.links == []


async def test_placeholder_header_registers_nothing(monkeypatch):
    """The end-to-end form of the security property, not just the validator."""
    _headers(
        monkeypatch,
        **{session.RUN_ID_HEADER: "${FORGE_RUN_ID}", session.TASK_ID_HEADER: "${FORGE_TASK_ID}"},
    )
    reg = _use(monkeypatch, _Registry())
    assert await session.attribute_current_call("developer") is None
    assert reg.upserts == []


async def test_registers_and_returns_run_id(monkeypatch):
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID, session.TASK_ID_HEADER: TASK_ID})
    reg = _use(monkeypatch, _Registry())

    assert await session.attribute_current_call("developer") == RUN_ID

    assert len(reg.upserts) == 1
    call = reg.upserts[0]
    assert call["session_id"] == RUN_ID
    assert call["transport"] == "headless"
    # agent_id comes from the broker, never from a header — the non-spoofable half.
    assert call["agent_id"] == "developer"


async def test_agent_id_is_not_taken_from_a_header(monkeypatch):
    """A header claiming a different agent must not influence the row."""
    _headers(
        monkeypatch,
        **{session.RUN_ID_HEADER: RUN_ID, "x-forge-agent-id": "sysadmin"},
    )
    reg = _use(monkeypatch, _Registry())
    await session.attribute_current_call("developer")
    assert reg.upserts[0]["agent_id"] == "developer"


async def test_disabled_registry_returns_none(monkeypatch):
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID})
    reg = _use(monkeypatch, _Registry(enabled=False))
    assert await session.attribute_current_call("developer") is None
    assert reg.upserts == []


async def test_failed_upsert_degrades_to_none_not_a_dangling_id(monkeypatch):
    """The FK is real: a failed upsert must never yield an id.

    upsert_session is fail-open and swallows its own errors, so the bool is the
    only signal. Returning the id here would hand the approval INSERT a session
    that does not exist.
    """
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID, session.TASK_ID_HEADER: TASK_ID})
    reg = _use(monkeypatch, _Registry(upsert_ok=False))

    assert await session.attribute_current_call("developer") is None
    # And it must not have linked a task to a session row that was never written.
    assert reg.links == []


async def test_failed_upsert_is_retried_on_the_next_call(monkeypatch):
    """A transient failure must not be memoised as done."""
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID})
    reg = _use(monkeypatch, _Registry(upsert_ok=False))
    await session.attribute_current_call("developer")
    await session.attribute_current_call("developer")
    assert len(reg.upserts) == 2


async def test_registers_once_per_run_not_once_per_call(monkeypatch):
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID})
    reg = _use(monkeypatch, _Registry())
    for _ in range(25):
        assert await session.attribute_current_call("developer") == RUN_ID
    assert len(reg.upserts) == 1


async def test_refresh_advances_last_seen_after_the_interval(monkeypatch):
    """Phase 3: last_seen_at must move over the life of a long run."""
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID})
    reg = _use(monkeypatch, _Registry())

    clock = [1000.0]
    monkeypatch.setattr(session.time, "monotonic", lambda: clock[0])

    await session.attribute_current_call("developer")
    clock[0] += session.REFRESH_SECONDS - 1
    await session.attribute_current_call("developer")
    assert len(reg.upserts) == 1, "refreshed too eagerly"

    clock[0] += 2
    await session.attribute_current_call("developer")
    assert len(reg.upserts) == 2, "never refreshed — last_seen_at would go stale"


async def test_distinct_runs_get_distinct_rows(monkeypatch):
    """The broker is long-lived and serves many runs; they must not collapse."""
    reg = _use(monkeypatch, _Registry())
    other = "99999999-8888-7777-6666-555555555555"
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID})
    await session.attribute_current_call("developer")
    _headers(monkeypatch, **{session.RUN_ID_HEADER: other})
    await session.attribute_current_call("developer")
    assert [c["session_id"] for c in reg.upserts] == [RUN_ID, other]


async def test_memo_is_bounded(monkeypatch):
    """A long-lived broker must not accumulate run ids without bound."""
    _use(monkeypatch, _Registry())
    for i in range(session._MEMO_MAX + 40):
        _headers(monkeypatch, **{session.RUN_ID_HEADER: f"{i:08d}-2222-3333-4444-555555555555"})
        await session.attribute_current_call("developer")
    assert len(session._seen) <= session._MEMO_MAX


# -- session ↔ task linkage (Phase 5) -----------------------------------------


async def test_links_session_to_task_once(monkeypatch):
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID, session.TASK_ID_HEADER: TASK_ID})
    reg = _use(monkeypatch, _Registry())
    for _ in range(5):
        await session.attribute_current_call("developer")
    assert len(reg.links) == 1
    assert reg.links[0] == {"session_id": RUN_ID, "task_id": TASK_ID, "role": "target"}


async def test_no_task_id_means_no_link(monkeypatch):
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID})
    reg = _use(monkeypatch, _Registry())
    await session.attribute_current_call("developer")
    assert reg.upserts and reg.links == []


async def test_failed_link_is_retried(monkeypatch):
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID, session.TASK_ID_HEADER: TASK_ID})
    reg = _use(monkeypatch, _Registry(link_ok=False))
    await session.attribute_current_call("developer")
    await session.attribute_current_call("developer")
    assert len(reg.links) == 2


# -- fail-open ----------------------------------------------------------------


async def test_registry_explosion_is_swallowed(monkeypatch):
    """Attribution is a paper trail; it may never propagate an error."""
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID})

    async def _boom():
        raise RuntimeError("vault down")

    monkeypatch.setattr("scoped_mcp.registry_db.get_registry", _boom)
    assert await session.attribute_current_call("developer") is None


# -- middleware ---------------------------------------------------------------


async def test_middleware_calls_next_and_registers(monkeypatch):
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID})
    reg = _use(monkeypatch, _Registry())
    mw = session.SessionAttributionMiddleware()

    async def _next():
        return "tool-result"

    ctx = AgentContext(agent_id="developer", agent_type="developer")
    assert await mw(ctx, "some_tool", {}, _next) == "tool-result"
    assert reg.upserts[0]["agent_id"] == "developer"


async def test_middleware_still_runs_the_tool_when_attribution_fails(monkeypatch):
    """A broken registry must not stop a tool call — the fail-open contract."""
    _headers(monkeypatch, **{session.RUN_ID_HEADER: RUN_ID})

    async def _boom():
        raise RuntimeError("db gone")

    monkeypatch.setattr("scoped_mcp.registry_db.get_registry", _boom)
    mw = session.SessionAttributionMiddleware()

    async def _next():
        return "tool-result"

    ctx = AgentContext(agent_id="developer", agent_type="developer")
    assert await mw(ctx, "some_tool", {}, _next) == "tool-result"
