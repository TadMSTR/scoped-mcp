"""v2 signatures, end to end against agent-bus's own verifier (vikunja#434).

The hook's output is fed to agent-bus ``_check_signature`` (installed test-only in CI, at a
pinned SHA). Checking the signature with a re-implementation here would only prove the two
copies agree with each other; the verifier is the contract.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from scoped_mcp.contrib.signing_hook import SIGNATURE_VERSION, create_signing_hook

_REQUIRED = os.environ.get("SCOPED_MCP_REQUIRE_AGENT_BUS") == "1"


def _keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    k = Ed25519PrivateKey.generate()
    return (
        base64.b64encode(k.private_bytes_raw()).decode(),
        base64.b64encode(k.public_key().public_bytes_raw()).decode(),
    )


@pytest.fixture
def bus(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """agent-bus's server module, with its key registry and nonce set isolated."""
    monkeypatch.setenv("AGENT_BUS_COMMS_DIR", str(tmp_path))  # first import mkdirs here
    try:
        server = importlib.import_module("server")
    except ImportError:
        if _REQUIRED:
            raise
        pytest.skip("agent-bus not installed (CI installs it; SCOPED_MCP_REQUIRE_AGENT_BUS=1)")
    if not hasattr(server, "_check_signature"):
        pytest.fail("the importable `server` module is not agent-bus")
    monkeypatch.setattr(server, "KEY_REGISTRY_PATH", tmp_path / "agent-keys.json")
    # Registered so teardown restores it: the tests below assign it directly.
    monkeypatch.setattr(server, "VERIFY_SIGNATURES", server.VERIFY_SIGNATURES)
    monkeypatch.setattr(server, "_seen_nonces", type(server._seen_nonces)())
    return server


def _register(bus: Any, source: str, public_b64: str) -> None:
    bus.KEY_REGISTRY_PATH.write_text(json.dumps({source: {"pubkey": public_b64}}))


def _as_bus_event(kwargs: dict[str, Any]) -> dict[str, Any]:
    """The event dict agent-bus log_event builds from the forwarded kwargs."""
    return {
        "id": str(uuid.uuid4()),
        "ts": datetime.now(UTC).isoformat(),
        "event": kwargs["event_type"],
        "scope": kwargs.get("scope", "cross-agent"),
        "source": kwargs["source"],
        "target": kwargs.get("target"),
        "artifact_path": kwargs.get("artifact_path"),
        "summary": kwargs["summary"],
        "hostname": "test",
        "metadata": kwargs.get("metadata") or {},
    }


_KWARGS = {
    "event_type": "build.started",
    "source": "developer",
    "summary": "Build started: x",
    "metadata": {"build_name": "x"},
}


async def test_the_hook_emits_v2_fields() -> None:
    priv, pub = _keypair()
    before = datetime.now(UTC)
    md = (await create_signing_hook(priv, pub)(dict(_KWARGS)))["metadata"]
    assert md["sig_v"] == SIGNATURE_VERSION == 2
    signed_at = datetime.fromisoformat(md["sig_ts"])
    assert signed_at.tzinfo is not None
    assert before - timedelta(seconds=1) <= signed_at <= datetime.now(UTC)
    assert uuid.UUID(md["sig_nonce"]).version == 4
    assert re.fullmatch(r"[0-9a-f]{8}", md["key_fp"])
    assert md["build_name"] == "x"


async def test_two_events_get_different_nonces() -> None:
    priv, pub = _keypair()
    hook = create_signing_hook(priv, pub)
    a = (await hook(dict(_KWARGS)))["metadata"]["sig_nonce"]
    b = (await hook(dict(_KWARGS)))["metadata"]["sig_nonce"]
    assert a != b


async def test_caller_supplied_replay_fields_are_overwritten() -> None:
    """A caller cannot pin an old timestamp or a known nonce into a fresh signature."""
    priv, pub = _keypair()
    stale = {"sig_v": 1, "sig_ts": "2020-01-01T00:00:00+00:00", "sig_nonce": "fixed"}
    md = (await create_signing_hook(priv, pub)({**_KWARGS, "metadata": stale}))["metadata"]
    assert md["sig_v"] == 2
    assert md["sig_nonce"] != "fixed"
    assert not md["sig_ts"].startswith("2020")


async def test_a_v2_event_is_accepted_by_agent_bus_with_no_reason(bus: Any) -> None:
    priv, pub = _keypair()
    _register(bus, "developer", pub)
    signed = await create_signing_hook(priv, pub)(dict(_KWARGS))
    for mode in ("warn", "enforce"):
        bus._seen_nonces.clear()
        bus.VERIFY_SIGNATURES = mode
        assert bus._check_signature(_as_bus_event(signed)) == (True, None), mode


async def test_the_replay_fields_are_covered_by_the_signature(bus: Any) -> None:
    """Editing sig_ts or sig_nonce after signing breaks the signature: they are signed."""
    priv, pub = _keypair()
    _register(bus, "developer", pub)
    bus.VERIFY_SIGNATURES = "enforce"
    signed = await create_signing_hook(priv, pub)(dict(_KWARGS))
    for field, value in (("sig_ts", datetime.now(UTC).isoformat()), ("sig_nonce", "other")):
        event = _as_bus_event(signed)
        event["metadata"] = {**event["metadata"], field: value}
        assert bus._check_signature(event) == (False, "signature_invalid"), field


async def test_a_replayed_event_is_rejected_under_enforce_and_logged_under_warn(
    bus: Any,
) -> None:
    priv, pub = _keypair()
    _register(bus, "developer", pub)
    signed = await create_signing_hook(priv, pub)(dict(_KWARGS))

    bus.VERIFY_SIGNATURES = "enforce"
    assert bus._check_signature(_as_bus_event(signed)) == (True, None)
    assert bus._check_signature(_as_bus_event(signed)) == (False, "nonce_reused")

    bus._seen_nonces.clear()
    bus.VERIFY_SIGNATURES = "warn"
    assert bus._check_signature(_as_bus_event(signed)) == (True, None)
    # warn: accepted, with the reason the caller logs as signature_policy.
    assert bus._check_signature(_as_bus_event(signed)) == (True, "nonce_reused")


async def test_a_stale_signature_is_expired_at_agent_bus(
    bus: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Signed longer ago than agent-bus's window: sig_expired."""
    from scoped_mcp.contrib import signing_hook

    priv, pub = _keypair()
    _register(bus, "developer", pub)
    bus.VERIFY_SIGNATURES = "enforce"
    long_ago = datetime.now(UTC) - timedelta(seconds=bus.SIG_MAX_AGE_SECONDS + 5)

    class _Then(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
            return long_ago

    monkeypatch.setattr(signing_hook, "datetime", _Then)
    signed = await create_signing_hook(priv, pub)(dict(_KWARGS))
    assert bus._check_signature(_as_bus_event(signed)) == (False, "sig_expired")


async def test_v1_control_a_v1_replay_is_not_caught(bus: Any) -> None:
    """The gap v2 closes, shown on agent-bus itself: without sig_v, a byte-identical replay
    of a validly signed event is accepted every time, even under enforce."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv, pub = _keypair()
    _register(bus, "developer", pub)
    bus.VERIFY_SIGNATURES = "enforce"
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv))
    metadata = {"build_name": "x", "key_fp": "00000000"}
    event = _as_bus_event({**_KWARGS, "metadata": metadata})
    event["metadata"]["sig"] = base64.b64encode(
        key.sign(bus._canonical_payload(event).encode())
    ).decode()
    assert bus._check_signature(event) == (True, None)
    assert bus._check_signature(event) == (True, None)


def test_agent_bus_window_is_120_seconds(bus: Any) -> None:
    """The window this release relies on (agent-bus 0.7.1 default)."""
    assert bus.SIG_MAX_AGE_SECONDS == 120
