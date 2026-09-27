"""Signed HITL approvals: the statement, the verifier, the approver, and the
retirement of every unsigned approval route under ``hitl.signing.mode: enforce``.

The approver talks to the state backend with full Dragonfly keys; the middleware
talks through an agent-prefixed StateBackend. Both run here over ONE fake store
with the real prefix, so an end-to-end test exercises the same key layout
production does.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from typing import Any

import pytest
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scoped_mcp import hitl_approver
from scoped_mcp.exceptions import HitlRejectedError, ManifestError
from scoped_mcp.hitl import HitlMiddleware, _canonical_args_hash, _preapproval_key
from scoped_mcp.hitl_cli import run_hitl_command
from scoped_mcp.hitl_signing import (
    ALL_REASONS,
    MAX_LIFETIME_SECONDS,
    REASON_AGENT_MISMATCH,
    REASON_ARGS_MISMATCH,
    REASON_BAD_SIGNATURE,
    REASON_BAD_VERSION,
    REASON_EXPIRED,
    REASON_LIFETIME_TOO_LONG,
    REASON_MALFORMED,
    REASON_NOT_YET_VALID,
    REASON_REPLAYED,
    REASON_TOOL_MISMATCH,
    ConsumedSet,
    SigningKeyError,
    _canonical_bytes,
    build_statement,
    check_owner_only,
    load_private_key,
    load_public_key,
    sign_statement,
    verify_statement,
)
from scoped_mcp.manifest import HitlConfig, load_manifest

AGENT = "developer"
TOOL = "githost-mcp_gitea_pr_merge"
ARGS = {"repo": "org/repo", "pr_number": 7, "merge_style": "squash"}
HASH = _canonical_args_hash(ARGS)


# ── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _signed(key: Ed25519PrivateKey, **over: Any) -> str:
    st = build_statement(
        agent_id=AGENT, approval_id=f"{AGENT}.aaaaaaaaaaaa", tool=TOOL, args_hash=HASH
    )
    st.update(over)
    return sign_statement(key, st)


def _verify(raw: str, key: Ed25519PrivateKey, **over: Any):
    kw = {"public_key": key.public_key(), "agent_id": AGENT, "tool": TOOL, "args_hash": HASH}
    kw.update(over)
    return verify_statement(raw, **kw)


class FakeRedis:
    """The subset of redis.asyncio the approver uses, over a shared dict."""

    def __init__(self) -> None:
        self.store: dict[str, str] = {}

    async def get(self, k: str) -> str | None:
        return self.store.get(k)

    async def getdel(self, k: str) -> str | None:
        return self.store.pop(k, None)

    async def delete(self, k: str) -> None:
        self.store.pop(k, None)

    async def set(self, k: str, v: str, ex: int | None = None) -> None:
        self.store[k] = v


class PrefixedState:
    """StateBackend over FakeRedis with DragonflyBackend's agent prefix."""

    def __init__(self, redis: FakeRedis, agent_id: str) -> None:
        self.r = redis
        self.p = f"scoped-mcp:{agent_id}:"

    async def get(self, k: str) -> str | None:
        return await self.r.get(self.p + k)

    async def get_delete(self, k: str) -> str | None:
        return await self.r.getdel(self.p + k)

    async def delete(self, k: str) -> None:
        await self.r.delete(self.p + k)

    async def set_with_ttl(self, k: str, v: str, ttl: int) -> None:
        await self.r.set(self.p + k, v, ex=ttl)


class _Notifier:
    async def notify(self, **kw: Any) -> None:
        pass


def _mw(
    state: Any, mode: str, key: Ed25519PrivateKey | None, hint: str | None = None
) -> HitlMiddleware:
    return HitlMiddleware(
        state=state,
        agent_id=AGENT,
        agent_type="build",
        approval_required=["*"],
        shadow=[],
        timeout_seconds=300,
        notifier=_Notifier(),
        signing_mode=mode,
        public_key=key.public_key() if key else None,
        approve_hint=hint,
    )


async def _executed() -> str:
    return "EXECUTED"


def _approval_id_from(exc: HitlRejectedError) -> str:
    msg = str(exc)
    return msg.split("approval ID: ", 1)[1].split(")", 1)[0]


# ── the verifier: every reason class ────────────────────────────────────────


def test_valid_statement_verifies(key):
    r = _verify(_signed(key), key)
    assert r.ok and r.reason is None and r.approval_id == f"{AGENT}.aaaaaaaaaaaa"


@pytest.mark.parametrize(
    "raw",
    [
        "approved",  # the pre-signing token shape
        json.dumps({"status": "approved", "approval_id": "developer.x"}),  # what the CLI writes
        "{not json",
        json.dumps({"statement": {}, "sig": "AAAA"}),
        json.dumps({"statement": "x", "sig": "AAAA"}),
        json.dumps({"sig": "AAAA"}),
    ],
)
def test_malformed(key, raw):
    assert _verify(raw, key).reason == REASON_MALFORMED


def test_non_base64_signature_is_malformed(key):
    outer = json.loads(_signed(key))
    outer["sig"] = "!!!not-base64!!!"
    assert _verify(json.dumps(outer), key).reason == REASON_MALFORMED


def test_extra_field_is_malformed(key):
    outer = json.loads(_signed(key))
    outer["statement"]["scope"] = "*"
    assert _verify(json.dumps(outer), key).reason == REASON_MALFORMED


def test_wrong_key_is_bad_signature(key):
    other = Ed25519PrivateKey.generate()
    assert _verify(_signed(other), key).reason == REASON_BAD_SIGNATURE


@pytest.mark.parametrize(
    "field,value",
    [
        ("tool", "githost-mcp_github_pr_merge"),
        ("args_hash", "0" * 16),
        ("agent_id", "sysadmin"),
        ("expires_at", 2**40),
        ("approval_id", "developer.bbbbbbbbbbbb"),
    ],
)
def test_tampered_field_is_bad_signature(key, field, value):
    """Editing a signed field after signing — the agent's only move — breaks the signature."""
    outer = json.loads(_signed(key))
    outer["statement"][field] = value
    assert _verify(json.dumps(outer), key).reason == REASON_BAD_SIGNATURE


def test_signature_does_not_cover_a_different_domain(key):
    """A signature over the bare canonical JSON (no domain prefix) never verifies."""
    st = build_statement(agent_id=AGENT, approval_id=f"{AGENT}.a1", tool=TOOL, args_hash=HASH)
    import base64

    # Built independently of _canonical_bytes, so dropping the prefix there is caught.
    bare = json.dumps(st, sort_keys=True, separators=(",", ":")).encode()
    assert _canonical_bytes(st).endswith(bare) and _canonical_bytes(st) != bare
    raw = json.dumps({"statement": st, "sig": base64.b64encode(key.sign(bare)).decode()})
    assert _verify(raw, key).reason == REASON_BAD_SIGNATURE


def test_bad_version(key):
    assert _verify(_signed(key, v=2), key).reason == REASON_BAD_VERSION


def test_agent_mismatch(key):
    assert _verify(_signed(key), key, agent_id="sysadmin").reason == REASON_AGENT_MISMATCH


def test_tool_mismatch(key):
    assert _verify(_signed(key), key, tool="other_tool").reason == REASON_TOOL_MISMATCH


def test_args_mismatch(key):
    assert _verify(_signed(key), key, args_hash="f" * 16).reason == REASON_ARGS_MISMATCH


def test_expired(key):
    now = time.time()
    raw = _signed(key, issued_at=int(now) - 200, expires_at=int(now) - 100)
    assert _verify(raw, key).reason == REASON_EXPIRED


def test_expiry_boundary_is_exclusive(key):
    raw = _signed(key)
    exp = json.loads(raw)["statement"]["expires_at"]
    assert _verify(raw, key, now=exp - 1).ok
    assert _verify(raw, key, now=exp).reason == REASON_EXPIRED


def test_not_yet_valid(key):
    now = int(time.time())
    raw = _signed(key, issued_at=now + 60, expires_at=now + 90)
    assert _verify(raw, key).reason == REASON_NOT_YET_VALID


def test_lifetime_too_long(key):
    now = int(time.time())
    raw = _signed(key, issued_at=now, expires_at=now + MAX_LIFETIME_SECONDS + 1)
    assert _verify(raw, key).reason == REASON_LIFETIME_TOO_LONG


def test_build_statement_refuses_long_lifetime():
    with pytest.raises(ValueError):
        build_statement(
            agent_id=AGENT, approval_id="a.b", tool=TOOL, args_hash=HASH, lifetime_seconds=121
        )


def test_consumed_set_expires_entries():
    s = ConsumedSet()
    s.add("a.1", expires_at=100)
    assert s.contains("a.1", now=50)
    assert not s.contains("a.1", now=10_000)
    assert len(s) == 0


# ── middleware: enforce ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_enforce_end_to_end_via_approver(key):
    """Reject → the approver signs → the retry runs, and logs hitl_signature_ok."""
    redis = FakeRedis()
    mw = _mw(PrefixedState(redis, AGENT), "enforce", key)

    with pytest.raises(HitlRejectedError) as ei:
        await mw(None, TOOL, dict(ARGS), _executed)
    aid = _approval_id_from(ei.value)

    rc = await hitl_approver.run(
        aid, deny=False, client=redis, private_key=key, confirm=lambda _p: True
    )
    assert rc == hitl_approver.EXIT_OK

    with structlog.testing.capture_logs() as logs:
        assert await mw(None, TOOL, dict(ARGS), _executed) == "EXECUTED"
    events = [e["event"] for e in logs]
    assert "hitl_signature_ok" in events and "hitl_preapproved" in events


@pytest.mark.asyncio
async def test_enforce_refuses_unsigned_token(key):
    """A hand-written token — the shape every retired writer produced — is no approval."""
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, "enforce", key)
    await state.set_with_ttl(
        _preapproval_key(TOOL, HASH), json.dumps({"status": "approved", "approval_id": "x"}), 300
    )
    with structlog.testing.capture_logs() as logs, pytest.raises(HitlRejectedError):
        await mw(None, TOOL, dict(ARGS), _executed)
    rej = [e for e in logs if e["event"] == "hitl_signature_rejected"]
    assert rej and rej[0]["reason"] == REASON_MALFORMED and rej[0]["accepted"] is False
    # No value from the token appears in the rejection line.
    assert "approved" not in json.dumps(rej[0], default=str).replace("accepted", "")


@pytest.mark.asyncio
async def test_enforce_refuses_other_key(key):
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, "enforce", key)
    await state.set_with_ttl(
        _preapproval_key(TOOL, HASH), _signed(Ed25519PrivateKey.generate()), 120
    )
    with structlog.testing.capture_logs() as logs, pytest.raises(HitlRejectedError):
        await mw(None, TOOL, dict(ARGS), _executed)
    assert [e["reason"] for e in logs if e["event"] == "hitl_signature_rejected"] == [
        REASON_BAD_SIGNATURE
    ]


@pytest.mark.asyncio
async def test_enforce_refuses_expired(key):
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, "enforce", key)
    now = int(time.time())
    await state.set_with_ttl(
        _preapproval_key(TOOL, HASH), _signed(key, issued_at=now - 300, expires_at=now - 200), 120
    )
    with structlog.testing.capture_logs() as logs, pytest.raises(HitlRejectedError):
        await mw(None, TOOL, dict(ARGS), _executed)
    assert [e["reason"] for e in logs if e["event"] == "hitl_signature_rejected"] == [
        REASON_EXPIRED
    ]


@pytest.mark.asyncio
async def test_enforce_refuses_replay(key):
    """Writing the consumed signed bytes back must not approve a second call."""
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, "enforce", key)
    raw = _signed(key)
    await state.set_with_ttl(_preapproval_key(TOOL, HASH), raw, 120)
    assert await mw(None, TOOL, dict(ARGS), _executed) == "EXECUTED"

    await state.set_with_ttl(_preapproval_key(TOOL, HASH), raw, 120)  # the replay
    with structlog.testing.capture_logs() as logs, pytest.raises(HitlRejectedError):
        await mw(None, TOOL, dict(ARGS), _executed)
    assert [e["reason"] for e in logs if e["event"] == "hitl_signature_rejected"] == [
        REASON_REPLAYED
    ]


@pytest.mark.asyncio
async def test_enforce_signature_for_other_args_does_not_approve(key):
    """A valid statement for harmless args is useless for harmful ones: different key, and
    even if copied under the harmful key, args_hash no longer matches."""
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, "enforce", key)
    harmful = {**ARGS, "repo": "org/other"}
    await state.set_with_ttl(
        _preapproval_key(TOOL, _canonical_args_hash(harmful)), _signed(key), 120
    )
    with structlog.testing.capture_logs() as logs, pytest.raises(HitlRejectedError):
        await mw(None, TOOL, harmful, _executed)
    assert [e["reason"] for e in logs if e["event"] == "hitl_signature_rejected"] == [
        REASON_ARGS_MISMATCH
    ]


@pytest.mark.asyncio
async def test_enforce_rejection_message_names_the_approve_command(key):
    mw = _mw(
        PrefixedState(FakeRedis(), AGENT),
        "enforce",
        key,
        hint="sudo -u approver scoped-mcp-approve",
    )
    with pytest.raises(HitlRejectedError) as ei:
        await mw(None, TOOL, dict(ARGS), _executed)
    msg = str(ei.value)
    assert "sudo -u approver scoped-mcp-approve " + _approval_id_from(ei.value) in msg
    assert "scoped-mcp hitl approve" not in msg


@pytest.mark.asyncio
async def test_signing_on_stores_canonical_arguments(key):
    redis = FakeRedis()
    mw = _mw(PrefixedState(redis, AGENT), "enforce", key)
    with pytest.raises(HitlRejectedError) as ei:
        await mw(None, TOOL, dict(ARGS), _executed)
    rec = json.loads(redis.store[f"scoped-mcp:{AGENT}:hitl:{_approval_id_from(ei.value)}"])
    assert rec["arguments"] == ARGS
    assert _canonical_args_hash(rec["arguments"]) == rec["args_hash"]


# ── middleware: observe and off ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_observe_accepts_unsigned_but_logs_it(key):
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, "observe", key)
    await state.set_with_ttl(_preapproval_key(TOOL, HASH), json.dumps({"status": "approved"}), 300)
    with structlog.testing.capture_logs() as logs:
        assert await mw(None, TOOL, dict(ARGS), _executed) == "EXECUTED"
    rej = [e for e in logs if e["event"] == "hitl_signature_rejected"]
    assert rej and rej[0]["accepted"] is True and rej[0]["signing_mode"] == "observe"


@pytest.mark.asyncio
async def test_observe_logs_signature_ok(key):
    state = PrefixedState(FakeRedis(), AGENT)
    mw = _mw(state, "observe", key)
    await state.set_with_ttl(_preapproval_key(TOOL, HASH), _signed(key), 120)
    with structlog.testing.capture_logs() as logs:
        assert await mw(None, TOOL, dict(ARGS), _executed) == "EXECUTED"
    assert "hitl_signature_ok" in [e["event"] for e in logs]


@pytest.mark.asyncio
async def test_off_is_unchanged(key):
    """Default mode: any token approves, nothing is verified, no arguments are stored."""
    redis = FakeRedis()
    state = PrefixedState(redis, AGENT)
    mw = _mw(state, "off", None)
    with pytest.raises(HitlRejectedError) as ei:
        await mw(None, TOOL, dict(ARGS), _executed)
    rec = json.loads(redis.store[f"scoped-mcp:{AGENT}:hitl:{_approval_id_from(ei.value)}"])
    assert "arguments" not in rec
    assert "scoped-mcp hitl approve" in str(ei.value)
    await state.set_with_ttl(_preapproval_key(TOOL, HASH), "anything", 300)
    with structlog.testing.capture_logs() as logs:
        assert await mw(None, TOOL, dict(ARGS), _executed) == "EXECUTED"
    assert not [e for e in logs if e["event"].startswith("hitl_signature")]


def test_middleware_refuses_signing_without_key():
    with pytest.raises(ValueError):
        _mw(PrefixedState(FakeRedis(), AGENT), "enforce", None)


# ── the approver ────────────────────────────────────────────────────────────


async def _pending(redis: FakeRedis, key: Ed25519PrivateKey, args: dict | None = None) -> str:
    mw = _mw(PrefixedState(redis, AGENT), "enforce", key)
    with pytest.raises(HitlRejectedError) as ei:
        await mw(None, TOOL, dict(args or ARGS), _executed)
    return _approval_id_from(ei.value)


@pytest.mark.asyncio
async def test_approver_refuses_summary_hash_swap(key):
    """The agent writes a pending record pairing harmless arguments with the hash of
    harmful ones. The approver recomputes the hash and refuses to sign."""
    redis = FakeRedis()
    aid = await _pending(redis, key)
    k = f"scoped-mcp:{AGENT}:hitl:{aid}"
    rec = json.loads(redis.store[k])
    rec["args_hash"] = _canonical_args_hash({**ARGS, "repo": "org/other"})
    redis.store[k] = json.dumps(rec)

    rc = await hitl_approver.run(
        aid, deny=False, client=redis, private_key=key, confirm=lambda _p: True
    )
    assert rc == hitl_approver.EXIT_MISMATCH
    assert not [x for x in redis.store if ":preapproved:" in x]


@pytest.mark.asyncio
async def test_approver_refuses_record_without_arguments(key):
    redis = FakeRedis()
    aid = await _pending(redis, key)
    k = f"scoped-mcp:{AGENT}:hitl:{aid}"
    rec = json.loads(redis.store[k])
    del rec["arguments"]
    redis.store[k] = json.dumps(rec)
    rc = await hitl_approver.run(
        aid, deny=False, client=redis, private_key=key, confirm=lambda _p: True
    )
    assert rc == hitl_approver.EXIT_MISMATCH


@pytest.mark.asyncio
async def test_approver_refuses_agent_mismatch_in_record(key):
    redis = FakeRedis()
    aid = await _pending(redis, key)
    k = f"scoped-mcp:{AGENT}:hitl:{aid}"
    rec = json.loads(redis.store[k])
    rec["agent_id"] = "sysadmin"
    redis.store[k] = json.dumps(rec)
    rc = await hitl_approver.run(
        aid, deny=False, client=redis, private_key=key, confirm=lambda _p: True
    )
    assert rc == hitl_approver.EXIT_MISMATCH


@pytest.mark.asyncio
async def test_approver_no_leaves_request_pending(key):
    redis = FakeRedis()
    aid = await _pending(redis, key)
    rc = await hitl_approver.run(
        aid, deny=False, client=redis, private_key=key, confirm=lambda _p: False
    )
    assert rc == hitl_approver.EXIT_REFUSED
    assert f"scoped-mcp:{AGENT}:hitl:{aid}" in redis.store
    assert not [x for x in redis.store if ":preapproved:" in x]


@pytest.mark.asyncio
async def test_approver_deny_drops_request(key):
    redis = FakeRedis()
    aid = await _pending(redis, key)
    rc = await hitl_approver.run(aid, deny=True, client=redis, private_key=None, confirm=None)
    assert rc == hitl_approver.EXIT_OK
    assert not [x for x in redis.store if aid in x]


@pytest.mark.asyncio
async def test_approver_unknown_id(key):
    rc = await hitl_approver.run(
        f"{AGENT}.000000000000",
        deny=False,
        client=FakeRedis(),
        private_key=key,
        confirm=lambda _p: True,
    )
    assert rc == hitl_approver.EXIT_NOT_FOUND


@pytest.mark.asyncio
async def test_approver_refuses_if_record_changes_during_prompt(key):
    redis = FakeRedis()
    aid = await _pending(redis, key)
    k = f"scoped-mcp:{AGENT}:hitl:{aid}"

    def swap(_p: str) -> bool:
        rec = json.loads(redis.store[k])
        rec["timestamp"] = 0
        redis.store[k] = json.dumps(rec)
        return True

    rc = await hitl_approver.run(aid, deny=False, client=redis, private_key=key, confirm=swap)
    assert rc == hitl_approver.EXIT_MISMATCH
    assert not [x for x in redis.store if ":preapproved:" in x]


def test_render_escapes_terminal_control_and_bidi():
    rec = {
        "agent_id": AGENT,
        "tool": "t\x1b[2K",
        "approval_id": "a.b",
        "arguments": {"command": "ls\rrm -rf /‮", "token": "s3cret"},
    }
    out = hitl_approver.render_request(rec)
    assert "\x1b" not in out and "\r" not in out and "‮" not in out
    assert "rm -rf /" in out  # shown, not hidden
    assert "s3cret" not in out  # sensitive key redacted


def test_render_does_not_truncate():
    long = "x" * 5000 + "TAIL"
    rec = {"agent_id": AGENT, "tool": TOOL, "approval_id": "a.b", "arguments": {"body": long}}
    assert "TAIL" in hitl_approver.render_request(rec)


def test_approver_main_requires_a_terminal(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert hitl_approver.main([f"{AGENT}.aaaaaaaaaaaa"]) == hitl_approver.EXIT_REFUSED


def test_parse_approval_id():
    assert hitl_approver.parse_approval_id("sysadmin-01.26964c0a776b") == "sysadmin-01"
    assert hitl_approver.parse_approval_id("nodot") is None
    assert hitl_approver.parse_approval_id("a.") is None
    assert hitl_approver.parse_approval_id("a.b:c") is None


# ── key and config files ────────────────────────────────────────────────────


def _write_pem(path, key, private: bool, mode: int) -> None:
    if private:
        data = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    else:
        data = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    path.write_bytes(data)
    os.chmod(path, mode)


def test_private_key_permissions_are_checked(tmp_path, key):
    p = tmp_path / "k.pem"
    _write_pem(p, key, private=True, mode=0o644)
    with pytest.raises(SigningKeyError, match="0644"):
        load_private_key(p)
    os.chmod(p, 0o400)
    assert (
        load_private_key(p).public_key().public_bytes_raw() == key.public_key().public_bytes_raw()
    )


def test_non_ed25519_keys_are_refused(tmp_path):
    ecd = ec.generate_private_key(ec.SECP256R1())
    priv, pub = tmp_path / "ec.pem", tmp_path / "ec.pub"
    _write_pem(priv, ecd, private=True, mode=0o600)
    _write_pem(pub, ecd, private=False, mode=0o644)
    with pytest.raises(SigningKeyError, match="Ed25519"):
        load_private_key(priv)
    with pytest.raises(SigningKeyError, match="Ed25519"):
        load_public_key(pub)


def test_config_permissions_are_checked(tmp_path):
    p = tmp_path / "approver.yml"
    p.write_text("state_url: redis://x\nprivate_key_path: /k\n")
    os.chmod(p, 0o640)
    with pytest.raises(SigningKeyError):
        hitl_approver.load_config(p)
    os.chmod(p, 0o600)
    assert hitl_approver.load_config(p)["state_url"] == "redis://x"


def test_check_owner_only_refuses_directory(tmp_path):
    with pytest.raises(SigningKeyError):
        check_owner_only(tmp_path)


# ── manifest and retired routes ─────────────────────────────────────────────


def test_manifest_refuses_interactive_with_enforce():
    with pytest.raises(ValueError, match="interactive"):
        HitlConfig(
            mode="interactive",
            approval_required=["*"],
            signing={"mode": "enforce", "public_key_path": "/k.pub"},
        )


def test_manifest_allows_interactive_with_observe():
    cfg = HitlConfig(mode="interactive", signing={"mode": "observe", "public_key_path": "/k.pub"})
    assert cfg.signing.mode == "observe"


def test_manifest_requires_key_when_signing():
    with pytest.raises(ValueError, match="public_key_path"):
        HitlConfig(signing={"mode": "enforce"})


def test_manifest_default_is_off():
    assert HitlConfig().signing.mode == "off"


def test_build_middleware_fails_closed_on_missing_key(tmp_path):
    from scoped_mcp.exceptions import ConfigError
    from scoped_mcp.hitl import build_hitl_middleware

    cfg = HitlConfig(
        approval_required=["*"],
        signing={"mode": "enforce", "public_key_path": str(tmp_path / "absent.pub")},
    )
    with pytest.raises(ConfigError):
        build_hitl_middleware(cfg, PrefixedState(FakeRedis(), AGENT), AGENT, "build")


def _manifest(tmp_path, signing_mode: str, pub) -> str:
    p = tmp_path / "m.yaml"
    p.write_text(
        "agent_type: build\nmodules:\n  filesystem:\n    mode: read\n"
        "    config:\n      base_path: /tmp/x\n"
        "state_backend:\n  type: dragonfly\n  url: 'redis://localhost:6379/15'\n"
        "hitl:\n  approval_required: ['*']\n"
        f"  signing:\n    mode: {signing_mode}\n    public_key_path: {pub}\n"
        "    approve_command: sudo -u approver scoped-mcp-approve\n"
    )
    return str(p)


def test_cli_approve_refuses_under_enforce(tmp_path, key, capsys):
    pub = tmp_path / "k.pub"
    _write_pem(pub, key, private=False, mode=0o444)
    ns = argparse.Namespace(
        manifest=_manifest(tmp_path, "enforce", pub),
        hitl_command="approve",
        approval_id="developer.abc",
    )
    assert run_hitl_command(ns) == 4
    assert "sudo -u approver scoped-mcp-approve developer.abc" in capsys.readouterr().err


def test_manifest_file_with_signing_loads(tmp_path, key):
    pub = tmp_path / "k.pub"
    _write_pem(pub, key, private=False, mode=0o444)
    m = load_manifest(_manifest(tmp_path, "observe", pub))
    assert m.hitl.signing.mode == "observe"


def test_manifest_file_interactive_enforce_is_a_load_error(tmp_path, key):
    pub = tmp_path / "k.pub"
    _write_pem(pub, key, private=False, mode=0o444)
    path = _manifest(tmp_path, "enforce", pub)
    with open(path, "a") as f:
        f.write("  mode: interactive\n")
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_approve_route_absent_under_enforce(monkeypatch):
    from fastmcp import FastMCP
    from starlette.testclient import TestClient

    from scoped_mcp.hitl_http import register_hitl_routes
    from scoped_mcp.identity import AgentContext
    from scoped_mcp.state import InProcessBackend

    monkeypatch.setenv("SCOPED_MCP_HITL_TOKEN", "t")
    state = InProcessBackend()
    # A real pending record, so a live approve route would answer 200 and write a
    # token. A 404 is only meaningful if "not found" cannot be the route's answer.
    state._store[f"hitl:{AGENT}.abc"] = (
        json.dumps(
            {"tool": TOOL, "agent_id": AGENT, "args_hash": HASH, "approval_id": f"{AGENT}.abc"}
        ),
        time.monotonic() + 300,
    )
    server = FastMCP("scoped-mcp/test")
    register_hitl_routes(
        server,
        state,
        AgentContext(agent_id=AGENT, agent_type="build"),
        allow_unsigned_approve=False,
    )
    with TestClient(server.http_app()) as client:
        h = {"Authorization": "Bearer t"}
        r = client.post("/hitl/approve", json={"approval_id": f"{AGENT}.abc"}, headers=h)
        assert r.status_code in (404, 405)
        assert not [k for k in state._store if ":preapproved:" in k or "preapproved:" in k]
        pending = client.get("/hitl/pending", headers=h).json()["pending"]
        assert [p["approval_id"] for p in pending] == [f"{AGENT}.abc"]
        # deny still works: it only deletes
        d = client.post("/hitl/deny", json={"approval_id": f"{AGENT}.abc"}, headers=h)
        assert d.status_code == 200 and d.json()["status"] == "denied"


def test_every_reason_class_has_a_test():
    """Guard: a new reason class must come with a test that produces it."""
    src = open(__file__).read()
    for r in ALL_REASONS:
        const = "REASON_" + r.upper()
        assert src.count(const) >= 2, f"{const} is not exercised"
