"""Tests for hitl_cli.py — operator HITL approval CLI."""

from __future__ import annotations

import argparse
import json

import pytest

from scoped_mcp.hitl_cli import (
    _decide,
    _key_for,
    _list_pending,
    _parse_approval_id,
    _preapproval_key_for,
    run_hitl_command,
)

# ── Pure unit tests (no Redis) ─────────────────────────────────────────────────


class TestParseApprovalId:
    def test_valid_returns_tuple(self):
        assert _parse_approval_id("agent-1.abcdef123456") == ("agent-1", "abcdef123456")

    def test_no_dot_returns_none(self):
        assert _parse_approval_id("nodot") is None

    def test_empty_agent_id_returns_none(self):
        assert _parse_approval_id(".abcdef123456") is None

    def test_empty_suffix_returns_none(self):
        assert _parse_approval_id("agent-1.") is None

    def test_rsplit_on_last_dot(self):
        # agent_id may contain dots — rsplit limit=1 splits on the last one
        result = _parse_approval_id("agent.with.dots.suffix")
        assert result == ("agent.with.dots", "suffix")


class TestKeyFor:
    def test_well_formed(self):
        assert _key_for("agent-1.abcdef123456") == "scoped-mcp:agent-1:hitl:agent-1.abcdef123456"

    def test_malformed_raises(self):
        with pytest.raises(ValueError, match="malformed"):
            _key_for("no-dot")


class TestPreapprovalKeyFor:
    def test_structure(self):
        key = _preapproval_key_for("agent-1", "githost-mcp_git_push", "abc123def45678")
        assert key == "scoped-mcp:agent-1:hitl:preapproved:githost-mcp_git_push:abc123def45678"


class TestRunHitlCommandNoRedis:
    def _make_args(self, tmp_path, manifest_yaml, hitl_command="list", **extra):
        p = tmp_path / "manifest.yaml"
        p.write_text(manifest_yaml)
        return argparse.Namespace(manifest=str(p), hitl_command=hitl_command, **extra)

    def test_missing_manifest_returns_1(self, tmp_path):
        ns = argparse.Namespace(
            manifest=str(tmp_path / "nonexistent.yaml"),
            hitl_command="list",
        )
        assert run_hitl_command(ns) == 1

    def test_in_process_backend_returns_1(self, tmp_path):
        yaml = (
            "agent_id: test-agent\nagent_type: research\n"
            "credential_source:\n  type: env\nmodules: []\n"
        )
        ns = self._make_args(tmp_path, yaml)
        assert run_hitl_command(ns) == 1

    def test_unknown_subcommand_returns_1(self, tmp_path):
        yaml = (
            "agent_id: test-agent\nagent_type: research\n"
            "credential_source:\n  type: env\nmodules: []\n"
            "state_backend:\n  type: dragonfly\n  url: 'redis://localhost:6379/15'\n"
        )
        ns = self._make_args(tmp_path, yaml, hitl_command="bogus-command")
        assert run_hitl_command(ns) == 1


# ── Async integration tests (require Redis on localhost:6379) ──────────────────

_REDIS_URL = "redis://localhost:6379/15"


@pytest.mark.asyncio
async def test_list_pending_empty(redis_client, capsys):
    rc = await _list_pending(_REDIS_URL, _client=redis_client)
    assert rc == 0
    assert "(no pending approvals)" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_list_pending_with_entry(redis_client, capsys):
    approval_id = "test-agent-1.aabbcc112233"
    key = f"scoped-mcp:test-agent-1:hitl:{approval_id}"
    payload = json.dumps(
        {"approval_id": approval_id, "agent_id": "test-agent-1", "tool": "git_push"}
    )
    await redis_client.set(key, payload, ex=60)
    try:
        rc = await _list_pending(_REDIS_URL, _client=redis_client)
        assert rc == 0
        out = capsys.readouterr().out
        assert approval_id in out
        assert "git_push" in out
    finally:
        await redis_client.delete(key)


@pytest.mark.asyncio
async def test_list_pending_skips_preapproval_keys(redis_client, capsys):
    pre_key = "scoped-mcp:test-agent-1:hitl:preapproved:git_push"
    await redis_client.set(pre_key, "approved", ex=60)
    try:
        rc = await _list_pending(_REDIS_URL, _client=redis_client)
        assert rc == 0
        out = capsys.readouterr().out
        # Pre-approval key must not surface as a pending approval
        assert "preapproved" not in out
    finally:
        await redis_client.delete(pre_key)


@pytest.mark.asyncio
async def test_decide_approve_writes_preapproval_and_deletes_pending(redis_client):
    approval_id = "test-agent-1.ddeeff445566"
    pending_key = f"scoped-mcp:test-agent-1:hitl:{approval_id}"
    args_hash = "deadbeef01234567"
    pre_key = f"scoped-mcp:test-agent-1:hitl:preapproved:git_push:{args_hash}"
    payload = json.dumps(
        {
            "approval_id": approval_id,
            "agent_id": "test-agent-1",
            "tool": "git_push",
            "args_hash": args_hash,
        }
    )
    await redis_client.set(pending_key, payload, ex=60)
    try:
        rc = await _decide(_REDIS_URL, approval_id, "approve", _client=redis_client)
        assert rc == 0
        assert await redis_client.get(pending_key) is None
        assert await redis_client.get(pre_key) == "approved"
    finally:
        await redis_client.delete(pending_key)
        await redis_client.delete(pre_key)


@pytest.mark.asyncio
async def test_decide_reject_deletes_pending_no_preapproval(redis_client):
    approval_id = "test-agent-1.778899aabbcc"
    pending_key = f"scoped-mcp:test-agent-1:hitl:{approval_id}"
    pre_key = "scoped-mcp:test-agent-1:hitl:preapproved:git_push"
    payload = json.dumps(
        {"approval_id": approval_id, "agent_id": "test-agent-1", "tool": "git_push"}
    )
    await redis_client.set(pending_key, payload, ex=60)
    try:
        rc = await _decide(_REDIS_URL, approval_id, "reject", _client=redis_client)
        assert rc == 0
        assert await redis_client.get(pending_key) is None
        assert await redis_client.get(pre_key) is None
    finally:
        await redis_client.delete(pending_key)
        await redis_client.delete(pre_key)


@pytest.mark.asyncio
async def test_decide_missing_approval_id_returns_3(redis_client):
    rc = await _decide(_REDIS_URL, "test-agent-1.nonexistentabc", "approve", _client=redis_client)
    assert rc == 3
