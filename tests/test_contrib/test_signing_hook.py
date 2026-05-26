"""Tests for contrib/signing_hook.py — ed25519 event signing."""

from __future__ import annotations

import base64
import json

import pytest


def _generate_keypair() -> tuple[str, str]:
    """Generate a fresh ed25519 keypair; return (private_b64, public_b64)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes_raw()
    public_bytes = private_key.public_key().public_bytes_raw()
    return base64.b64encode(private_bytes).decode(), base64.b64encode(public_bytes).decode()


@pytest.mark.asyncio
async def test_signing_hook_injects_sig_and_key_fp() -> None:
    from scoped_mcp.contrib.signing_hook import create_signing_hook

    priv, pub = _generate_keypair()
    hook = create_signing_hook(priv, pub)

    kwargs = {
        "event_type": "build-plan.created",
        "source": "dev",
        "summary": "something happened",
    }
    result = await hook(kwargs)
    assert "sig" in result["metadata"]
    assert "key_fp" in result["metadata"]
    assert len(result["metadata"]["key_fp"]) == 8  # first 8 hex chars


@pytest.mark.asyncio
async def test_signing_hook_sig_is_valid_ed25519() -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from scoped_mcp.contrib.signing_hook import create_signing_hook

    priv, pub = _generate_keypair()
    hook = create_signing_hook(priv, pub)

    kwargs = {
        "event_type": "task.dispatched",
        "source": "research",
        "summary": "dispatched a task",
        "scope": "cross-agent",
        "target": "dev",
        "artifact_path": None,
        "metadata": {},
    }
    result = await hook(kwargs)

    sig = base64.b64decode(result["metadata"]["sig"])
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub))

    # Reconstruct canonical payload (same as signing_hook.py)
    metadata = {k: v for k, v in result["metadata"].items() if k not in ("sig", "prev_hash")}
    payload = {
        "event_type": result["event_type"],
        "source": result["source"],
        "summary": result["summary"],
        "scope": result.get("scope", "cross-agent"),
        "target": result.get("target"),
        "artifact_path": result.get("artifact_path"),
        "metadata": metadata,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    # Should not raise
    public_key.verify(sig, canonical.encode())


@pytest.mark.asyncio
async def test_signing_hook_preserves_existing_metadata() -> None:
    from scoped_mcp.contrib.signing_hook import create_signing_hook

    priv, pub = _generate_keypair()
    hook = create_signing_hook(priv, pub)

    kwargs = {
        "event_type": "session.started",
        "source": "dev",
        "summary": "session",
        "metadata": {"session_id": "abc-123", "outcome": "ok"},
    }
    result = await hook(kwargs)
    assert result["metadata"]["session_id"] == "abc-123"
    assert result["metadata"]["outcome"] == "ok"
    assert "sig" in result["metadata"]


@pytest.mark.asyncio
async def test_signing_hook_excludes_sig_from_canonical_payload() -> None:
    """Two calls with different sig values in metadata produce the same canonical payload."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from scoped_mcp.contrib.signing_hook import create_signing_hook

    priv, pub = _generate_keypair()
    hook = create_signing_hook(priv, pub)

    base_kwargs = {
        "event_type": "session.started",
        "source": "dev",
        "summary": "hi",
        "metadata": {},
    }
    # First call
    r1 = await hook(dict(base_kwargs))
    # Second call with stale sig in metadata — sig field must be excluded from canonical
    r2 = await hook({**base_kwargs, "metadata": {"sig": "stale_sig"}})

    # Both signatures should be valid
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub))
    for r in (r1, r2):
        sig = base64.b64decode(r["metadata"]["sig"])
        metadata = {k: v for k, v in r["metadata"].items() if k not in ("sig", "prev_hash")}
        payload = {
            "event_type": r["event_type"],
            "source": r["source"],
            "summary": r["summary"],
            "scope": r.get("scope", "cross-agent"),
            "target": r.get("target"),
            "artifact_path": r.get("artifact_path"),
            "metadata": metadata,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        public_key.verify(sig, canonical.encode())  # should not raise
