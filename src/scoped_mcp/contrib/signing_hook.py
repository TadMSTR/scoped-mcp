"""agent-bus ed25519 signing hook for scoped-mcp.

Creates a pre-call hook (for use with hooks.register_before) that signs
agent-bus log_event payloads before they are forwarded to agent-bus.

The hook injects two fields into the event's ``metadata`` dict:
  - ``sig``    — base64-encoded ed25519 signature over the canonical payload
  - ``key_fp`` — first 8 hex chars of SHA-256(public key), for key rotation tracking

Requires: pip install scoped-mcp[vault]  (pulls in the cryptography package)

Usage::

    from scoped_mcp.contrib.signing_hook import create_signing_hook
    from scoped_mcp.hooks import register_before

    hook = create_signing_hook(
        private_key_b64=credentials["signing_private_key"],
        public_key_b64=credentials["signing_public_key"],
    )
    register_before("agent-bus", "log_event", hook)
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from typing import Any


def _compute_fingerprint(public_key_b64: str) -> str:
    """Return the first 8 hex chars of SHA-256(raw public key bytes)."""
    raw = base64.b64decode(public_key_b64)
    return hashlib.sha256(raw).hexdigest()[:8]


def create_signing_hook(
    private_key_b64: str,
    public_key_b64: str,
) -> Callable[[dict[str, Any]], Any]:
    """Return an async pre-call hook that signs log_event kwargs.

    Args:
        private_key_b64: base64-encoded 32-byte ed25519 private key (seed).
        public_key_b64:  base64-encoded 32-byte ed25519 public key.

    Returns:
        An async callable suitable for ``hooks.register_before``.

    Raises:
        ImportError: if the ``cryptography`` package is not installed.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise ImportError(
            "signing_hook requires the 'cryptography' package. "
            "Install with: pip install scoped-mcp[vault]"
        ) from exc

    private_key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
    key_fp = _compute_fingerprint(public_key_b64)

    async def sign_event_hook(kwargs: dict[str, Any]) -> dict[str, Any]:
        """Sign the log_event payload and inject sig + key_fp into metadata."""
        metadata: dict[str, Any] = dict(kwargs.get("metadata") or {})

        # key_fp is included in the signed payload so verifiers can identify
        # the key without accessing the full registry. Add it before canonicalization.
        metadata["key_fp"] = key_fp

        # Canonical payload: deterministic key order, no whitespace.
        # Exclude sig/prev_hash — sig is being computed now; prev_hash is added
        # by agent-bus after signing.
        payload = {
            "event_type": kwargs.get("event_type", ""),
            "source": kwargs.get("source", ""),
            "summary": kwargs.get("summary", ""),
            "scope": kwargs.get("scope", "cross-agent"),
            "target": kwargs.get("target"),
            "artifact_path": kwargs.get("artifact_path"),
            "metadata": {k: v for k, v in metadata.items() if k not in ("sig", "prev_hash")},
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        sig_bytes = private_key.sign(canonical.encode())

        metadata["sig"] = base64.b64encode(sig_bytes).decode()

        return {**kwargs, "metadata": metadata}

    return sign_event_hook
