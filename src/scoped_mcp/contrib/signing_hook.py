"""agent-bus ed25519 signing hook for scoped-mcp.

Creates a pre-call hook (for use with hooks.register_before) that signs
agent-bus log_event payloads before they are forwarded to agent-bus.

The hook injects these fields into the event's ``metadata`` dict:
  - ``sig``       — base64-encoded ed25519 signature over the canonical payload
  - ``key_fp``    — first 8 hex chars of SHA-256(public key), for key rotation tracking
  - ``sig_v``     — signature format version, ``2``
  - ``sig_ts``    — UTC ISO 8601 time of signing
  - ``sig_nonce`` — a fresh uuid4 per event

Everything but ``sig`` is added before canonicalisation, so the signature covers them.
That is what makes a v2 signature replay-checkable: agent-bus assigns the event's own
``ts`` and ``id`` after signing, so freshness and uniqueness have to come from the signer
(agent-bus ``_check_replay``). The guarantee agent-bus can then give is: a valid
signature, a nonce seen at most once per agent-bus process, and a signing time within
its window (``AGENT_BUS_SIG_MAX_AGE``, 120 s by default since agent-bus 0.7.1). Values a
caller put in those keys are overwritten.

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
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

# The signature format this hook emits. agent-bus replay-checks sig_v >= 2.
SIGNATURE_VERSION = 2


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
        """Sign the log_event payload and inject the v2 signature fields into metadata."""
        metadata: dict[str, Any] = dict(kwargs.get("metadata") or {})

        # key_fp is included in the signed payload so verifiers can identify
        # the key without accessing the full registry. The replay fields are signed
        # for the same reason: a verifier must be able to trust them. All of them
        # are added before canonicalization, overwriting anything the caller sent.
        metadata["key_fp"] = key_fp
        metadata["sig_v"] = SIGNATURE_VERSION
        metadata["sig_ts"] = datetime.now(UTC).isoformat()
        metadata["sig_nonce"] = str(uuid.uuid4())

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
