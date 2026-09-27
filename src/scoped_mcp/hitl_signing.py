"""Signed HITL approval statements (Ed25519).

Before this module, a HITL pre-approval was *the existence of a state key*:
``hitl.py`` forwarded a gated call if ``hitl:preapproved:{tool}:{args_hash}``
existed and never read its value. Anything that could write the state backend
could approve — and the requesting agent can usually reach the backend.

With ``hitl.signing.mode`` set to ``observe`` or ``enforce``, the value of that
key must be a **statement signed by an approver key** whose public half is named
in the manifest. The private half belongs to an operator-controlled account the
agent cannot read, so writing the key forges nothing.

Statement (canonical JSON, signed with Ed25519)::

    {v, agent_id, approval_id, tool, args_sha256, issued_at, expires_at}

``args_sha256`` is ``hitl._canonical_args_digest`` — the FULL SHA-256 of the
canonical arguments. The 16-hex ``args_hash`` that names the state key is a
prefix of the same digest and is never what a signature binds: the requesting
agent picks both the arguments it shows and the ones it runs, so 64 bits would
let it birthday-search a colliding pair (~2^32 work). Stored value::

    {"statement": {...}, "sig": "<base64>", "approval_id": "<id>"}

The top-level ``approval_id`` is advisory (it predates signing and is read by
audit code); only the signed ``statement.approval_id`` is ever trusted.

The signed bytes are a fixed domain-separation prefix followed by the canonical
JSON, so a signature made by this key for any other purpose can never verify as
an approval.

This module is shared by the verifier (``hitl.HitlMiddleware``) and the signer
(``hitl_approver``). Keep them on one definition of the statement.
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

STATEMENT_VERSION = 1

# Upper bound on expires_at - issued_at. Short on purpose: a signed statement
# sits in a backend the agent can write, so its lifetime is the replay window
# that the in-process consumed-set has to cover.
MAX_LIFETIME_SECONDS = 120

# Tolerated clock difference between signer and verifier. Both normally run on
# the same host; this only absorbs sub-second rounding and small drift.
CLOCK_SKEW_SECONDS = 5

_DOMAIN = b"scoped-mcp/hitl-approval/v1\n"

_FIELDS = ("v", "agent_id", "approval_id", "tool", "args_sha256", "issued_at", "expires_at")

# Rejection reason classes. Logged as-is; never accompanied by the values that
# failed, so a rejection log line cannot be used to learn what would pass.
REASON_MALFORMED = "malformed"
REASON_BAD_VERSION = "bad_version"
REASON_BAD_SIGNATURE = "bad_signature"
REASON_AGENT_MISMATCH = "agent_mismatch"
REASON_TOOL_MISMATCH = "tool_mismatch"
REASON_ARGS_MISMATCH = "args_mismatch"
REASON_EXPIRED = "expired"
REASON_NOT_YET_VALID = "not_yet_valid"
REASON_LIFETIME_TOO_LONG = "lifetime_too_long"
REASON_REPLAYED = "replayed"

ALL_REASONS = (
    REASON_MALFORMED,
    REASON_BAD_VERSION,
    REASON_BAD_SIGNATURE,
    REASON_AGENT_MISMATCH,
    REASON_TOOL_MISMATCH,
    REASON_ARGS_MISMATCH,
    REASON_EXPIRED,
    REASON_NOT_YET_VALID,
    REASON_LIFETIME_TOO_LONG,
    REASON_REPLAYED,
)


class SigningKeyError(Exception):
    """A key file is missing, unreadable, not Ed25519, or unsafely permissioned."""


def _canonical_bytes(statement: dict[str, Any]) -> bytes:
    body = {k: statement[k] for k in _FIELDS}
    return _DOMAIN + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def build_statement(
    *,
    agent_id: str,
    approval_id: str,
    tool: str,
    args_sha256: str,
    lifetime_seconds: int = MAX_LIFETIME_SECONDS,
    now: float | None = None,
) -> dict[str, Any]:
    if not 0 < lifetime_seconds <= MAX_LIFETIME_SECONDS:
        raise ValueError(f"lifetime_seconds must be in 1..{MAX_LIFETIME_SECONDS}")
    if len(args_sha256) != 64:
        raise ValueError("args_sha256 must be a full 64-hex SHA-256 digest")
    issued = int(time.time() if now is None else now)
    return {
        "v": STATEMENT_VERSION,
        "agent_id": agent_id,
        "approval_id": approval_id,
        "tool": tool,
        "args_sha256": args_sha256,
        "issued_at": issued,
        "expires_at": issued + lifetime_seconds,
    }


def sign_statement(private_key: Any, statement: dict[str, Any]) -> str:
    """Sign a statement and return the JSON value to store as the pre-approval token."""
    sig = private_key.sign(_canonical_bytes(statement))
    return json.dumps(
        {
            "statement": statement,
            "sig": base64.b64encode(sig).decode(),
            "approval_id": statement["approval_id"],
        },
        sort_keys=True,
    )


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: str | None = None
    approval_id: str | None = None
    expires_at: int | None = None


def verify_statement(
    raw: str,
    *,
    public_key: Any,
    agent_id: str,
    tool: str,
    args_sha256: str,
    now: float | None = None,
) -> VerifyResult:
    """Check a stored pre-approval value against the call it is meant to authorise.

    Order matters: the signature is checked before any field is compared, so an
    unsigned value can never produce a reason class that depends on its content.
    Replay is NOT checked here — that needs state the caller owns (the
    middleware's consumed-set).
    """
    from cryptography.exceptions import InvalidSignature

    try:
        outer = json.loads(raw)
        statement = outer["statement"]
        sig = base64.b64decode(outer["sig"], validate=True)
        if not isinstance(statement, dict) or set(statement) != set(_FIELDS):
            return VerifyResult(False, REASON_MALFORMED)
        signed = _canonical_bytes(statement)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, binascii.Error):
        return VerifyResult(False, REASON_MALFORMED)

    try:
        public_key.verify(sig, signed)
    except InvalidSignature:
        return VerifyResult(False, REASON_BAD_SIGNATURE)

    if statement["v"] != STATEMENT_VERSION:
        return VerifyResult(False, REASON_BAD_VERSION)
    issued, expires = statement["issued_at"], statement["expires_at"]
    if not isinstance(issued, int) or not isinstance(expires, int):
        return VerifyResult(False, REASON_MALFORMED)
    if statement["agent_id"] != agent_id:
        return VerifyResult(False, REASON_AGENT_MISMATCH)
    if statement["tool"] != tool:
        return VerifyResult(False, REASON_TOOL_MISMATCH)
    if statement["args_sha256"] != args_sha256:
        return VerifyResult(False, REASON_ARGS_MISMATCH)
    if expires - issued > MAX_LIFETIME_SECONDS:
        return VerifyResult(False, REASON_LIFETIME_TOO_LONG)
    t = time.time() if now is None else now
    if issued > t + CLOCK_SKEW_SECONDS:
        return VerifyResult(False, REASON_NOT_YET_VALID)
    if t >= expires:
        return VerifyResult(False, REASON_EXPIRED)
    approval_id = statement["approval_id"]
    if not isinstance(approval_id, str) or not approval_id:
        return VerifyResult(False, REASON_MALFORMED)
    return VerifyResult(True, None, approval_id, expires)


class ConsumedSet:
    """approval_ids already used, held until their statement could no longer verify.

    Needed because the signed value lives in a backend the agent can write: after
    the middleware deletes a consumed token, the agent could write the same signed
    bytes back and call again within the statement's lifetime. The signature is
    still valid; only memory of having used it stops the replay.

    In-process by design. It covers every call into one scoped-mcp process. It
    does NOT survive a restart and is not shared between processes serving the
    same agent_id (e.g. several stdio sessions) — see SECURITY.md.
    """

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def _prune(self, now: float) -> None:
        for aid in [a for a, until in self._seen.items() if until <= now]:
            del self._seen[aid]

    def contains(self, approval_id: str, now: float | None = None) -> bool:
        self._prune(time.time() if now is None else now)
        return approval_id in self._seen

    def add(self, approval_id: str, expires_at: int) -> None:
        self._seen[approval_id] = expires_at + CLOCK_SKEW_SECONDS

    def __len__(self) -> int:
        return len(self._seen)


def load_public_key(path: str | Path) -> Any:
    """Load an Ed25519 public key from a PEM (SubjectPublicKeyInfo) file."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        data = Path(path).read_bytes()
    except OSError as e:
        raise SigningKeyError(f"cannot read public key {path}: {type(e).__name__}") from None
    try:
        key = load_pem_public_key(data)
    except ValueError:
        raise SigningKeyError(f"public key {path} is not a PEM public key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise SigningKeyError(f"public key {path} is not Ed25519")
    return key


def check_owner_only(path: str | Path) -> None:
    """Refuse a secret file that anyone but its owner can read or write.

    Checked with stat, not assumed: the whole scheme rests on the private key
    being readable by the approver account alone.
    """
    import os
    import stat as _stat

    try:
        st = os.stat(path)
    except OSError as e:
        raise SigningKeyError(f"cannot stat {path}: {type(e).__name__}") from None
    if not _stat.S_ISREG(st.st_mode):
        raise SigningKeyError(f"{path} is not a regular file")
    if st.st_mode & 0o077:
        raise SigningKeyError(
            f"{path} has mode {_stat.S_IMODE(st.st_mode):04o}; it must not be accessible "
            "to group or others (use 0400 or 0600)"
        )
    if st.st_uid != os.geteuid():
        raise SigningKeyError(f"{path} is not owned by the user running this command")


def load_private_key(path: str | Path) -> Any:
    """Load an Ed25519 private key from a PEM (PKCS#8) file, after the permission check."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    check_owner_only(path)
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        raise SigningKeyError(f"cannot read private key {path}: {type(e).__name__}") from None
    try:
        key = load_pem_private_key(data, password=None)
    except (ValueError, TypeError):
        raise SigningKeyError(f"private key {path} is not an unencrypted PEM private key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningKeyError(f"private key {path} is not Ed25519")
    return key


__all__ = [
    "ALL_REASONS",
    "MAX_LIFETIME_SECONDS",
    "STATEMENT_VERSION",
    "ConsumedSet",
    "SigningKeyError",
    "VerifyResult",
    "build_statement",
    "check_owner_only",
    "load_private_key",
    "load_public_key",
    "sign_statement",
    "verify_statement",
]
