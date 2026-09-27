"""``scoped-mcp-approve`` — the signing approver for HITL requests.

Run by the operator, in a terminal, as an account that alone can read the
approver private key (typically via ``sudo -u <approver-account>``, which asks
for the operator's password). It is the only thing that can produce an approval
an agent with ``hitl.signing.mode: enforce`` will accept.

    scoped-mcp-approve <approval_id>          # show the request, ask, sign
    scoped-mcp-approve --deny <approval_id>   # drop the request

What it does on approve:

1. Reads the pending record for ``approval_id`` from the state backend.
2. Recomputes the full SHA-256 of the canonical arguments stored in that record
   and **refuses** unless both the stored digest and the stored short
   ``args_hash`` match it. The statement it signs carries the recomputed digest.
   The requesting agent can write that record, so a stored summary or hash
   proves nothing by itself; what is displayed and what is signed must both be
   derived from the same arguments.
3. Shows agent, tool and those arguments — nothing truncated or pattern-redacted,
   values under secret-looking keys replaced by their length and a digest prefix
   (hidden, but still distinguishable), and every control or non-ASCII character
   escaped so the text cannot redraw the terminal — and asks ``Approve? [y/N]``.
4. On ``y``: claims the pending record (atomically), signs the statement and
   writes it as the pre-approval token, valid for at most 120 s.

It never takes a key, a hash or a statement on the command line, and it refuses
to run without a terminal. It reads its own configuration file — never an agent's
environment — and refuses both that file and the private key if anyone but their
owner can read them.

Configuration (YAML), default ``~/.config/scoped-mcp/approver.yml`` of the
account running the command (resolved from the password database, not $HOME, so
``sudo`` environment handling cannot redirect it)::

    state_url: redis://…            # the same Dragonfly the agents' proxies use
    private_key_path: /…/approver.key   # PEM PKCS#8 Ed25519, mode 0400/0600
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import pwd
import sys
from pathlib import Path
from typing import Any

import yaml

from .audit import _key_looks_sensitive
from .hitl import _canonical_args_digest, _otp_key, _preapproval_key, _short_args_hash
from .hitl_signing import (
    MAX_LIFETIME_SECONDS,
    SigningKeyError,
    build_statement,
    check_owner_only,
    load_private_key,
    sign_statement,
)
from .state import _sanitize_key_component

EXIT_OK = 0
EXIT_REFUSED = 1  # operator said no, or no terminal
EXIT_CONFIG = 2
EXIT_NOT_FOUND = 3
EXIT_MISMATCH = 5


def _default_config_path() -> Path:
    home = pwd.getpwuid(os.geteuid()).pw_dir
    return Path(home) / ".config" / "scoped-mcp" / "approver.yml"


def load_config(path: Path) -> dict[str, str]:
    check_owner_only(path)
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError) as e:
        raise SigningKeyError(f"cannot read config {path}: {type(e).__name__}") from None
    if not isinstance(data, dict):
        raise SigningKeyError(f"config {path} must be a mapping")
    missing = [k for k in ("state_url", "private_key_path") if not data.get(k)]
    if missing:
        raise SigningKeyError(f"config {path} is missing: {', '.join(missing)}")
    return {"state_url": str(data["state_url"]), "private_key_path": str(data["private_key_path"])}


def parse_approval_id(approval_id: str) -> str | None:
    """Return the agent_id encoded in ``{agent_id}.{hex}``, or None if malformed."""
    if "." not in approval_id:
        return None
    agent_id, suffix = approval_id.rsplit(".", 1)
    if not agent_id or not suffix or not suffix.isalnum():
        return None
    return agent_id


def _prefix(agent_id: str) -> str:
    # Must match DragonflyBackend's agent-scoped prefix exactly.
    return f"scoped-mcp:{_sanitize_key_component(agent_id)}:"


def _fingerprint(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, default=str)
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return f"<hidden: {len(canonical)} chars, sha256 {digest}>"


def _display_value(value: Any, key: str = "") -> Any:
    """What the operator reads before signing. It must show what is signed.

    Unlike the audit sanitiser, this never truncates and never pattern-redacts:
    the requesting agent controls every value, so text rewritten to
    ``<redacted-hex>`` (a commit SHA, say) or cut at 500 characters is text the
    operator approves without seeing. Only a value under a secret-looking key is
    kept off the screen, and even then it is replaced by its length and a digest
    prefix, so two different hidden values never look identical.
    """
    if key and _key_looks_sensitive(key):
        return _fingerprint(value)
    if isinstance(value, dict):
        return {k: _display_value(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_display_value(v) for v in value]
    return value


def render_request(record: dict[str, Any]) -> str:
    """Terminal-safe rendering of what is about to be signed.

    json.dumps with ensure_ascii escapes every control character (ESC, CR,
    backspace) and every non-ASCII code point (bidi overrides, homoglyphs), so
    agent-supplied text cannot rewrite or disguise what the operator reads.
    """
    esc = lambda s: json.dumps(s, ensure_ascii=True)  # noqa: E731
    args = json.dumps(
        _display_value(record["arguments"]), indent=2, sort_keys=True, ensure_ascii=True
    )
    return (
        f"agent:       {esc(record['agent_id'])}\n"
        f"tool:        {esc(record['tool'])}\n"
        f"approval id: {esc(record['approval_id'])}\n"
        f"arguments:\n{args}\n"
    )


def check_record(record: Any, approval_id: str, agent_id: str) -> str | None:
    """Return None if the pending record is internally consistent, else why not."""
    if not isinstance(record, dict):
        return "pending record is not an object"
    if record.get("approval_id") != approval_id:
        return "pending record approval_id does not match"
    if record.get("agent_id") != agent_id:
        return "pending record agent_id does not match the approval id"
    if not isinstance(record.get("tool"), str) or not record["tool"]:
        return "pending record has no tool"
    if "arguments" not in record or record["arguments"] is None:
        return (
            "pending record carries no canonical arguments (the agent's proxy is not running "
            "with hitl.signing enabled, or the arguments were unhashable)"
        )
    if not isinstance(record["arguments"], dict):
        return "pending record arguments are not an object"
    digest = _canonical_args_digest(record["arguments"])
    if record.get("args_sha256") != digest:
        return "stored args_sha256 does not match the stored arguments"
    if record.get("args_hash") != _short_args_hash(digest):
        return "stored args_hash does not match the stored arguments"
    return None


async def run(
    approval_id: str,
    *,
    deny: bool,
    client: Any,
    private_key: Any,
    confirm: Any,
    out: Any = sys.stdout,
    err: Any = sys.stderr,
) -> int:
    agent_id = parse_approval_id(approval_id)
    if agent_id is None:
        print("error: malformed approval id", file=err)
        return EXIT_CONFIG
    prefix = _prefix(agent_id)
    pending_key = f"{prefix}hitl:{approval_id}"

    if deny:
        claimed = await client.getdel(pending_key)
        await client.delete(prefix + _otp_key(approval_id))
        if claimed is None:
            print("error: no pending approval with that id (expired or already decided)", file=err)
            return EXIT_NOT_FOUND
        print(f"denied: {approval_id}", file=out)
        return EXIT_OK

    raw = await client.get(pending_key)
    if raw is None:
        print("error: no pending approval with that id (expired or already decided)", file=err)
        return EXIT_NOT_FOUND
    try:
        record = json.loads(raw)
    except json.JSONDecodeError:
        record = None
    problem = check_record(record, approval_id, agent_id)
    if problem is not None:
        print(f"refusing to sign: {problem}", file=err)
        return EXIT_MISMATCH

    print(render_request(record), file=out)
    if not confirm("Approve? [y/N] "):
        print("not approved (request left pending; use --deny to drop it)", file=out)
        return EXIT_REFUSED

    statement = build_statement(
        agent_id=agent_id,
        approval_id=approval_id,
        tool=record["tool"],
        args_sha256=_canonical_args_digest(record["arguments"]),
    )
    value = sign_statement(private_key, statement)

    # Claim the pending record before writing the token, so one request yields
    # at most one approval even if two operators race.
    claimed = await client.getdel(pending_key)
    if claimed is None:
        print("error: request was decided or expired while you were reading it", file=err)
        return EXIT_NOT_FOUND
    if claimed != raw:
        print("refusing to sign: the pending record changed while you were reading it", file=err)
        return EXIT_MISMATCH
    await client.delete(prefix + _otp_key(approval_id))
    await client.set(
        prefix + _preapproval_key(record["tool"], record["args_hash"]),
        value,
        ex=MAX_LIFETIME_SECONDS,
    )
    print(
        f"approved: {approval_id} — valid for {MAX_LIFETIME_SECONDS} s; "
        "the agent must retry the same call now",
        file=out,
    )
    return EXIT_OK


def _tty_confirm(prompt: str) -> bool:
    try:
        with open("/dev/tty") as tty_in:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            return tty_in.readline().strip().lower() in ("y", "yes")
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scoped-mcp-approve",
        description="Approve (sign) or deny a pending scoped-mcp HITL request.",
    )
    parser.add_argument("approval_id", metavar="APPROVAL_ID")
    parser.add_argument("--deny", action="store_true", help="drop the request instead")
    parser.add_argument("--config", type=Path, default=None, metavar="PATH")
    args = parser.parse_args(argv)

    # A human decision needs a human at a terminal. Reading the answer from
    # /dev/tty (not stdin) means piping "y" in does not count as one.
    if not args.deny and not (sys.stdin.isatty() and os.path.exists("/dev/tty")):
        print("error: scoped-mcp-approve must be run interactively in a terminal", file=sys.stderr)
        return EXIT_REFUSED

    try:
        cfg = load_config(args.config or _default_config_path())
        private_key = None if args.deny else load_private_key(cfg["private_key_path"])
    except SigningKeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        import redis.asyncio as aioredis
    except ImportError:
        print("error: scoped-mcp[dragonfly] is required", file=sys.stderr)
        return EXIT_CONFIG

    async def _go() -> int:
        client = aioredis.from_url(cfg["state_url"], decode_responses=True)
        try:
            return await run(
                args.approval_id,
                deny=args.deny,
                client=client,
                private_key=private_key,
                confirm=_tty_confirm,
            )
        finally:
            await client.aclose()

    return asyncio.run(_go())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
