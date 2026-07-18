"""Operator CLI for HITL approvals (v1.1 — reject-then-wait).

Talks directly to Dragonfly using the URL from the manifest's
``state_backend`` config. Bypasses ``StateBackend`` deliberately — operator
operations are not agent-scoped and need to enumerate keys across agents
for ``hitl list``.

Approval ID format (mirrored from hitl.py): ``"{agent_id}.{uuid_hex_12}"``.
The agent_id is parsed out of the approval_id and used to construct the
agent-scoped key prefix when reading the payload or publishing a decision.

Approve flow (v1.1):
  1. Verify pending key exists.
  2. Read the payload to extract ``tool`` name.
  3. Write a one-time pre-approval token: ``scoped-mcp:{agent_id}:hitl:preapproved:{tool}``
     with a short TTL so the agent can retry and proceed.
  4. Delete the pending key.

Reject flow (v1.1):
  1. Verify pending key exists.
  2. Delete the pending key (no pre-approval token written).

Subcommands:
    scoped-mcp hitl list                          — pending approvals
    scoped-mcp hitl approve <approval_id>
    scoped-mcp hitl reject  <approval_id> [reason]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .hitl import PREAPPROVAL_TTL_SECONDS
from .manifest import load_manifest


def _parse_approval_id(approval_id: str) -> tuple[str, str] | None:
    """Return (agent_id, uuid_suffix) or None on malformed input."""
    if "." not in approval_id:
        return None
    agent_id, suffix = approval_id.rsplit(".", 1)
    if not agent_id or not suffix:
        return None
    return agent_id, suffix


def _key_for(approval_id: str) -> str:
    """Build the full Dragonfly key for a given approval_id."""
    parsed = _parse_approval_id(approval_id)
    if parsed is None:
        raise ValueError(f"malformed approval_id: {approval_id!r}")
    agent_id, _ = parsed
    return f"scoped-mcp:{agent_id}:hitl:{approval_id}"


def _preapproval_key_for(agent_id: str, tool_name: str, args_hash: str) -> str:
    """Build the full Dragonfly key for the pre-approval token bound to (tool, args)."""
    return f"scoped-mcp:{agent_id}:hitl:preapproved:{tool_name}:{args_hash}"


async def _list_pending(redis_url: str, _client=None) -> int:
    try:
        import redis.asyncio as aioredis
    except ImportError:
        print(
            "error: scoped-mcp[dragonfly] is required for HITL CLI. "
            "Install with: pip install scoped-mcp[dragonfly]",
            file=sys.stderr,
        )
        return 1

    client = _client if _client is not None else aioredis.from_url(redis_url, decode_responses=True)
    try:
        pending: list[dict] = []
        async for key in client.scan_iter(match="scoped-mcp:*:hitl:*.*"):
            # Skip pre-approval tokens — they share the hitl: namespace but
            # are not pending approvals. Approval IDs never contain "preapproved:".
            if ":preapproved:" in key:
                continue
            raw = await client.get(key)
            if raw is None:
                continue
            try:
                pending.append(json.loads(raw))
            except json.JSONDecodeError:
                continue
        if not pending:
            print("(no pending approvals)")
            return 0
        for p in pending:
            print(
                f"{p.get('approval_id', '?')}  "
                f"agent={p.get('agent_id', '?')}  "
                f"tool={p.get('tool', '?')}"
            )
        return 0
    finally:
        if _client is None:
            await client.aclose()


async def _decide(redis_url: str, approval_id: str, decision: str, _client=None) -> int:
    try:
        import redis.asyncio as aioredis
    except ImportError:
        print(
            "error: scoped-mcp[dragonfly] is required for HITL CLI.",
            file=sys.stderr,
        )
        return 1

    parsed = _parse_approval_id(approval_id)
    if parsed is None:
        print(f"error: malformed approval_id: {approval_id!r}", file=sys.stderr)
        return 2
    agent_id, _ = parsed

    try:
        key = _key_for(approval_id)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    client = _client if _client is not None else aioredis.from_url(redis_url, decode_responses=True)
    try:
        # Verify the approval is still pending — guards against typoed IDs
        # and prevents acting on a request that has already expired.
        raw = await client.get(key)
        if raw is None:
            print(
                f"error: no pending approval with ID {approval_id!r} "
                f"(may have expired or been decided already)",
                file=sys.stderr,
            )
            return 3

        if decision == "approve":
            # Extract tool name and args_hash from the stored payload to write a
            # pre-approval token bound to (tool, args). The middleware checks for
            # this token on the agent's next call and consumes it to proceed.
            # The args_hash binding prevents approving tool "X with args A" from
            # authorising a later call to "X with args B" during the TTL window (H-01).
            try:
                payload = json.loads(raw)
                tool_name = payload.get("tool", "")
                args_hash = payload.get("args_hash", "")
            except (json.JSONDecodeError, AttributeError):
                tool_name = ""
                args_hash = ""

            # The approval_id rides along in the token value (not just "approved")
            # so the middleware can resolve the audit row to "consumed" once the
            # token is actually used (SMCP-39).
            token_value = json.dumps({"status": "approved", "approval_id": approval_id})

            if tool_name and args_hash:
                pre_key = _preapproval_key_for(agent_id, tool_name, args_hash)
                await client.set(pre_key, token_value, ex=PREAPPROVAL_TTL_SECONDS)
            elif tool_name:
                # Legacy payload without args_hash (pre-H-01 fix): fall back to
                # tool-name-only key so old pending approvals still work after upgrade.
                pre_key = f"scoped-mcp:{agent_id}:hitl:preapproved:{tool_name}"
                await client.set(pre_key, token_value, ex=PREAPPROVAL_TTL_SECONDS)
                print(
                    "warning: stored payload has no args_hash — writing tool-name-only "
                    "pre-approval token (upgrade scoped-mcp to get argument binding)",
                    file=sys.stderr,
                )
            else:
                print(
                    "warning: could not extract tool name from payload — "
                    "pre-approval token not written; retry may not proceed",
                    file=sys.stderr,
                )

        # Delete the pending key in both approve and reject cases.
        await client.delete(key)

        verb = "approved" if decision == "approve" else "rejected"
        print(f"{verb}: {approval_id}")
        return 0
    finally:
        if _client is None:
            await client.aclose()


def run_hitl_command(args: argparse.Namespace) -> int:
    """Entry point invoked from server.main() when args.command == 'hitl'."""
    from .exceptions import ManifestError

    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if manifest.state_backend.type != "dragonfly" or not manifest.state_backend.url:
        print(
            "error: hitl CLI requires state_backend.type: dragonfly with a url",
            file=sys.stderr,
        )
        return 1
    redis_url = manifest.state_backend.url

    cmd = args.hitl_command
    if cmd == "list":
        return asyncio.run(_list_pending(redis_url))
    if cmd == "approve":
        return asyncio.run(_decide(redis_url, args.approval_id, "approve"))
    if cmd == "reject":
        reason = getattr(args, "reason", None)
        decision = "reject" if not reason else f"reject:{reason}"
        return asyncio.run(_decide(redis_url, args.approval_id, decision))

    print(f"error: unknown hitl subcommand {cmd!r}", file=sys.stderr)
    return 1
