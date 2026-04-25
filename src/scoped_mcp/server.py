"""Entry point for scoped-mcp.

Wires together identity → manifest → credentials → registry → FastMCP server.
Fails fast with clear messages on any misconfiguration.
"""

from __future__ import annotations

import argparse
import sys

from .audit import configure_logging, get_ops_logger
from .identity import AgentContext
from .manifest import load_manifest
from .registry import build_server


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scoped-mcp",
        description="Per-agent scoped MCP tool proxy with credential isolation and audit logging.",
    )
    parser.add_argument(
        "--manifest",
        required=True,
        metavar="PATH",
        help="Path to the agent manifest YAML/JSON file.",
    )
    parser.add_argument(
        "--audit-log",
        default=None,
        metavar="PATH",
        help="Optional file path for audit log output (stderr always enabled).",
    )
    parser.add_argument(
        "--ops-log",
        default=None,
        metavar="PATH",
        help="Optional file path for ops log output (stderr always enabled).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    configure_logging(audit_log=args.audit_log, ops_log=args.ops_log)
    ops = get_ops_logger()

    try:
        ops.info(
            "startup",
            manifest=args.manifest,
            audit_log=args.audit_log,
            ops_log=args.ops_log,
        )

        agent_ctx = AgentContext.from_env()
        ops.info("identity_resolved", agent_id=agent_ctx.agent_id, agent_type=agent_ctx.agent_type)

        manifest = load_manifest(args.manifest)
        ops.info(
            "manifest_loaded",
            agent_type=manifest.agent_type,
            modules=list(manifest.modules.keys()),
        )

        server = build_server(agent_ctx, manifest)
        ops.info("server_ready", transport="stdio")

        server.run(transport="stdio")

    except Exception as e:
        ops.error("startup_failed", error=type(e).__name__, detail=str(e))
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
