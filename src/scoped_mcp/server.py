"""Entry point for scoped-mcp.

Wires together identity → manifest → credentials → registry → FastMCP server.
Fails fast with clear messages on any misconfiguration.
"""

from __future__ import annotations

import argparse
import os
import sys

from .audit import configure_logging, get_ops_logger
from .identity import AgentContext
from .manifest import load_manifest
from .middleware import ToolCallMiddleware
from .registry import build_server
from .state import StateBackend, build_state_backend


def _build_middleware(
    agent_id: str,
    state: StateBackend,
    rate_limits_cfg: object,
    argument_filters_cfg: object,
) -> list[ToolCallMiddleware]:
    """Build the middleware stack from manifest config and environment."""
    middleware: list[ToolCallMiddleware] = []

    # Rate limiting — auto-registered when rate_limits is present in manifest
    if rate_limits_cfg is not None:
        from .contrib.rate_limit import RateLimitMiddleware

        middleware.append(
            RateLimitMiddleware(
                state=state,
                agent_id=agent_id,
                global_limit=rate_limits_cfg.global_limit,
                per_tool=rate_limits_cfg.per_tool,
            )
        )

    # Argument filtering — auto-registered when argument_filters is present.
    # Placed AFTER rate-limiting so a flood of policy-violating calls still
    # counts toward the rate limit.
    if argument_filters_cfg:
        from .contrib.arg_filter import ArgumentFilterMiddleware

        middleware.append(
            ArgumentFilterMiddleware(
                rules=[r.model_dump() for r in argument_filters_cfg],
                agent_id=agent_id,
            )
        )

    # OTel — auto-enabled when OTEL_EXPORTER_OTLP_ENDPOINT is set
    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        try:
            from .contrib.otel import OtelMiddleware

            middleware.append(OtelMiddleware())
        except ImportError:
            pass

    return middleware


def _run_validate(args: argparse.Namespace) -> None:
    """Validate a manifest file and print results. Exit 0 on success, 1 on failure."""
    from .exceptions import ManifestError

    try:
        manifest = load_manifest(args.manifest)
    except ManifestError as e:
        print(f"INVALID: {e}", file=sys.stderr)
        sys.exit(1)

    print(
        f"OK: manifest valid — agent_type={manifest.agent_type!r}, "
        f"modules={list(manifest.modules.keys())}",
        file=sys.stderr,
    )


def _run_serve(args: argparse.Namespace) -> None:
    audit_log = getattr(args, "audit_log", None)
    ops_log = getattr(args, "ops_log", None)
    configure_logging(audit_log=audit_log, ops_log=ops_log)
    ops = get_ops_logger()

    try:
        ops.info(
            "startup",
            manifest=args.manifest,
            audit_log=audit_log,
            ops_log=ops_log,
        )

        agent_ctx = AgentContext.from_env()
        ops.info("identity_resolved", agent_id=agent_ctx.agent_id, agent_type=agent_ctx.agent_type)

        manifest = load_manifest(args.manifest)
        ops.info(
            "manifest_loaded",
            agent_type=manifest.agent_type,
            modules=list(manifest.modules.keys()),
        )

        state = build_state_backend(
            backend_type=manifest.state_backend.type,
            url=manifest.state_backend.url,
            agent_id=agent_ctx.agent_id,
        )

        middleware = _build_middleware(
            agent_id=agent_ctx.agent_id,
            state=state,
            rate_limits_cfg=manifest.rate_limits,
            argument_filters_cfg=manifest.argument_filters,
        )

        server = build_server(agent_ctx, manifest, middleware=middleware)
        ops.info("server_ready", transport="stdio")

        server.run(transport="stdio")

    except Exception as e:
        ops.error("startup_failed", error=type(e).__name__, detail=str(e))
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scoped-mcp",
        description="Per-agent scoped MCP tool proxy with credential isolation and audit logging.",
    )
    subparsers = parser.add_subparsers(dest="command")

    # "run" subcommand
    run_parser = subparsers.add_parser("run", help="Start the scoped-mcp proxy server.")
    run_parser.add_argument("--manifest", required=True, metavar="PATH")
    run_parser.add_argument("--audit-log", default=None, metavar="PATH")
    run_parser.add_argument("--ops-log", default=None, metavar="PATH")

    # "validate" subcommand
    validate_parser = subparsers.add_parser(
        "validate", help="Validate a manifest file (exit 0 on success, 1 on failure)."
    )
    validate_parser.add_argument("--manifest", required=True, metavar="PATH")

    # Legacy flat args for backwards compatibility (no subcommand given)
    parser.add_argument("--manifest", default=None, metavar="PATH")
    parser.add_argument("--audit-log", default=None, metavar="PATH")
    parser.add_argument("--ops-log", default=None, metavar="PATH")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if args.command == "validate":
        _run_validate(args)
        return

    # "run" subcommand or legacy flat invocation
    if args.manifest is None:
        parse_args(["--help"])
        sys.exit(1)

    _run_serve(args)


if __name__ == "__main__":
    main()
