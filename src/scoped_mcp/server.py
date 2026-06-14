"""Entry point for scoped-mcp.

Wires together identity → manifest → credentials → registry → FastMCP server.
Fails fast with clear messages on any misconfiguration.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys

from .audit import SESSION_ID, configure_audit, configure_logging, get_ops_logger
from .identity import AgentContext
from .manifest import load_manifest
from .middleware import ToolCallMiddleware
from .registry import build_server
from .state import StateBackend, build_state_backend


def _build_middleware(
    agent_id: str,
    agent_type: str,
    state: StateBackend,
    rate_limits_cfg: object,
    argument_filters_cfg: object,
    hitl_cfg: object,
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

    # HITL — auto-registered when hitl is present. Placed last among the
    # gating middleware so an approval request reflects the call as it would
    # actually run (post rate-limit, post arg-filter).
    if hitl_cfg is not None and (hitl_cfg.approval_required or hitl_cfg.shadow):
        from .hitl import build_hitl_middleware

        middleware.append(
            build_hitl_middleware(
                hitl_cfg=hitl_cfg,
                state=state,
                agent_id=agent_id,
                agent_type=agent_type,
            )
        )

    # OTel — auto-enabled when OTEL_EXPORTER_OTLP_ENDPOINT is set
    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        try:
            from opentelemetry import trace as _trace

            from .contrib.otel import OtelMiddleware

            if "sdk" not in type(_trace.get_tracer_provider()).__module__:
                from opentelemetry.sdk.resources import Resource
                from opentelemetry.sdk.trace import TracerProvider
                from opentelemetry.sdk.trace.export import BatchSpanProcessor

                if os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "").startswith("http"):
                    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                        OTLPSpanExporter,
                    )
                else:
                    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                        OTLPSpanExporter,
                    )

                _provider = TracerProvider(resource=Resource.create())
                _provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
                _trace.set_tracer_provider(_provider)

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

        # Configure audit runtime: session ID, arg logging, agent-bus, response filter.
        _response_filter = None
        if manifest.response_filters:
            from .contrib.response_filter import ResponseFilter

            _response_filter = ResponseFilter(
                rules=[r.model_dump() for r in manifest.response_filters],
                agent_id=agent_ctx.agent_id,
            )
        audit_cfg = manifest.audit
        configure_audit(
            log_args=audit_cfg.log_args if audit_cfg else True,
            agent_bus_emit=audit_cfg.agent_bus_emit if audit_cfg else False,
            agent_bus_comms_dir=audit_cfg.agent_bus_comms_dir if audit_cfg else None,
            response_filter=_response_filter,
        )
        ops.info("session_ready", session_id=SESSION_ID)

        middleware = _build_middleware(
            agent_id=agent_ctx.agent_id,
            agent_type=agent_ctx.agent_type,
            state=state,
            rate_limits_cfg=manifest.rate_limits,
            argument_filters_cfg=manifest.argument_filters,
            hitl_cfg=manifest.hitl,
        )

        server = build_server(agent_ctx, manifest, middleware=middleware)
        ops.info("server_ready", transport="stdio")

        # SMCP-3: graceful shutdown on SIGTERM.
        # Claude Desktop / Claude Code spawn scoped-mcp as a stdio subprocess and
        # send SIGTERM when the session ends.  Without a handler the process is
        # killed mid-flight, bypassing module shutdown() hooks (open sockets,
        # background renewal tasks, etc.).  sys.exit() inside the handler raises
        # SystemExit which propagates through anyio back to FastMCP's lifespan
        # finally-block, giving every module a clean chance to release resources.
        def _sigterm_handler(signum: int, frame: object) -> None:
            ops.info("sigterm_received")
            sys.exit(0)

        signal.signal(signal.SIGTERM, _sigterm_handler)

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

    # "hitl" subcommand group — operator approval flow
    hitl_parser = subparsers.add_parser(
        "hitl", help="Inspect or decide pending HITL approval requests."
    )
    hitl_parser.add_argument("--manifest", required=True, metavar="PATH")
    hitl_sub = hitl_parser.add_subparsers(dest="hitl_command", required=True)
    hitl_sub.add_parser("list", help="List pending approval requests across all agents.")
    approve_p = hitl_sub.add_parser("approve", help="Approve a pending request by ID.")
    approve_p.add_argument("approval_id", metavar="APPROVAL_ID")
    reject_p = hitl_sub.add_parser("reject", help="Reject a pending request by ID.")
    reject_p.add_argument("approval_id", metavar="APPROVAL_ID")
    reject_p.add_argument("reason", nargs="?", default="", metavar="REASON")

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

    if args.command == "hitl":
        from .hitl_cli import run_hitl_command

        sys.exit(run_hitl_command(args))

    # "run" subcommand or legacy flat invocation
    if args.manifest is None:
        parse_args(["--help"])
        sys.exit(1)

    _run_serve(args)


if __name__ == "__main__":
    main()
