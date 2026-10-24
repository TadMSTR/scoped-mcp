"""Tests for server.py helpers — the middleware builder, manifest-validate CLI, and
main() dispatch. The async serve loop (_run_serve) needs a live transport harness and is
intentionally left out of scope (see the coverage plan)."""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path

import pytest

from scoped_mcp.contrib.arg_filter import ArgumentFilterMiddleware
from scoped_mcp.contrib.rate_limit import RateLimitMiddleware
from scoped_mcp.hitl import HitlMiddleware
from scoped_mcp.manifest import ArgumentFilterRule, HitlConfig, RateLimitsConfig
from scoped_mcp.server import _build_middleware, _run_validate, main
from scoped_mcp.session import SessionAttributionMiddleware
from scoped_mcp.state import build_state_backend


def _state():
    return build_state_backend("in_process")


# ── _build_middleware ─────────────────────────────────────────────────────────


def test_build_middleware_only_attribution_when_no_config(monkeypatch) -> None:
    """With no manifest config the stack is session attribution alone.

    Attribution is unconditional (vikunja#596): it is a no-op without
    AGENT_REGISTRY_DSN and a no-op for any session the launcher did not mint a
    run id for, so gating it on config would only add a way to forget it.
    """
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    mw = _build_middleware("agent-x", "research", _state(), None, None, None)
    assert [type(m) for m in mw] == [SessionAttributionMiddleware]


def test_build_middleware_assembles_full_stack(monkeypatch) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    mw = _build_middleware(
        "agent-x",
        "research",
        _state(),
        RateLimitsConfig(global_limit="5/minute"),
        [ArgumentFilterRule(name="no-secrets", pattern="secret")],
        HitlConfig(approval_required=["dangerous_*"]),
    )
    # Order matters: rate-limit → arg-filter → attribution → HITL (documented in
    # server.py). Attribution sits BEFORE HITL because hitl_approvals carries a
    # real foreign key to sessions, and AFTER the rate limiter because it does a
    # database write that must not run unmetered.
    assert [type(m) for m in mw] == [
        RateLimitMiddleware,
        ArgumentFilterMiddleware,
        SessionAttributionMiddleware,
        HitlMiddleware,
    ]


def test_build_middleware_skips_hitl_when_empty(monkeypatch) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    # approval_required and shadow both empty → no HITL middleware.
    mw = _build_middleware("agent-x", "research", _state(), None, None, HitlConfig())
    assert [type(m) for m in mw] == [SessionAttributionMiddleware]
    assert not any(isinstance(m, HitlMiddleware) for m in mw)


def test_build_middleware_appends_otel_when_endpoint_set(monkeypatch) -> None:
    """OTEL_EXPORTER_OTLP_ENDPOINT auto-enables the OtelMiddleware (offline-patched)."""
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace
    from opentelemetry.sdk.trace import export as sdk_trace_export

    from scoped_mcp.contrib.otel import OtelMiddleware

    grpc_trace = pytest.importorskip("opentelemetry.exporter.otlp.proto.grpc.trace_exporter")

    from unittest.mock import MagicMock

    # Neuter the span export path so building the provider starts no network exporter.
    # The processor is only stored on the provider, never exercised (no spans emitted).
    monkeypatch.setattr(trace, "set_tracer_provider", lambda p: None)
    monkeypatch.setattr(sdk_trace_export, "BatchSpanProcessor", lambda *a, **k: MagicMock())
    monkeypatch.setattr(grpc_trace, "OTLPSpanExporter", lambda *a, **k: object())
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_PROTOCOL", raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.test:4317")

    mw = _build_middleware("agent-x", "research", _state(), None, None, None)
    # Otel is appended last, after the always-present attribution middleware.
    assert [type(m) for m in mw] == [SessionAttributionMiddleware, OtelMiddleware]


# ── _run_validate + main() dispatch ───────────────────────────────────────────

_VALID_MANIFEST = """\
    agent_type: research
    description: A research agent
    modules:
      filesystem:
        mode: read
        config:
          base_path: /tmp/agents
"""


def _write(tmp_path: Path, content: str) -> str:
    f = tmp_path / "manifest.yml"
    f.write_text(textwrap.dedent(content))
    return str(f)


def test_run_validate_ok(tmp_path: Path, capsys) -> None:
    _run_validate(argparse.Namespace(manifest=_write(tmp_path, _VALID_MANIFEST)))
    assert "OK: manifest valid" in capsys.readouterr().err


def test_run_validate_invalid_exits_1(tmp_path: Path, capsys) -> None:
    path = _write(tmp_path, "agent_type: research\nmodules: not-a-mapping\n")
    with pytest.raises(SystemExit) as exc:
        _run_validate(argparse.Namespace(manifest=path))
    assert exc.value.code == 1
    assert "INVALID:" in capsys.readouterr().err


def test_main_validate_dispatch(tmp_path: Path, capsys) -> None:
    main(["validate", "--manifest", _write(tmp_path, _VALID_MANIFEST)])
    assert "OK: manifest valid" in capsys.readouterr().err


def test_main_without_manifest_exits() -> None:
    # No subcommand and no legacy --manifest → prints help and exits non-zero.
    with pytest.raises(SystemExit):
        main([])


def test_attribution_runs_after_rate_limit_and_before_hitl(monkeypatch) -> None:
    """Both halves of the placement are load-bearing, so pin both.

    Before HITL: hitl_approvals.session_id is a real foreign key, so the sessions
    row must exist before the gate mints an approval referencing it.
    After the rate limiter: this middleware performs a database write, and an
    unmetered write ahead of the limiter would let an agent looping calls with a
    fresh run id grow the sessions table without ever hitting the limit.
    """
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    mw = _build_middleware(
        "agent-x",
        "research",
        _state(),
        RateLimitsConfig(global_limit="5/minute"),
        [ArgumentFilterRule(name="no-secrets", pattern="secret")],
        HitlConfig(approval_required=["dangerous_*"]),
    )
    types = [type(m) for m in mw]
    assert types.index(SessionAttributionMiddleware) > types.index(RateLimitMiddleware)
    assert types.index(SessionAttributionMiddleware) > types.index(ArgumentFilterMiddleware)
    assert types.index(SessionAttributionMiddleware) < types.index(HitlMiddleware)


# ── HTTP pre-flight refusals (vikunja#1219) ───────────────────────────────────


@pytest.mark.parametrize(
    "environ", [{}, {"SCOPED_MCP_BEARER_TOKEN": ""}, {"SCOPED_MCP_BEARER_TOKEN": "  \n"}]
)
def test_http_auth_refuses_without_bearer_token(environ: dict) -> None:
    from scoped_mcp.exceptions import ConfigError
    from scoped_mcp.identity import AgentContext
    from scoped_mcp.server import _build_http_auth

    with pytest.raises(ConfigError, match="refusing to bind an unauthenticated HTTP port"):
        _build_http_auth(AgentContext(agent_id="dev", agent_type="developer"), environ)


async def test_http_auth_claim_equals_the_env_identity() -> None:
    """Pins today's single-issuer equality: the token's agent_id claim is the identity
    modules scope by. resolve_request_identity prefers the claim for the audit record, so a
    divergence would make the audit log name a different agent than the one scoped."""
    from scoped_mcp.identity import AgentContext
    from scoped_mcp.server import _build_http_auth

    ctx = AgentContext(agent_id="dev-07", agent_type="developer")
    verifier = _build_http_auth(ctx, {"SCOPED_MCP_BEARER_TOKEN": "placeholder-token"})
    assert await verifier.verify_token("wrong-token-xx") is None
    access = await verifier.verify_token("placeholder-token")
    assert access is not None
    assert access.claims["agent_id"] == ctx.agent_id
    assert access.client_id == ctx.agent_id


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.12", "::", "example.com", ""])
def test_http_bind_refuses_non_loopback_host(host: str) -> None:
    from scoped_mcp.exceptions import ConfigError
    from scoped_mcp.server import _check_http_bind

    with pytest.raises(ConfigError, match="refuses non-loopback host"):
        _check_http_bind(host, 8080)


def test_http_bind_requires_a_port() -> None:
    from scoped_mcp.exceptions import ConfigError
    from scoped_mcp.server import _check_http_bind

    with pytest.raises(ConfigError, match="requires --port"):
        _check_http_bind("127.0.0.1", 0)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_http_bind_accepts_loopback(host: str) -> None:
    from scoped_mcp.server import _check_http_bind

    _check_http_bind(host, 8080)


def test_run_serve_refuses_http_without_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    """The extracted check is the one _run_serve calls: no token → exit 1, nothing served."""
    from unittest.mock import patch

    manifest = _write(tmp_path, _VALID_MANIFEST)
    monkeypatch.setenv("AGENT_ID", "dev")
    monkeypatch.setenv("AGENT_TYPE", "research")
    monkeypatch.delenv("SCOPED_MCP_BEARER_TOKEN", raising=False)
    args = argparse.Namespace(
        manifest=manifest, transport="http", host="127.0.0.1", port=8080, path="/mcp"
    )
    with (
        patch("scoped_mcp.server.configure_logging"),
        patch("scoped_mcp.server.build_server") as build,
        pytest.raises(SystemExit) as exc,
    ):
        from scoped_mcp.server import _run_serve

        _run_serve(args)
    assert exc.value.code == 1
    build.assert_not_called()
    assert "SCOPED_MCP_BEARER_TOKEN" in capsys.readouterr().err


def test_run_serve_refuses_non_loopback_bind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    from unittest.mock import patch

    manifest = _write(tmp_path, _VALID_MANIFEST)
    monkeypatch.setenv("AGENT_ID", "dev")
    monkeypatch.setenv("AGENT_TYPE", "research")
    monkeypatch.setenv("SCOPED_MCP_BEARER_TOKEN", "placeholder-token")
    args = argparse.Namespace(
        manifest=manifest, transport="http", host="0.0.0.0", port=8080, path="/mcp"
    )
    with (
        patch("scoped_mcp.server.configure_logging"),
        patch("scoped_mcp.server.build_server") as build,
        patch("scoped_mcp.server.signal.signal"),
        pytest.raises(SystemExit) as exc,
    ):
        from scoped_mcp.server import _run_serve

        _run_serve(args)
    assert exc.value.code == 1
    build.return_value.run.assert_not_called()
    assert "non-loopback" in capsys.readouterr().err
