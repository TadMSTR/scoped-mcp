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
from scoped_mcp.state import build_state_backend


def _state():
    return build_state_backend("in_process")


# ── _build_middleware ─────────────────────────────────────────────────────────


def test_build_middleware_empty_when_no_config(monkeypatch) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    mw = _build_middleware("agent-x", "research", _state(), None, None, None)
    assert mw == []


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
    # Order matters: rate-limit → arg-filter → HITL (gating order documented in server.py).
    assert [type(m) for m in mw] == [
        RateLimitMiddleware,
        ArgumentFilterMiddleware,
        HitlMiddleware,
    ]


def test_build_middleware_skips_hitl_when_empty(monkeypatch) -> None:
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    # approval_required and shadow both empty → no HITL middleware.
    mw = _build_middleware("agent-x", "research", _state(), None, None, HitlConfig())
    assert mw == []


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
    assert len(mw) == 1
    assert isinstance(mw[0], OtelMiddleware)


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
