"""Tests for manifest.py — YAML loading and Pydantic validation."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from scoped_mcp.exceptions import ManifestError
from scoped_mcp.manifest import Manifest, load_manifest


def write_manifest(tmp_path: Path, content: str) -> str:
    f = tmp_path / "manifest.yml"
    f.write_text(textwrap.dedent(content))
    return str(f)


def test_load_valid_manifest(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        description: A research agent
        modules:
          filesystem:
            mode: read
            config:
              base_path: /tmp/agents
    """,
    )
    manifest = load_manifest(path)
    assert manifest.agent_type == "research"
    assert "filesystem" in manifest.modules
    assert manifest.modules["filesystem"].mode == "read"


def test_load_manifest_write_mode(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: build
        modules:
          filesystem:
            mode: write
    """,
    )
    manifest = load_manifest(path)
    assert manifest.modules["filesystem"].mode == "write"


def test_load_manifest_no_mode(tmp_path: Path) -> None:
    """Modules with no mode declared (e.g. notification modules) should be valid."""
    path = write_manifest(
        tmp_path,
        """\
        agent_type: notifier
        modules:
          ntfy: {}
    """,
    )
    manifest = load_manifest(path)
    assert manifest.modules["ntfy"].mode is None


def test_load_manifest_file_credentials(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: build
        credentials:
          source: file
          path: /run/secrets/agent.yml
        modules:
          ntfy: {}
    """,
    )
    manifest = load_manifest(path)
    assert manifest.credentials.source == "file"
    assert manifest.credentials.path == "/run/secrets/agent.yml"


def test_load_manifest_file_not_found() -> None:
    with pytest.raises(ManifestError, match="not found"):
        load_manifest("/nonexistent/manifest.yml")


def test_load_manifest_invalid_yaml(tmp_path: Path) -> None:
    f = tmp_path / "bad.yml"
    f.write_text(": broken:\n  yaml: [\n")
    with pytest.raises(ManifestError):
        load_manifest(str(f))


def test_load_manifest_missing_agent_type(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        modules:
          filesystem:
            mode: read
    """,
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_load_manifest_empty_modules(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules: {}
    """,
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_load_manifest_file_credentials_missing_path(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: build
        credentials:
          source: file
        modules:
          ntfy: {}
    """,
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


# ── type: field tests ─────────────────────────────────────────────────────────


def test_module_config_type_field():
    """type: field is accepted and stored on ModuleConfig."""
    raw = {
        "agent_type": "test",
        "modules": {
            "task-queue": {
                "type": "mcp_proxy",
                "config": {"url": "http://127.0.0.1:8485/mcp"},
            }
        },
    }
    manifest = Manifest.model_validate(raw)
    assert manifest.modules["task-queue"].type == "mcp_proxy"


def test_module_config_type_defaults_none():
    """type: field defaults to None when absent (backwards compatible)."""
    raw = {
        "agent_type": "test",
        "modules": {"matrix": {"config": {"allowed_rooms": ["!abc:test"]}}},
    }
    manifest = Manifest.model_validate(raw)
    assert manifest.modules["matrix"].type is None
