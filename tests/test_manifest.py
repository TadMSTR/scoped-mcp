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
            config:
              base_path: /tmp/agents
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


# ── agent_type pattern validation ─────────────────────────────────────────────


def test_agent_type_valid_patterns() -> None:
    for valid in ["research", "build-agent", "agent_01", "a", "a1b2c3"]:
        m = Manifest.model_validate({"agent_type": valid, "modules": {"ntfy": {}}})
        assert m.agent_type == valid


def test_agent_type_invalid_uppercase(tmp_path: Path) -> None:
    path = write_manifest(tmp_path, "agent_type: Research\nmodules:\n  ntfy: {}\n")
    with pytest.raises(ManifestError, match="agent_type"):
        load_manifest(path)


def test_agent_type_invalid_starts_with_hyphen(tmp_path: Path) -> None:
    path = write_manifest(tmp_path, "agent_type: -bad\nmodules:\n  ntfy: {}\n")
    with pytest.raises(ManifestError, match="agent_type"):
        load_manifest(path)


def test_agent_type_invalid_too_long(tmp_path: Path) -> None:
    long_name = "a" * 64
    path = write_manifest(tmp_path, f"agent_type: {long_name}\nmodules:\n  ntfy: {{}}\n")
    with pytest.raises(ManifestError, match="agent_type"):
        load_manifest(path)


# ── module config completeness ────────────────────────────────────────────────


def test_filesystem_requires_base_path(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          filesystem:
            mode: read
            config: {}
        """,
    )
    with pytest.raises(ManifestError, match="base_path"):
        load_manifest(path)


def test_filesystem_valid_with_base_path(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          filesystem:
            mode: read
            config:
              base_path: /tmp/agents
        """,
    )
    m = load_manifest(path)
    assert m.modules["filesystem"].config["base_path"] == "/tmp/agents"


def test_mcp_proxy_requires_upstream(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          proxy:
            type: mcp_proxy
            config: {}
        """,
    )
    with pytest.raises(ManifestError, match=r"url.*command|command.*url"):
        load_manifest(path)


def test_smtp_requires_all_fields(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: build
        modules:
          smtp:
            config:
              host: smtp.example.com
        """,
    )
    with pytest.raises(ManifestError, match=r"from_address|allowed_recipients"):
        load_manifest(path)


# ── extra fields rejected ─────────────────────────────────────────────────────


def test_extra_top_level_field_rejected(tmp_path: Path) -> None:
    """Manifest rejects unknown top-level fields (prevents shadowing attacks)."""
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        unknown_field: bad
        """,
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


# ── state_backend config ──────────────────────────────────────────────────────


def test_state_backend_defaults_to_in_process() -> None:
    m = Manifest.model_validate({"agent_type": "research", "modules": {"ntfy": {}}})
    assert m.state_backend.type == "in_process"


def test_state_backend_dragonfly_requires_url(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        state_backend:
          type: dragonfly
        """,
    )
    with pytest.raises(ManifestError, match="url"):
        load_manifest(path)


def test_state_backend_dragonfly_valid(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        state_backend:
          type: dragonfly
          url: "redis://localhost:6379/0"
        """,
    )
    m = load_manifest(path)
    assert m.state_backend.type == "dragonfly"
    assert m.state_backend.url == "redis://localhost:6379/0"


# ── rate_limits config ────────────────────────────────────────────────────────


def test_rate_limits_valid(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        rate_limits:
          global: 100/minute
          per_tool:
            filesystem.write_file: 10/minute
            mcp_proxy.*: 50/hour
        """,
    )
    m = load_manifest(path)
    assert m.rate_limits is not None
    assert m.rate_limits.global_limit == "100/minute"
    assert m.rate_limits.per_tool["filesystem.write_file"] == "10/minute"


def test_rate_limits_invalid_format(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        rate_limits:
          global: 100/fortnight
        """,
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_rate_limits_absent_when_not_specified() -> None:
    m = Manifest.model_validate({"agent_type": "research", "modules": {"ntfy": {}}})
    assert m.rate_limits is None


# ── credentials.source: vault ─────────────────────────────────────────────────


def test_credentials_vault_requires_vault_block(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        credentials:
          source: vault
        """,
    )
    with pytest.raises(ManifestError, match="vault"):
        load_manifest(path)


def test_credentials_vault_valid(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        credentials:
          source: vault
          vault:
            addr: "https://vault.example.com"
            auth: approle
            path: "secret/data/scoped-mcp/research"
        """,
    )
    m = load_manifest(path)
    assert m.credentials.source == "vault"
    assert m.credentials.vault is not None
    assert m.credentials.vault.addr == "https://vault.example.com"
