"""Tests for manifest.py — YAML loading and Pydantic validation."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from scoped_mcp.exceptions import ManifestError
from scoped_mcp.manifest import Manifest, _expand_env_vars, load_manifest


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
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_agent_type_invalid_starts_with_hyphen(tmp_path: Path) -> None:
    path = write_manifest(tmp_path, "agent_type: -bad\nmodules:\n  ntfy: {}\n")
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_agent_type_invalid_too_long(tmp_path: Path) -> None:
    long_name = "a" * 64
    path = write_manifest(tmp_path, f"agent_type: {long_name}\nmodules:\n  ntfy: {{}}\n")
    with pytest.raises(ManifestError):
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
    with pytest.raises(ManifestError):
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
    with pytest.raises(ManifestError):
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
    with pytest.raises(ManifestError):
        load_manifest(path)


# ── extra fields rejected ─────────────────────────────────────────────────────


def test_extra_top_level_field_rejected(tmp_path: Path) -> None:
    """load_manifest() raises ManifestError on unknown top-level fields.

    Prevents shadowing attacks; exercises the load_manifest() code path
    (YAML parse → validate → ManifestError wrapper).  The model-level guard
    (Manifest.model_validate raises ValidationError directly) is covered by
    test_real_manifests.py::test_unknown_top_level_field_still_rejected, which
    also documents the SMCP-4 regression context.  Both tests must pass; neither
    is redundant.
    """
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


def test_rate_limits_extra_field_rejected(tmp_path: Path) -> None:
    """RateLimitsConfig rejects typos/unknown fields (extra=forbid)."""
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        rate_limits:
          global: 10/minute
          per_tol:
            filesystem.*: 5/minute
        """,
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_module_config_extra_field_rejected(tmp_path: Path) -> None:
    """ModuleConfig rejects unknown fields (extra=forbid catches typos like mde: read)."""
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          filesystem:
            mde: read
            config:
              base_path: /tmp/agents
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
    with pytest.raises(ManifestError):
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
    with pytest.raises(ManifestError):
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


# ── argument_filters (v0.9) ──────────────────────────────────────────────────


def test_argument_filters_minimal(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        argument_filters:
          - name: creds
            pattern: "(password|secret)"
        """,
    )
    m = load_manifest(path)
    assert m.argument_filters is not None
    assert len(m.argument_filters) == 1
    rule = m.argument_filters[0]
    assert rule.name == "creds"
    assert rule.action == "block"
    assert rule.fields == ["*"]


def test_argument_filters_full(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        argument_filters:
          - name: trav
            pattern: "\\\\.\\\\./"
            fields: ["path", "file_path"]
            action: block
            decode: [url]
            case_insensitive: false
        """,
    )
    m = load_manifest(path)
    rule = m.argument_filters[0]
    assert rule.fields == ["path", "file_path"]
    assert rule.decode == ["url"]


def test_argument_filters_invalid_regex_rejected(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        argument_filters:
          - name: bad
            pattern: "[unclosed"
        """,
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_argument_filters_invalid_decode_step_rejected(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        argument_filters:
          - name: x
            pattern: ".*"
            decode: [rot13]
        """,
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_argument_filters_extra_field_rejected(tmp_path: Path) -> None:
    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          ntfy: {}
        argument_filters:
          - name: x
            pattern: ".*"
            unknown_field: yes
        """,
    )
    with pytest.raises(ManifestError):
        load_manifest(path)


def test_mcp_proxy_mode_read_emits_warning(tmp_path: Path) -> None:
    """Phase 2.5b: mode:read on mcp_proxy emits a startup warning (it's a no-op)."""
    import structlog.testing

    path = write_manifest(
        tmp_path,
        """\
        agent_type: research
        modules:
          proxy:
            type: mcp_proxy
            mode: read
            config:
              url: http://localhost:8080/mcp
        """,
    )
    with structlog.testing.capture_logs() as captured:
        load_manifest(path)

    warnings = [e for e in captured if e.get("event") == "mcp_proxy_mode_read_noop"]
    assert len(warnings) == 1
    assert warnings[0]["module"] == "proxy"


# ---------------------------------------------------------------------------
# _expand_env_vars unit tests
# ---------------------------------------------------------------------------


def test_expand_env_vars_substitutes_defined_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_SECRET", "hunter2")
    assert (
        _expand_env_vars("url: redis://:${MY_SECRET}@host:6379")
        == "url: redis://:hunter2@host:6379"
    )


def test_expand_env_vars_substitutes_multiple_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOST", "localhost")
    monkeypatch.setenv("PORT", "6379")
    result = _expand_env_vars("${HOST}:${PORT}")
    assert result == "localhost:6379"


def test_expand_env_vars_raises_on_undefined_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_VAR", raising=False)
    with pytest.raises(ManifestError, match="MISSING_VAR"):
        _expand_env_vars("url: redis://:${MISSING_VAR}@host")


def test_expand_env_vars_reports_all_missing_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FOO", raising=False)
    monkeypatch.delenv("BAR", raising=False)
    with pytest.raises(ManifestError) as exc_info:
        _expand_env_vars("${FOO} and ${BAR}")
    msg = str(exc_info.value)
    assert "FOO" in msg
    assert "BAR" in msg


def test_expand_env_vars_no_placeholders(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "agent_type: research\nmodules:\n  filesystem: {}\n"
    assert _expand_env_vars(text) == text


def test_expand_env_vars_does_not_expand_unbraced_dollar(monkeypatch: pytest.MonkeyPatch) -> None:
    """$VAR without braces must not be expanded."""
    monkeypatch.setenv("VAR", "oops")
    result = _expand_env_vars("value: $VAR")
    assert result == "value: $VAR"


def test_expand_env_vars_error_names_var_not_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """ManifestError must name the variable, not the value — value may be secret."""
    monkeypatch.delenv("SECRET_PASS", raising=False)
    with pytest.raises(ManifestError) as exc_info:
        _expand_env_vars("${SECRET_PASS}")
    assert "SECRET_PASS" in str(exc_info.value)


# ---------------------------------------------------------------------------
# load_manifest env var integration tests
# ---------------------------------------------------------------------------


def test_load_manifest_expands_env_var_in_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    path = write_manifest(
        tmp_path,
        """\
        agent_type: sysadmin
        modules:
          filesystem:
            mode: read
            config:
              base_path: /tmp/agents
        state_backend:
          type: dragonfly
          url: ${REDIS_URL}
        """,
    )
    manifest = load_manifest(path)
    assert manifest.state_backend.url == "redis://localhost:6379/0"


def test_load_manifest_raises_manifest_error_on_undefined_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DRAGONFLY_PASSWORD", raising=False)
    path = write_manifest(
        tmp_path,
        """\
        agent_type: sysadmin
        modules:
          filesystem:
            mode: read
            config:
              base_path: /tmp/agents
        state_backend:
          type: dragonfly
          url: redis://:${DRAGONFLY_PASSWORD}@host:6379
        """,
    )
    with pytest.raises(ManifestError, match="DRAGONFLY_PASSWORD"):
        load_manifest(path)


def test_load_manifest_yaml_special_chars_safe_when_quoted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Expanded value with YAML-special chars is safe when the field is YAML-quoted.

    A password containing ':' would corrupt the YAML structure if unquoted
    (url: redis://:pa:ss@host becomes a nested mapping). Quoting the field
    ("${VAR}") prevents this — the substituted text is treated as a string.
    """
    monkeypatch.setenv("REDIS_PASS", "pa:ss{word}")
    path = write_manifest(
        tmp_path,
        """\
        agent_type: sysadmin
        modules:
          filesystem:
            mode: read
            config:
              base_path: /tmp/agents
        state_backend:
          type: dragonfly
          url: "redis://:${REDIS_PASS}@host:6379"
        """,
    )
    manifest = load_manifest(path)
    assert manifest.state_backend.url == "redis://:pa:ss{word}@host:6379"
