"""Tests for credentials.py — env and file credential resolution."""

from __future__ import annotations

import textwrap

import pytest

from scoped_mcp.credentials import resolve_credentials
from scoped_mcp.exceptions import CredentialError

# ── env source ────────────────────────────────────────────────────────────────


def test_env_source_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_TOKEN", "secret-value")
    result = resolve_credentials("env", ["MY_TOKEN"])
    assert result == {"MY_TOKEN": "secret-value"}


def test_env_source_multiple_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEY_A", "val-a")
    monkeypatch.setenv("KEY_B", "val-b")
    result = resolve_credentials("env", ["KEY_A", "KEY_B"])
    assert result["KEY_A"] == "val-a"
    assert result["KEY_B"] == "val-b"


def test_env_source_missing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_KEY", raising=False)
    with pytest.raises(CredentialError, match="MISSING_KEY"):
        resolve_credentials("env", ["MISSING_KEY"])


def test_env_source_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    result = resolve_credentials("env", [])
    assert result == {}


# ── file source ───────────────────────────────────────────────────────────────


def _write_secrets(tmp_path: object, content: str, mode: int = 0o600) -> str:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    secrets_file = tmp_path / "secrets.yml"
    secrets_file.write_text(content)
    secrets_file.chmod(mode)
    return str(secrets_file)


def test_file_source_success(tmp_path: object) -> None:
    path = _write_secrets(
        tmp_path,
        textwrap.dedent("""\
        MY_TOKEN: file-secret-value
        OTHER_KEY: other-value
    """),
    )
    result = resolve_credentials("file", ["MY_TOKEN"], file_path=path)
    assert result == {"MY_TOKEN": "file-secret-value"}


def test_file_source_missing_key(tmp_path: object) -> None:
    path = _write_secrets(tmp_path, "OTHER_KEY: value\n")
    with pytest.raises(CredentialError, match="MY_TOKEN"):
        resolve_credentials("file", ["MY_TOKEN"], file_path=path)


def test_file_source_file_not_found() -> None:
    with pytest.raises(CredentialError, match="not found"):
        resolve_credentials("file", ["MY_TOKEN"], file_path="/nonexistent/path/secrets.yml")


def test_file_source_requires_path() -> None:
    with pytest.raises(CredentialError, match="path"):
        resolve_credentials("file", ["MY_TOKEN"])


def test_file_source_invalid_yaml(tmp_path: object) -> None:
    path = _write_secrets(tmp_path, ": invalid: yaml: :\n")
    with pytest.raises(CredentialError):
        resolve_credentials("file", ["MY_TOKEN"], file_path=path)


# ── M6: secrets file permission / ownership check ────────────────────────────


def test_file_source_rejects_world_readable(tmp_path: object) -> None:
    path = _write_secrets(tmp_path, "MY_TOKEN: v\n", mode=0o644)
    with pytest.raises(CredentialError, match="insecure permissions"):
        resolve_credentials("file", ["MY_TOKEN"], file_path=path)


def test_file_source_rejects_group_readable(tmp_path: object) -> None:
    path = _write_secrets(tmp_path, "MY_TOKEN: v\n", mode=0o640)
    with pytest.raises(CredentialError, match="insecure permissions"):
        resolve_credentials("file", ["MY_TOKEN"], file_path=path)


def test_file_source_strict_permissions_false_warns(
    tmp_path: object, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    path = _write_secrets(tmp_path, "MY_TOKEN: v\n", mode=0o644)
    with caplog.at_level(logging.WARNING, logger="scoped_mcp.credentials"):
        result = resolve_credentials("file", ["MY_TOKEN"], file_path=path, strict_permissions=False)
    assert result == {"MY_TOKEN": "v"}
    assert any("insecure permissions" in r.getMessage() for r in caplog.records)


def test_file_source_0600_passes(tmp_path: object) -> None:
    path = _write_secrets(tmp_path, "MY_TOKEN: v\n", mode=0o600)
    assert resolve_credentials("file", ["MY_TOKEN"], file_path=path) == {"MY_TOKEN": "v"}


# ── unknown source ────────────────────────────────────────────────────────────


def test_unknown_source_raises() -> None:
    with pytest.raises(CredentialError, match="Unknown credential source"):
        resolve_credentials("magic", ["MY_TOKEN"])  # type: ignore[arg-type]


def test_vault_source_raises_descriptive_error() -> None:
    with pytest.raises(CredentialError, match="VaultCredentialSource"):
        resolve_credentials("vault", ["MY_TOKEN"])  # type: ignore[arg-type]


# ── L2: optional_keys ─────────────────────────────────────────────────────────


def test_env_optional_key_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REQUIRED_KEY", "a")
    monkeypatch.setenv("OPTIONAL_KEY", "b")
    result = resolve_credentials("env", ["REQUIRED_KEY"], optional_keys=["OPTIONAL_KEY"])
    assert result == {"REQUIRED_KEY": "a", "OPTIONAL_KEY": "b"}


def test_env_optional_key_absent_does_not_raise(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REQUIRED_KEY", "a")
    monkeypatch.delenv("OPTIONAL_KEY", raising=False)
    result = resolve_credentials("env", ["REQUIRED_KEY"], optional_keys=["OPTIONAL_KEY"])
    assert result == {"REQUIRED_KEY": "a"}


def test_env_required_missing_still_raises_when_optional_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("REQUIRED_KEY", raising=False)
    monkeypatch.setenv("OPTIONAL_KEY", "b")
    with pytest.raises(CredentialError, match="REQUIRED_KEY"):
        resolve_credentials("env", ["REQUIRED_KEY"], optional_keys=["OPTIONAL_KEY"])


def test_file_optional_key_present(tmp_path: object) -> None:
    path = _write_secrets(tmp_path, "REQUIRED_KEY: a\nOPTIONAL_KEY: b\n")
    result = resolve_credentials(
        "file", ["REQUIRED_KEY"], file_path=path, optional_keys=["OPTIONAL_KEY"]
    )
    assert result == {"REQUIRED_KEY": "a", "OPTIONAL_KEY": "b"}


def test_file_optional_key_absent_does_not_raise(tmp_path: object) -> None:
    path = _write_secrets(tmp_path, "REQUIRED_KEY: a\n")
    result = resolve_credentials(
        "file", ["REQUIRED_KEY"], file_path=path, optional_keys=["OPTIONAL_KEY"]
    )
    assert result == {"REQUIRED_KEY": "a"}
