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


def test_file_source_success(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    secrets_file = tmp_path / "secrets.yml"
    secrets_file.write_text(
        textwrap.dedent("""\
        MY_TOKEN: file-secret-value
        OTHER_KEY: other-value
    """)
    )
    result = resolve_credentials("file", ["MY_TOKEN"], file_path=str(secrets_file))
    assert result == {"MY_TOKEN": "file-secret-value"}


def test_file_source_missing_key(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    secrets_file = tmp_path / "secrets.yml"
    secrets_file.write_text("OTHER_KEY: value\n")
    with pytest.raises(CredentialError, match="MY_TOKEN"):
        resolve_credentials("file", ["MY_TOKEN"], file_path=str(secrets_file))


def test_file_source_file_not_found() -> None:
    with pytest.raises(CredentialError, match="not found"):
        resolve_credentials("file", ["MY_TOKEN"], file_path="/nonexistent/path/secrets.yml")


def test_file_source_requires_path() -> None:
    with pytest.raises(CredentialError, match="path"):
        resolve_credentials("file", ["MY_TOKEN"])


def test_file_source_invalid_yaml(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    bad_file = tmp_path / "bad.yml"
    bad_file.write_text(": invalid: yaml: :\n")
    with pytest.raises(CredentialError):
        resolve_credentials("file", ["MY_TOKEN"], file_path=str(bad_file))


# ── unknown source ────────────────────────────────────────────────────────────


def test_unknown_source_raises() -> None:
    with pytest.raises(CredentialError, match="Unknown credential source"):
        resolve_credentials("vault", ["MY_TOKEN"])  # type: ignore[arg-type]
