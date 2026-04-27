"""Tests for credentials_vault.py — VaultCredentialSource."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scoped_mcp.credentials import filter_vault_credentials
from scoped_mcp.exceptions import CredentialError

# ── filter_vault_credentials ──────────────────────────────────────────────────


def test_filter_returns_required_keys() -> None:
    bundle = {"API_KEY": "secret", "DB_PASS": "dbpass", "OTHER": "x"}
    result = filter_vault_credentials(bundle, required_keys=["API_KEY"])
    assert result == {"API_KEY": "secret"}


def test_filter_includes_present_optional_keys() -> None:
    bundle = {"API_KEY": "secret", "OPTIONAL": "opt-val"}
    result = filter_vault_credentials(bundle, ["API_KEY"], optional_keys=["OPTIONAL"])
    assert result == {"API_KEY": "secret", "OPTIONAL": "opt-val"}


def test_filter_omits_absent_optional_keys() -> None:
    bundle = {"API_KEY": "secret"}
    result = filter_vault_credentials(bundle, ["API_KEY"], optional_keys=["MISSING_OPT"])
    assert result == {"API_KEY": "secret"}


def test_filter_raises_on_missing_required() -> None:
    bundle = {"OTHER": "x"}
    with pytest.raises(CredentialError, match="API_KEY"):
        filter_vault_credentials(bundle, required_keys=["API_KEY"])


def test_filter_empty_bundle_empty_keys() -> None:
    assert filter_vault_credentials({}, required_keys=[]) == {}


# ── VaultCredentialSource — init validation ───────────────────────────────────

# hvac is an optional dependency — skip all tests if not installed
pytest.importorskip("hvac")

from scoped_mcp.credentials_vault import VaultCredentialSource  # noqa: E402


def test_init_raises_on_missing_role_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
    monkeypatch.setenv("VAULT_SECRET_ID", "s3cr3t")
    with pytest.raises(CredentialError, match="VAULT_ROLE_ID"):
        VaultCredentialSource(
            addr="https://vault.example.com",
            role_id_env="VAULT_ROLE_ID",
            secret_id_env="VAULT_SECRET_ID",
            path="secret/data/creds",
            agent_type="research",
        )


def test_init_raises_on_missing_secret_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ROLE_ID", "role-abc")
    monkeypatch.delenv("VAULT_SECRET_ID", raising=False)
    with pytest.raises(CredentialError, match="VAULT_SECRET_ID"):
        VaultCredentialSource(
            addr="https://vault.example.com",
            role_id_env="VAULT_ROLE_ID",
            secret_id_env="VAULT_SECRET_ID",
            path="secret/data/creds",
            agent_type="research",
        )


def test_init_raises_on_path_traversal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ROLE_ID", "role-abc")
    monkeypatch.setenv("VAULT_SECRET_ID", "s3cr3t")
    with pytest.raises(CredentialError, match=r"\.\."):
        VaultCredentialSource(
            addr="https://vault.example.com",
            role_id_env="VAULT_ROLE_ID",
            secret_id_env="VAULT_SECRET_ID",
            path="secret/data/../../../etc/passwd",
            agent_type="research",
        )


def test_init_interpolates_agent_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ROLE_ID", "role-abc")
    monkeypatch.setenv("VAULT_SECRET_ID", "s3cr3t")
    src = VaultCredentialSource(
        addr="https://vault.example.com",
        role_id_env="VAULT_ROLE_ID",
        secret_id_env="VAULT_SECRET_ID",
        path="secret/data/scoped-mcp/{agent_type}",
        agent_type="research",
    )
    assert src._path == "secret/data/scoped-mcp/research"


# ── VaultCredentialSource — fetch ─────────────────────────────────────────────


def _make_source(monkeypatch: pytest.MonkeyPatch) -> VaultCredentialSource:
    monkeypatch.setenv("VAULT_ROLE_ID", "role-abc")
    monkeypatch.setenv("VAULT_SECRET_ID", "s3cr3t")
    return VaultCredentialSource(
        addr="https://vault.example.com",
        role_id_env="VAULT_ROLE_ID",
        secret_id_env="VAULT_SECRET_ID",
        path="secret/data/creds",
        agent_type="research",
        kv_version=2,
    )


def test_fetch_success_kv2(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _make_source(monkeypatch)

    mock_client = MagicMock()
    mock_client.auth.approle.login.return_value = {"auth": {"lease_duration": 7200}}
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"API_KEY": "abc123", "DB_PASS": "hunter2"}}
    }

    with patch("scoped_mcp.credentials_vault.hvac.Client", return_value=mock_client):
        result = src.fetch()

    assert result == {"API_KEY": "abc123", "DB_PASS": "hunter2"}
    assert src._token_lease_duration == 7200
    # secret_id must be discarded immediately after auth
    assert src._secret_id == ""


def test_fetch_success_kv1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ROLE_ID", "role-abc")
    monkeypatch.setenv("VAULT_SECRET_ID", "s3cr3t")
    src = VaultCredentialSource(
        addr="https://vault.example.com",
        role_id_env="VAULT_ROLE_ID",
        secret_id_env="VAULT_SECRET_ID",
        path="secret/creds",
        agent_type="research",
        kv_version=1,
    )

    mock_client = MagicMock()
    mock_client.auth.approle.login.return_value = {"auth": {"lease_duration": 3600}}
    mock_client.secrets.kv.v1.read_secret.return_value = {"data": {"TOKEN": "v1-token"}}

    with patch("scoped_mcp.credentials_vault.hvac.Client", return_value=mock_client):
        result = src.fetch()

    assert result == {"TOKEN": "v1-token"}


def test_fetch_raises_on_vault_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import hvac.exceptions

    src = _make_source(monkeypatch)
    mock_client = MagicMock()
    mock_client.auth.approle.login.side_effect = hvac.exceptions.VaultError("bad token")

    with patch("scoped_mcp.credentials_vault.hvac.Client", return_value=mock_client):
        with pytest.raises(CredentialError, match="Vault authentication failed"):
            src.fetch()


def test_fetch_raises_on_connection_error(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _make_source(monkeypatch)
    mock_client = MagicMock()
    mock_client.auth.approle.login.side_effect = ConnectionRefusedError("connection refused")

    with patch("scoped_mcp.credentials_vault.hvac.Client", return_value=mock_client):
        with pytest.raises(CredentialError, match="Failed to connect to Vault"):
            src.fetch()


def test_fetch_raises_on_unsupported_kv_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ROLE_ID", "role-abc")
    monkeypatch.setenv("VAULT_SECRET_ID", "s3cr3t")
    src = VaultCredentialSource(
        addr="https://vault.example.com",
        role_id_env="VAULT_ROLE_ID",
        secret_id_env="VAULT_SECRET_ID",
        path="secret/creds",
        agent_type="research",
        kv_version=3,
    )

    mock_client = MagicMock()
    mock_client.auth.approle.login.return_value = {"auth": {"lease_duration": 3600}}

    with patch("scoped_mcp.credentials_vault.hvac.Client", return_value=mock_client):
        with pytest.raises(CredentialError, match="Unsupported kv_version"):
            src.fetch()


# ── VaultCredentialSource — renewal lifecycle ─────────────────────────────────


@pytest.mark.asyncio
async def test_close_cancels_renewal_task(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _make_source(monkeypatch)
    # Plant a never-ending task to simulate a running renewal loop
    src._renewal_task = asyncio.create_task(asyncio.sleep(9999))
    await src.close()
    assert src._renewal_task is None


@pytest.mark.asyncio
async def test_close_is_idempotent_when_no_task(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _make_source(monkeypatch)
    await src.close()  # _renewal_task is None — should not raise


@pytest.mark.asyncio
async def test_renewal_increments_consecutive_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _make_source(monkeypatch)
    src._client = MagicMock()

    with patch("asyncio.to_thread", new_callable=AsyncMock, side_effect=RuntimeError("down")):
        await src._renew_once()

    assert src._consecutive_failures == 1


@pytest.mark.asyncio
async def test_renewal_resets_failures_on_success(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _make_source(monkeypatch)
    src._client = MagicMock()
    src._consecutive_failures = 2

    renewal_resp = {"auth": {"lease_duration": 1800}}
    with patch("asyncio.to_thread", new_callable=AsyncMock, return_value=renewal_resp):
        await src._renew_once()

    assert src._consecutive_failures == 0
    assert src._token_lease_duration == 1800
