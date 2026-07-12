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

from scoped_mcp.credentials_vault import _MAX_RENEWAL_FAILURES, VaultCredentialSource


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
    # secret_id is never held as instance state — only the env var *name* is kept,
    # so _login() can re-read it at renewal time while a traceback-with-locals
    # capture reachable via self can never expose the value.
    assert not hasattr(src, "_secret_id")
    assert src._secret_id_env == "VAULT_SECRET_ID"


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


@pytest.mark.asyncio
async def test_renewal_uses_real_hvac_token_renew_self(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: renewal must call auth.token.renew_self, not auth.renew_self.

    A real hvac.Client has renew_self nested under .auth.token; the top-level
    .auth.renew_self does not exist. Earlier tests patched asyncio.to_thread
    wholesale and so never exercised the actual attribute chain, letting a wrong
    path ship. This test uses a real client so a bad path raises AttributeError.
    """
    import hvac

    src = _make_source(monkeypatch)
    client = hvac.Client(url="https://vault.example.com")
    client.auth.token.renew_self = MagicMock(return_value={"auth": {"lease_duration": 1800}})
    src._client = client
    src._consecutive_failures = 3

    await src._renew_once()  # real asyncio.to_thread — exercises the true attribute path

    client.auth.token.renew_self.assert_called_once()
    assert src._consecutive_failures == 0
    assert src._token_lease_duration == 1800


# ── L1 self-heal re-auth + credential health (SMCP-26) ────────────────────────


def _make_reauth_source(monkeypatch: pytest.MonkeyPatch) -> VaultCredentialSource:
    monkeypatch.setenv("SCOPED_MCP_VAULT_REAUTH", "1")
    return _make_source(monkeypatch)


@pytest.mark.parametrize(
    "value,expected",
    [("1", True), ("true", True), ("YES", True), ("on", True), ("0", False), ("", False)],
)
def test_reauth_flag_parsing(monkeypatch: pytest.MonkeyPatch, value: str, expected: bool) -> None:
    monkeypatch.setenv("SCOPED_MCP_VAULT_REAUTH", value)
    src = _make_source(monkeypatch)
    assert src._reauth_enabled is expected


def test_credential_health_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _make_source(monkeypatch)
    health = src.credential_health()
    assert set(health) == {
        "source",
        "token_healthy",
        "consecutive_failures",
        "last_renewal_ok_ts",
        "last_reauth_ts",
        "seconds_to_expiry_est",
        "reauth_enabled",
    }
    assert health["source"] == "vault"
    assert health["token_healthy"] is True
    assert health["consecutive_failures"] == 0


@pytest.mark.asyncio
async def test_reauth_on_forbidden_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 403-class renewal failure with re-auth enabled mints a fresh token via _login."""
    import hvac
    import hvac.exceptions

    src = _make_reauth_source(monkeypatch)
    assert src._reauth_enabled is True

    # Real client whose renew_self raises Forbidden — do NOT patch asyncio.to_thread.
    client = hvac.Client(url="https://vault.example.com")
    client.auth.token.renew_self = MagicMock(
        side_effect=hvac.exceptions.Forbidden("permission denied")
    )
    src._client = client

    # _login() (run in a thread) authenticates against a fresh patched hvac.Client.
    login_client = MagicMock()
    login_client.auth.approle.login.return_value = {"auth": {"lease_duration": 1200}}

    with patch("scoped_mcp.credentials_vault.hvac.Client", return_value=login_client):
        await src._renew_once()

    assert src._consecutive_failures == 0
    assert src._token_healthy is True
    assert src._last_reauth_ts is not None
    assert src._token_lease_duration == 1200
    assert src._client is login_client


@pytest.mark.asyncio
async def test_no_reauth_when_disabled_degrades_and_fires_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-auth disabled: repeated failures flip token_healthy false and fire one alert."""
    import hvac

    monkeypatch.delenv("SCOPED_MCP_VAULT_REAUTH", raising=False)
    src = _make_source(monkeypatch)
    assert src._reauth_enabled is False

    client = hvac.Client(url="https://vault.example.com")
    client.auth.token.renew_self = MagicMock(side_effect=RuntimeError("vault down"))
    src._client = client

    transitions: list[dict] = []

    async def _cb(health: dict) -> None:
        transitions.append(health)

    src.set_health_change_callback(_cb)

    for _ in range(_MAX_RENEWAL_FAILURES):
        await src._renew_once()

    assert src._consecutive_failures == _MAX_RENEWAL_FAILURES
    assert src._token_healthy is False
    # Exactly one transition (healthy → degraded), not one per failed cycle.
    assert len(transitions) == 1
    assert transitions[0]["token_healthy"] is False


@pytest.mark.asyncio
async def test_health_callback_fires_once_per_edge_including_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Degrade then recover — callback fires exactly once on each transition edge."""
    import hvac

    src = _make_source(monkeypatch)  # re-auth disabled
    client = hvac.Client(url="https://vault.example.com")
    src._client = client

    edges: list[bool] = []

    async def _cb(health: dict) -> None:
        edges.append(health["token_healthy"])

    src.set_health_change_callback(_cb)

    # Degrade.
    client.auth.token.renew_self = MagicMock(side_effect=RuntimeError("down"))
    for _ in range(_MAX_RENEWAL_FAILURES):
        await src._renew_once()
    assert src._token_healthy is False

    # Recover.
    client.auth.token.renew_self = MagicMock(return_value={"auth": {"lease_duration": 1800}})
    await src._renew_once()
    assert src._token_healthy is True

    assert edges == [False, True]


@pytest.mark.asyncio
async def test_reauth_failure_keeps_degraded_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the re-login itself fails, the failure state persists (L2 will alert)."""
    import hvac

    src = _make_reauth_source(monkeypatch)
    client = hvac.Client(url="https://vault.example.com")
    client.auth.token.renew_self = MagicMock(side_effect=RuntimeError("down"))
    src._client = client

    # _login raises (Vault unreachable) — re-auth cannot recover.
    with patch(
        "scoped_mcp.credentials_vault.hvac.Client",
        side_effect=ConnectionRefusedError("no route"),
    ):
        for _ in range(_MAX_RENEWAL_FAILURES):
            await src._renew_once()

    assert src._token_healthy is False
    assert src._consecutive_failures >= _MAX_RENEWAL_FAILURES


@pytest.mark.asyncio
async def test_health_callback_exception_never_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A raising health callback is swallowed — it can never crash the renewal loop."""
    import hvac

    src = _make_source(monkeypatch)
    client = hvac.Client(url="https://vault.example.com")
    client.auth.token.renew_self = MagicMock(side_effect=RuntimeError("down"))
    src._client = client

    async def _bad_cb(health: dict) -> None:
        raise ValueError("sink is broken")

    src.set_health_change_callback(_bad_cb)

    for _ in range(_MAX_RENEWAL_FAILURES):
        await src._renew_once()  # must not raise despite the bad callback

    assert src._token_healthy is False
