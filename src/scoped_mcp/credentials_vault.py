"""HashiCorp Vault credential source for scoped-mcp.

Requires: pip install scoped-mcp[vault]

Authentication: AppRole (role_id + secret_id from env vars).
The secret_id is discarded immediately after authentication.

Startup flow:
  1. Authenticate with AppRole → receive a client token + lease TTL
  2. Read the KV secret bundle at the configured path
  3. Return credentials dict to the caller

Background renewal:
  - start_renewal() starts an asyncio.Task that sleeps 2/3 of the token TTL
  - On renewal failure the error is logged; on 3 consecutive failures → critical log
  - close() cancels the renewal task cleanly
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from typing import Any

import structlog

from .exceptions import CredentialError

try:
    import hvac
    import hvac.exceptions
except ImportError as _e:
    raise ImportError(
        "VaultCredentialSource requires hvac. Install with: pip install scoped-mcp[vault]"
    ) from _e

_log = structlog.get_logger("ops")
_MAX_RENEWAL_FAILURES = 3


class VaultCredentialSource:
    """Fetch and renew credentials from HashiCorp Vault using AppRole auth.

    Usage::

        source = VaultCredentialSource(
            addr="https://vault.example.com",
            role_id_env="VAULT_ROLE_ID",
            secret_id_env="VAULT_SECRET_ID",
            path="secret/data/scoped-mcp/{agent_type}",
            agent_type="research",
            kv_version=2,
        )
        credentials = source.fetch()          # sync — call before event loop starts
        await source.start_renewal()          # async — call from lifespan startup
        # ... server runs ...
        await source.close()                  # async — call from lifespan shutdown
    """

    def __init__(
        self,
        addr: str,
        role_id_env: str,
        secret_id_env: str,
        path: str,
        agent_type: str,
        kv_version: int = 2,
    ) -> None:
        self._addr = addr

        role_id = os.environ.get(role_id_env, "")
        secret_id = os.environ.get(secret_id_env, "")
        if not role_id:
            raise CredentialError(f"Vault AppRole: env var {role_id_env!r} is not set or empty")
        if not secret_id:
            raise CredentialError(f"Vault AppRole: env var {secret_id_env!r} is not set or empty")

        self._role_id = role_id
        self._secret_id = secret_id

        # Interpolate {agent_type} and reject path traversal sequences
        interpolated = path.replace("{agent_type}", agent_type)
        if ".." in interpolated:
            raise CredentialError(
                f"Vault path {interpolated!r} contains '..' — path traversal is not permitted"
            )
        self._path = interpolated
        self._kv_version = kv_version

        self._client: Any = None  # hvac.Client set after auth
        self._token_lease_duration: int = 3600
        self._renewal_task: asyncio.Task[None] | None = None
        self._consecutive_failures: int = 0

    def fetch(self) -> dict[str, str]:
        """Authenticate with AppRole and return the credential bundle.

        Synchronous — call before the asyncio event loop is running.
        Raises CredentialError on any failure; the proxy will not start.
        """
        # Drop secret_id off the instance before any hvac code runs.
        # On a login exception, traceback-with-locals capture cannot reach the
        # value via self — only the local `secret_id` binding, which is freed
        # when the frame unwinds.
        secret_id = self._secret_id
        self._secret_id = ""
        try:
            client = hvac.Client(url=self._addr)
            auth_resp = client.auth.approle.login(
                role_id=self._role_id,
                secret_id=secret_id,
            )

            self._token_lease_duration = auth_resp["auth"].get("lease_duration", 3600)
            self._client = client
            credentials = self._read_secret()
            _log.info(
                "vault_credentials_fetched",
                path=self._path,
                kv_version=self._kv_version,
                lease_duration=self._token_lease_duration,
            )
            return credentials

        except CredentialError:
            raise
        except hvac.exceptions.VaultError as e:
            raise CredentialError(f"Vault authentication failed at {self._addr!r}: {e}") from e
        except Exception as e:
            raise CredentialError(
                f"Failed to connect to Vault at {self._addr!r}: {type(e).__name__}: {e}"
            ) from e

    def _read_secret(self) -> dict[str, str]:
        try:
            if self._kv_version == 2:
                resp = self._client.secrets.kv.v2.read_secret_version(path=self._path)
                raw = resp["data"]["data"]
            elif self._kv_version == 1:
                resp = self._client.secrets.kv.v1.read_secret(path=self._path)
                raw = resp["data"]
            else:
                raise CredentialError(
                    f"Unsupported kv_version {self._kv_version!r}: expected 1 or 2"
                )
            if not isinstance(raw, dict):
                raise CredentialError(
                    f"Vault path {self._path!r}: expected a dict of credentials, "
                    f"got {type(raw).__name__}"
                )
            return {k: str(v) for k, v in raw.items()}
        except CredentialError:
            raise
        except hvac.exceptions.VaultError as e:
            raise CredentialError(f"Failed to read Vault secret at {self._path!r}: {e}") from e

    async def start_renewal(self) -> None:
        """Start the background token renewal task."""
        self._renewal_task = asyncio.create_task(self._renewal_loop())

    async def _renewal_loop(self) -> None:
        while True:
            # Sleep 2/3 of current lease duration before renewing
            sleep_seconds = max(60, (self._token_lease_duration * 2) // 3)
            await asyncio.sleep(sleep_seconds)
            await self._renew_once()

    async def _renew_once(self) -> None:
        try:
            resp = await asyncio.to_thread(self._client.auth.renew_self)
            self._token_lease_duration = resp["auth"].get(
                "lease_duration", self._token_lease_duration
            )
            self._consecutive_failures = 0
            _log.info(
                "vault_token_renewed",
                path=self._path,
                lease_duration=self._token_lease_duration,
            )
        except Exception as e:
            self._consecutive_failures += 1
            level = "critical" if self._consecutive_failures >= _MAX_RENEWAL_FAILURES else "error"
            getattr(_log, level)(
                "vault_token_renewal_failed",
                path=self._path,
                consecutive_failures=self._consecutive_failures,
                error=type(e).__name__,
            )

    async def close(self) -> None:
        """Cancel the renewal task on server shutdown.

        If a renewal HTTP call is in flight inside ``asyncio.to_thread``, the
        worker thread cannot be cancelled. Bound the wait to 5 seconds so a
        Vault outage at shutdown time cannot stall server termination.
        """
        if self._renewal_task is not None:
            self._renewal_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(self._renewal_task), timeout=5.0)
            self._renewal_task = None
