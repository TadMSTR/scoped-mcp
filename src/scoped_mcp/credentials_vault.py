"""HashiCorp Vault credential source for scoped-mcp.

Requires: pip install scoped-mcp[vault]

Authentication: AppRole (role_id + secret_id from env vars).
The secret_id is never held on the instance — it is read from the environment
only for the duration of a login call.

Startup flow:
  1. Authenticate with AppRole → receive a client token + lease TTL
  2. Read the KV secret bundle at the configured path
  3. Return credentials dict to the caller

Background renewal + self-heal:
  - start_renewal() starts an asyncio.Task that sleeps 2/3 of the token TTL
  - On renewal failure the error is logged; on 3 consecutive failures → critical log
  - L1 self-heal: when re-auth is enabled (SCOPED_MCP_VAULT_REAUTH=1) and the
    failure is a permission/403 class or the failure streak has crossed the
    critical threshold, a fresh AppRole login mints a new token. This covers the
    hard 24h token_max_ttl ceiling that renew-self alone cannot exceed.
  - credential_health() exposes a Vault-independent snapshot for scoped_mcp_status,
    the refreshable health file, and the /health endpoint.
  - A health-change callback fires once per healthy⇄degraded transition so callers
    can rewrite the health file and send an out-of-band ops alert.
  - close() cancels the renewal task cleanly

Re-auth safety: re-login is gated on SCOPED_MCP_VAULT_REAUTH=1, which the platform
sets only for AppRoles known to have ``secret_id_num_uses=0`` (a reusable secret_id).
Re-logging in with a single-use secret_id would burn the only credential and turn a
soft, recoverable failure into an unrecoverable one — so when the flag is unset, L1
is a no-op and the loop falls through to L2 alerting only.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from collections.abc import Awaitable, Callable
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

# Values of SCOPED_MCP_VAULT_REAUTH that enable L1 self-heal re-login.
_REAUTH_TRUTHY = frozenset({"1", "true", "yes", "on"})

HealthChangeCallback = Callable[[dict], Awaitable[None]]


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
        # The secret_id itself is never stored on the instance — _login() re-reads it
        # from the environment at call time. We keep only the env var *name* so a
        # re-auth after the process has been running can mint a fresh token.
        self._secret_id_env = secret_id_env

        # Interpolate {agent_type} and reject path traversal sequences
        interpolated = path.replace("{agent_type}", agent_type)
        if ".." in interpolated:
            raise CredentialError(
                f"Vault path {interpolated!r} contains '..' — path traversal is not permitted"
            )
        self._path = interpolated
        self._kv_version = kv_version

        # L1 self-heal opt-in. The platform sets this only for AppRoles with a
        # reusable secret_id (secret_id_num_uses=0). Never re-login otherwise.
        self._reauth_enabled = (
            os.environ.get("SCOPED_MCP_VAULT_REAUTH", "").strip().lower() in _REAUTH_TRUTHY
        )

        self._client: Any = None  # hvac.Client set after auth
        self._token_lease_duration: int = 3600
        self._renewal_task: asyncio.Task[None] | None = None
        self._consecutive_failures: int = 0

        # Credential-health tracking (Vault-independent — read by L2/L3).
        self._token_healthy: bool = True
        self._last_renewal_ok_ts: float | None = None
        self._last_reauth_ts: float | None = None
        self._on_health_change: HealthChangeCallback | None = None

    # ── public API ────────────────────────────────────────────────────────────

    def fetch(self) -> dict[str, str]:
        """Authenticate with AppRole and return the credential bundle.

        Synchronous — call before the asyncio event loop is running.
        Raises CredentialError on any failure; the proxy will not start.
        """
        try:
            self._login()
            credentials = self._read_secret()
            _log.info(
                "vault_credentials_fetched",
                path=self._path,
                kv_version=self._kv_version,
                lease_duration=self._token_lease_duration,
                reauth_enabled=self._reauth_enabled,
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

    def set_health_change_callback(self, callback: HealthChangeCallback | None) -> None:
        """Register an async callback fired once per token-health transition.

        The callback receives ``credential_health()``. It must be best-effort and
        non-raising — this class swallows and logs any exception it raises so a
        misbehaving sink can never crash the renewal loop.
        """
        self._on_health_change = callback

    def credential_health(self) -> dict:
        """Return a Vault-independent snapshot of credential health.

        Contains only booleans, counts, and derived timestamps/durations — never
        the client token or any lease/secret string — so it is safe to surface via
        scoped_mcp_status, the health file, and the unauthenticated /health route.
        """
        seconds_to_expiry: int | None = None
        if self._last_renewal_ok_ts is not None:
            seconds_to_expiry = int(
                self._last_renewal_ok_ts + self._token_lease_duration - time.time()
            )
        return {
            "source": "vault",
            "token_healthy": self._token_healthy,
            "consecutive_failures": self._consecutive_failures,
            "last_renewal_ok_ts": self._last_renewal_ok_ts,
            "last_reauth_ts": self._last_reauth_ts,
            "seconds_to_expiry_est": seconds_to_expiry,
            "reauth_enabled": self._reauth_enabled,
        }

    async def start_renewal(self) -> None:
        """Start the background token renewal task."""
        self._renewal_task = asyncio.create_task(self._renewal_loop())

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

    # ── internal ──────────────────────────────────────────────────────────────

    def _login(self) -> None:
        """Authenticate via AppRole and install a fresh client + token lease.

        Re-reads secret_id from the environment at call time (the env var persists
        for the life of the process), so the renewal loop can mint a brand-new
        token after the old one has died. Raises on failure — callers decide
        whether that is fatal (startup ``fetch``) or recoverable (renewal loop).

        The secret_id lives only as a local binding here; it is never stored on the
        instance, so a traceback-with-locals capture reachable via ``self`` cannot
        expose it, and the local is freed when this frame unwinds.
        """
        secret_id = os.environ.get(self._secret_id_env, "")
        if not secret_id:
            raise CredentialError(
                f"Vault AppRole: env var {self._secret_id_env!r} is not set or empty"
            )
        client = hvac.Client(url=self._addr)
        auth_resp = client.auth.approle.login(
            role_id=self._role_id,
            secret_id=secret_id,
        )
        self._token_lease_duration = auth_resp["auth"].get("lease_duration", 3600)
        self._client = client
        self._last_renewal_ok_ts = time.time()

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

    async def _renewal_loop(self) -> None:
        while True:
            # Sleep 2/3 of current lease duration before renewing
            sleep_seconds = max(60, (self._token_lease_duration * 2) // 3)
            await asyncio.sleep(sleep_seconds)
            await self._renew_once()

    async def _renew_once(self) -> None:
        was_healthy = self._token_healthy
        try:
            resp = await asyncio.to_thread(self._client.auth.token.renew_self)
            self._token_lease_duration = resp["auth"].get(
                "lease_duration", self._token_lease_duration
            )
            self._consecutive_failures = 0
            self._last_renewal_ok_ts = time.time()
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
            # L1 self-heal: renew-self cannot extend a token past token_max_ttl, and a
            # permission-class failure will never recover on retry. When re-auth is
            # permitted, mint a fresh token via a full AppRole login instead.
            if self._reauth_enabled and self._should_attempt_reauth(e):
                await self._attempt_reauth(e)

        # Recompute health and fire the transition callback at most once per edge.
        self._token_healthy = self._consecutive_failures < _MAX_RENEWAL_FAILURES
        if self._token_healthy != was_healthy:
            await self._notify_health_change()

    def _should_attempt_reauth(self, error: Exception) -> bool:
        """Re-auth on a permission/403-class failure or a sustained failure streak.

        A ``403 Forbidden`` (e.g. a policy that denies renew-self) will never
        recover on retry, so re-auth immediately rather than waiting out the streak.
        Otherwise fall back to the critical-threshold streak so transient blips
        (network, 5xx) get a few plain retries first.
        """
        if isinstance(error, hvac.exceptions.Forbidden):
            return True
        return self._consecutive_failures >= _MAX_RENEWAL_FAILURES

    async def _attempt_reauth(self, cause: Exception) -> None:
        try:
            await asyncio.to_thread(self._login)
            self._consecutive_failures = 0
            self._last_reauth_ts = time.time()
            _log.info(
                "vault_token_reauthenticated",
                path=self._path,
                lease_duration=self._token_lease_duration,
                after_error=type(cause).__name__,
            )
        except Exception as e:
            # Keep the failure state; L2 alerting fires off the persistent
            # consecutive_failures / unhealthy signal on the next health check.
            _log.error(
                "vault_token_reauth_failed",
                path=self._path,
                consecutive_failures=self._consecutive_failures,
                error=type(e).__name__,
            )

    async def _notify_health_change(self) -> None:
        cb = self._on_health_change
        if cb is None:
            return
        try:
            await cb(self.credential_health())
        except Exception as exc:
            _log.warning("credential_health_callback_failed", error=type(exc).__name__)
