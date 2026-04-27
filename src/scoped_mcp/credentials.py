"""Credential provider — reads secrets from env vars or a YAML secrets file.

Credential values are injected into module contexts at startup. They are
never logged, never returned in tool responses, and never exposed in error
messages (only the key name is referenced in errors, never the value).

Security model (2026-04-16 audit, finding M6):
When reading from a YAML secrets file, the module refuses by default to
load a file that is group- or other-readable, or one not owned by the
running user. Operators can opt out by passing ``strict_permissions=False``
(mapped from the manifest), which downgrades the check to a logged warning.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

from .exceptions import CredentialError

_log = logging.getLogger(__name__)


def resolve_credentials(
    source: str,
    required_keys: list[str],
    file_path: str | None = None,
    strict_permissions: bool = True,
    optional_keys: list[str] | None = None,
) -> dict[str, str]:
    """Resolve a list of credential keys from the configured source.

    Args:
        source: "env" to read from environment variables, "file" to read
                from a YAML secrets file.
        required_keys: credential keys the module cannot start without — a
                missing required key raises ``CredentialError``.
        file_path: path to the YAML secrets file (required when source="file").
        strict_permissions: when True (default), require a secrets file to
                be mode 0600 (no group/other access) and owned by the running
                user. Only applies when source="file".
        optional_keys: credential keys that are loaded if present but do not
                raise if absent. Absent optional keys are simply omitted from
                the returned dict.

    Returns:
        Dict mapping key names to their resolved values. Contains every
        required key; contains optional keys only when the source provided
        a value.

    Raises:
        CredentialError: if a required key is missing or the source is misconfigured.
    """
    opts = list(optional_keys or [])
    if source == "env":
        return _from_env(required_keys, opts)
    elif source == "file":
        if not file_path:
            raise CredentialError("Credential source is 'file' but no path was provided")
        return _from_file(
            required_keys, file_path, strict_permissions=strict_permissions, optional_keys=opts
        )
    elif source == "vault":
        raise CredentialError(
            "Vault credentials must be fetched via VaultCredentialSource before calling "
            "resolve_credentials(). Use filter_vault_credentials() to extract module keys "
            "from the pre-fetched bundle."
        )
    else:
        raise CredentialError(
            f"Unknown credential source: '{source}'. Expected 'env', 'file', or 'vault'"
        )


def _from_env(required_keys: list[str], optional_keys: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    missing: list[str] = []

    for key in required_keys:
        value = os.environ.get(key)
        if value is None:
            missing.append(key)
        else:
            result[key] = value

    if missing:
        raise CredentialError(f"Missing required environment variable(s): {', '.join(missing)}")

    for key in optional_keys:
        value = os.environ.get(key)
        if value is not None:
            result[key] = value

    return result


def _from_file(
    required_keys: list[str],
    file_path: str,
    strict_permissions: bool = True,
    optional_keys: list[str] | None = None,
) -> dict[str, str]:
    path = Path(file_path)
    if not path.exists():
        raise CredentialError(f"Secrets file not found: {file_path}")

    _check_secrets_file_permissions(path, strict_permissions=strict_permissions)

    try:
        raw: Any = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise CredentialError(f"Failed to parse secrets file '{file_path}': {e}") from e

    if not isinstance(raw, dict):
        raise CredentialError(f"Secrets file '{file_path}' must be a YAML mapping at the top level")

    result: dict[str, str] = {}
    missing: list[str] = []

    for key in required_keys:
        if key not in raw:
            missing.append(key)
        else:
            result[key] = str(raw[key])

    if missing:
        raise CredentialError(f"Missing credential key(s) in '{file_path}': {', '.join(missing)}")

    for key in optional_keys or []:
        if key in raw:
            result[key] = str(raw[key])

    return result


def _check_secrets_file_permissions(path: Path, strict_permissions: bool) -> None:
    """Enforce (or warn on) mode 0600 + matching owner for a secrets file.

    Windows has no POSIX uid/mode — the check is skipped there.
    """
    if os.name != "posix":
        return

    st = path.stat()
    mode_bits = st.st_mode & 0o077
    uid_mismatch = st.st_uid != os.getuid()

    problems: list[str] = []
    if mode_bits != 0:
        problems.append(
            f"mode {oct(st.st_mode & 0o777)} is group/other-accessible; run: chmod 600 {path}"
        )
    if uid_mismatch:
        problems.append(f"file is owned by uid {st.st_uid}, not the running user ({os.getuid()})")

    if not problems:
        return

    msg = f"Secrets file '{path}' has insecure permissions: {'; '.join(problems)}"
    if strict_permissions:
        raise CredentialError(
            msg + ". Set strict_permissions=False in the manifest to downgrade this to a warning."
        )
    _log.warning("%s (strict_permissions=False)", msg)


def filter_vault_credentials(
    vault_bundle: dict[str, str],
    required_keys: list[str],
    optional_keys: list[str] | None = None,
) -> dict[str, str]:
    """Extract module-specific keys from a pre-fetched Vault credential bundle.

    Args:
        vault_bundle: the full dict returned by VaultCredentialSource.fetch().
        required_keys: keys the module cannot start without.
        optional_keys: keys that are included if present but not required.

    Returns:
        Dict containing all required keys and any present optional keys.

    Raises:
        CredentialError: if any required key is absent from the bundle.
    """
    missing = [k for k in required_keys if k not in vault_bundle]
    if missing:
        raise CredentialError(
            f"Vault bundle is missing required credential key(s): {', '.join(missing)}"
        )

    result = {k: vault_bundle[k] for k in required_keys}
    for k in optional_keys or []:
        if k in vault_bundle:
            result[k] = vault_bundle[k]
    return result
