#!/usr/bin/env bash
# One-time Vault / OpenBao setup for scoped-mcp AppRole auth.
# Requires the Vault CLI (`vault`) or the OpenBao CLI (`bao`) with an admin token already
# exported. `bao` is a drop-in for `vault` here: same subcommands, same flags, and it
# reads the same VAULT_ADDR / VAULT_TOKEN env vars (BAO_ADDR / BAO_TOKEN also work).
#
# Usage (HashiCorp Vault):
#   export VAULT_ADDR=https://vault.example.com
#   export VAULT_TOKEN=<admin-token>
#   bash examples/vault/setup.sh
#
# Usage (OpenBao):
#   export VAULT_ADDR=https://openbao.example.com
#   export VAULT_TOKEN=<admin-token>
#   VAULT_CLI=bao bash examples/vault/setup.sh
#
# Use a scoped admin token (one that can write policies, enable auth methods and manage
# AppRoles), not a root token, where your server allows it. Keep the token out of shell
# history, e.g. `read -rs VAULT_TOKEN && export VAULT_TOKEN`.

set -euo pipefail

VAULT_CLI="${VAULT_CLI:-vault}"
POLICY_NAME="scoped-mcp-research"
ROLE_NAME="scoped-mcp-research"
KV_MOUNT="secret"
AGENT_TYPE="research"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v "${VAULT_CLI}" >/dev/null 2>&1; then
    echo "error: '${VAULT_CLI}' not found on PATH (set VAULT_CLI=vault or VAULT_CLI=bao)" >&2
    exit 1
fi

echo "==> Using CLI: ${VAULT_CLI}"

echo "==> Enabling KV v2 at ${KV_MOUNT}/ (skip if already enabled)"
"${VAULT_CLI}" secrets enable -path="${KV_MOUNT}" kv-v2 2>/dev/null || true

echo "==> Writing policy ${POLICY_NAME}"
"${VAULT_CLI}" policy write "${POLICY_NAME}" "${SCRIPT_DIR}/vault-policy.hcl"

echo "==> Enabling AppRole auth (skip if already enabled)"
"${VAULT_CLI}" auth enable approle 2>/dev/null || true

echo "==> Creating AppRole role ${ROLE_NAME}"
"${VAULT_CLI}" write "auth/approle/role/${ROLE_NAME}" \
    token_policies="${POLICY_NAME}" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_num_uses=1

echo "==> Reading role_id"
"${VAULT_CLI}" read -field=role_id "auth/approle/role/${ROLE_NAME}/role-id"

echo ""
echo "==> Generating a new secret_id (one-time use)"
"${VAULT_CLI}" write -field=secret_id -force "auth/approle/role/${ROLE_NAME}/secret-id"

echo ""
echo "==> Writing example credentials to ${KV_MOUNT}/data/agents/${AGENT_TYPE}"
"${VAULT_CLI}" kv put "${KV_MOUNT}/agents/${AGENT_TYPE}" \
    EXAMPLE_API_KEY="replace-with-real-value"

echo ""
echo "Done. Export VAULT_ADDR, VAULT_ROLE_ID and VAULT_SECRET_ID before running scoped-mcp."
