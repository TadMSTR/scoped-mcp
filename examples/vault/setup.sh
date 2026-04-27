#!/usr/bin/env bash
# One-time Vault setup for scoped-mcp AppRole auth.
# Requires the Vault CLI with a root/admin token already exported.
#
# Usage:
#   export VAULT_ADDR=https://vault.example.com
#   export VAULT_TOKEN=<root-token>
#   bash examples/vault/setup.sh

set -euo pipefail

POLICY_NAME="scoped-mcp-research"
ROLE_NAME="scoped-mcp-research"
KV_MOUNT="secret"
AGENT_TYPE="research"

echo "==> Enabling KV v2 at ${KV_MOUNT}/ (skip if already enabled)"
vault secrets enable -path="${KV_MOUNT}" kv-v2 2>/dev/null || true

echo "==> Writing policy ${POLICY_NAME}"
vault policy write "${POLICY_NAME}" vault-policy.hcl

echo "==> Enabling AppRole auth (skip if already enabled)"
vault auth enable approle 2>/dev/null || true

echo "==> Creating AppRole role ${ROLE_NAME}"
vault write "auth/approle/role/${ROLE_NAME}" \
    token_policies="${POLICY_NAME}" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_num_uses=1

echo "==> Reading role_id"
vault read -field=role_id "auth/approle/role/${ROLE_NAME}/role-id"

echo ""
echo "==> Generating a new secret_id (one-time use)"
vault write -field=secret_id -force "auth/approle/role/${ROLE_NAME}/secret-id"

echo ""
echo "==> Writing example credentials to ${KV_MOUNT}/data/scoped-mcp/${AGENT_TYPE}"
vault kv put "${KV_MOUNT}/scoped-mcp/${AGENT_TYPE}" \
    EXAMPLE_API_KEY="replace-with-real-value"

echo ""
echo "Done. Export VAULT_ROLE_ID and VAULT_SECRET_ID before running scoped-mcp."
