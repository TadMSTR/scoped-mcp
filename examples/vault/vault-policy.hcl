# Vault policy for scoped-mcp agents.
# Apply with: vault policy write scoped-mcp-research vault-policy.hcl

# Allow read access to the agent's credential bundle.
# Adjust the path to match your KV mount and agent_type.
path "secret/data/scoped-mcp/research" {
  capabilities = ["read"]
}

# If using multiple agent types, add a rule per type or use a wildcard:
# path "secret/data/scoped-mcp/*" {
#   capabilities = ["read"]
# }

# Background token renewal needs the renew-self capability. Vault's built-in
# `default` policy already grants `auth/token/renew-self` ["update"], and scoped-mcp
# AppRoles keep the default policy — so you normally do NOT need the rule below.
# Add it ONLY if your AppRole sets `token_no_default_policy = true`, which strips the
# default grant and otherwise leaves background renewal failing 403 on every cycle.
#
# path "auth/token/renew-self" {
#   capabilities = ["update"]
# }
#
# Note: renew-self can only extend a token up to its `token_max_ttl`; it can never
# exceed that ceiling. For processes that must outlive `token_max_ttl`, either set
# `token_period` on the AppRole (periodic tokens renew indefinitely) or enable
# scoped-mcp's app-side re-auth with SCOPED_MCP_VAULT_REAUTH=1 (requires a reusable
# secret_id, i.e. secret_id_num_uses=0). See the README "Vault Credentials" section.
