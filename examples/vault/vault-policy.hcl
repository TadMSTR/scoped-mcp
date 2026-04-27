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
