# Vault / OpenBao policy for one scoped-mcp agent (here: research).
# The HCL is identical for both servers. Apply with either CLI:
#   vault policy write scoped-mcp-research vault-policy.hcl
#   bao   policy write scoped-mcp-research vault-policy.hcl

# Read access to this agent's own credential bundle, and nothing else.
# Adjust the path to match your KV mount and agent_type.
path "secret/data/agents/research" {
  capabilities = ["read"]
}

# One policy per agent, each naming its own exact path. Do NOT use a wildcard such as
# "secret/data/agents/*": a shared wildcard lets every agent's AppRole read every other
# agent's credentials, which defeats per-agent scoping. For a second agent, copy this
# file, change the path, and bind the new policy to that agent's own AppRole.

# Background token renewal needs the renew-self capability. The built-in `default`
# policy (Vault and OpenBao alike) already grants `auth/token/renew-self` ["update"], and
# scoped-mcp AppRoles keep the default policy — so you normally do NOT need the rule below.
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
# secret_id, i.e. secret_id_num_uses=0). See the README section
# "Credential Health, Self-Heal & Alerting".
