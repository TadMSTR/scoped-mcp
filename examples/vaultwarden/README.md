# Vaultwarden credentials

How to populate scoped-mcp credentials from a self-hosted
[Vaultwarden](https://github.com/dani-garcia/vaultwarden) instance.

scoped-mcp reads credentials from environment variables (`source: env`) or a YAML
secrets file (`source: file`). Neither requires scoped-mcp to know about Vaultwarden
— the `bw` CLI fetches and injects the values before scoped-mcp starts.

## Prerequisites

```bash
# Install the Bitwarden CLI
npm install -g @bitwarden/cli    # or: brew install bitwarden-cli

# Point it at your Vaultwarden instance
export BW_SERVER=https://vault.example.com
bw config server $BW_SERVER

# Log in once (interactive)
bw login
```

## Pattern A: secrets file (recommended for headless agents)

This is the cleanest production pattern. A script pulls credentials from Vaultwarden,
writes a 0600 YAML secrets file, then starts scoped-mcp with `source: file`. The file
is the runtime credential surface; Vaultwarden is only accessed at startup.

**`scripts/start-ops-agent.sh`:**
````bash
#!/usr/bin/env bash
set -euo pipefail

SECRETS_FILE="/run/user/$(id -u)/scoped-mcp-ops-secrets.yml"
trap 'rm -f "$SECRETS_FILE"' EXIT

# Unlock vault (requires BW_SESSION or interactive unlock)
# To get a session token:  export BW_SESSION=$(bw unlock --raw)
: "${BW_SESSION:?BW_SESSION must be set — run: export BW_SESSION=\$(bw unlock --raw)}"

# Pull credentials and write secrets file
bw get item "ops-agent-influxdb" | jq -r '
  "INFLUXDB_URL: " + (.fields[] | select(.name=="url") | .value),
  "INFLUXDB_TOKEN: " + (.fields[] | select(.name=="token") | .value)
' > "$SECRETS_FILE"

bw get item "ops-agent-grafana" | jq -r '
  "GRAFANA_URL: " + (.fields[] | select(.name=="url") | .value),
  "GRAFANA_SERVICE_ACCOUNT_TOKEN: " + (.fields[] | select(.name=="token") | .value)
' >> "$SECRETS_FILE"

bw get password "ops-agent-ntfy-url" | \
  awk '{ print "NTFY_URL: " $0 }' >> "$SECRETS_FILE"

chmod 600 "$SECRETS_FILE"

# Start scoped-mcp — secrets file is deleted on exit by trap
AGENT_ID=ops-01 AGENT_TYPE=ops \
  scoped-mcp \
    --manifest manifests/ops-agent-vaultwarden.yml \
    --audit-log /var/log/scoped-mcp/ops-audit.jsonl \
    --ops-log /var/log/scoped-mcp/ops.jsonl
````

**`manifests/ops-agent-vaultwarden.yml`** (use `source: file` instead of `source: env`):
```yaml
agent_type: ops
description: "Operations agent — credentials from Vaultwarden secrets file"

credentials:
  source: file
  path: /run/user/1000/scoped-mcp-ops-secrets.yml
```

> **Note:** `/run/user/1000/` is the XDG runtime directory for UID 1000 (world-inaccessible
> by default on Linux). Adjust the UID if your user is different. The file is written by
> the startup script and deleted on exit via the `trap`.

## Pattern B: environment variables (Claude Code native)

For interactive Claude Code sessions, unlock Vaultwarden once in your shell, then
export the credentials as env vars. Claude Code picks them up from `settings.json`.

```bash
# Unlock once per terminal session
export BW_SESSION=$(bw unlock --raw)

# Export credentials for the ops agent
export INFLUXDB_URL=$(bw get item "ops-agent-influxdb" | jq -r '.fields[] | select(.name=="url") | .value')
export INFLUXDB_TOKEN=$(bw get item "ops-agent-influxdb" | jq -r '.fields[] | select(.name=="token") | .value')
export GRAFANA_URL=$(bw get item "ops-agent-grafana" | jq -r '.fields[] | select(.name=="url") | .value')
export GRAFANA_SERVICE_ACCOUNT_TOKEN=$(bw get item "ops-agent-grafana" | jq -r '.fields[] | select(.name=="token") | .value')
export NTFY_URL=$(bw get password "ops-agent-ntfy-url")

# Then open Claude Code — settings.json passes these through to scoped-mcp
```

The env vars are inherited by Claude Code and forwarded to scoped-mcp via the
`env` block in `settings.json`. No credentials in config files.

## Fully headless (no interactive unlock)

For agents that start automatically (e.g. on boot via PM2 or systemd), interactive
unlock is not possible. Options:

1. **Store a long-lived BW_SESSION token** in a secured env file loaded by the service
   manager. This is a reasonable tradeoff for a local Vaultwarden instance.
2. **Pre-generate the secrets file** on a machine with vault access and deploy it
   to the headless host with strict permissions. Rotate on a schedule.
3. **Use a different secrets source** for headless deployments — e.g. Docker secrets,
   Kubernetes secrets, or a hardware token — and reserve Vaultwarden for interactive agents.

## Vaultwarden item structure

The examples above assume your Vaultwarden items have named custom fields. A
consistent naming convention makes the `bw` commands predictable:

| Item name | Fields |
|---|---|
| `ops-agent-influxdb` | `url` (text), `token` (hidden) |
| `ops-agent-grafana` | `url` (text), `token` (hidden) |
| `ops-agent-ntfy-url` | password field (hidden) |
| `research-agent-ntfy-url` | password field (hidden) |

Use "hidden" field type for token values so they're masked in the Vaultwarden UI.
