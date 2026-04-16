# Manifest Schema Reference

Manifests are YAML or JSON files passed to scoped-mcp via `--manifest`.

## Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_type` | string | yes | Role identifier (e.g. "research", "build", "monitor") |
| `description` | string | no | Human-readable description of this agent role |
| `modules` | object | yes | Map of module name → module config (at least one required) |
| `credentials` | object | no | Credential source config (defaults to `source: env`) |

## Module config

Each key under `modules` is a module name. The value is:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `"read"` or `"write"` | `null` | Tool mode. `read` = read-only tools; `write` = read + write tools; `null` = all tools (write-only modules like ntfy) |
| `config` | object | `{}` | Module-specific configuration |

## Credential source config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `source` | `"env"` or `"file"` | `"env"` | Where to read credentials from |
| `path` | string | — | Path to a YAML secrets file (required when `source: file`) |

## Secrets file format

When `source: file`, the file must be a YAML mapping of key names to values:

```yaml
NTFY_TOKEN: your-token-here
SMTP_PASSWORD: your-password-here
GRAFANA_SERVICE_ACCOUNT_TOKEN: glsa_abc123
```

## Complete example

```yaml
agent_type: ops
description: "Operations agent with infrastructure access"

credentials:
  source: file
  path: /run/secrets/ops-agent.yml

modules:
  filesystem:
    mode: write
    config:
      base_path: /data/agents

  sqlite:
    mode: write
    config:
      db_path: /data/shared.db

  influxdb:
    mode: write
    config:
      org: "homelab"
      buckets:
        - "metrics"
        - "alerts"

  grafana:
    mode: write

  ntfy:
    config:
      topic: "ops-{agent_id}"
      max_priority: urgent

  http_proxy:
    mode: read
    config:
      allowed_services:
        - name: "status_api"
          base_url: "https://status.internal"
          credential_key: "STATUS_API_TOKEN"
```
