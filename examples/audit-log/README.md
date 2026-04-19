# Audit log integration

How to ship scoped-mcp audit logs to Loki and query them in Grafana.

scoped-mcp emits two structured JSON-L streams:

- **Audit log** (`"logger": "audit"`) — every tool call, every scope violation.
  Fields: `event`, `agent_id`, `tool`, `args`, `status`, `elapsed_ms`, `timestamp`.
- **Ops log** (`"logger": "ops"`) — startup, shutdown, config events.
  Fields: `event`, `agent_id`, `agent_type`, `manifest`, `modules`, `timestamp`.

Write both to files using `--audit-log` and `--ops-log`, then ship with Alloy or Promtail.

## Alloy (Grafana Agent Flow)

```hcl
// alloy/scoped-mcp.alloy

local.file_match "scoped_mcp_logs" {
  path_targets = [
    {
      "__path__"   = "/var/log/scoped-mcp/*.jsonl",
      "job"        = "scoped-mcp",
      "host"       = constants.hostname,
    },
  ]
}

loki.source.file "scoped_mcp" {
  targets    = local.file_match.scoped_mcp_logs.targets
  forward_to = [loki.process.scoped_mcp.receiver]
}

loki.process "scoped_mcp" {
  // Parse JSON-L and promote key fields to labels for efficient filtering
  stage.json {
    expressions = {
      agent_id   = "agent_id",
      agent_type = "agent_type",
      event      = "event",
      logger     = "logger",
      status     = "status",
    }
  }

  stage.labels {
    values = {
      agent_id   = "",
      agent_type = "",
      event      = "",
      logger     = "",
      status     = "",
    }
  }

  forward_to = [loki.write.default.receiver]
}

loki.write "default" {
  endpoint {
    url = "http://loki:3100/loki/api/v1/push"
  }
}
```

## Promtail

```yaml
# promtail/scoped-mcp-job.yml — add to your existing Promtail config under scrape_configs

scrape_configs:
  - job_name: scoped-mcp
    static_configs:
      - targets:
          - localhost
        labels:
          job: scoped-mcp
          host: claudebox
          __path__: /var/log/scoped-mcp/*.jsonl

    pipeline_stages:
      - json:
          expressions:
            agent_id:   agent_id
            agent_type: agent_type
            event:      event
            logger:     logger
            status:     status
      - labels:
          agent_id:
          agent_type:
          event:
          logger:
          status:
```

## Log file setup

Use `--audit-log` and `--ops-log` to write logs to the directory Alloy/Promtail scrapes.
In PM2 `ecosystem.config.js`:

````js
{
  name: "ops-agent",
  script: "scoped-mcp",
  args: [
    "--manifest", "/home/ted/manifests/ops-agent.yml",
    "--audit-log", "/var/log/scoped-mcp/ops-audit.jsonl",
    "--ops-log",   "/var/log/scoped-mcp/ops.jsonl",
  ],
  env: { AGENT_ID: "ops-01", AGENT_TYPE: "ops", ... }
}
````

Create the directory and set permissions:
```bash
sudo mkdir -p /var/log/scoped-mcp
sudo chown ted:ted /var/log/scoped-mcp
```

Add logrotate to prevent unbounded growth:
```
# /etc/logrotate.d/scoped-mcp
/var/log/scoped-mcp/*.jsonl {
    daily
    rotate 14
    compress
    missingok
    notifempty
    copytruncate
}
```

## Useful LogQL queries

```logql
# All scope violations across all agents
{job="scoped-mcp", event="scope_violation"}

# Tool calls for a specific agent
{job="scoped-mcp", agent_id="ops-01", event="tool_call"}

# All blocked calls (scope violations + errors)
{job="scoped-mcp"} | json | status != "ok"

# Slow tool calls (>500ms)
{job="scoped-mcp", event="tool_call"} | json | elapsed_ms > 500

# Startup events only
{job="scoped-mcp", logger="ops", event="startup"}

# Count tool calls by tool name in the last hour
sum by (tool) (
  count_over_time({job="scoped-mcp", event="tool_call"}[1h])
)
```

## Grafana dashboard panels

Suggested panels for a scoped-mcp overview dashboard:

| Panel | Type | Query |
|---|---|---|
| Tool calls / min | Time series | `rate({job="scoped-mcp", event="tool_call"}[1m])` |
| Scope violations | Stat + alert | `count_over_time({job="scoped-mcp", event="scope_violation"}[1h])` |
| p95 tool latency | Time series | Parse `elapsed_ms` from audit events |
| Active agents | Table | Distinct `agent_id` values from ops `server_ready` events |
| Violations by agent | Bar chart | Group `scope_violation` events by `agent_id` |

Import the dashboard from `examples/audit-log/grafana-dashboard.json` if present,
or build panels manually using the queries above.
