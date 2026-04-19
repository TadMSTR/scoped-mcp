# Multi-Agent Setup

How to run multiple agents, each with their own scoped-mcp instance.

## One manifest per agent type

Each agent role gets a manifest file. Multiple agent instances of the same type share a manifest but have unique `AGENT_ID` values.

```
manifests/
├── research-agent.yml   # read-only: filesystem, sqlite, ntfy
├── build-agent.yml      # read-write: filesystem, sqlite, http_proxy, ntfy, slack
└── ops-agent.yml        # infra: influxdb, grafana, ntfy
```

## Claude Code: one project per agent

Create a separate `.claude/` directory (or project workspace) per agent. Each gets its own `settings.json`:

**Research agent (`~/.claude/projects/research/settings.json`):**
```json
{
  "mcpServers": {
    "tools": {
      "command": "scoped-mcp",
      "args": ["--manifest", "/home/ted/manifests/research-agent.yml"],
      "env": {
        "AGENT_ID": "research-01",
        "AGENT_TYPE": "research",
        "NTFY_URL": "https://ntfy.example.com"
      }
    }
  }
}
```

**Build agent (`~/.claude/projects/build/settings.json`):**
```json
{
  "mcpServers": {
    "tools": {
      "command": "scoped-mcp",
      "args": ["--manifest", "/home/ted/manifests/build-agent.yml"],
      "env": {
        "AGENT_ID": "build-01",
        "AGENT_TYPE": "build",
        "NTFY_URL": "https://ntfy.example.com",
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/..."
      }
    }
  }
}
```

## Process management

### Claude Code (native — recommended)

If you're using Claude Code, no external process manager is needed. scoped-mcp
is declared as an MCP server in each project's `settings.json`. Claude Code starts
it when the project opens and stops it when it closes. Each agent project runs its
own isolated scoped-mcp process automatically.

This is the recommended setup: no daemon configuration, no startup scripts, and
process lifetime is tied to the agent session.

### PM2 (persistent / headless agents)

For agents that run continuously outside of a Claude Code session, PM2 keeps them
alive and captures structured logs per agent:

**`ecosystem.config.js`:**
````js
module.exports = {
  apps: [
    {
      name: "research-agent",
      script: "scoped-mcp",
      args: ["--manifest", "/home/ted/manifests/research-agent.yml"],
      env: {
        AGENT_ID: "research-01",
        AGENT_TYPE: "research",
        NTFY_URL: "https://ntfy.example.com",
      },
    },
    {
      name: "ops-agent",
      script: "scoped-mcp",
      args: ["--manifest", "/home/ted/manifests/ops-agent.yml"],
      env: {
        AGENT_ID: "ops-01",
        AGENT_TYPE: "ops",
        INFLUXDB_URL: "https://influxdb.example.com",
        INFLUXDB_TOKEN: "your-token",
        GRAFANA_URL: "https://grafana.example.com",
        GRAFANA_SERVICE_ACCOUNT_TOKEN: "glsa_abc123",
        NTFY_URL: "https://ntfy.example.com",
      },
    },
  ],
};
````

```bash
pm2 start ecosystem.config.js
pm2 save          # persist across reboots
```

**Important:** `AGENT_ID` and `AGENT_TYPE` must be in the `env` block. They are
read by scoped-mcp at startup to configure the agent's identity and load the
correct manifest.

### Systemd (server deployments)

For production server deployments, a systemd unit per agent type is the standard
approach. scoped-mcp emits structured JSON-L logs to stdout, which systemd captures
via journald. See `docs/` for a sample unit file.

## Verifying isolation

These checks confirm the two core claims — resource isolation and credential
non-exposure — without reading the source.

### Filesystem isolation

With the research agent (`AGENT_ID=research-01`) active:

```
filesystem_write_file("private.txt", "agent1 only")
# → writes to /tmp/scoped-mcp-data/agents/research-01/private.txt
```

Switch to the build agent (`AGENT_ID=build-01`) and attempt to read the same
absolute path:

```
filesystem_read_file("/tmp/scoped-mcp-data/agents/research-01/private.txt")
# → ScopeViolation: Path '...' is outside the agent scope for 'build-01'.
#   Expected prefix: /tmp/scoped-mcp-data/agents/build-01
```

The build agent cannot reach research-01's files regardless of the path used,
including `../research-01/private.txt` traversal attempts.

### Credential non-exposure

Credentials are never returned in tool responses or error messages. To verify:

1. Configure the ntfy module with a real `NTFY_URL` value.
2. Call any tool that fails (e.g. `ntfy_send` with an invalid topic).
3. Inspect the error message — it will name the missing/invalid field but
   never contain the `NTFY_URL` value itself.

The same applies to InfluxDB tokens, Grafana service account tokens, SMTP
passwords, and webhook URLs — only key names appear in logs and errors,
never values.

### Audit log confirmation

Every tool call produces a structured JSON-L audit entry on stdout:

```json
{"event": "tool_call", "agent_id": "research-01", "tool": "filesystem_read_file",
 "args": {"path": "private.txt"}, "status": "ok", "timestamp": "..."}
```

Scope violations are logged with `"status": "blocked"` and `"event": "scope_violation"` before the
call is blocked. No backend operation occurs after a violation.

## Audit log aggregation

Both agents log to stdout. Collect with:

```bash
# PM2: logs per service
pm2 logs research-agent
pm2 logs build-agent

# Docker: labels for filtering
docker logs research-01 2>&1 | grep '"logger":"audit"'
```

For Loki, configure Alloy or Promtail to scrape the stdout streams and add `agent_id` as a label.

For a complete Loki integration with Grafana dashboards, see
`examples/audit-log/`.
