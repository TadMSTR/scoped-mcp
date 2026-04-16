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

## Verifying isolation

To verify that Agent A cannot access Agent B's files:

1. Start the research agent, write a file: `filesystem_write_file("secret.txt", "agent1 data")`
2. Start the build agent (different `AGENT_ID`), try to read the same absolute path
3. Expect: `ScopeViolation` — the path is outside `agents/build-01/`

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
