# Launcher Scripts

Template scripts for two common patterns when deploying scoped-mcp and its
stdio-mode proxied tools.

## Why launchers?

### Per-session log isolation (`run-scoped-mcp.sh`)

When multiple sessions of the same agent run concurrently, they interleave
writes to `--audit-log` and `--ops-log` if both point at the same file. The
launcher creates per-session log files using `$$` (PID) and a timestamp, so
each session produces its own `audit-<pid>-<ts>.jsonl` and
`ops-<pid>-<ts>.jsonl`. Log consumers can then correlate all events from a
single session without write collisions.

### stdio subprocess env inheritance (`run-langfuse-mcp.sh`)

The MCP protocol sanitizes the subprocess environment when launching stdio
servers. Variables set in the parent shell — including anything in a
`settings.json` env block — are **not** visible to stdio subprocess tools.
If a proxied MCP server needs credentials (API keys, URLs, passwords), they
must be explicitly exported in a launcher script that runs before `exec`ing
the server.

Without a launcher, the subprocess starts with a clean environment and any
credential reads fail silently or with confusing errors.

## Using these templates

1. Copy the relevant template to a stable location on PATH
   (e.g. `~/scripts/run-my-service.sh`).
2. Replace placeholder paths with your actual paths.
3. Set the `command` field in your `mcp_proxy` manifest entry to the launcher
   path instead of the MCP server binary directly.

```yaml
modules:
  my_service:
    type: mcp_proxy
    config:
      command: /path/to/scripts/run-my-service.sh
```
