# Troubleshooting

Common problems and how to diagnose them.

## Startup errors

scoped-mcp fails fast at startup and exits with a clear message. The ops log
(stderr / `--ops-log`) shows the sequence of initialization steps and where
it stopped.

### Missing `AGENT_ID` or `AGENT_TYPE`

```
error: AGENT_ID environment variable is not set
```

Both must be set before starting scoped-mcp. In Claude Code `settings.json`,
set them in the `env` block. On the command line:

```bash
AGENT_ID=research-01 AGENT_TYPE=research scoped-mcp --manifest manifests/research-agent.yml
```

### Missing required credentials

```
error: Missing required environment variable(s): INFLUXDB_TOKEN, GRAFANA_URL
```

scoped-mcp lists every missing credential in one error and exits without
starting partially. Set the missing env vars and restart. The credential
reference table in the README lists required and optional vars for each module.

### Manifest not found or invalid

```
error: [Errno 2] No such file or directory: 'manifests/research-agent.yml'
error: manifest validation error: modules: field required
```

Check the path passed to `--manifest`. Paths are relative to the working
directory at startup, not the manifest's location. Use an absolute path to
avoid ambiguity.

### Module not recognized

```
error: Unknown module 'redis' — not registered. Available: filesystem, sqlite, ...
```

Custom modules must be importable from the Python environment. See
`examples/custom-module/` for the registration pattern.

---

## Confirming successful startup

On clean startup, the ops log emits four events in sequence:

```json
{"event": "startup", "logger": "ops", "manifest": "manifests/ops-agent.yml", ...}
{"event": "identity_resolved", "logger": "ops", "agent_id": "ops-01", "agent_type": "ops", ...}
{"event": "manifest_loaded", "logger": "ops", "modules": ["influxdb", "grafana", "ntfy"], ...}
{"event": "server_ready", "logger": "ops", "transport": "stdio", ...}
```

If `server_ready` does not appear, look at the last ops event for the failure point.

To write ops logs to a file for easier inspection:

```bash
scoped-mcp --manifest manifests/ops-agent.yml --ops-log /tmp/ops.jsonl
```

---

## Scope violations

### Reading a scope violation in the audit log

Every scope violation is logged as a `scope_violation` event with `status: blocked`:

```json
{
  "event": "scope_violation",
  "logger": "audit",
  "level": "warning",
  "agent_id": "build-01",
  "tool": "filesystem_read_file",
  "args": {"path": "/data/agents/research-01/private.txt"},
  "status": "blocked",
  "error": "Path '/data/agents/research-01/private.txt' is outside the agent scope for 'build-01'. Expected prefix: /data/agents/build-01",
  "elapsed_ms": 0.12,
  "timestamp": "..."
}
```

The `error` field contains the full scope message. The `args` field shows
exactly what the agent passed. No backend operation occurs after a violation.

### "I got a ScopeViolation but the path looks correct"

Check that `base_path` in the manifest resolves to the same directory the
agent is writing to. A common issue: `base_path: /tmp/scoped-mcp-data` resolves
differently if a symlink is involved. Prefer absolute paths without symlinks.

For traversal-style paths (`../`, symlinks in the path), scoped-mcp resolves
the full path before checking — the resolved path must fall under
`{base_path}/agents/{agent_id}/`.

### Filtering violations in the audit log

```bash
# All scope violations for a specific agent
cat audit.jsonl | jq 'select(.event == "scope_violation" and .agent_id == "build-01")'

# All tool calls that were blocked
cat audit.jsonl | jq 'select(.status == "blocked")'

# All tool calls by tool name
cat audit.jsonl | jq 'select(.event == "tool_call" and .tool == "filesystem_write_file")'
```

---

## Audit and ops log flags

By default, both log streams go to stdout as JSON-L. To write to files:

```bash
scoped-mcp \
  --manifest manifests/ops-agent.yml \
  --audit-log /var/log/scoped-mcp/ops-audit.jsonl \
  --ops-log /var/log/scoped-mcp/ops.jsonl
```

Stdout output continues even when file paths are set — both destinations
receive all events. The file output is useful for log shipping (Loki, Splunk,
ELK) without losing terminal visibility.

Audit events have `"logger": "audit"`. Ops events have `"logger": "ops"`.
Filter by logger when both streams go to the same destination.

---

## Tools not appearing in Claude Code

If scoped-mcp starts but tools don't appear in the Claude Code tool list:

1. Check that `server_ready` appears in the ops log — if not, startup failed silently.
2. Verify the manifest module names match the built-in module registry (see README).
3. Check that the `mode` field is set correctly — `mode: read` gives only read tools;
   write-only modules like `ntfy` need no `mode` field.
4. Restart Claude Code after changing `settings.json` — MCP servers are started once
   per session.

---

## Credential values appearing in logs

This should not happen — the sanitization processor redacts values whose keys match
known sensitive suffixes (`_TOKEN`, `_PASSWORD`, `_SECRET`, `_KEY`, etc.) and a
fixed set of common names (`token`, `password`, `api_key`, etc.).

If you observe a credential value in a log entry, open a security issue via the
private channels in `SECURITY.md` rather than a public GitHub issue.
