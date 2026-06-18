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
| `type` | string | `null` | Module class name. Set when multiple instances of the same module class are needed (e.g. two `mcp_proxy` entries for separate upstream servers). When absent, the manifest key is used as the class name. |
| `config` | object | `{}` | Module-specific configuration |

### mcp_proxy config

Proxy any existing MCP server (HTTP streamable-http or stdio) through scoped-mcp without
writing a custom module. Because multiple independent upstream servers can be proxied, use
`type: mcp_proxy` with a unique manifest key per server.

```yaml
modules:
  task-queue:
    type: mcp_proxy
    config:
      url: http://127.0.0.1:8485/mcp   # streamable-http server
      tool_allowlist: []               # empty = all tools exposed
      tool_denylist: []

  # stdio example — opens a persistent subprocess for the server's lifetime.
  # Discovery uses a short-lived subprocess; tool calls reuse the persistent one.
  agent-bus:
    type: mcp_proxy
    config:
      command: /path/to/python3
      args: [/path/to/mcp_server.py]
```

| Config key | Type | Default | Description |
|------------|------|---------|-------------|
| `url` | string | — | URL of an HTTP streamable-http MCP server (mutually exclusive with `command`) |
| `command` | string | — | Executable for a stdio MCP server (mutually exclusive with `url`) |
| `args` | list[str] | `[]` | Arguments passed to `command` |
| `tool_allowlist` | list[str] | `[]` | If non-empty, only these upstream tools are exposed |
| `tool_denylist` | list[str] | `[]` | These upstream tools are always hidden (applied after allowlist) |
| `discovery_timeout_seconds` | float | `10.0` | Timeout for connecting to the upstream server at startup |

> **stdio transport lifecycle:** Two subprocess spawns occur per module lifetime. A short-lived
> subprocess runs during startup for tool discovery (`tools/list`). A persistent subprocess is
> then opened when the server starts and reused for all tool calls. It is closed cleanly on
> server shutdown. HTTP transport reconnects per-call (no persistent connection).

> **Note:** The `mode:` field has no effect for `mcp_proxy`. Use `tool_allowlist` or
> `tool_denylist` to restrict which upstream tools are exposed. If no filter is set, all
> upstream tools are registered regardless of the `mode:` value.

## Credential source config

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `source` | `"env"`, `"file"`, or `"vault"` | `"env"` | Where to read credentials from |
| `path` | string | — | Path to a YAML secrets file (required when `source: file`) |

For Vault-backed credentials, see [Vault credential source](#vault-credential-source) below.

## Secrets file format

When `source: file`, the file must be a YAML mapping of key names to values:

```yaml
NTFY_TOKEN: your-token-here
SMTP_PASSWORD: your-password-here
GRAFANA_SERVICE_ACCOUNT_TOKEN: glsa_abc123
```

## Vault credential source

Set `credentials.source: vault` to fetch credentials from HashiCorp Vault via AppRole auth.
Credentials are fetched once at startup; the client token is renewed automatically in the background.
Requires `pip install scoped-mcp[vault]`.

```yaml
credentials:
  source: vault
  vault:
    addr: https://vault.example.com
    auth: approle
    role_id_env: VAULT_ROLE_ID        # env var holding the AppRole role ID
    secret_id_env: VAULT_SECRET_ID    # env var holding the AppRole secret ID
    path: secret/data/scoped-mcp/{agent_type}  # {agent_type} interpolated at startup
    kv_version: 2                     # 1 or 2 (default: 2)
```

Path traversal sequences (`..`) in the interpolated path are rejected at startup.
See `examples/vault/` for a working manifest, AppRole policy, and setup script.

## Environment variable substitution

Manifest fields support `${VAR_NAME}` placeholders, expanded from the process environment
before YAML parsing:

```yaml
state_backend:
  type: dragonfly
  url: "redis://:${REDIS_PASSWORD}@host:6379/0"   # always quote substitution sites

credentials:
  source: file
  path: "${SECRETS_FILE}"
```

Rules:
- Only the braced form is expanded (`${VAR}`, not `$VAR`).
- Undefined variables at startup are a hard error — the agent will not start.
- Expanded values are never written to audit or ops logs.
- **Always YAML-quote fields receiving substitution** — a secret value containing `:`, `{`, or `}` can corrupt YAML structure if the field is unquoted.

## state_backend

Pluggable backend for shared state used by rate limiting and HITL. Optional; defaults to `in_process`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `"in_process"` or `"dragonfly"` | `"in_process"` | Backend type |
| `url` | string | — | Redis-compatible URL (required when `type: dragonfly`) |

`in_process` — asyncio-based, no external deps. State is not shared across processes; rate limits and HITL approvals are local to the current process only.

`dragonfly` — Lua-scripted sliding window on any Redis-compatible server (Dragonfly, Valkey, Redis). Required for rate limiting and HITL across multiple concurrent agent processes. Requires `pip install scoped-mcp[dragonfly]`.

```yaml
state_backend:
  type: dragonfly
  url: "redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
```

## rate_limits

Sliding-window rate limits per agent. Optional. Works with `in_process` backend for single-process deployments; use `dragonfly` for cross-process limits.

```yaml
rate_limits:
  global: 60/minute            # all tools combined, per agent instance
  per_tool:
    filesystem_write_file: 10/minute
    "mcp_proxy_*": 30/minute   # glob — all matched tools share one counter
```

Format: `<N>/second`, `<N>/minute`, or `<N>/hour`. Glob patterns in `per_tool` share a single sliding window across all matched tool names. Rate limit violations fail closed — backend errors block tool calls rather than silently bypassing limits.

> **Pattern grammar:** Tool names are always `{manifest_key}_{method}` (underscore-joined). Use `mcp_proxy_*`, not `mcp_proxy.*` — a dotted glob matches nothing. scoped-mcp warns at startup for any `per_tool` pattern that matches no registered tool.

## argument_filters

Pattern-based blocking or alerting on tool argument values. Optional. Registered automatically after rate limiting in the middleware chain.

```yaml
argument_filters:
  - name: no-credentials
    pattern: '(?i)(password|secret|token)\s*[:=]\s*\S+'
    fields: [path, query, body]       # top-level argument names to inspect
    action: block                     # or: warn
    decode: [base64, urlsafe_base64, url]   # optional decode steps before matching
    case_insensitive: true            # default: false
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Identifier used in audit log entries |
| `pattern` | string | yes | Python regex; compiled at manifest load (malformed pattern = startup error) |
| `fields` | list[str] | yes | Top-level argument names to inspect |
| `action` | `"block"` or `"warn"` | yes | `block` returns an error to the agent; `warn` logs and continues |
| `decode` | list[str] | no | Decode steps applied before matching: `base64`, `urlsafe_base64`, `url`. Capped at 64 KiB |
| `case_insensitive` | bool | no | Case-insensitive matching (default: false) |

**Argument filters inspect top-level string arguments only — nested dicts/lists are not walked.** If a tool accepts a structured argument (e.g. `body: {...}`, `metadata: {...}`, `points: [...]`), patterns in `fields` will not match strings nested inside it. For deep inspection, write tool-specific rules targeting the exact top-level field that carries the sensitive data, or use HITL approval for tools with structured args. `response_filter` (which does recurse) is intentionally asymmetric — don't assume argument filters have equivalent depth. Block rules short-circuit on first match. The audit log records rule name, tool name, field name, and a `raw`/`decoded` label — never the matched value.

## hitl

Human-in-the-loop approval for selected tools. Optional. Requires `state_backend.type: dragonfly`.

```yaml
hitl:
  approval_required: ["filesystem_delete_*", "sqlite_execute"]
  shadow: ["mcp_proxy_*"]    # log-only — return synthetic empty-success, never forward
  timeout_seconds: 300        # auto-reject after this many seconds (default: 300)
  notify:
    type: ntfy               # log (default), ntfy, webhook, or matrix
    topic: homelab-hitl
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `approval_required` | list[str] | `[]` | Glob patterns — matching tools require explicit operator approval before forwarding |
| `shadow` | list[str] | `[]` | Glob patterns — matching tools log a sanitised summary and return synthetic empty-success without forwarding upstream |
| `timeout_seconds` | int | `300` | Auto-reject if no decision arrives within this window |
| `notify.type` | `"log"`, `"ntfy"`, `"webhook"`, `"matrix"` | `"log"` | Notification channel for pending approval requests |

Shadow takes precedence: a tool matched by both `shadow` and `approval_required` is always shadowed. Transport failures in the notifier are logged and swallowed — a notification outage cannot wedge the approval loop.

> **Pattern grammar:** Tool names are `{manifest_key}_{method}` (underscore-joined, e.g. `mcp_proxy_call`, `filesystem_read_file`). Use `mcp_proxy_*`, not `mcp_proxy.*` — a dotted glob matches nothing and the rule silently never fires (fail-open). scoped-mcp warns at startup for any `approval_required` or `shadow` pattern that matches no registered tool.

Approve or reject from the CLI:

```bash
scoped-mcp hitl list
scoped-mcp hitl approve <id>
scoped-mcp hitl reject <id> [reason]
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
      db_dir: /data/sqlite       # each agent gets /data/sqlite/agent_{agent_id}.db

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
