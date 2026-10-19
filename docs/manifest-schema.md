# Manifest Schema Reference

Manifests are YAML or JSON files passed to scoped-mcp via `--manifest`.

## Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_type` | string | yes | Role identifier (e.g. "research", "build", "monitor") |
| `description` | string | no | Human-readable description of this agent role |
| `modules` | object | yes | Map of module name → module config (at least one required) |
| `credentials` | object | no | Credential source config (defaults to `source: env`) |
| `content_limits` | object | no | Size limits on content forwarded from upstreams. See [content_limits](#content_limits) (v1.19.0) |

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
      # env:                          # optional — a stdio child inherits nothing
      #   API_TOKEN: "${API_TOKEN}"   # from scoped-mcp; name what the child needs here
```

| Config key | Type | Default | Description |
|------------|------|---------|-------------|
| `url` | string | — | URL of an HTTP streamable-http MCP server (mutually exclusive with `command`) |
| `command` | string | — | Executable for a stdio MCP server (mutually exclusive with `url`) |
| `args` | list[str] | `[]` | Arguments passed to `command` |
| `tool_allowlist` | list[str] | `[]` | If non-empty, only these upstream tools are exposed |
| `tool_denylist` | list[str] | `[]` | These upstream tools are always hidden (applied after allowlist) |
| `discovery_timeout_seconds` | float | `10.0` | Timeout for connecting to the upstream server at startup |
| `max_binary_bytes` | int | manifest `content_limits.max_binary_bytes` | Per-module override of the binary block cap. `0` disables it for this module (v1.19.0) |
| `env` | dict[str,str] | `{}` | Environment variables for a spawned stdio child. Ignored on HTTP transport (warns since v1.16.0). Extends the MCP SDK's conditionally-forwarded safe base rather than replacing it — a child inherits nothing else from scoped-mcp. |

> **stdio transport lifecycle:** Two subprocess spawns occur per module lifetime. A short-lived
> subprocess runs during startup for tool discovery (`tools/list`). A persistent subprocess is
> then opened when the server starts and reused for all tool calls. It is closed cleanly on
> server shutdown. HTTP transport reconnects per-call (no persistent connection).

> **Note:** The `mode:` field has no effect for `mcp_proxy`. Use `tool_allowlist` or
> `tool_denylist` to restrict which upstream tools are exposed. If no filter is set, all
> upstream tools are registered regardless of the `mode:` value.

## content_limits

```yaml
content_limits:
  max_binary_bytes: 10485760   # default, 10 MiB; 0 disables the cap
```

`max_binary_bytes` caps each binary block an `mcp_proxy` module forwards: an image or audio
block, or an embedded resource blob. The cap is on the **decoded** size, not on the base64
text, which is a third larger. It is measured on the string as sent, padding and whitespace
included, plus any extra fields, `_meta` or annotations the block carries beside its data. A block over the cap is replaced with a text block such as
`[scoped-mcp: image image/png of 12582912 bytes dropped; cap 10485760]`, and the other
blocks in the result are kept. The drop is logged to ops as `mcp_proxy_binary_dropped` with
the module, tool, kind, MIME type and sizes, never the payload. An upstream MIME type that
isn't a plain `type/subtype` is reported as `unknown`. Text blocks and embedded text
resources are not capped. Set `config.max_binary_bytes` on one `mcp_proxy` module to
override the value for that module only. (v1.19.0, vikunja#1071)

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

**Argument filters inspect top-level string arguments only — nested dicts/lists are not walked.** If a tool accepts a structured argument (e.g. `body: {...}`, `metadata: {...}`, `points: [...]`), patterns in `fields` will not match strings nested inside it. For deep inspection, write tool-specific rules targeting the exact top-level field that carries the sensitive data, or use HITL approval for tools with structured args. `response_filter` (which recurses into dicts and lists and, since v1.17.2, scans every string value on MCP content blocks and decodes text-typed blobs — dict keys excepted) is intentionally asymmetric — don't assume argument filters have equivalent depth. Block rules short-circuit on first match. The audit log records rule name, tool name, field name, and a `raw`/`decoded` label — never the matched value.

## hitl

Human-in-the-loop approval for selected tools. Optional. Requires `state_backend.type: dragonfly`.

```yaml
hitl:
  mode: interactive           # enforce (default) or interactive
  approval_required: ["filesystem_delete_*", "sqlite_execute"]
  shadow: ["mcp_proxy_*"]    # log-only — return synthetic empty-success, never forward
  timeout_seconds: 300        # auto-reject after this many seconds (default: 300)
  notify:
    type: ntfy               # log (default), ntfy, webhook, or matrix
    topic: homelab-hitl
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `mode` | `"enforce"`, `"interactive"` | `"enforce"` | Resolution mode for gated calls (see below) |
| `approval_required` | list[str] | `[]` | Glob patterns — matching tools require explicit operator approval before forwarding |
| `shadow` | list[str] | `[]` | Glob patterns — matching tools log a sanitised summary and return synthetic empty-success without forwarding upstream |
| `timeout_seconds` | int | `300` | Auto-reject if no decision arrives within this window |
| `notify.type` | `"log"`, `"ntfy"`, `"webhook"`, `"matrix"` | `"log"` | Notification channel for pending approval requests |

Shadow takes precedence: a tool matched by both `shadow` and `approval_required` is always shadowed. Transport failures in the notifier are logged and swallowed — a notification outage cannot wedge the approval loop.

### mode: enforce vs interactive

Both modes fire the same Matrix/notify prompt and both reject the gated call immediately, so the agent always stops and asks — they differ only in **how the decision is returned**.

- **`enforce`** (default) — resolution comes from an out-of-band channel the requesting agent cannot write to: the matrix-hitl-bot approve endpoint or the operator CLI (`scoped-mcp hitl approve <id>`). This is the correct mode for headless / clone-pool agents that run unattended. Unchanged from prior releases; any manifest that omits `mode` behaves exactly as before.
- **`interactive`** — for an agent working live in a session with the operator watching the transcript. A companion tool, **`scoped_mcp_hitl_confirm(approval_id, decision)`**, is registered **only** for interactive-mode agents. After the operator gives an explicit approve/deny in the conversation, the agent calls this tool to resolve the pending request in one step, over its own connection — no Matrix round-trip, no `system-ops` shell workaround. It reuses the exact same pre-approval token-write logic as the bot path.

> **Trust tradeoff (interactive only).** `scoped_mcp_hitl_confirm` trusts the agent's own report that the operator approved in the current turn — it does **not** cryptographically verify an out-of-band decision. This is the same trust level every other interactive tool call already runs under. It is registered **only** for interactive-mode agents, so an `enforce`-mode (e.g. unattended) agent can never reach it. Agent guidance must state plainly: only call it after an explicit, unambiguous operator approve/deny **in the current conversation turn** — never speculatively, never on an old approval, never chained automatically.

Every resolution is tagged in the audit trail with a `resolved_via` channel — `matrix_bot` / `courier` (the real out-of-band paths) vs `interactive_self_service` (the in-session shortcut) — so an audit can always tell them apart. Recording the tag requires the `0002_hitl_resolved_via.sql` migration; without it the resolution still works (the column write fails open) but the tag is not persisted.

> **Pattern grammar:** Tool names are `{manifest_key}_{method}` (underscore-joined, e.g. `mcp_proxy_call`, `filesystem_read_file`). Use `mcp_proxy_*`, not `mcp_proxy.*` — a dotted glob matches nothing and the rule silently never fires (fail-open). scoped-mcp warns at startup for any `approval_required` or `shadow` pattern that matches no registered tool.

Approve or reject from the CLI:

```bash
scoped-mcp hitl list
scoped-mcp hitl approve <id>
scoped-mcp hitl reject <id> [reason]
```

### signing: approvals only the operator can produce

> **Why this exists.** Without signing, an approval is a pre-approval key that *exists*
> in the state backend — its value is never checked. `enforce` above says resolution
> comes from a channel the agent cannot write to, but that holds only if the agent
> cannot reach the state backend, the `SCOPED_MCP_HITL_TOKEN` secret, or the CLI. When
> the agent runs as the same OS user as its proxy, it usually can reach all three.

```yaml
hitl:
  mode: enforce
  approval_required: ["*_pr_merge"]
  signing:
    mode: enforce                              # off (default) | observe | enforce
    public_key_path: /etc/scoped-mcp/approver.pub
    approve_command: "sudo -u approver scoped-mcp-approve"   # shown to the agent
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `signing.mode` | `"off"`, `"observe"`, `"enforce"` | `"off"` | `off`: any pre-approval token approves (the behaviour above). `observe`: every token is verified and logged (`hitl_signature_ok` / `hitl_signature_rejected`), but unsigned tokens still approve — for rollout only. `enforce`: only a valid signed statement approves |
| `signing.public_key_path` | str | — | Ed25519 public key, PEM. Required unless `mode: off`. A missing or non-Ed25519 key is a startup error |
| `signing.approve_command` | str | `"scoped-mcp-approve"` | The command the rejection message tells the agent to ask the operator to run, followed by the approval id |

Under `signing.mode: enforce`:

- The pre-approval value must be an Ed25519 statement over
  `{v, agent_id, approval_id, tool, args_sha256, issued_at, expires_at}`, signed by the key
  whose public half is at `public_key_path`, for **this** agent, tool and arguments, valid
  for at most 120 s, and not already used by this process. Anything else is logged with a
  reason class (`malformed`, `bad_signature`, `bad_version`, `agent_mismatch`,
  `tool_mismatch`, `args_mismatch`, `expired`, `not_yet_valid`, `lifetime_too_long`,
  `replayed`) — never the values — and counts as **no approval**: the call is rejected as a
  new request.
- `scoped_mcp_hitl_confirm` is not registered, and `hitl.mode: interactive` is a manifest
  validation error — it would be self-approval.
- `POST /hitl/approve` is not registered. `/hitl/deny` and `/hitl/pending` remain.
- `scoped-mcp hitl approve` refuses and prints `approve_command`. `list` and `reject`
  still work.
- The pending record additionally stores the call's canonical arguments, so the approver
  can check what it signs.

The operator approves with **`scoped-mcp-approve <approval_id>`**, run in a terminal as the
account that owns the private key:

```bash
scoped-mcp-approve <approval_id>          # shows agent, tool and arguments; asks y/N; signs
scoped-mcp-approve --deny <approval_id>
```

It recomputes the argument digest from the stored arguments and refuses on a mismatch,
shows the arguments **untruncated and without pattern redaction** (a value under a
secret-looking key becomes its length and a digest prefix), with control and non-ASCII
characters escaped, reads the answer from `/dev/tty`, and refuses to run without a terminal.
Its configuration — `~/.config/scoped-mcp/approver.yml` of the running account, resolved
from the password database rather than `$HOME` — holds `state_url` and `private_key_path`.
Both that file and the key must be accessible to their owner only (`0400`/`0600`), checked
with `stat`.

Generate a keypair as the approver account:

```bash
openssl genpkey -algorithm ed25519 -out approver.key && chmod 400 approver.key
openssl pkey -in approver.key -pubout -out approver.pub
```

**Deploy order matters.** Install the key and the approver first, then `observe`, prove
a signed approval end to end, and only then `enforce`. A proxy at `enforce` with no working
signer leaves every gated call unapprovable.

What signing does **not** stop is in [the threat model](threat-model.md#hitl-approvals).

### HITL lifecycle events (agent-bus outbox)

Off by default. To turn it on:

```yaml
audit:
  agent_bus_comms_dir: ~/.claude/comms
  agent_bus_hitl_emit: true
```

With it on, the proxy writes one JSON file per HITL event to
`<agent_bus_comms_dir>/outbox/scoped-mcp/` (directory `0700`, files `0600`), using agent-bus's
producer-outbox contract. agent-bus drains the directory into its hash-chained log.
scoped-mcp does not depend on agent-bus.

| Event | When | Metadata |
|---|---|---|
| `hitl.requested` | a gated call is rejected and a request registered | `approval_id`, `agent_id`, `agent_type`, `tool`, `args_sha256_prefix` (12 hex), `expires_at`, `signing_mode` |
| `hitl.approved` | an approval token is redeemed and the call runs | `approval_id`, `agent_id`, `tool`, `signing_mode` |
| `hitl.refused` | a presented token fails signature verification (`accepted: true` under `observe`) | `agent_id`, `tool`, `reason`, `accepted`, `signing_mode` (no `approval_id`, which is unverified) |
| `hitl.closed` | a request is denied, or expires unused | `approval_id`, `agent_id`, `tool`, `outcome` (`denied` / `expired`) |

**No event carries an argument value.** Not the arguments, not the redacted summary, not
the signed record. A test runs every path under `off`, `observe` and `enforce` with a
sentinel value and checks that it reaches no file. **A failed emit never changes the gate's
decision.** Every error is logged and swallowed.

`hitl.closed` comes from a reconcile loop. One runs per process, scoped to that process's
agent, every 30 s, starting after the first tool call. It needs the session registry
(`AGENT_REGISTRY_DSN`), because the `hitl_approvals` row is the record it closes.
- A `pending` row whose request was dropped by `scoped-mcp-approve --deny` or
  `scoped-mcp hitl reject` is closed `denied`. Both write a `hitl:denied:<id>` tombstone
  (TTL 1 h) for this.
- A `pending` row older than `timeout_seconds` plus a grace period is closed `expired`. The
  grace is the lifetime of an approval token the proxy would still accept: 120 s (signed)
  under `signing.mode: enforce`, and 300 s (unsigned) under `off`/`observe`. So a request
  approved at the last moment is never closed while its approval is still redeemable.
- Each emit is bounded at 2 s, so a hung filesystem under `agent_bus_comms_dir` delays a
  gated call by at most that long. Keep the directory on local disk anyway.
- The update is guarded on `state = 'pending'`, so a row is closed, and reported, once.
- A deny through the HTTP endpoint is reported where it happens.

Bus events are for display. Never approve, grant or launch anything from one.

### Audit log files and redaction

Since v1.19.0 the audit and ops files (`--audit-log`, `--ops-log`, including rotated
files) are `0600` whatever the process umask: created so, and an existing one the process
owns is tightened on open. A missing log directory is created `0700`; an existing one keeps
its mode (`--audit-log ~/audit.log` must not re-mode the home directory). The session JSONL
under `agent_bus_comms_dir/logs/` is created `0600` when scoped-mcp creates it, but it is
shared with agent-bus, so a file another writer made keeps its mode.

Before a record is written, every string in it is redacted twice:
- **By value.** At startup the proxy collects the values in its own environment whose
  names look sensitive (`*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `*_SECRET_ID`,
  `*_ROLE_ID`, `*_DSN`, `*_BEARER`, `*_PAT`, `*_WEBHOOK[_URL]`, ... and names like `token` or
  `api_key`), every URL value with a username or password in it, `SCOPED_MCP_ALERT_NTFY_URL`,
  and every variable the manifest references as `${VAR}`, whatever it is called. Each occurrence is replaced with
  `<redacted-value:NAME>`. Values under 12 characters, digit-only values and bare URL
  origins (`https://host:port`) are skipped. A URL with userinfo, a path or a query is
  kept, because any of those can carry the credential. Values held only in Vault or a
  secrets file are not in the environment, so this pass does not see them.
- **By pattern.** JWTs, bearer tokens, GitHub tokens, Vault tokens and hex runs of 32+.

The same two passes run over stdlib log records on stderr. Only the number of values is
logged (`value_redaction_configured`), never the values, their lengths or hashes.

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
