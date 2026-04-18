---
tier: showcase
promoted: null
---

# AGENTS.md — scoped-mcp

A per-agent scoped MCP tool proxy built on FastMCP. One server process per
agent session — manifest-driven module loading, resource scoping, credential
isolation, and structured audit logging.

## Architecture

```
server.py          Entry point. Reads AGENT_ID/AGENT_TYPE from env,
                   loads manifest, registers modules, starts FastMCP.

identity.py        AgentContext dataclass. Source of truth for agent_id,
                   agent_type, and resolved manifest path.

manifest.py        Parses + validates YAML/JSON manifests. Returns which
                   modules to load, their mode (read/write), and config.

registry.py        Discovers module classes in scoped_mcp/modules/,
                   filters to manifest-allowed set, instantiates them.

credentials.py     Reads secrets from env or file. Injects into module
                   contexts. Agents never receive credential values.

audit.py           @audited decorator. Wraps every tool call with
                   structured JSON logging: agent_id, tool, args, result,
                   timing. Emits to stdout and/or file.

scoping.py         Reusable scope strategies:
                   - PrefixScope: path/key prefix enforcement
                   - NamespaceScope: key-value namespace prefixing
                   - SchemaScope: deprecated — no built-in module uses it
                   Module authors pick a strategy or implement ScopeStrategy.
                   The sqlite module does not use a ScopeStrategy — each agent
                   gets its own database file at {db_dir}/agent_{agent_id}.db.
```

## Module Contract

Tool modules live in `src/scoped_mcp/modules/`. Each module:

- Subclasses `ToolModule` from `_base.py`
- Declares `name`, `scoping` strategy, and `required_credentials`
- Decorates tool methods with `@tool(mode="read")` or `@tool(mode="write")`
- The manifest controls which mode is loaded — `mode: read` registers only
  read-decorated tools; `mode: write` registers both read and write tools
- Notification modules (ntfy, smtp, matrix, slack, discord) are write-only
  by design — they have no read mode

When adding a new module:
1. Create `src/scoped_mcp/modules/<name>.py`
2. Add tests in `tests/test_modules/test_<name>.py`
3. Add an example manifest entry in `examples/manifests/`
4. Update the module table in README.md

## Testing

```bash
# Run all tests
pytest

# Run scoping enforcement tests only (the critical path)
pytest tests/test_scoping.py

# Run a specific module's tests
pytest tests/test_modules/test_filesystem.py
```

Tests use in-memory/mock backends — no external services needed.
The `conftest.py` provides fixtures for:
- `agent_context` — mock AgentContext with configurable id/type
- `mock_credentials` — fake credential provider
- `audit_capture` — captures audit log entries for assertion

**Scoping tests are the most important tests in this repo.** Every module
must have tests verifying that:
- Agent A cannot access Agent B's resources
- Prefix/schema/namespace boundaries reject out-of-scope requests
- Scope enforcement works regardless of input encoding or traversal attempts

## Key Conventions

- **No credentials in examples or tests** — use placeholder values like
  `EXAMPLE_TOKEN` or `test://localhost`. Real credentials never appear in
  the repo, not even in comments.
- **Modules are self-contained** — one file per module, no cross-module
  imports. A module depends only on `_base.py`, `scoping.py`, and its
  backend client library.
- **Audit logging is not optional** — the `@audited` decorator is applied
  by the registry at registration time. Module authors don't need to add
  it manually, but they must not suppress or bypass it. `@audited` handles
  logging only; it does NOT call `scope.enforce()`.
- **Scope enforcement is the module's responsibility** — every tool method
  MUST either (a) call `self.scoping.enforce(value, self.agent_ctx)` on
  each argument that addresses a backend resource, or (b) validate the
  argument against an explicit allowlist held in `self.config` (e.g. the
  Grafana `allowed_datasources`, SMTP `allowed_recipients`, InfluxDB
  `allowed_buckets`, http_proxy `allowed_services`, matrix `allowed_rooms`
  patterns). Every new module MUST include tests that verify a
  cross-agent / out-of-scope request raises `ScopeViolation` (or the
  module-specific equivalent) before any backend call is made.
- **Manifest is the source of truth** — if a module isn't in the manifest,
  it doesn't load. The registry refuses to register unlisted modules even
  if they exist in the modules directory.

## What Not to Change Without Discussion

- The `ToolModule` base class interface in `_base.py` — this is the public
  contract that all modules (including third-party) depend on
- The manifest schema — breaking changes affect every user's config
- The audit log format — downstream consumers (log aggregators, dashboards)
  depend on the field names and structure
- Scoping strategy interface in `scoping.py` — same reason as ToolModule

## Dependencies

- `fastmcp` — MCP server framework (composition, tool registration, transport)
- `pydantic` — manifest validation, config models
- `structlog` — structured audit logging

Keep the dependency list minimal. Backend client libraries (redis, psycopg,
boto3, etc.) are optional dependencies — only required if the corresponding
module is used.
