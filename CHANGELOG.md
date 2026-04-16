# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **C1 (Critical) — SQLite isolation:** The sqlite module now gives each agent
  its own database file at `{db_dir}/agent_{agent_id}.db`. Previously,
  `SchemaScope` + SQLite `ATTACH DATABASE ':memory:'` left unqualified table
  references resolving against the shared `main` schema — effectively no
  isolation. Addressed by 2026-04-16 audit finding C1.
- **M7 — sqlite `create_table` validation:** Column names must pass
  `str.isidentifier()`; column types must match a closed allowlist
  (`INTEGER`, `TEXT`, `REAL`, `BLOB`, `NUMERIC`, `BOOLEAN`, and common
  `PRIMARY KEY` / `NOT NULL` / `UNIQUE` combinations). Unknown values raise
  `ValueError` before any SQL is issued.
- **H1 (High) — Flux injection:** `influxdb.query()` no longer takes a raw
  Flux `predicate` string. Agents now pass a list of structured
  `{field, op, value}` filter dicts; every segment is validated (field against
  a Flux identifier regex, op against a closed set of comparison operators)
  and string values are rendered through `json.dumps()` so a value cannot
  close its own literal and escape the filter. Time ranges are validated
  against an RFC3339 / Flux-duration / `now()` grammar. Addressed by
  2026-04-16 audit finding H1.
- **M2 — Line-protocol escaping:** `influxdb.write_points()` now escapes tag
  keys, tag values, and field keys per the InfluxDB v2 line-protocol spec
  (backslash, comma, equals, space) and rejects any value containing a
  newline or carriage return. Previously, unescaped tag values could be used
  to inject arbitrary lines into the write batch.
- **M3 — Measurement validation:** Measurement names are now validated
  against `^[A-Za-z_][A-Za-z0-9_-]*$` in every tool that accepts one
  (`query` filters on `_measurement`, `get_schema`, `write_points`,
  `delete_points`). `delete_points` previously embedded the measurement into
  a Flux predicate string without escaping.

### Breaking Changes

- **`sqlite` config:** `db_path` (pointing at a file) → `db_dir` (pointing at a
  directory). Passing `db_path` now raises a clear `ValueError` with migration
  instructions. Each agent's data lives in `{db_dir}/agent_{agent_id}.db`.

  Migration:
  ```yaml
  # before
  sqlite:
    config:
      db_path: /data/shared.db
  # after
  sqlite:
    config:
      db_dir: /data/sqlite
  ```
- **`influxdb.query` signature:** `predicate: str` → `filters: list[dict]`.

  Migration:
  ```python
  # before
  query(bucket="metrics", predicate='r._measurement == "cpu"')
  # after
  query(
      bucket="metrics",
      filters=[{"field": "_measurement", "op": "==", "value": "cpu"}],
  )
  ```
  Multiple filters are combined with the `logical_op` parameter
  (`"and"` — default — or `"or"`).

### Deprecated

- `scoped_mcp.scoping.SchemaScope` — retained for backwards compatibility but
  not used by any built-in module. New modules should use `PrefixScope`,
  `NamespaceScope`, or a per-agent file.

## [0.1.0] — 2026-04-16

Initial release.

### Added

- **Core framework**: `ToolModule` base class with `@tool(mode="read"|"write")` decorator;
  `AgentContext` identity; `Manifest` YAML/JSON loader; `build_server()` registry that
  discovers and mounts modules onto a parent FastMCP server
- **Scope strategies**: `PrefixScope` (filesystem paths with symlink defense),
  `SchemaScope` (SQL schema isolation), `NamespaceScope` (key-value namespace isolation)
- **Credential isolation**: resolved from env vars or YAML secrets file at startup;
  never exposed in tool responses or audit logs
- **Structured audit logging**: `@audited` decorator wraps every registered tool call;
  JSON-L structlog output with sensitive-key redaction (`_TOKEN`, `_PASSWORD`, `_SECRET`,
  `_KEY`, `_CREDENTIALS`)
- **10 built-in modules**:
  - `filesystem` — read, write, list, delete within a scoped directory tree
  - `sqlite` — scoped schema queries and writes; AST validation blocks PRAGMA/ATTACH/DETACH/DROP
  - `ntfy` — send notifications to scoped topics with priority capping
  - `smtp` — send email to an allowlisted recipient set
  - `matrix` — post to allowlisted Matrix rooms via direct httpx (no matrix-nio)
  - `slack_webhook` — post to a single Slack channel via incoming webhook
  - `discord_webhook` — post to a single Discord channel via webhook (2000 char limit)
  - `http_proxy` — allowlisted outbound HTTP with SSRF prevention (RFC1918 / loopback / link-local / 169.254.169.254)
  - `grafana` — dashboard CRUD scoped to an agent-owned folder
  - `influxdb` — time-series query/write restricted to an allowlisted bucket set
- **Documentation**: README, ARCHITECTURE, CONTRIBUTING, AGENTS.md, four Mermaid diagrams,
  quickstart and module reference docs
- **CI**: GitHub Actions matrix (Python 3.11–3.14), ruff lint + format, pytest with 80% coverage gate
- **Release**: tag-triggered PyPI publish via OIDC trusted publishing

### Commits

- `b43a8f4` — chore: scaffold project structure and packaging config
- `437db97` — feat: implement core framework (Phase 1)
- `5d8e783` — feat: add storage modules — filesystem and sqlite (Phase 2)
- `6c57abe` — feat: add notification modules — ntfy, smtp, matrix, slack, discord (Phase 3)
- `ad9ea0e` — feat: add HTTP proxy, Grafana, InfluxDB modules (Phase 4)
- `cbb7853` — docs: add full documentation suite (Phase 5)
- `94def51` — ci: add CI/CD workflows and fix all lint issues (Phase 6)
