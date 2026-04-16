# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
