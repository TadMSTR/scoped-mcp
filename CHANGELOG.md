# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Removed

- `SchemaScope` — removed at alpha; the sqlite module deprecated it in v0.2.0
  (audit finding C1) and there is no installed base to protect. New modules
  should use `PrefixScope` (file-per-agent) or `NamespaceScope` (key-prefix).

### Added

- `SECURITY.md` — vulnerability disclosure policy covering private reporting channels,
  scope definition, and response SLA. Required for showcase-tier compliance.
- `.pre-commit-config.yaml` — local pre-commit hooks: ruff lint+format,
  trailing-whitespace, end-of-file-fixer, check-yaml, check-toml.

### Fixed

- `src/scoped_mcp/__init__.py`: `__version__` was `0.1.0`; bumped to `0.2.1` to match
  `pyproject.toml`. The mismatch was a stale artifact from before 0.2.x releases.
- `modules/influxdb.py`, `modules/sqlite.py`: two `UP038` ruff violations
  (isinstance tuple syntax — `(X, Y)` → `X | Y`), surfaced by pre-commit run.

## [0.2.1] — 2026-04-16

Post-release hygiene. No API or behavior changes to any module; one breaking
pip install-config change (see Changed).

### Changed

- **Ruff lint rules:** expanded selection to include `UP` (pyupgrade),
  `B` (flake8-bugbear), `SIM` (flake8-simplify), and `RUF` (ruff-specific).
  Fixed all resulting findings: `raise ... from None` inside except blocks
  in `scoping.py` / `modules/filesystem.py`, `strict=False` on `zip()` in
  `modules/influxdb.py`, ternary in `filesystem._resolve`, raw-string regex
  in the sqlite deprecated-config test, `ClassVar` annotation in
  `tests/test_registry.py`, and hyphen-minus (not en-dash) in the
  identity-validation error messages.
- **Pip extras — breaking install-config change:** removed per-service HTTP
  extras (`[grafana]`, `[influxdb]`, `[ntfy]`, `[slack]`, `[discord]`,
  `[matrix]`). Install `scoped-mcp[http]` instead — it enables every
  HTTP-based module. `[smtp]`, `[sqlite]`, `[all]`, and `[dev]` are unchanged.
- **Coverage threshold:** moved `fail_under` from the CI flag
  (`--cov-fail-under=75`) to `[tool.coverage.report]` in `pyproject.toml` so
  local `pytest --cov=scoped_mcp` runs enforce it too. Raised the floor from
  75% to 80% (current is ~83%).

### Fixed

- Added `.ruff_cache/` to `.gitignore`.
- Removed redundant `pythonpath = ["src"]` from the pytest config — with a
  src-layout package and editable install, pytest resolves `scoped_mcp` from
  installed package metadata, and the override could mask install-config bugs.

## [0.2.0] — 2026-04-16

Security remediation release addressing all 14 findings from the 2026-04-16
internal audit. Contains breaking config and API changes — see the Breaking
Changes section below for migration guidance.

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
- **H2 (High) — SSRF defense in http_proxy:** The blocklist now covers
  IPv4-mapped IPv6 (`::ffff:0:0/96`), IPv6 link-local (`fe80::/10`),
  IPv6 unspecified (`::/128`), NAT64 (`64:ff9b::/96`), CGNAT
  (`100.64.0.0/10`), and the `0.0.0.0/8` range — in addition to the
  existing loopback / RFC1918 / 169.254.0.0/16 / unique-local sets.
  Every request now re-resolves the hostname via `getaddrinfo` at request
  time and rejects the call if any returned address is in the blocklist,
  defeating DNS-rebinding attacks where a whitelisted hostname flips to an
  internal IP between init and tool invocation. Addressed by 2026-04-16
  audit finding H2.
- **M5 — Identity validation:** `AgentContext.from_env()` now validates
  `AGENT_ID` against `^[a-z0-9][a-z0-9-]{0,62}$` and `AGENT_TYPE` against
  `^[a-z0-9][a-z0-9_-]{0,62}$`. Values containing slashes, spaces,
  uppercase, leading hyphens, or exceeding 63 characters raise
  `ConfigError` before any scope is applied. Prevents an operator
  misconfiguration from injecting path traversal or unexpected characters
  into filesystem / schema / namespace scopes downstream.
- **M6 — Credential file permissions:** `resolve_credentials("file", ...)`
  now checks that the secrets file is mode `0600` (or stricter) and owned
  by the invoking uid. Group- or world-readable files raise
  `CredentialError` by default. Operators who explicitly accept the risk
  can pass `strict_permissions: false` on the credential source config in
  the manifest; `scoped-mcp` will log a `WARNING` and proceed.
- **M8 — PrefixScope ancestor-walk defense:** `enforce()` now walks each
  existing component of the resolved path between the agent root and the
  target, and rejects the call if any component is a symlink that
  resolves outside the agent root. Previously, an operator-seeded symlink
  used as an ancestor of a non-existent write target could pass the
  `relative_to` check because the non-existent-tail fallback resolved the
  nearest existing ancestor without inspecting the intermediate
  components. The `docs/scoping-strategies.md` operator guidance now
  calls out that scope directories should not contain pre-seeded symlinks.
- **H3 — `@audited` contract honestified:** The `scope_strategy` parameter
  on the `@audited` decorator was documented as "the thing that enforces
  scope" but never actually called `enforce()`. It has been removed. The
  module-author contract is now explicit in `AGENTS.md` and
  `docs/module-authoring.md`: every tool method must call
  `self.scoping.enforce(value, self.agent_ctx)` (or validate against an
  explicit allowlist in `self.config`) before issuing any backend call.
  `@audited` provides structured audit logging only. `ARCHITECTURE.md`
  and `scoping.py` docstrings were updated to match.
- **M1 — Grafana datasource allowlist:** `grafana.query_datasource` now
  requires the module config to include `allowed_datasources: list[str]`;
  calls to any datasource not in that list raise `ScopeViolation`. Without
  an allowlist the tool is disabled entirely (previously it would run
  against any datasource the SA token could see — which, for Grafana SA
  tokens, is the full org). `list_datasources` is also filtered to the
  allowlist when one is configured.
- **L1 — Broader audit-log redaction:** The structlog sanitizer now walks
  the full `event_dict` (not just the `args` sub-mapping) so credentials
  leaking into `error`, `detail`, or any other field are still caught.
  The sensitive-suffix list expanded to `_PWD`, `_PASS`, `_AUTH`; full-match
  keys now include `authorization`, `cookie`, `session`, `bearer`,
  `password`, `token`, `secret`, `api_key`, `apikey`, `access_token`, and
  `refresh_token`. Pattern-based redaction was added for JWTs, `Bearer <tok>`
  substrings, long hex strings, and GitHub PATs. The log-frame fields
  `event`, `level`, `logger`, `timestamp`, and `status` are preserved so
  labels like `"scope_violation"` can never be clobbered.
- **L2 — `ntfy` bearer token now loaded:** Modules can declare
  `optional_credentials: list[str]` as a ClassVar. The registry loads
  those keys non-fatally from env or the secrets file; missing optional
  keys are simply omitted from `self.credentials`. `NtfyModule` now
  declares `NTFY_TOKEN` as an optional credential, so configuring it in
  the environment / secrets file actually attaches
  `Authorization: Bearer <token>` to outbound ntfy requests. Previously
  the module's docstring claimed the header was sent when `NTFY_TOKEN`
  was set, but the registry never loaded the key and the header was never
  attached.
- **L3 — GitHub Actions pinned to commit SHAs:** `.github/workflows/ci.yml`
  and `.github/workflows/release.yml` now pin every action to a full
  commit SHA with a comment naming the version — `actions/checkout`,
  `actions/setup-python`, `actions/upload-artifact`,
  `actions/download-artifact`, and `pypa/gh-action-pypi-publish`. Floating
  tag references reachable by the upstream maintainer or via tag hijack
  could have published a backdoored wheel under the project name via the
  `id-token: write` OIDC publisher.

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
- **`@audited` decorator signature:** the `scope_strategy` parameter was
  removed. Third-party module authors who relied on the (never-actually-wired)
  invariant that `@audited` enforces scope must explicitly call
  `self.scoping.enforce(value, self.agent_ctx)` in every tool method, or
  validate the argument against an allowlist. See the updated module-author
  checklist in `AGENTS.md` and the "Scope enforcement is your responsibility"
  callout in `docs/module-authoring.md`. None of the built-in modules relied
  on the removed parameter — every one of them already enforced scope
  inside its tool methods.
- **`grafana.query_datasource` now requires an allowlist:** callers using
  the Grafana module in `mode: write` must add
  `allowed_datasources: ["name1", "name2"]` to the module config. Without
  it, `query_datasource` raises `ScopeViolation` on every call.

  Migration:
  ```yaml
  # before
  grafana:
    mode: write
    config: {}
  # after
  grafana:
    mode: write
    config:
      allowed_datasources: ["prom-agent", "postgres-agent"]
  ```

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
