# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0] — 2026-04-27

### Added

- **`VaultCredentialSource`** — fetch agent credentials from HashiCorp Vault using
  AppRole auth. Supports KV v1 and v2, `{agent_type}` interpolation in the secret
  path, and a background renewal task that refreshes the client token at 2/3 of
  the lease TTL. The `secret_id` is removed from the instance attribute before
  the AppRole login call so it cannot leak via traceback-with-locals capture on
  auth failure. Requires the new `[vault]` optional extra (`hvac>=2.0,<3`).

- **`credentials.vault:` manifest section** — set `credentials.source: vault` and
  configure `addr`, `auth: approle`, `role_id_env`, `secret_id_env`, `path`, and
  `kv_version`. Path traversal sequences (`..`) in the interpolated path are
  rejected at startup. The vault bundle is fetched once during `build_server()`
  and filtered per module so each module receives only the keys it declares.

- **Vault token redaction in audit logs** — `_VAULT_TOKEN_RE` matches modern
  base64url SSTs (`hvs.`/`hvb.`/`hvr.` with `_` and `-` characters) and all
  legacy prefixes (`s.`/`b.`/`r.`). `secret_id`, `role_id`, `lease_id`, and
  `accessor` are added to the `_SENSITIVE_KEYS` redaction set.

- **Renewal shutdown timeout** — `VaultCredentialSource.close()` bounds the wait
  for an in-flight renewal HTTP call to 5 seconds so a Vault outage at shutdown
  cannot stall server termination.

- **`examples/vault/`** — drop-in manifest, Vault policy HCL, and AppRole setup
  script for getting Vault-backed credentials running.

## [0.7.0] — 2026-04-27

### Added

- **`StateBackend` protocol** — pluggable shared state for rate limiting and HITL.
  `InProcessBackend` (default, no external dependencies) uses asyncio locks and a
  sliding-window deque. `DragonflyBackend` (optional `[dragonfly]` extra) uses
  redis-py with a Lua sorted-set sliding window for atomic multi-process rate limiting.
  Keys are namespaced `scoped-mcp:{agent_id}:` to prevent cross-agent bleed.

- **`[dragonfly]` optional extra** — `redis>=5.0,<6`. Enables `DragonflyBackend` for
  shared state across processes. Works with any Redis-compatible server (Dragonfly,
  Valkey, Redis).

- **`RateLimitMiddleware`** — sliding window rate limiting in `scoped_mcp.contrib.rate_limit`.
  Configures via `rate_limits:` manifest section. Supports a global per-agent limit and
  per-tool limits with glob pattern support (`mcp_proxy.*`). Glob patterns share a single
  counter so all matched tools count against the same window. Fail-closed: backend errors
  block tool calls rather than silently bypassing limits.

- **`scoped-mcp validate` CLI subcommand** — validates a manifest file, exits 0 on success
  and 1 on failure. Suitable for CI pre-flight checks. Usage:
  `scoped-mcp validate --manifest /path/to/manifest.yml`

- **`scoped-mcp run` CLI subcommand** — explicit subcommand replacing the legacy flat
  invocation. Legacy flat args (`scoped-mcp --manifest ...`) are preserved for backwards
  compatibility.

- **`state_backend:` manifest section** — configures the state backend.
  `type: in_process` (default) or `type: dragonfly` (requires `url:`).

- **`rate_limits:` manifest section** — declares global and per-tool sliding window limits.
  Format: `<N>/second|minute|hour`. Supports glob patterns in `per_tool:`.

- **`credentials.source: vault`** — manifest schema now accepts Vault as a credential source
  (schema validation only in v0.7; full Vault integration ships in v0.8). Requires a
  `vault:` block with `addr`, `auth`, and `path`.

- **`[vault]` optional extra** — `hvac>=2.0,<3`. Reserved for v0.8 Vault integration.

### Changed

- **Manifest validation strengthened** — all Pydantic config models now use
  `extra="forbid"`, including `RateLimitsConfig` and `ModuleConfig`. Unknown fields in
  any manifest section raise `ManifestError` at load time.

- **`build_state_backend()` factory** — wires the `StateBackend` from manifest config.
  Called automatically by `scoped-mcp run`; available for programmatic use.

## [0.6.0] — 2026-04-27

### Added

- **Tool call middleware** — `ToolCallMiddleware` protocol and `MiddlewareChain`
  for composable per-call interception (`src/scoped_mcp/middleware.py`). Middleware
  wraps every tool invocation at the registry level, after scoping and before
  execution. ASGI-style `call_next` chain. Pass a list of middleware to
  `build_server(middleware=[...])`.

- **`OtelMiddleware`** — reference implementation in `scoped_mcp.contrib.otel`.
  Emits one OpenTelemetry span per tool call with `scoped_mcp.*` attributes
  (`agent.id`, `agent.type`, `tool.name`, `call.status`). Tool arguments are
  excluded from spans to prevent credential leakage. Auto-enabled when
  `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Install with `pip install scoped-mcp[otel]`.
  Works with SigNoz, Grafana Tempo, Jaeger, and Langfuse OTLP ingest.

- **`[otel]` optional extra** — `opentelemetry-api>=1.20`, `opentelemetry-sdk>=1.20`,
  `opentelemetry-exporter-otlp-proto-grpc>=1.20`.

- **`build_server()` `middleware=` parameter** — pass a list of `ToolCallMiddleware`
  instances for programmatic configuration. Empty list is the default (no overhead).

## [0.5.0] — 2026-04-27

### Added

- **Module lifecycle hooks** — `ToolModule` base class now exposes `startup()` and
  `shutdown()` async methods. `startup()` is called once after the server event loop
  starts; `shutdown()` is called on graceful server stop, in reverse module order.
  Default implementations are no-ops; modules override them to open and release
  persistent resources.

- **Persistent stdio subprocess for `mcp_proxy`** — stdio-transport `mcp_proxy`
  entries now open a persistent subprocess in `startup()` that is reused for all
  tool calls, then closed cleanly in `shutdown()`. Previously each tool call spawned
  a fresh subprocess. HTTP transport is unchanged (reconnects per-call).

- **Registry lifespan wiring** — `build_server()` now passes a FastMCP-compatible
  `lifespan` context manager to the parent server. The lifespan calls `startup()` on
  all modules in manifest order and `shutdown()` in reverse order, ensuring dependent
  modules (e.g. persistent stdio subprocesses) are torn down safely.

## [0.4.0] — 2026-04-27

### Added

- **`mcp_proxy` module** — proxy any existing MCP server through scoped-mcp.
  Supports HTTP (streamable-http) and stdio transports. Tools discovered at
  startup via `tools/list`; forwarded per-call via `fastmcp.Client`.
  `tool_allowlist` and `tool_denylist` config options control which upstream
  tools are exposed. No new dependencies required.

- **`type:` field in module config** — allows multiple instances of the same
  module class under different manifest keys. Example: two `mcp_proxy` entries
  for separate upstream servers (`task-queue` and `memory-search`). Backwards
  compatible — existing manifests without `type:` are unchanged.

### Security

- `mcp_proxy` intentionally does not apply `http_proxy`'s SSRF blocklist.
  Upstream URLs are operator-declared in the manifest, not user-supplied.
  See `docs/threat-model.md` for the security boundary distinction.

## [0.3.3] — 2026-04-25

### Fixed

- **`agent_id` logged as `"unknown"` in audit events:** The `@audited` decorator
  was resolving `agent_ctx` from `args[0]` at call time, assuming the first
  positional argument was the module instance (`self`). When the registry wraps
  bound tool methods, `args[0]` is actually the first tool argument (e.g. the
  `room` string for `matrix.send`), so `agent_id` always fell back to
  `"unknown"`. Fixed by capturing `agent_ctx` from `fn.__self__` at decoration
  time; falls back to `args[0]` for the unbound case used in tests.

## [0.3.2] — 2026-04-25

### Fixed

- **Audit log corrupting stdio MCP stream:** `configure_logging()` was using
  `structlog.PrintLoggerFactory()` which defaults to stdout. Since scoped-mcp
  runs as a stdio MCP server, stdout is the JSON-RPC wire — any log line
  written there would corrupt the protocol. Fixed by switching to
  `structlog.stdlib.LoggerFactory()` with a `StreamHandler(sys.stderr)` on
  the root logger. All log output now goes to stderr.
- **`--audit-log` / `--ops-log` flags silently ignored:** `configure_logging()`
  accepted path arguments but discarded them (`_ = audit_log, ops_log`). File
  sinks are now wired via stdlib `FileHandler`s attached to the named `audit`
  and `ops` loggers. When a path is provided, output goes to both stderr (via
  root propagation) and the specified file. The `startup` ops event now
  includes the active `audit_log` and `ops_log` paths.

### Changed

- **`--audit-log` / `--ops-log` help text** corrected from "stdout always
  enabled" to "stderr always enabled".

### Tests

- Extracted `MatrixModule` tests from `test_notifications.py` into a dedicated
  `tests/test_modules/test_matrix.py`, consistent with the per-module pattern
  used by `test_influxdb.py`, `test_grafana.py`, etc. Matrix is bidirectional
  (send + receive via matrix-channel) and conceptually distinct from one-way
  notification webhooks.

## [0.3.1] — 2026-04-19

### Added

- Credential reference table in README — lists required and optional env vars for all
  10 built-in modules, with startup-fail behavior note and pointer to Vaultwarden example.
- Process management section in `examples/claude-code/multi-agent-setup.md` — covers
  Claude Code native (recommended), PM2 with `ecosystem.config.js` example, and systemd
  pointer.
- `## Security` section in README — links to `docs/threat-model.md` and
  `docs/security-audit.md`; replaces thin 3-bullet verification section with a full
  walkthrough covering filesystem isolation, credential non-exposure, and audit log
  confirmation.
- Provenance note in README intro — 2 sentences noting scoped-mcp was built using the
  same multi-agent pattern it secures, with link to TadMSTR/homelab-agent.
- `examples/vaultwarden/README.md` — Pattern A (secrets file via `bw` CLI, recommended
  for headless agents) and Pattern B (env vars for interactive Claude Code sessions),
  headless unlock options, and Vaultwarden item naming convention. Surfaces
  `--audit-log` and `--ops-log` CLI flags in Pattern A script.
- `docs/troubleshooting.md` — startup errors, clean startup event sequence, scope
  violation log format and jq filter patterns, `--audit-log`/`--ops-log` flag usage,
  tools-not-appearing checklist, and credential sanitization assurance.
- `examples/audit-log/README.md` — Alloy (Flow/HCL) and Promtail configs with
  `agent_id`/`event`/`status` label promotion, log directory setup, logrotate
  (`copytruncate`), LogQL query library, and Grafana dashboard panel table.

## [0.3.0] — 2026-04-19

### Added

- `SECURITY.md` — vulnerability disclosure policy covering private reporting channels,
  scope definition, and response SLA. Required for showcase-tier compliance.
- `.pre-commit-config.yaml` — local pre-commit hooks: ruff lint+format,
  trailing-whitespace, end-of-file-fixer, check-yaml, check-toml.
- `modules/_influxdb_validators.py` — private helper module extracted from `influxdb.py`
  (8 functions + 6 constants). No behavior change; `influxdb.py` imports from it.
- CI: `create-github-release` job added to `release.yml`. On each version tag, attaches
  the wheel and sdist to a GitHub Release and auto-generates release notes from commits.
  Requires no secrets (uses built-in `github.token`).
- Claude Code badge added to README header.

### Changed

- `PrefixScope.enforce` docstring tightened — removes redundant re-explanation of the
  symlink-walk logic; adds forward reference to `_check_ancestor_symlinks`.

### Removed

- `SchemaScope` — removed at alpha; the sqlite module deprecated it in v0.2.0
  (audit finding C1) and there is no installed base to protect. New modules
  should use `PrefixScope` (file-per-agent) or `NamespaceScope` (key-prefix).

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
