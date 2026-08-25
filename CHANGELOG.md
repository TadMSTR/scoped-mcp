# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Release workflow could not publish to PyPI.** `pypa/gh-action-pypi-publish` was pinned
  at v1.14.0, whose bundled Twine rejects `Metadata-Version: 2.5` outright
  (`InvalidDistribution: '2.5' is not a valid metadata version`). Current `hatchling`
  (1.32.0) emits exactly that, and `build-system.requires` does not pin it — so the
  release path broke on dependency drift alone, with no change on our side. v1.12.0
  published fine on 2026-07-27; v1.13.0 was the first tag to hit it. Bumped the pin to
  v1.14.2, which ships Twine v7 specifically to accept metadata 2.5.

  Consequence for v1.13.0: the `create-github-release` job `needs: publish-pypi`, so it
  was skipped and the tag was left with no GitHub release and no PyPI artifact. The
  package itself is unaffected — forge deploys from a locally built wheel, not PyPI.

## [1.13.0] — 2026-08-25

### Added

- **Per-module tool inventory in `scoped_mcp_status`, `GET /health` and the health
  file.** An `mcp_proxy` enumerates its upstream exactly once, in `_discover_tools()`
  at `__init__`, and never widens that set afterwards — `_refresh_schemas_from_client()`
  deliberately refuses to add a tool, so a misconfigured or malicious upstream cannot
  widen the surface via a refresh. The consequence is that **a new upstream tool is
  invisible to a running proxy until the process restarts**, and nothing in the process
  notices. Each running proxy module now reports what it actually registered:

  ```json
  "tool_inventory": {
    "vikunja-mcp": {"tool_count": 73, "transport": "http",
                    "allowlisted": false, "denylisted": false,
                    "discovered_at": "2026-08-25T14:01:32+00:00"}
  }
  ```

  Two agents proxying the same upstream under the same filtering must report the same
  `tool_count`; a mismatch means one of them is serving a stale tool set and needs a
  restart. That comparison needs **no upstream credentials**, which is the point — a
  fleet-wide drift check must not be handed every upstream's secrets to query
  `tools/list` itself. `allowlisted`/`denylisted` are what keep the comparison sound: a
  count difference between a filtered and an unfiltered agent is expected, not drift.
  `discovered_at` is recorded at discovery rather than inferred from process start
  time, because the two diverge — the self-healer re-instantiates a recovered module
  and it re-discovers mid-process.

  Only `running` modules appear. A module that instantiated but failed `startup()`
  discovered tools it cannot serve; reporting its count would tell a consumer the agent
  serves a surface it does not. Its failure is already visible in `failed_count`.

  **Security:** `GET /health` is unauthenticated. It and the on-disk health file carry
  counts, transport and filtering booleans only — never tool names, schemas, URLs or
  headers. Only the authenticated `scoped_mcp_status` tool includes names, and the names
  it reports are the **normalized** ones this proxy registered (`[a-zA-Z0-9_]+`), not the
  raw upstream strings: the raw name is upstream-controlled, and the payload lands in an
  agent's context from where that agent may render it into Matrix or a tracker ticket.
  Escaping belongs to those destinations and can't be assumed here, so the value is
  constrained at the source instead. This matches
  the existing redaction contract, where `/health` already reduces module detail to
  counts and the health file carries `error_type` in place of the raw exception message.
  Every scoped-mcp binds `127.0.0.1`.

  The inventory builder is duck-typed on `tool_inventory()` rather than
  isinstance-checking `McpProxyModule`. Non-proxy modules have no upstream to drift from
  and are simply absent; an agent with no proxies gets no `tool_inventory` key at all,
  leaving its payload unchanged. A module that *raises* from `tool_inventory()` is
  reported as `{"error_type": ...}` — the exception never propagates (this feeds three
  health reporters and must not be able to fail any of them), and only the exception
  **type** is reported, matching the `_redact_module_errors` convention. The failure is
  also logged once per `(module, exception type)` per process rather than on every call,
  since `/health` is polled every two minutes.

  (vikunja#517, Phase 4 of `scoped-mcp-tool-drift-detection-2026-08`. Phases 1–3 — the
  hourly drift check, the health prober's agent enumeration, and naming the restart set
  at config-apply and MCP-deploy time — shipped in `host-forge-scripts`.)

## [1.12.0] — 2026-07-27

Security audit: 0 Critical, 0 High, 0 Medium, 1 Low, 2 Info — all resolved before merge
(`scoped-mcp-module-init-selfheal-2026-07`).

### Added

- **Module init self-heal** — a module that fails to initialise is now retried in
  the background instead of staying dead for the life of the process. Two
  mechanisms, in `module_selfheal.py`:
  - **Dependency-ready gate.** Before instantiating a module whose config carries
    a *loopback* HTTP `url`, the registry polls that port until it accepts a TCP
    connection, within a bounded budget (`dependency_wait_timeout_seconds`,
    default 30s; `dependency_wait_interval_seconds`, default 1s — both new
    per-module manifest fields). This removes the start-ordering race against a
    co-located dependency at source. Only loopback URLs gate startup: a remote
    dependency may be `optional: true` and deliberately powered off (SMCP-31), so
    blocking on it would turn a supported state into an outage. On expiry the
    module falls through to the existing `failed_init` path — startup never hangs.
  - **Background re-init loop.** After startup, any module left in `failed_init`
    or `failed_startup` is retried by one asyncio task with exponential backoff
    (5s → 5min cap), cancelled cleanly on shutdown. On success the module's tools
    are registered onto its already-mounted child server, `module_health` flips to
    `running` with the recorded error cleared, and the health file is rewritten —
    so `/health` returns 200 on the very next probe and the external prober emits
    its own RECOVERED, with **no restart**. Modelled on
    `credentials_vault.start_renewal()`. `failed_import` is never retried: the
    class does not exist in this process.
  - Ops alerts `module_init_degraded` / `module_recovered`, one per state
    transition and never per retry attempt. Optional modules keep the SMCP-31
    event names (`optional_module_offline` / `optional_module_recovered`) and are
    not double-alerted. Alert payloads carry the exception **type** only, never
    the message, which can embed a credentialed URL.

  Fixes the failure behind two multi-hour fleet degradations (2026-07-20/21 and
  2026-07-26/27) in which all five `scoped-mcp-*` proxies raced their shared local
  `system-ops` at startup, went `failed_init`, and stayed degraded-but-serving
  until manually restarted.

### Security

- **The health file no longer carries raw exception messages.** `SCOPED_MCP_HEALTH_FILE`
  entries now expose `error_type` (the exception class name) in place of `error`
  (`f"{type(exc).__name__}: {exc}"`). A module constructor can raise with a message
  echoing back a dependency URL that carries inline credentials, and the health file
  is a plain on-disk artifact polled by external watchers — so it is now held to the
  same contract the ops alerts and the `/health` route already had. The full message
  remains available through the ops log (`module_init_failed`) and the authenticated
  `scoped_mcp_status` tool. Pre-existing gap, widened by this release's new retry call
  site; found by the security audit of this build.
  **Schema note:** anything parsing `modules.<name>.error` out of the health file must
  read `modules.<name>.error_type` instead. No forge consumer does today.

### Changed

- The registry now mounts a child FastMCP server for **every** declared module,
  including ones that failed to instantiate, rather than only successful ones.
  `mount()` is a live link, so a module recovering later only has to add tools to
  its existing child for them to become dispatchable on the parent.
- `server.mount(child, prefix=…)` → `namespace=…`; `prefix` is deprecated in
  FastMCP 3.x. Tool naming is unchanged (`<module>_<tool>`).

## [1.11.0] — 2026-07-21

### Added

- **HITL interactive mode** (`hitl.mode: enforce | interactive`) — a formal,
  cheap, in-session approval path for agents working live with the operator,
  replacing the ad-hoc "read the Matrix message and self-resolve via a shell
  call" workaround.
  - New manifest field `hitl.mode` (`manifest.py`), default `enforce` — no
    behavior change for any manifest that does not opt in. `enforce` keeps the
    existing reject-then-wait via the matrix-hitl-bot endpoint / operator CLI.
  - `interactive` mode fires the same Matrix notify and the same immediate
    reject (the agent still stops and asks), but registers a companion tool
    **`scoped_mcp_hitl_confirm(approval_id, decision)`** (`registry.py`) that
    the agent calls directly to resolve the pending request. It reuses the
    shared `hitl_endpoint.approve`/`deny` logic — no duplicated approval path,
    no Matrix round-trip. The tool is registered **only** for interactive-mode
    agents that actually gate tools, so an `enforce`-mode / unattended agent can
    never reach it.
  - Audit rows now carry a `resolved_via` channel (`hitl_endpoint.py`,
    `hitl_http.py`, `registry_db.py`) — `matrix_bot` / `courier` for the real
    out-of-band paths vs `interactive_self_service` for the in-session shortcut
    — so an audit can always distinguish them. New migration
    `migrations/0002_hitl_resolved_via.sql` (`ADD COLUMN IF NOT EXISTS`, safe to
    apply before the code; the column write fails open until applied).
  - **Trust tradeoff (interactive only, by design):** `scoped_mcp_hitl_confirm`
    trusts the agent's own report that the operator approved in the current
    conversation turn — the same trust level every other interactive tool call
    already runs under. Agent guidance must only call it after an explicit
    in-conversation approve/deny, never speculatively. Enforce mode (unchanged)
    remains the correct mode for headless / clone-pool agents.

### Security

- Audit `scoped-mcp-hitl-bypass-mode-2026-07`: 1 HIGH (accepted), 2 Info.
  - **HIGH (accepted risk, tracked):** because scoped-mcp runs as one shared
    long-lived HTTP process per agent, the `scoped_mcp_hitl_confirm` registration
    gate (static `hitl.mode` field) cannot distinguish an attended session from a
    headless `workflow_mode: auto` launch of the same agent identity — so enabling
    interactive mode for an agent that is ever run headless-auto is a self-approval
    bypass. The scoped-mcp code ships safe (default `enforce`, dormant); the risk is
    realised only by the manifest flip + running those agents unattended. Accepted
    by the operator (developer/sysadmin not run headless-auto today); to be secured
    at the dispatcher layer before that changes.
  - **Info (fixed):** added test coverage for `scoped_mcp_hitl_confirm`'s fail-closed
    `backend_unavailable` path (a state-backend error must never fabricate an
    approval). `resolved_via` SQL param threading verified correct — no change.

## [1.10.1] — 2026-07-18

### Fixed

- **SMCP-37 — HITL agent-id clone-pool suffix normalization** (`hitl_http.py`):
  `/hitl/pending`'s `agent_id` query-param check hard-rejected any non-exact
  match against the deployed `AGENT_ID`, even though the check is advisory
  (the actual list is always filtered server-side to the process's own
  agent). Every scoped-mcp process deploys with a forward-compat numeric
  suffix (e.g. `sysadmin-01`), which previously forced matrix-hitl-bot's
  config to track that exact suffix instead of a stable bare alias. A
  trailing `-\d+` suffix is now stripped from both sides before comparing,
  so a bare alias and a suffixed deployed id both resolve, while a
  genuinely different agent still correctly does not match. Companion fix
  in `matrix-hitl-bot`. Audit: clean (1 Info finding, unrelated to this repo,
  fixed in matrix-dispatcher).

## [1.10.0] — 2026-07-18

### Fixed

- **SMCP-39 — HITL consumed-state transition** (`hitl.py`, `hitl_endpoint.py`,
  `hitl_cli.py`): the middleware now resolves a HITL audit row to `consumed`
  when the one-time pre-approval token is actually used, instead of leaving
  `hitl_approvals.state` stuck at `approved` forever. Previously, if a thread
  resumed via the normal reply path inside the ~10s window before the
  matrix-dispatcher's reconcile pass fired, the next pass still saw
  `state='approved'` and issued a spurious retry-nudge into an already-resolved
  session. The pre-approval token now carries the `approval_id` (both the
  in-session HTTP approve path and the operator CLI approve path write it), so
  the middleware can resolve the audit row on consumption. Fails open on a
  malformed or pre-upgrade plain-string token — the call still proceeds, only
  the audit resolve is skipped. `resolve_hitl_approval` gained an optional
  `expected_state` guard (`AND state = ...`, logged instead of silently
  applied on a mismatch) so the consumed-resolve can never clobber a row that
  raced to some other terminal state first (pre-merge audit finding).

### Added

- **SMCP-31 — allowed-offline manifest modules** (`manifest.py`, `registry.py`):
  a per-module `optional: true` manifest flag whose `failed_import` /
  `failed_init` / `failed_startup` no longer counts toward `failed_count` /
  `healthy` in `scoped_mcp_status`, the health file, or the `/health` route.
  Failures are tracked separately under `offline_optional_modules` so they
  stay visible without flipping the whole process to degraded/503 — built for
  `claudebox-ops`, which is expected to be down whenever claudebox is
  intentionally powered off. A healthy&harr;offline transition of an optional
  module fires exactly one low-severity ops alert via the existing SMCP-26
  Matrix&rarr;ntfy path (comparing against the previous process's state,
  persisted in the health file itself), so an *unplanned* outage is still
  caught, but a restart while the module stays offline does not re-alert.
  Non-optional module failures are unaffected — same degrade-to-503 behavior
  as before. Health-file reads now tolerate syntactically-valid-but-non-dict
  JSON (fall back to an empty set instead of raising), so a stale/foreign
  file at the configured path can no longer crash module lifespan startup
  for the whole process (pre-merge audit finding).

## [1.9.0] — 2026-07-17

### Added

- **SMCP-14 — in-session HITL approval endpoint + OTP** (`hitl_http.py`,
  `hitl_endpoint.py`, `hitl.py`, `state.py`, `state_dragonfly.py`): a scoped-mcp
  HTTP approve path so an operator can approve a gated tool call by replying in
  Matrix (via `matrix-hitl-bot`) instead of self-approving on a shell. New
  loopback routes `POST /hitl/approve`, `POST /hitl/deny`, `GET /hitl/pending`,
  registered only under the HTTP transport when the agent gates tools.
  - The routes self-authenticate with a **dedicated** bearer,
    `SCOPED_MCP_HITL_TOKEN` (distinct from the MCP tool bearer) — FastMCP custom
    routes bypass the MCP `BearerTokenVerifier`, so the check is enforced inside
    each handler. Only the trusted bot/courier holds it; the requesting agent
    never does.
  - On gate reject the middleware now mints a high-entropy one-time token (OTP,
    256-bit) stored **only** in Dragonfly (`hitl:otp:{approval_id}`, TTL =
    approval window), never in the operator notification — the requesting agent
    can read its own notify room, so no secret is ever posted there.
  - One-time semantics via new atomic `StateBackend.get_delete` (GETDEL); a new
    `StateBackend.scan` backs `/hitl/pending`. The OTP is bound to
    `{approval_id, tool_name}`; the pre-approval token stays bound to
    `{tool, args_hash}` as before.
  - **Fail-closed** on the state backend (rule M1): a Dragonfly error denies
    (503), never approves. The Postgres audit write is fail-open.
- **Agent session registry** (`registry_db.py`,
  `migrations/0001_agent_session_registry.sql`, new `[postgres]` extra): a
  fail-open asyncpg DAL over a v1 session registry on agent-postgres. First
  consumer is the HITL audit trail (`hitl_approvals`, storing only the OTP
  **hash**). Disabled unless `AGENT_REGISTRY_DSN` is set; every write is
  best-effort and can never block a tool call. P2/P3 tables are designed-in for
  later consumers.

## [1.8.0] — 2026-07-12

### Added

- **SMCP-27 — ntfy fallback sink for ops-alert** (`ops_alert.py`): the Vault-independent
  operational alerter now falls back to an ntfy topic when the primary Matrix sink is down
  or unconfigured. Configured from plain env (`SCOPED_MCP_ALERT_NTFY_URL`, optional
  `SCOPED_MCP_ALERT_NTFY_TOKEN`). This is a **fallback, not fan-out** — on the happy path
  (Matrix accepts) ntfy is never contacted; the fire-once-per-transition dedup still yields
  one alert overall. Deploying ntfy on a host external to forge keeps the fallback alive
  even when forge itself is degraded. Like every ops-alert sink it never touches Vault and
  never raises into the caller. Because ntfy is the one scoped-mcp path that leaves the
  host, the topic token is withheld (never sent) when the configured URL is not `https://`,
  so an operator misconfiguration cannot leak it in cleartext (audit INFO-1).

### Fixed

- **SMCP-16 / F-03 — stateless HTTP clients no longer share an audit trail**
  (`identity.py`): under the long-lived HTTP transport a client that negotiated no MCP
  session id fell back to the process-global `SESSION_ID`, so every such client collapsed
  onto one audit `session_id` and their trails merged. The resolver now derives a stable
  per-connection id from the TCP peer (`host:port`) — distinct concurrent connections get
  distinct ids, a kept-alive connection stays stable across calls, and the address is run
  through the same non-reversible `uuid5` mapping as a real session id so nothing
  connection-level leaks into a log. Falls back to the process default only when no peer is
  resolvable (stdio). Resolves the finding deferred from the v1.6.0 HTTP audit.

### Changed

- **Test coverage lifted to ~90%** and the coverage gate raised from `fail_under = 82` to
  `88`. New unit tests cover `contrib/otel.py` (observable-gauge registration + SDK-provider
  install path), `contrib/response_filter.py` (base64/url decode candidates), `modules/influxdb.py`
  and `modules/grafana.py` (HTTP CRUD happy paths + write-points input validation), `audit.py`
  (rotating file sinks + error-path agent-bus emit), and `server.py` (`_build_middleware`,
  the manifest-`validate` CLI, and `main()` dispatch). CI now installs the `[otel]` extra so
  the credential-metrics tests execute rather than skip. `server.py`'s `_run_serve` async
  serve loop and signal handlers are intentionally left uncovered (they need a live-transport
  integration harness for low value).

## [1.7.0] — 2026-07-12

### Added

- **SMCP-26 — Vault credential resilience + silent-failure alerting**: turns a silent,
  days-long credential failure into something that self-recovers and fails loud on
  independent channels. Four layers:
  - **L1 self-heal re-auth** (`credentials_vault.py`): on a permission/403-class renewal
    failure or a sustained failure streak, a full AppRole re-login mints a fresh token —
    covering the hard `token_max_ttl` (24h) ceiling that `renew-self` alone can never
    exceed. Gated on `SCOPED_MCP_VAULT_REAUTH=1` and safe only for a reusable secret_id
    (`secret_id_num_uses=0`); a guard refuses to re-login otherwise. The secret_id is no
    longer held as instance state — `_login()` re-reads it from the environment at call
    time. Adds `credential_health()`.
  - **L2 loud in-process** (`registry.py`): `scoped_mcp_status` gains a `credentials`
    block and drags top-level `healthy` to false when the token is unhealthy; the health
    file is now refreshable (rewritten on each health transition, with `written_at`); and
    a Vault-independent Matrix ops-alert (`ops_alert.py`) fires once per healthy⇄degraded
    transition, configured from plain env (`SCOPED_MCP_ALERT_MATRIX_*`) so it works when
    Vault is the broken dependency. Sink is pluggable (ntfy fallback deferred to SMCP-27).
  - **L2b 401-burst detection** (`http_auth.py`, SMCP-28 class): the bearer verifier
    counts recent `401`s in a sliding window and fires one rate-limited ops-alert on a
    burst — the misconfigured-client signal a session-start status check can't catch,
    because a 401'd client never reaches any tool.
  - **L3 `/health` route** (`registry.py`): under `--transport http`, an unauthenticated
    `GET /health` returns `200`/`503` (booleans/counts only — never token or lease values)
    so an external prober or load balancer can act on the status code alone.
  - **L4 OTel metrics** (`contrib/otel.py`): observable gauges
    `scoped_mcp.credentials.healthy` and `scoped_mcp.vault.consecutive_renewal_failures`
    export to SigNoz when `OTEL_EXPORTER_OTLP_ENDPOINT` is set, for a durable, queryable
    alert rule. No-op when the endpoint or `[otel]` extra is absent.

### Fixed

- **`examples/vault/vault-policy.hcl` documented only `read`** and said nothing about
  renew-self. Added a commented `auth/token/renew-self` rule plus notes on when it's
  needed (`token_no_default_policy = true`) and on the `token_max_ttl` ceiling vs.
  `token_period` / app-side re-auth — so a downstream user following the example doesn't
  hit a silent renewal failure.

- **SMCP-25 — `__version__` drifted from `pyproject.toml`** (`__init__.py`): was a
  hardcoded string last bumped at `0.3.3` while the package moved on to `1.6.1`. Now
  derived from `importlib.metadata.version("scoped-mcp")` — the installed package's own
  metadata is the single source of truth, so this can't drift from `pyproject.toml`
  again. Falls back to `"0.0.0+unknown"` if run from an uninstalled source checkout.

### Security

- **Health file written atomically** (`registry.py`): the now-refreshable health file is
  written to a sibling `.tmp` and `os.replace()`d into place, so the external prober that
  polls it can never read half-serialized JSON (pre-audit baseline FW-01).
- **401-burst tracking deque bounded** (`http_auth.py`): `_recent_401s` is capped
  (`maxlen=256`, well above the burst threshold) so a sustained local flood of bad bearers
  cannot inflate the sliding window; burst detection is unchanged (audit INFO-1).

## [1.6.1] — 2026-07-09

### Added

- **Manifest staleness detection** (`registry.py`): `scoped_mcp_status` now reports
  `manifest_path` and `manifest_loaded_at`, and adds `manifest_stale: true` plus a
  restart hint if the manifest file's mtime has moved since this process loaded it.
  Root cause of SMCP-24: under SMCP-15's long-lived HTTP transport, module discovery
  runs once at process start, so a manifest edit (new `tool_allowlist` entries, new
  modules) silently has no effect until a `pm2 restart scoped-mcp-<agent>` — this was
  implicit and automatic under `stdio` (fresh process per session) and undocumented
  under `http`. The staleness check is a soft diagnostic signal — a missing/unreadable
  manifest path at check time degrades to omitting the staleness fields, it never fails
  the call. `build_server()` gains an optional `manifest_path` parameter to enable it.

### Fixed

- **Vault token renewal called the wrong hvac API** (`credentials_vault.py`):
  `_renew_once()` called `self._client.auth.renew_self`, which does not exist on
  `hvac.Client` — the method is nested under `.auth.token.renew_self`. Every renewal
  raised `AttributeError`, so AppRole tokens were never renewed after process start
  (100% failure across all per-agent `scoped-mcp-*` PM2 processes since the 1.6.0
  PM2/HTTP deploy on 2026-07-02). Added a regression test that exercises the real
  hvac attribute chain instead of patching `asyncio.to_thread` wholesale.

## [1.6.0] — 2026-07-02

### Added

- **SMCP-15 — long-lived HTTP transport**: `scoped-mcp run` gains `--transport {stdio,http}`
  (default `stdio`, unchanged) plus `--host`/`--port`/`--path`. Under `http` the server runs
  as a long-lived streamable-http process (one per agent, under PM2), so a per-turn client
  recycle only drops a connection to a warm process — tool discovery no longer re-runs and
  tools never disappear mid-session. (`server.py`, `registry.py`)
- **Per-agent bearer authentication** (`http_auth.py`): the HTTP transport requires
  `Authorization: Bearer <SCOPED_MCP_BEARER_TOKEN>` and rejects missing/invalid tokens with
  401 before any tool dispatch (constant-time compare). Binds `127.0.0.1` only; a non-loopback
  `--host` is refused. stdio keeps its implicit private-pipe isolation (no auth). The verifier
  stamps the caller's `agent_id` onto the access token (`client_id` + `claims`) as a
  forward-compat guardrail for the future clone pool.
- **Per-connection session identity**: audit `session_id` is now resolved per request from the
  MCP connection context, not the process global — so one long-lived HTTP process emits distinct
  `session_id` values for concurrent clients. The raw MCP session id is mapped to a stable,
  non-reversible UUID so it both survives the audit sanitizer and never leaks a session secret
  into logs. `RequestIdentity` also carries a per-connection `agent_id` (clone-pool ready).
  (`identity.py`, `audit.py`)

### Changed

- **mcp_proxy self-healing**: a persistent stdio upstream call that fails with a dead-transport
  error (broken/closed pipe, subprocess exit) now transparently reconnects **once** and retries,
  logging `mcp_proxy_reconnect`. Long-lived processes previously left a dead pipe until restart;
  normal tool errors still propagate untouched so real outages are not masked. (`mcp_proxy.py`)
- **Audit/ops log rotation**: file sinks use a size-based `RotatingFileHandler`
  (`SCOPED_MCP_LOG_MAX_BYTES`, default 50 MiB; `SCOPED_MCP_LOG_BACKUPS`, default 5) so a
  long-lived process cannot grow an unbounded audit/ops file. stdio-per-turn behaviour is
  unchanged. (`audit.py`)

### Security

- Hardening from the SMCP-15 security audit (all Low/Info, none exploitable at ship):
  - **F-01**: the per-connection `agent_id` token claim is validated against
    `_AGENT_ID_PATTERN` before use, so a future clone-pool token issuer cannot introduce a
    path-traversal / scope-escape via a malformed claim. (`identity.py`)
  - **F-02**: the mcp_proxy dead-transport reconnect is serialized with an `asyncio.Lock` and
    re-checks the handle under the lock — concurrent callers no longer race to tear down and
    replace the persistent client. (`mcp_proxy.py`)
  - **F-04**: bearer comparison encodes to bytes so a non-ASCII token fails closed (clean 401)
    instead of raising. (`http_auth.py`)
  - **F-05**: a redaction filter scrubs the root stderr handler, so a dependency logging an
    `Authorization` header at DEBUG cannot persist a bearer to the long-lived process's logs.
    (`audit.py`)

## [1.5.2] — 2026-06-18

### Fixed

- **HITL pre-approval TTL too short**: `PREAPPROVAL_TTL_SECONDS` was 60 seconds — shorter
  than the default `hitl.timeout_seconds` of 300 seconds. After the operator ran
  `scoped-mcp hitl approve <id>`, the CLI wrote a 60-second one-time pre-approval token
  and deleted the pending key. If the agent took longer than 60 seconds to retry (common
  in a Claude session where reasoning steps occur between tool calls), the token expired,
  the middleware found no pre-approval, generated a fresh UUID, and fired a new
  notification — creating an infinite approval loop. Fixed by raising
  `PREAPPROVAL_TTL_SECONDS` to 300 seconds to match the approval window. (`hitl.py`)

## [1.5.1] — 2026-06-18

### Fixed

- **SMCP-9 — mcp_proxy stdio env propagation**: `McpProxyModule` now reads the `env`
  key from the manifest config block and passes it to the `mcpServers` stdio transport
  spec. Previously the key was silently dropped, causing tools that rely on environment
  variables (e.g. `DOCKHAND_ENDPOINT`) to fail with "required env var missing" on the
  post-HITL-approval retry — the only code path that actually spawns the subprocess.
  (`modules/mcp_proxy.py`)

## [1.5.0] — 2026-06-18

### Security (SMCP-8)

- **H-01 — HITL pre-approval token bound to (tool, args) hash**: Previously, approving
  a tool call wrote a token keyed by tool name only, allowing any call to the same tool
  within the 60-second TTL to proceed regardless of arguments. Tokens are now bound to
  a SHA-256 hash of the canonicalized arguments; a retry with different arguments does
  not consume the token and triggers a fresh approval request. CLI updated to read and
  store `args_hash` from the stored payload; legacy payloads (no `args_hash`) fall back
  to tool-name-only with a warning. (`hitl.py`, `hitl_cli.py`)

- **H-02 — Startup validation of gating glob patterns**: `approval_required`, `shadow`,
  and `rate_limits.per_tool` patterns that match no registered tool now emit a WARNING
  at startup. Tool names follow `{manifest_key}_{method}` format (underscores); dotted
  patterns such as `mcp_proxy.*` matched nothing and silently failed open. (`registry.py`)

- **H-02 — Docs: corrected glob pattern examples**: `mcp_proxy.*` fixed to `mcp_proxy_*`
  in rate_limit and hitl examples; tool naming convention documented with explicit
  fail-open warning. (`docs/manifest-schema.md`)

- **L-01 — DNS rebinding TOCTOU closed in http_proxy**: `_resolve_and_check` now returns
  the validated IP, and `_PinnedHostTransport` connects directly to that IP instead of
  letting httpx re-resolve the hostname. TLS SNI uses the original hostname via the
  `sni_hostname` extension so certificate validation is unaffected. Contradictory
  threat-model docs reconciled. (`modules/http_proxy.py`, `docs/threat-model.md`)

- **L-02 — arg_filter top-level-only scope documented prominently**: `_iter_string_fields`,
  `ArgumentFilterMiddleware`, and the manifest-schema docs now prominently state that
  argument filters inspect top-level string fields only — nested dicts/lists are not
  walked. (`contrib/arg_filter.py`, `docs/manifest-schema.md`)

- **M-01 / I-01 — mcp_proxy code comments**: Added comment on `scoping=None` explaining
  that room/resource scoping must be enforced at the upstream token level; added
  reliability note on stdio client multiplexing. (`modules/mcp_proxy.py`)

## [1.4.3] — 2026-06-17

### Changed
- **CI: Redis 7 service added to test matrix** — Dragonfly-gated tests in
  `test_state.py` now run in CI instead of being skipped; all four Python
  versions (3.11–3.14) exercise the DragonflyBackend. (SMCP-7 addendum)
- **tests: `dragonfly_backend` fixture moved to `conftest.py`** — shared by
  `test_state.py` and the new `test_hitl_cli.py`; `redis_client` async fixture
  added for raw-client injection. (SMCP-7 addendum)
- **`hitl_cli`: `_client=None` injection param on `_list_pending` and `_decide`**
  — allows tests to supply a pre-seeded client instead of calling
  `aioredis.from_url()` internally; production path unchanged. (SMCP-7 addendum)
- **tests: new `test_hitl_cli.py`** — 11 unit tests (no Redis) covering
  `_parse_approval_id`, `_key_for`, `_preapproval_key_for`, and
  `run_hitl_command` validation paths; 6 async integration tests covering
  `_list_pending` and `_decide` (approve, reject, missing ID). (SMCP-7 addendum)

## [1.4.2] — 2026-06-17

### Changed
- **tests: `pytest.importorskip()` guards on 6 test files** — `test_grafana`,
  `test_http_proxy`, `test_influxdb`, `test_matrix`, `test_notifications`, and
  `test_sqlite` now skip gracefully when optional extras (`respx`, `aiosqlite`) are
  absent instead of hard-failing at collection time. (SMCP-7)
- **tests: coverage raised to 83% (`fail_under` 80 → 82)** — added `SmtpModule`
  tests (`smtp.py` 14% → 100%) and `hitl_notify` tests covering `LogNotifier`,
  `NtfyNotifier`, `WebhookNotifier`, `MatrixNotifier`, `_format_message`, and
  `build_notifier` (`hitl_notify.py` 24% → 87%). (SMCP-7)
- **ruff: `E402` added to `tests/**/*.py` per-file-ignores** — suppresses the
  "import not at top of file" warning that the `importorskip` pattern legitimately
  triggers in test files. (SMCP-7)

### Fixed
- **filesystem: redundant `enforce()` call removed from `list_dir`** — `_resolve()`
  already enforces scope; the second call on the same resolved path was dead motion.
  (SMCP-7)

## [1.4.1] — 2026-06-17

### Fixed
- **mcp_proxy: `anyOf:[T,null]` params now advertise correct type** — FastMCP 2.x emits
  `anyOf: [{type: X}, {type: null}]` for `Optional[T]` fields (e.g. `list[str] | None`).
  `py_type()` in `_signature_from_schema` previously only handled the older
  `type: [X, null]` list form, so optional array/object params got annotation `Any`.
  scoped-mcp re-advertised these params with no type info, causing LLMs to pass JSON
  strings instead of arrays — which were then rejected by `_validate_arguments` with
  `_ProxyValidationError`. Fix: `py_type()` now unwraps `anyOf` and extracts the first
  non-null type. Affects `assignees`, `labels`, and other `list[str] | None` params on
  `plane-mcp create_work_item` and similar tools. (SMCP-6)

## [1.4.0] — 2026-06-17

### Added
- **registry: module fault isolation** — a single module failing to import, instantiate,
  or start up no longer kills the entire scoped-mcp process. Each phase is now isolated:
  - **Import failure** (`_discover_module_classes`): if a module file raises on import (e.g.
    missing optional dependency, syntax error), it is recorded in `failed_imports` and
    discovery continues for all remaining modules. Only truly unknown modules (not in
    `available` AND not in `failed_imports`) still raise `ManifestError` at startup.
  - **Init failure** (`build_server`): if `module_cls.__init__()` raises (bad config,
    missing credential), the exception is caught per-module; other modules are still
    instantiated and registered normally.
  - **Startup failure** (`_make_module_lifespan`): `asyncio.gather` now runs with
    `return_exceptions=True` so a single `startup()` failure does not abort the lifespan.
    Failed modules are recorded in `module_health`; the server yields and the remaining
    modules' tools stay available. (SMCP-5)
- **registry: `scoped_mcp_status` built-in tool** — always registered on the parent server
  regardless of manifest content. Returns `{modules, failed_count, total_count, healthy}`.
  Status values: `running`, `failed_import`, `failed_init`, `failed_startup`. Operators
  can call this at session start to identify and diagnose degraded modules before running
  tasks. (SMCP-5)
- **registry: `SCOPED_MCP_HEALTH_FILE` env var** — if set, the lifespan writes a JSON
  health report to this path after startup completes (success or failure). Intended for
  session-start hooks and external health-check scripts that need stable file-based status
  without calling MCP tools. (SMCP-5)

### Changed
- **registry: `_discover_module_classes` now returns `tuple[dict, dict]`** — the first
  element is the existing `{name: class}` map; the second is `{file_stem: error_string}`
  for modules that failed to import. Callers that patched this function in tests must
  update their `return_value` to a two-element tuple: `({"name": cls}, {})`.
- **registry: `_make_module_lifespan` takes `list[tuple[str, ToolModule]]`** — module
  instances must now be passed as `(manifest_name, instance)` pairs so the lifespan can
  use manifest-key names in health records and logs rather than the class-level `.name`
  attribute (which differs when `type:` is used).

## [1.3.4] — 2026-06-14

### Fixed
- **server: install SIGTERM handler for graceful shutdown** — Claude Desktop / Claude Code
  send SIGTERM to the scoped-mcp subprocess when a session ends. Without a handler the
  process could be killed mid-flight, bypassing module `shutdown()` hooks (open sockets,
  Vault token-renewal tasks, mcp_proxy subprocess handles, etc.). The handler calls
  `sys.exit(0)`, which raises `SystemExit` through anyio into FastMCP's lifespan
  finally-block and then into `_make_module_lifespan`'s finally-block, giving every module
  a clean shutdown. Prevents orphaned scoped-mcp processes. (SMCP-3)

### Changed
- **tests: clarify docstring for `test_extra_top_level_field_rejected`** — the test was
  correct after the SMCP-4 fix but its docstring predated the two-phase story. Updated to
  note it exercises the `load_manifest()` → `ManifestError` code path, distinct from the
  model-level guard in `test_real_manifests.py::test_unknown_top_level_field_still_rejected`.
  (SMCP-2)

## [1.3.3] — 2026-06-13

### Fixed
- **manifest: model `workspace_access` as an explicit optional field** — regression fix
  (SMCP-4). 1.3.2 restored `extra="forbid"` on the top-level `Manifest` model, which rejected
  the `workspace_access` block present in every agent manifest with
  `ValidationError: workspace_access extra_forbidden`, breaking scoped-mcp connections
  forge-wide after the venv upgraded. Rather than reverting to `extra="ignore"` (which
  silently swallows all unknown top-level fields and loses shadowing-attack protection),
  `workspace_access` is now a typed `list[WorkspaceAccessEntry]` field. `Manifest` keeps
  `extra="forbid"`, so genuinely unknown fields are still rejected. (SMCP-4)

### Added
- **test: regression guard loading every real agent manifest** — `tests/test_real_manifests.py`
  validates all `~/.claude/manifests/*-agent.yml` through `Manifest.model_validate` so a future
  stale-branch merge cannot silently re-break manifest validation. (SMCP-4)

## [1.3.2] — 2026-06-13

### Changed
- **registry: start upstream modules concurrently** — `_make_module_lifespan` now starts
  all proxied modules with `asyncio.gather` instead of serially, cutting cold-start time
  from ~5.5s (17 upstreams) to roughly the slowest single module (<1s). Removes the
  tool-unavailable window during per-connection restarts (e.g. under CloudCLI's stream-json
  driver). (SMCP-1)

### Fixed
- **registry: guard against subprocess handle leak on partial startup failure** — modules
  are now registered to the `started` list before `await mod.startup()` so the `finally`
  cleanup block can call `shutdown()` on any module that was cancelled or failed mid-startup.
  `shutdown()` already guards with `if self._client_handle is not None`, making the call a
  no-op for modules whose handles were never set. (SMCP-1)
- **manifest: restore `extra="forbid"` on top-level Manifest model** — a prior commit
  loosened this to `extra="ignore"`, silently dropping unknown top-level fields and
  removing the shadowing-attack protection. All other models in the file use `extra="forbid"`;
  this aligns `Manifest` with them. (SMCP-2)

## [1.3.1] — 2026-05-30

### Fixed

- **`hitl.py`: switch HITL from suspend-and-wait to reject-then-wait** — the v1.0
  design blocked the MCP connection while waiting for a pub/sub approval decision,
  causing session deadlocks in Claude (tool call hangs; no other tools can run,
  including the CLI approval command). The middleware now rejects immediately with
  an approval ID and retry instructions. The operator runs `scoped-mcp hitl approve
  <id>`, which writes a one-time pre-approval token to Dragonfly (60 s TTL). The
  agent retries the tool call; the middleware finds and consumes the token and
  forwards the call upstream.
- **`hitl_cli.py`: filter preapproval keys from `hitl list`** — the scan pattern
  `*:hitl:*.*` matched preapproval keys for tools with dots in their names (e.g.
  `mcp_proxy.delete_file`). Preapproval keys are now explicitly skipped before the
  GET to avoid unnecessary Redis operations and silent `JSONDecodeError` swallowing.

## [1.3.0] — 2026-05-29

### Added

- **`mcp_proxy.py`: header injection for upstream HTTP connections** — new `headers`
  config field on `McpProxyModule`. When set, uses `StreamableHttpTransport` to pass
  custom headers (e.g. `Authorization: Bearer ${TOKEN}`) to upstream MCP servers.
  Stdio transports log a warning and ignore headers. Supports `${VAR}` substitution
  via scoped-mcp's existing env-var expansion.
- **`manifest.py`: `max_auto_risk` and `interaction_permissions` manifest fields** — new
  optional top-level fields accepted by the `Manifest` model. These are platform metadata
  consumed by the task dispatcher and agent bus; scoped-mcp parses and stores them but
  does not act on them. Fixes `ValidationError` for agents whose manifests include these
  fields.

## [1.2.2] — 2026-05-27

### Security

- **`manifest.py`: suppress secret values from `ManifestError` messages** — `yaml.YAMLError`
  and Pydantic `ValidationError` messages were interpolated directly into `ManifestError`
  strings. After env var substitution, those messages could include expanded secret values
  (e.g. a password that corrupts YAML, or a Pydantic field dump). The YAML path now emits
  a static `"YAML syntax error"` string; the validation path emits only `type(e).__name__`.
  The `__cause__` chain is preserved for debugging. Docstring warning added to
  `_expand_env_vars()` advising that substitution sites should be YAML-quoted to prevent
  structure corruption from special characters in secret values.

## [1.2.1] — 2026-05-26

### Fixed

- **`registry.py`: double module prefix in tool names** — `child.tool(name=tool_name)` was
  registering tools with the full `{module}_{method}` name, then `server.mount(prefix=module)`
  added the prefix a second time, producing `{module}_{module}_{method}`. HITL
  `approval_required` and `rate_limits.per_tool` patterns never matched as a result — approvals
  were silently bypassed on forge. Fixed by registering with `child.tool(name=method.__name__)`
  (bare name) and letting `mount()` add the prefix once.
- **`audit.py`: tilde not expanded in agent-bus comms path** — `Path(_agent_bus_comms_dir)` did
  not call `.expanduser()`, so paths like `~/.claude/comms` were resolved relative to CWD.
  Events were being written to `{CWD}/~/.claude/comms/logs/` instead of the intended
  `/home/ted/.claude/comms/logs/`. Fixed by adding `.expanduser()`.

### Changed

- **`pyproject.toml` version bumped to 1.2.1** — version was not bumped during the v1.2.0
  release.

## [1.2.0] — 2026-05-26

### Added

- **Manifest env var substitution** (`manifest.py`) — `${VAR_NAME}` placeholders in manifest
  files are expanded from the process environment before YAML parsing. Only the braced form
  is supported (`${VAR}`, not `$VAR`) to prevent accidental expansion. Undefined variables
  at startup are a hard error (`ManifestError` naming the variable, never its value) — the
  agent will not start with incomplete config. Expanded values are never written to audit or
  ops JSONL output.

## [1.1.1] — 2026-05-26

### Security

- **`contrib/otel.py`: replace `record_exception` with `add_event`** — `span.record_exception(exc)`
  emits a separate OTel event with an unredacted `exception.message`, bypassing `_redact_string()`.
  Replaced with `span.add_event("exception", attributes={...})` so only the redacted message
  reaches the OTLP collector. `exception.type` (class name) included for schema compatibility.

## [1.1.0] — 2026-05-26

### Added

- **Pre-call hook registry** (`hooks.py`) — `register_before(server, tool, handler)` /
  `run_before_hooks(server, tool, kwargs)` pattern. Hooks chain in registration order and
  fire in `mcp_proxy.proxy_call()` before each upstream call. Used by the signing hook and
  available to contrib extensions.
- **ed25519 signing hook** (`contrib/signing_hook.py`) — `create_signing_hook(priv_b64, pub_b64)`
  factory returns an async hook that signs agent-bus `log_event` calls with an ed25519
  private key loaded from Vault at startup. Key fingerprint is included in the signed
  canonical payload; the raw key never appears in logs or event metadata.
- **Auto-registration** (`registry._register_signing_hook_if_available`) — if the Vault
  bundle contains `signing_private_key` + `signing_public_key`, the signing hook is
  registered automatically on server startup; no manifest change required.
- **`_manifest_key` on `McpProxyModule` instances** — registry sets this attribute after
  instantiation so hooks are keyed to the logical server name (e.g. `"agent-bus"`) rather
  than the class name.

### Security

- **OTel span exception redaction** — `exception.message` span attribute now passes through
  `_redact_string` to prevent upstream exception messages from leaking request data
  (embedded tokens, quoted argument values) to the OTLP collector. The status description
  was already redacted; this closes the remaining gap.

## [1.0.2] — 2026-05-26

### Added

- **Session ID** — `SESSION_ID` UUID generated at process start; injected into every audit
  log entry and OTel span as `session.id`. Allows correlating all tool calls within a
  single agent session.
- **Agent-bus event emission** — `_emit_agent_bus_event()` writes a JSONL event to
  `~/.claude/comms/logs/` after each tool call. Emits `tool_name`, `outcome`,
  `elapsed_ms`, and error type only — kwargs and result content are never included.
- **OTel session span injection** — `_inject_session_id_to_current_span()` adds `session.id`
  to the active OTel span when one is present.
- **`AuditConfig` and `ResponseFilterRule` manifest models** — opt-in audit configuration
  and per-field response scanning rules wired at server startup.
- **Response filter** (`contrib/response_filter.py`) — post-execution content scanning with
  `block` / `warn` / `redact` modes. Redact applies only to `isinstance(value, str)` leaves
  in structured responses — never to serialized dict/list blobs.

## [1.0.1] — 2026-05-26

### Fixed

- **fastmcp 3.x compatibility** — Five patches to resolve breaking changes introduced in
  fastmcp 3.2.4: `ToolAnnotations` constructor kwarg rejection (P1), stdio subprocess
  config format (P2), `None` result serialization (P3), `TracerProvider` OTel init
  signature (P4), middleware tool signature passthrough (P5). scoped-mcp is now
  compatible with fastmcp >=3.2.0 as declared in the project dependencies.
- **Silent exception handlers** — Bare `pass` blocks in exception handlers replaced with
  structured `_log.warning(...)` calls. Startup failures now surface in logs rather than
  manifesting as silently missing tools.

### Changed

- **`mode: read` + `mcp_proxy` warning** — Emits a startup warning when a manifest
  combines `mode: read` with an `mcp_proxy` module, since `mode: read` has no effect on
  proxied tools. Use `tool_denylist` to restrict tool access for `mcp_proxy` modules.

### Added

- **`examples/launcher/`** — Template launcher scripts for the stdio subprocess env
  inheritance pattern (`run-scoped-mcp.sh`, `run-langfuse-mcp.sh`) with documentation.

## [1.0.0] — 2026-04-27

Final phase of the scoped-mcp hardening roadmap. Project moves to
`Development Status :: 4 - Beta` — the four core guardrails (per-agent
credential isolation, scope enforcement, audit logging, and now
operator-in-the-loop approval) are stable and exercised by 432 tests at
82% coverage.

### Added

- **`HitlMiddleware`** (`scoped_mcp.hitl`) — human-in-the-loop approval
  middleware. Glob-pattern matching against tool names selects calls that
  require explicit operator approval (`approval_required`) or are logged-only
  (`shadow`). Shadow takes precedence: a tool matched by both shadow and
  approval_required returns a synthetic empty-success response without ever
  forwarding upstream, regardless of operator decision. Auto-rejects after
  `timeout_seconds` (default 300s) with no decision. Backend write failures
  fail closed — the agent receives `HitlRejectedError`, not a forwarded call.

- **Notifier abstraction** (`scoped_mcp.hitl_notify`) — `LogNotifier`
  (default, no extra deps), `NtfyNotifier`, `WebhookNotifier`, `MatrixNotifier`.
  All transport failures are logged and swallowed so a notification outage
  cannot wedge the approval loop. Notifiers receive only the sanitised
  argument summary — raw values never reach the operator channel.

- **HITL operator CLI** (`scoped-mcp hitl …`) — `list`, `approve <id>`,
  `reject <id> [reason]`. Reads the Dragonfly URL from the manifest.
  Verifies the approval key is still pending before publishing a decision.

- **`hitl:` manifest section** — `approval_required`, `shadow`,
  `timeout_seconds`, `notify` (type + topic/room/url with format validators).
  Manifest validator: HITL with non-empty patterns requires
  `state_backend.type: dragonfly`.

- **`HitlRejectedError`** — raised on explicit reject, `reject:<reason>`, or
  timeout. Generic agent-facing message; rule/pattern detail stays in the
  audit log.

- **Approval ID format** — `{agent_id}.{uuid_hex_12}` with 48 bits of entropy
  in the random suffix. The agent_id prefix lets the operator CLI find the
  right Dragonfly key prefix without a separate lookup key.

### Changed

- **`StateBackend.subscribe()` is now a coroutine returning an async iterator**
  (was an async generator). Registration / network handshake completes
  synchronously when awaited, eliminating a publish-before-subscribe race
  that caused fast operator decisions to be lost. Callers must use
  `sub = await state.subscribe(channel)` before `async for msg in sub`.

- **Project status: `Development Status :: 4 - Beta`** — bumped from Alpha now
  that the v0.7 → v1.0 hardening roadmap is complete.

## [0.9.0] — 2026-04-27

### Added

- **mcp_proxy inputSchema validation** — every proxied `tools/call` is validated
  against the upstream tool's JSON Schema before forwarding. Schemas are cached
  at discovery and refreshed on stdio reconnect. The refresh path filters new
  tools through `tool_allowlist`/`tool_denylist` so a malicious upstream cannot
  widen the exposed surface, and *merges* into the cache rather than replacing
  it — tools that disappear from a refresh keep their cached schema (fail-safe
  to stale-but-strict over silent no-validation). Validation failures log the
  argument *keys* only, never values.

- **`ArgumentFilterMiddleware`** (`scoped_mcp.contrib.arg_filter`) — pattern-based
  blocking or alerting on tool argument values. Configured via the new
  `argument_filters:` manifest section; auto-registered after rate limiting.
  Supports optional decode steps `base64`, `urlsafe_base64`, and `url` to catch
  obfuscated payloads. Decode results are capped at 64 KiB to bound the ReDoS
  amplification surface. Block rules are evaluated before warn rules and
  short-circuit on the first hit. The structured audit log records the rule
  name, tool name, field name, and a `raw`/`decoded` label — never the matched
  value. The agent-facing block error is generic so an agent cannot enumerate
  filter configuration via probe-and-observe.

- **`argument_filters:` manifest section** — list of rules with `name`, `pattern`,
  `fields`, `action` (`block`|`warn`), `decode`, and `case_insensitive`. Patterns
  are compiled at manifest load so a malformed regex fails the manifest, not
  the first call. `extra="forbid"` on every rule.

### Changed

- **`jsonschema` pin tightened to `>=4.18`** — earlier versions ship a legacy
  `RefResolver` that auto-fetches external `$ref` URLs, turning a permissive
  upstream `inputSchema` into a controlled outbound HTTP channel. 4.18+ uses
  the `referencing` library where external refs are unresolvable by default.

- **`docs/threat-model.md`** — added explicit sections on the schema-validation
  semantic gap (shape ≠ intent) and the argument-filter limits (top-level
  strings only, 64 KiB decode cap, no per-match regex timeout).

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
