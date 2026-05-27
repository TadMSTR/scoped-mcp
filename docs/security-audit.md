# Security Audit

## Audit History

| Date | Version / Scope | Findings | Status |
|------|-----------------|----------|--------|
| 2026-04-16 | v0.1.0 — full source review | 18 (1 critical, 3 high, 8 medium, 6 low) | Remediated in v0.2.0 |
| 2026-04-19 | v0.2.1 — compliance additions | 0 (2 informational) | Clean |
| 2026-04-20 | v0.2.1 — verification pass | 0 (1 informational) | All 6 targeted findings confirmed resolved |
| 2026-04-27 | v0.4.0 — mcp_proxy module | 0 critical / 0 high / 1 medium / 2 low | Remediated in v0.5.0 |
| 2026-04-27 | v0.5.0 — mcp_proxy lifecycle hooks | 0 critical / 0 high / 1 medium / 2 low | Remediated in v0.6.0 |
| 2026-04-27 | v0.6.0 — middleware + OTel | 0 critical / 0 high / 0 medium / 2 low | L1 carried; L2 documented. L1 resolved in v1.1.1 |
| 2026-04-27 | v0.7.0 — rate limits + state backend | 0 critical / 0 high / 1 medium / 2 low | Remediated before merge |
| 2026-04-27 | v0.8.0 — Vault credential source | 0 critical / 0 high / 1 medium / 3 low | Remediated before merge |
| 2026-04-27 | v0.9.0 — schema validation + arg filters | 0 critical / 0 high / 1 medium / 3 low | Remediated before merge |
| 2026-04-27 | v1.0.0 — HITL + shadow mode | 0 critical / 0 high / 1 medium / 3 low | Remediated before merge |
| 2026-05-26 | v1.0.1 — OTel TracerProvider + mcp_proxy | 0 critical / 0 high / 0 medium / 1 low | L1 partially mitigated; fully resolved in v1.1.1 |
| 2026-05-26 | Phase 7 — audit, hooks, response filter, loki-mcp, agent-bus | 0 critical / 0 high / 0 medium / 3 low | All 3 findings triaged and fixed |
| 2026-05-26 | Phase 7 forge — manifests, OTel v1.1.0, Vault AppRole config | 0 critical / 0 high / 0 medium / 4 low | Triaged; Vault per-agent policy pending |

## Summary

All audits since v0.1.0 have returned 0 critical and 0 high findings. The 18 findings from
the initial v0.1.0 audit — including unenforced SQLite isolation, Flux query injection, SSRF
bypass variants, and missing scope enforcement wiring — were fully remediated by v0.2.0 and
verified clean in a follow-up audit on 2026-04-20.

Subsequent feature audits (v0.4.0 through v1.0.0, all conducted 2026-04-27 as part of the
scoped-mcp-proxy and hardening roadmap) found only medium and low findings, each remediated
before the feature branch merged. The one recurring theme was OTel exception message
redaction: first reported as L1 in the v0.6.0 audit, partially addressed in v1.0.1, and
fully resolved in v1.1.1 (replacing `span.record_exception()` with a manually redacted span
event to prevent raw exception messages from reaching the OTLP collector).

The 2026-05-26 audits (v1.0.1, Phase 7, and Phase 7 forge deployment) returned 0 critical,
0 high, and 0 medium findings. Eight low-severity hardening items were identified across
three audits; seven were triaged and fixed immediately. One outstanding item (per-agent Vault
policies replacing the shared wildcard policy, Phase 7 forge L3) remains for a future
configuration update.

## Findings and Remediation

### 2026-04-16 audit — v0.1.0

All 18 findings were remediated in v0.2.0. See [CHANGELOG v0.2.0](../CHANGELOG.md) for
detailed descriptions of each finding, its severity, and the fix applied.

### 2026-04-19 audit — v0.2.1

Targeted review of showcase compliance additions (`SECURITY.md`, `.pre-commit-config.yaml`,
`__version__` sync, two `isinstance` lint fixes). Zero actionable findings; two informational
observations, no action required.

### 2026-04-20 verification — C1, H1, H2, H3, M5, M6

Confirmed all six targeted findings from the 2026-04-16 audit fully resolved:

- **C1** — SQLite per-agent file isolation: OS-level `agent_<id>.db` path replaces ATTACH schema
- **H1** — Flux injection: structured `filters: list[dict]` API replaces free-form predicate
- **H2** — SSRF IPv6 completeness: `::ffff:0:0/96`, `fc00::/7`, `fe80::/10` added; per-request DNS
  resolution prevents rebinding
- **H3** — `@audited` contract: corrected in docstrings — decorator is logging-only; modules are
  responsible for `enforce()`
- **M5** — `agent_id` validation: `^[a-z0-9][a-z0-9-]{0,62}$` enforced in `AgentContext.from_env()`
- **M6** — Secrets file permissions: 0600 + owner check, strict by default

One informational item (InfluxDB `create_bucket` name not format-validated) had no security
impact and required no action.

### 2026-04-27 audits — v0.4.0 through v1.0.0

Eight feature-branch audits conducted as part of the scoped-mcp-proxy build and the
four-phase hardening roadmap. All medium findings were remediated before their branch
merged. See the individual audit reports in the `security-audits/` repo for full details.

**Notable medium findings and resolutions:**

| Version | Finding | Resolution |
|---------|---------|-----------|
| v0.4.0 M1 | `mcp_proxy` `mode:` bypass undocumented; operators could rely on it incorrectly | Warning block added to `manifest-schema.md` |
| v0.5.0 M1 | Partial startup failure left persistent stdio subprocesses unreaped | `started[]` tracking with cleanup in `finally` regardless of which module failed |
| v0.7.0 M1 | Rate limit middleware had no explicit fail-closed policy on backend error | `try/except` with re-raise added; test confirms backend errors reject the call |
| v0.8.0 M1 | Vault token redaction regex missed base64url (`-`/`_`) characters | `_VAULT_TOKEN_RE` updated to accept base64url alphabet; legacy `b.`/`r.` prefixes added |
| v0.9.0 M1 | Schema cache wholesale-replace left orphaned proxy methods without validation | Merge-on-refresh semantics; fail-closed if previously-schemaed tool goes missing |
| v1.0.0 M1 | HITL subscribe was a lazy async generator; fast operator approvals silently dropped | `subscribe()` converted to `async def` returning a registered iterator before returning |

**Recurring low finding — OTel exception message sanitization (v0.6.0 L1):**

First identified in v0.6.0: `span.record_exception(exc)` forwarded raw exception messages
to the OTLP collector without the structlog `_sanitize_processor` redaction applied. Partially
addressed in v1.0.1 (added `set_attribute("exception.message", _redact_string(str(exc)))`),
but the OTel SDK's `record_exception()` also emits an exception event that the attribute
override does not overwrite. Fully resolved in v1.1.1 by replacing `record_exception()` with
`span.add_event("exception", ...)` using manually redacted fields.

### 2026-05-26 audit — v1.0.1

Audit of OTel TracerProvider wiring, mcp_proxy signature synthesis (P1–P3), stdio wrapping,
and example launcher templates. Zero critical, high, or medium findings. One low finding:

- **L1** — `span.record_exception()` set a redacted `exception.message` span attribute but
  the SDK-emitted event still carried the raw message. Partial fix applied in v1.0.1; fully
  resolved in v1.1.1. See OV-13 in the Phase 7 forge audit for the complete fix.

### 2026-05-26 audit — Phase 7 (core + loki-mcp + agent-bus)

Audit of Phase 7 additions to scoped-mcp (signing hook, response filter, mcp_proxy updates)
and two companion servers (loki-mcp v0.1.0, agent-bus). Zero critical, high, or medium
findings. Three low findings, all triaged and fixed in the same session:

- **L1** (loki-mcp) — `get_label_values()` label name interpolated into URL path without
  validation; `..`-containing values reachable via GET. Fixed with `_LABEL_RE` validation.
- **L2** (agent-bus) — `verify_chain()` date parameter used in filename construction without
  sanitization; path traversal possible. Fixed with `_DATE_RE` validation.
- **L3** (agent-bus) — `get_status()` returned integration URLs verbatim, exposing any
  embedded auth tokens in query strings. Fixed by stripping query strings before returning.

### 2026-05-26 audit — Phase 7 forge deployment

Audit of the forge production deployment: five agent manifests, OTel v1.1.0 installation,
`.env` file permissions, `agent-keys.json`, and Vault AppRole configuration. Zero critical,
high, or medium findings. Four low findings:

- **L1** — Research agent manifest was missing `argument_filters` present on all four other
  agents (including the only `action: block` path-traversal rule). Fixed by adding the three
  standard filter rules to `research-agent.yml`.
- **L2** (OV-13) — `span.record_exception()` in `contrib/otel.py` still emitted unredacted
  exception events via the OTel SDK despite the `set_attribute` fix in v1.0.1. Fully
  resolved in v1.1.1 by replacing `record_exception()` with `span.add_event()` using
  manually redacted `exception.type`, `exception.message`, and empty `exception.stacktrace`.
- **L3** — Vault AppRole shared wildcard policy (`secret/data/agents/*`) allowed each agent
  to read any other agent's signing private key from Vault KV. Per-agent scoped policies
  recommended. **Outstanding** — Vault policy split not yet applied.
- **L4** — Dragonfly connection URL (including password) embedded in sysadmin manifest rather
  than the `.env` file used by other agents. Fixed by moving to `.env` with env var
  substitution in the manifest.

## Scope

**2026-04-16 audit:** Full source review of v0.1.0 — all 10 modules, scoping engine,
credential loading, audit logging, context validation, CI workflows. Code review,
dependency audit (`pip-audit`), and threat model validation against the documented
scoping contract.

**2026-04-19 audit:** Targeted review of the showcase compliance additions only:
`SECURITY.md`, `.pre-commit-config.yaml`, `__version__` sync, and two `isinstance`
lint fixes.

**2026-04-20 verification:** Verification of C1, H1, H2, H3, M5, M6 from the 2026-04-16
audit. Full re-read of the six affected files; live isolation and SSRF boundary tests.

**2026-04-27 feature audits (v0.4.0–v1.0.0):** Incremental diff-focused audits of each
feature branch in the scoped-mcp-proxy build and hardening roadmap. Each audit covered
only the changed files for that phase. Individual audit reports are in the
`security-audits/` repo.

**2026-05-26 v1.0.1 audit:** OTel TracerProvider wiring, mcp_proxy signature synthesis
and `mode: read` improvements, example launcher templates, and `manifest.py` changes.

**2026-05-26 Phase 7 audits:** scoped-mcp `audit.py`, `hooks.py`, `contrib/signing_hook.py`,
`contrib/response_filter.py`, `modules/mcp_proxy.py`; agent-bus `server.py`; loki-mcp
`server.py` and `pyproject.toml`. Separate deployment audit of the forge production
environment: five agent manifests, Vault AppRole configuration, `.env` file permissions,
and `agent-keys.json`.

## What's Not Covered

- Runtime infrastructure, host security, or network-level threats
- The MCP transport layer (stdio) and the Claude Code runtime itself
- Deployed agent manifests or credential files (operator-managed trust boundaries)
- Third-party FastMCP internals beyond the scoped-mcp integration surface
