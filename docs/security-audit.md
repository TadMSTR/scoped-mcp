# Security Audit

## Audit History

| Date | Version | Findings | Status |
|------|---------|----------|--------|
| 2026-04-16 | v0.1.0 | 18 findings (1 critical, 3 high, 8 medium, 6 low) | Remediated in v0.2.0 |
| 2026-04-19 | v0.2.1 | 0 findings (2 informational) | Clean |

## Summary

An internal security audit of v0.1.0 identified 18 findings, the most significant being
unenforced SQLite isolation, Flux query injection, SSRF bypass variants, and missing
scope enforcement wiring. All findings were remediated in v0.2.0. A follow-up audit of
the v0.2.1 showcase compliance additions (SECURITY.md, `.pre-commit-config.yaml`,
version sync) returned clean with no actionable findings.

## Findings and Remediation

All findings from the 2026-04-16 audit have been remediated. See
[CHANGELOG v0.2.0](../CHANGELOG.md) for detailed descriptions of each finding,
its severity, and the fix applied.

## Scope

**2026-04-16 audit:** Full source review of v0.1.0 — all 10 modules, scoping engine,
credential loading, audit logging, context validation, CI workflows. Covered:
code review, dependency audit (pip-audit), and threat model validation against
the documented scoping contract.

**2026-04-19 audit:** Targeted review of the showcase compliance additions only:
`SECURITY.md`, `.pre-commit-config.yaml`, `__version__` sync, and two `isinstance`
lint fixes.

## What's Not Covered

- Runtime infrastructure, host security, or network-level threats
- The MCP transport layer (stdio) and the Claude Code runtime itself
- Deployed agent manifests or credential files (operator-managed trust boundaries)
- Third-party FastMCP internals beyond the scoped-mcp integration surface
