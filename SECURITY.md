# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, use one of these channels:

- **GitHub private disclosure:** Use the [Security tab](https://github.com/TadMSTR/scoped-mcp/security/advisories/new) to submit a private advisory.
- **Email:** Send a description to `security.i9v75@8alias.com` with the subject line `[scoped-mcp] Security Report`.

Include as much detail as possible: the affected component, steps to reproduce, and potential impact.

## Scope

**In scope:**

- Tool scoping bypass — an agent accessing tools or arguments outside its declared scope
- Credential isolation failure — credential leakage between agents or tool invocations
- Path traversal or sandbox escape in the manifest loader or path validators
- Input validation failures that allow injection or unintended command execution
- Dependency vulnerabilities with a plausible exploitation path in scoped-mcp's usage
- HITL approval forgery under `hitl.signing.mode: enforce` — a gated call proceeding
  without a statement signed by the configured approver key, or a signed statement
  approving a different agent, tool, argument set, or a second call

**Out of scope:**

- Vulnerabilities in the host system, MCP transport layer, or Claude Code itself
- Issues that require attacker control of the scoped-mcp config file or manifest directory
  (those are operator-controlled trust boundaries, not input attack surfaces)
- Theoretical weaknesses without a realistic attack path
- The documented residuals of signed HITL approvals ([threat model](docs/threat-model.md#hitl-approvals)):
  an agent that shares an OS user with its proxy replacing or editing the proxy process,
  and replay of a consumed statement within its 120 s lifetime after a proxy restart or into
  a second process serving the same agent. These are accepted and need OS-level separation,
  not a code fix. Without signing (`mode: off`, the default) an approval is not
  authenticated at all; that is the documented behaviour, not a vulnerability

## Response Expectations

| Stage | Timeline |
|-------|----------|
| Acknowledgement | Within 3 business days |
| Initial assessment | Within 7 business days |
| Fix or remediation plan | Within 30 days for critical/high; 60 days for medium/low |

This is a personal project maintained by one developer. Response times are best-effort.
If you haven't heard back within 3 business days, a follow-up email is welcome.

## Disclosure

Coordinated disclosure is preferred. Please allow time for a fix to be released before
public disclosure. The CHANGELOG documents remediated findings at an appropriate level
of detail after each release.
