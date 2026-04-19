# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, use one of these channels:

- **GitHub private disclosure:** Use the [Security tab](https://github.com/TadMSTR/scoped-mcp/security/advisories/new) to submit a private advisory.
- **Email:** Send a description to `claude.ervlu@simplelogin.com` with the subject line `[scoped-mcp] Security Report`.

Include as much detail as possible: the affected component, steps to reproduce, and potential impact.

## Scope

**In scope:**

- Tool scoping bypass — an agent accessing tools or arguments outside its declared scope
- Credential isolation failure — credential leakage between agents or tool invocations
- Path traversal or sandbox escape in the manifest loader or path validators
- Input validation failures that allow injection or unintended command execution
- Dependency vulnerabilities with a plausible exploitation path in scoped-mcp's usage

**Out of scope:**

- Vulnerabilities in the host system, MCP transport layer, or Claude Code itself
- Issues that require attacker control of the scoped-mcp config file or manifest directory
  (those are operator-controlled trust boundaries, not input attack surfaces)
- Theoretical weaknesses without a realistic attack path

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
