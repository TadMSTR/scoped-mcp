# Threat Model

What scoped-mcp protects against, and what it doesn't.

## Protected

**Horizontal data access between agents**
Agent A cannot read Agent B's files, database rows, time-series buckets, or Grafana dashboards. Each agent's proxy enforces a scope boundary before any backend I/O.

**Credential exposure to agents**
API keys, passwords, tokens, and webhook URLs are held by the proxy process. They are injected into module constructors at startup and never passed to the agent or included in tool responses. The structlog processor redacts credential-like keys from audit logs.

**Scope mode bypass**
An agent configured with `mode: read` cannot invoke write tools — the registry only registers tools matching the manifest's declared mode.

**Traversal attacks on filesystem paths**
`../` traversal is caught by resolving to an absolute path before comparing against the agent root. Symlinks are followed and the resolved path is checked.

**Cross-agent SQLite access**
Each agent gets its own database file at `{db_dir}/agent_{agent_id}.db` — isolation is a filesystem property, not a SQL property. Two agents cannot read or write each other's data regardless of SQL shape. As defense in depth, sqlglot AST parsing blocks ATTACH, DETACH, PRAGMA, DROP, and multi-statement batches. `create_table` validates column names against `str.isidentifier()` and column types against a closed allowlist.

**SSRF via http_proxy**
Requests to RFC1918 addresses, loopback, link-local, and known cloud metadata endpoints (169.254.169.254) are blocked at proxy init time (base_url validation) and per-request (constructed URL validation).

**Bucket/namespace pollution**
InfluxDB bucket names and other namespaced resources are validated against a per-agent allowlist. Bucket creation adds the agent ID as a prefix.

**HITL self-approval (with `hitl.signing.mode: enforce`)**
A gated call runs only if the pre-approval token carries an Ed25519 statement signed by an
approver key the agent cannot read, bound to this agent, tool, argument hash and approval
id, valid for at most 120 s, and not already used. Writing the state backend, reading
`SCOPED_MCP_HITL_TOKEN`, running `scoped-mcp hitl approve`, or calling
`scoped_mcp_hitl_confirm` produces nothing the proxy accepts. The approver recomputes the
argument hash from the stored arguments before it shows them, so a pending record that
pairs a harmless summary with harmful arguments is refused rather than signed.

## Not protected

### HITL approvals

Signing closes every approval route that only needs *write access to something the agent
can reach*. It does **not** make HITL tamper-proof when the agent shares an OS user with
its proxy:

- **Process substitution.** An agent that can stop the proxy and start a modified copy on
  the same port — with the credentials in an environment file it can read — has no HITL at
  all. Signing cannot help: the verifier is in the process being replaced. The mitigations
  are OS-level: run the proxy under a user the agent is not, from a root-owned install,
  with credentials the agent cannot read.
- **Editable verifier.** If the agent can write the installed package, it can delete the
  check. Install scoped-mcp root-owned (not writable by the agent's user).
- **Replay across processes and restarts.** Replay protection is an in-process set of used
  approval ids, held for the statement's lifetime. A restart clears it, and two processes
  serving the same `agent_id` (for example several stdio sessions) do not share it. Within
  the 120 s lifetime, a consumed statement written back after a restart, or into another
  process for the same agent, approves the same call — same tool, same arguments — once
  more. Restarting the proxy is itself the process-substitution route above.
- **`signing.mode: observe`** accepts unsigned tokens by design. It is a rollout step, not
  a security setting.

**Prompt injection**
If an agent reads malicious content from a tool response (e.g., a file containing `Ignore previous instructions`) and acts on it, scoped-mcp does not prevent this. Use a prompt injection detection layer separately.

**Network-level isolation**
scoped-mcp enforces logical resource boundaries. If two agents run in the same network and one is compromised, it could make direct network calls to backends, bypassing the proxy entirely. For true isolation, run agents in separate network namespaces or containers.

**Compromised proxy process**
If the scoped-mcp process itself is compromised (e.g., via a malicious module loaded from an untrusted source), all credential isolation breaks. Only load modules from trusted sources.

**Unix user isolation**
scoped-mcp runs as a single OS user. An agent that achieves code execution in the proxy process has access to all modules' credentials. For process-level isolation, run each agent's proxy in a separate container.

**Encrypted agent-to-proxy transit**
stdio transport (the default) runs in-process. If you use HTTP/SSE transport, TLS configuration is your responsibility.

**E2EE Matrix messages**
The Matrix module supports unencrypted rooms only. No libolm dependency.

**DNS-based SSRF**
Per-request async DNS resolution (`_resolve_and_check`) validates all resolved IPs before each HTTP call, preventing DNS rebinding attacks where an initially-safe hostname is flipped to an internal IP between requests. The resolved IP is pinned for the connection (`_PinnedHostTransport`) to eliminate the TOCTOU window between validation and the actual TCP connect. This applies only to hostname inputs — literal IPs in `base_url` are validated at init time by `_is_ssrf_target`. The `base_url` is operator-declared; agents control only the `path`. Defense in depth: run in a restricted network environment regardless.

**mcp_proxy loopback access**
Unlike `http_proxy`, `mcp_proxy` does not block loopback or RFC1918 URLs — its purpose is specifically to proxy services running on the local host. The upstream URL or command is operator-declared in the manifest, not user-supplied. Agents can call any tool exposed by the upstream server that passes `tool_allowlist`/`tool_denylist` filtering. If an upstream server has weak input validation, that is not a scoped-mcp concern.

**mcp_proxy schema validation — semantic gap (v0.9)**
v0.9 introduced JSON Schema validation of arguments forwarded through `mcp_proxy`: the upstream tool's declared `inputSchema` is cached at startup and every `tools/call` is validated before forwarding. This catches *shape* and *type* errors — missing required fields, wrong types, out-of-range values declared by the schema, and unknown fields when the schema sets `additionalProperties: false`.

Schema validation does **not** prevent semantic abuse: a syntactically valid argument that exploits the upstream tool's behaviour is forwarded unchanged. A `read_file` tool whose schema accepts any string in `path` will accept `/etc/shadow` if the upstream allows it; schema validation cannot reason about which paths are sensitive. Operators must restrict `mcp_proxy` upstreams to trusted servers and pair schema validation with `tool_allowlist`, `ArgumentFilterMiddleware` rules for known-bad patterns, and (where appropriate) HITL approval on dangerous tools.

A malicious or misconfigured upstream can also serve a permissive `inputSchema` (e.g., `additionalProperties: true`, no required fields, no type constraints) — schema validation accepts whatever the upstream declared. Schema cache refresh respects the operator's `tool_allowlist`/`tool_denylist`, so a refreshed `tools/list` cannot widen the exposed tool surface, but it cannot tighten an already-permissive schema either.

**Argument filter middleware — encoding limits (v0.9)**
`ArgumentFilterMiddleware` inspects top-level string arguments only. Nested structures (dicts, lists) are not walked; operators needing deep inspection should write more specific upstream tool wrappers. Base64 decode is capped at 64 KiB — larger candidates are matched against the raw string only, so a payload buried in a >64 KiB base64 blob can evade decode-aware rules. Operator-supplied regex patterns are trusted; Python's stdlib `re` has no per-match timeout, so a pathological pattern can stall the middleware chain. Review patterns for catastrophic backtracking before deploying.

## Security properties summary

| Property | Enforced by |
|----------|-------------|
| Tool filtering | Registry (manifest-driven) |
| Resource scoping | ScopeStrategy.enforce() via @audited |
| Credential isolation | ToolModule.__init__ + structlog sanitizer |
| Read/write mode | Registry (mode filtering at registration) |
| SQL injection prevention | sqlglot AST validation in sqlite module |
| SSRF prevention | _is_ssrf_target() in http_proxy module |
| Audit trail | @audited decorator (always applied by registry) |
| HITL approval authenticity | Ed25519 statement verified in HitlMiddleware (`hitl.signing.mode: enforce`) |
