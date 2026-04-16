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

## Not protected

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
The Matrix module supports unencrypted rooms only (v0.1). No libolm dependency.

**DNS-based SSRF**
The http_proxy SSRF check validates IP addresses at init time but cannot perform DNS resolution without an async context. If a hostname resolves to an internal IP, this is not caught by the proxy — it relies on network-level controls. Run in a restricted network environment for defense in depth.

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
