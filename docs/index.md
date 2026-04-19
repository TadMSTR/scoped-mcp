---
title: scoped-mcp
---

# scoped-mcp

Per-agent scoped MCP tool proxy. One process per agent — loads only the tools that agent's manifest allows, scopes backend resources to that agent's namespace, injects credentials so the agent never sees them, and writes every tool call to a structured audit trail.

```bash
pip install scoped-mcp
```

[GitHub](https://github.com/TadMSTR/scoped-mcp) · [PyPI](https://pypi.org/project/scoped-mcp/)

---

## Documentation

- [Manifest Schema Reference](manifest-schema) — all manifest fields and options
- [Scoping Strategies](scoping-strategies) — PrefixScope, NamespaceScope, and custom strategies
- [Module Authoring Guide](module-authoring) — write a custom tool module
- [Threat Model](threat-model) — security boundaries and assumptions
