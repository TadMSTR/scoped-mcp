# Custom Module Example: Redis

This directory shows how to write a custom scoped-mcp module.

`redis_tools.py` — a Redis module using `NamespaceScope` to isolate agents into
separate key namespaces. Copy it to `src/scoped_mcp/modules/redis.py` and add
`redis.asyncio` to your dependencies to use it.

## What it demonstrates

- Subclassing `ToolModule`
- Using `NamespaceScope` to isolate agents within a shared Redis instance
- Injecting credentials without exposing them to the agent
- `@tool(mode="read")` vs `@tool(mode="write")` decoration
- Calling `scoping.apply()` and `scoping.enforce()` within tool methods

## Usage in a manifest

```yaml
agent_type: build
modules:
  redis:
    mode: write
    config: {}
```

## Adding to dependencies

```bash
pip install redis[asyncio]
```

Or add to `pyproject.toml`:
```toml
[project.optional-dependencies]
redis = ["redis[asyncio]>=5.0"]
```

## Full walkthrough

See `docs/module-authoring.md` for the complete module authoring guide.
