# Module Authoring Guide

How to write a custom scoped-mcp tool module.

## The Contract

A tool module is a Python class that:

1. Subclasses `ToolModule` from `scoped_mcp.modules._base`
2. Declares a unique `name` (used in manifests and as the tool name prefix)
3. Declares a `scoping` strategy (or `None` for modules with no resource scoping)
4. Lists `required_credentials` by key name
5. Implements async methods decorated with `@tool(mode="read")` or `@tool(mode="write")`

The registry does the rest: discovery, instantiation, credential injection, tool registration with FastMCP, and `@audited` wrapping.

## Scope enforcement is your responsibility

`@audited` (applied by the registry) provides structured audit logging only — it does NOT call `scope.enforce()` for you. Every tool method you write MUST either:

1. Call `self.scoping.apply(value, self.agent_ctx)` and/or `self.scoping.enforce(value, self.agent_ctx)` on each argument that addresses a backend resource (paths, keys, bucket names), OR
2. Validate the argument against an explicit allowlist held in `self.config` when the scope is not a transformable value (e.g. a REST service name, a queue topic, a datasource name).

If neither applies to your module, you have no scope boundary and should declare `scoping = None` AND gate access at the credential level (the built-in write-only notifiers — Slack, Discord, ntfy — use this pattern: one credential = one channel).

Every new module MUST ship with at least one test that a cross-agent or out-of-scope argument raises `ScopeViolation` (or the module-specific equivalent) before any backend call is made. See the `test_cross_agent_blocked` pattern below.

## Example: Redis module

```python
# src/scoped_mcp/modules/redis.py
from __future__ import annotations

from typing import ClassVar

from ._base import ToolModule, tool
from ..scoping import NamespaceScope


class RedisModule(ToolModule):
    name: ClassVar[str] = "redis"
    scoping: ClassVar[NamespaceScope] = NamespaceScope()
    required_credentials: ClassVar[list[str]] = ["REDIS_URL"]

    def __init__(self, agent_ctx, credentials, config):
        super().__init__(agent_ctx, credentials, config)
        import redis.asyncio as aioredis
        self._redis = aioredis.from_url(credentials["REDIS_URL"])

    @tool(mode="read")
    async def get_key(self, key: str) -> str | None:
        """Get a value by key (scoped to agent namespace).

        Args:
            key: Key name. Automatically prefixed with '{agent_id}:'.

        Returns:
            Value string, or None if not found.
        """
        scoped_key = self.scoping.apply(key, self.agent_ctx)
        self.scoping.enforce(scoped_key, self.agent_ctx)
        return await self._redis.get(scoped_key)

    @tool(mode="write")
    async def set_key(self, key: str, value: str, ttl: int = 0) -> bool:
        """Set a key-value pair (scoped to agent namespace).

        Args:
            key: Key name. Automatically prefixed with '{agent_id}:'.
            value: String value to store.
            ttl: Optional expiry in seconds (0 = no expiry).

        Returns:
            True on success.
        """
        scoped_key = self.scoping.apply(key, self.agent_ctx)
        self.scoping.enforce(scoped_key, self.agent_ctx)
        return bool(await self._redis.set(scoped_key, value, ex=ttl or None))
```

## Registering the module

The registry discovers subclasses automatically by scanning `scoped_mcp/modules/`. No registration step is needed — just create the file.

Add the module to a manifest:

```yaml
modules:
  redis:
    mode: read
    config: {}
```

For agents that should write: `mode: write`.

## Using config

The `config` dict comes from the manifest's `modules.<name>.config` block.

```yaml
modules:
  redis:
    mode: write
    config:
      db_index: 1
      key_prefix: "custom-"
```

Access in `__init__`:

```python
def __init__(self, agent_ctx, credentials, config):
    super().__init__(agent_ctx, credentials, config)
    self._db = config.get("db_index", 0)
```

## Handling credentials

Declare required credential keys in `required_credentials`. The framework resolves them from the environment (or secrets file) and passes them in the `credentials` dict.

```python
required_credentials: ClassVar[list[str]] = ["REDIS_URL", "REDIS_PASSWORD"]

def __init__(self, agent_ctx, credentials, config):
    super().__init__(agent_ctx, credentials, config)
    self._redis = aioredis.from_url(
        credentials["REDIS_URL"],
        password=credentials["REDIS_PASSWORD"],
    )
```

**Never** pass credential values to the agent in tool responses. The structlog processor redacts keys ending in `_TOKEN`, `_PASSWORD`, `_SECRET`, `_KEY` from audit logs, but tool return values are not sanitized — that's your responsibility.

## Writing tests

Every module needs tests in `tests/test_modules/test_<name>.py`. Minimum coverage:

```python
@pytest.mark.asyncio
async def test_get_key_success(agent_ctx):
    mod = RedisModule(agent_ctx=agent_ctx, credentials={"REDIS_URL": "redis://test"}, config={})
    # ... mock Redis, test happy path

@pytest.mark.asyncio
async def test_cross_agent_blocked(agent_ctx, other_agent_ctx):
    # Verify Agent A cannot access Agent B's keys

@pytest.mark.asyncio
async def test_scope_enforcement(agent_ctx):
    # Verify ScopeViolation raised for out-of-scope keys

def test_credential_not_in_config(agent_ctx):
    mod = RedisModule(...)
    assert "REDIS_URL" not in mod.config
```

## Choosing a scoping strategy

| Backend type | Strategy |
|---|---|
| Filesystem, object storage, any prefix-addressable store | `PrefixScope` |
| Embedded SQL database (SQLite) | Per-agent file — `{db_dir}/agent_{agent_id}.db` |
| Key-value store, message queue, time-series buckets | `NamespaceScope` |
| Webhook (single-channel) | `None` — one credential = one channel |
| REST API with allowlist | Custom — validate against declared services |

`SchemaScope` was removed in the 2026-04-19 cleanup build — do not reference it. See the 2026-04-16 audit (finding C1) for background.

If none of the built-in strategies fit, implement `ScopeStrategy`:

```python
from scoped_mcp.scoping import ScopeStrategy, ScopeViolation
from scoped_mcp.identity import AgentContext

class TenantScope(ScopeStrategy):
    def apply(self, value: str, agent_ctx: AgentContext) -> str:
        return f"tenant/{agent_ctx.agent_id}/{value}"

    def enforce(self, value: str, agent_ctx: AgentContext) -> None:
        prefix = f"tenant/{agent_ctx.agent_id}/"
        if not value.startswith(prefix):
            raise ScopeViolation(
                f"Resource '{value}' is outside tenant scope for '{agent_ctx.agent_id}'"
            )
```
