# Tool Call Middleware

scoped-mcp supports composable middleware that intercepts every tool invocation.
Middleware runs after scoping is applied and before the tool handler executes.

## Protocol

Each middleware is an async callable implementing `ToolCallMiddleware`:

```python
from scoped_mcp.middleware import ToolCallMiddleware

class MyMiddleware:
    async def __call__(
        self,
        agent_ctx,        # AgentContext — agent_id, agent_type
        tool_name: str,   # namespaced name, e.g. "matrix_send_message"
        kwargs: dict,     # the tool's keyword arguments
        call_next,        # coroutine function — call to continue the chain
    ):
        # before
        result = await call_next()
        # after
        return result
```

> **Important:** Middleware must call `await call_next()` exactly once.
> Omitting the call silently short-circuits the chain — subsequent middleware
> and the tool handler will not run.

> **Note:** `kwargs` is a copy of the original arguments — mutations do not
> propagate to subsequent middleware or the handler. The handler always receives
> the original, unmodified kwargs.

## Composing middleware

Pass a list to `build_server()`. Middleware runs in list order (index 0 is the
outermost wrapper):

```python
from scoped_mcp.middleware import MiddlewareChain
from scoped_mcp.contrib.otel import OtelMiddleware

server = build_server(
    agent_ctx, manifest,
    middleware=[LoggingMiddleware(), OtelMiddleware()],
)
```

With `[LoggingMiddleware, OtelMiddleware]`, execution order is:

```
LoggingMiddleware.before → OtelMiddleware.before → handler → OtelMiddleware.after → LoggingMiddleware.after
```

## OpenTelemetry middleware

`OtelMiddleware` emits one span per tool call. Install the `[otel]` extra:

```bash
pip install scoped-mcp[otel]
```

### Auto-enable via environment variable

`OtelMiddleware` is activated automatically when `OTEL_EXPORTER_OTLP_ENDPOINT`
is set. No code changes needed:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://signoz-host:4317
export OTEL_SERVICE_NAME=scoped-mcp
```

If `OTEL_EXPORTER_OTLP_ENDPOINT` is set but `[otel]` is not installed,
the server starts normally — the OTel dependency is silently skipped.

### Span attributes

| Attribute | Value |
|-----------|-------|
| `scoped_mcp.agent.id` | Agent identifier from `AGENT_ID` env var |
| `scoped_mcp.agent.type` | Agent type from `AGENT_TYPE` env var |
| `scoped_mcp.tool.name` | Full namespaced tool name (e.g. `matrix_send_message`) |
| `scoped_mcp.call.status` | `"ok"` or `"error"` |

Tool arguments (kwargs) are intentionally **not** included in spans to prevent
credentials or sensitive data from being sent to the OTLP collector. Exception
messages in error spans are run through the structlog redaction filter before
being recorded (JWTs, bearer tokens, long hex strings, and GitHub PATs are
replaced with `<redacted-*>` placeholders).

### SigNoz setup

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://signoz-host:4317
export OTEL_SERVICE_NAME=scoped-mcp
# Start scoped-mcp — spans appear in SigNoz automatically
```

### Langfuse setup

Langfuse accepts OTLP traces. Use the Langfuse OTLP endpoint with Basic auth:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.langfuse.com
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic $(echo -n 'pk-lf-...:sk-lf-...' | base64)"
export OTEL_SERVICE_NAME=scoped-mcp
```

> **Note:** When pointing `OTEL_EXPORTER_OTLP_ENDPOINT` at a cloud endpoint,
> span metadata including `agent_id`, `agent_type`, and tool names is sent to
> that service. This is operational metadata, not PII. Tool arguments are never
> included in spans. Store `OTEL_EXPORTER_OTLP_HEADERS` as a credential (e.g.
> in your secrets file) — not in shell history or `.bashrc`.

Tool call spans nest inside LLM trace spans if the calling framework propagates
W3C `traceparent` headers into the MCP session context.

## Writing custom middleware

```python
import structlog

class AuditCountMiddleware:
    """Example: count tool calls by name."""

    def __init__(self):
        self._counts = {}
        self._log = structlog.get_logger()

    async def __call__(self, agent_ctx, tool_name, kwargs, call_next):
        self._counts[tool_name] = self._counts.get(tool_name, 0) + 1
        result = await call_next()
        self._log.info("tool_call_count", tool=tool_name, count=self._counts[tool_name])
        return result
```

## Programmatic use

```python
from scoped_mcp.registry import build_server
from scoped_mcp.contrib.otel import OtelMiddleware

server = build_server(agent_ctx, manifest, middleware=[OtelMiddleware()])
```
