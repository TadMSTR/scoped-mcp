---
name: Bug report
about: Something behaves differently from how it is documented
labels: bug
---

<!--
Found a way to make the router ACCEPT a request it should have rejected, or a credential
reaching a log or the database? That is a vulnerability, not a bug — please report it privately:
https://github.com/TadMSTR/scoped-mcp/security/advisories/new
-->

## What happened

## What you expected

## Reproduction

**Your `config.yml`** — redact your secrets, but keep the structure. The `verify` and `dedup`
blocks are usually where the answer is.

```yaml

```

**How the request was sent** (`curl`, or the producer and event type):

```

```

## Relevant log lines

Logs are JSON on stdout. `LOG_LEVEL=DEBUG` gives more. Redact anything sensitive.

```json

```

## Environment

- scoped-mcp version (`pip show scoped-mcp`):
- Python version (`python --version`):
- How you run it (pip, uv, PM2, systemd):
- Transport (stdio or streamable-http):
- `scoped-mcp validate --manifest <your manifest>` output:

<!--
Please attach your manifest with credentials REDACTED. The manifest is almost always the
fastest route to a diagnosis, and `validate` will tell you if the problem is the manifest
itself before anyone has to read it.
-->

## Scoping details, if the report is about access

<!--
Only if the bug is "an agent could reach something it should not" or "an agent cannot reach
something it should". If it is the former, please use the private advisory link at the top of
this template instead of filing a public issue.
-->

- Module and tool involved:
- Agent ID and the value passed:
- Expected: permitted / refused —
